//! Lazy, single-owner Unix host process. Requests are never automatically replayed.

use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use intent_atomic_proto::{Command, HostIdentity, Reply};
use tokio::{
    net::UnixStream,
    process::Child,
    sync::{Mutex, Semaphore},
    time::Instant,
};

use crate::{
    client::HostClient,
    spool::{ensure_private_directory, Spool},
    HostError, Result,
};

mod lanes;
use lanes::{Client, ControlAttempt, Generation, ReadLease, WireStream, READ_CONNECTIONS};

#[cfg(test)]
mod concurrency_tests;

#[derive(Clone, Debug)]
pub struct HostLaunchConfig {
    /// Explicit bundled or configured binary. Never searched on PATH.
    pub executable: PathBuf,
    pub daemon_data_dir: PathBuf,
    /// Canonical-store parent, normally `<workspacesRoot>/.atomic-stores`.
    pub stores_dir: PathBuf,
    pub identity: HostIdentity,
    pub startup_timeout: Duration,
    pub request_timeout: Duration,
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
}

impl HostLaunchConfig {
    #[must_use]
    pub fn new(executable: PathBuf, daemon_data_dir: PathBuf, stores_dir: PathBuf) -> Self {
        Self {
            executable,
            daemon_data_dir,
            stores_dir,
            identity: HostIdentity::default(),
            startup_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(100),
            maximum_backoff: Duration::from_secs(5),
        }
    }
}

struct RestartBackoff {
    next_start: Option<Instant>,
    delay: Duration,
    initial: Duration,
    maximum: Duration,
}

impl RestartBackoff {
    fn new(initial: Duration, maximum: Duration) -> Self {
        Self {
            next_start: None,
            delay: initial,
            initial,
            maximum,
        }
    }

    fn failed(&mut self, now: Instant) {
        self.next_start = Some(now + self.delay);
        self.delay = self.delay.saturating_mul(2).min(self.maximum);
    }

    fn ready(&mut self) {
        self.next_start = None;
        self.delay = self.initial;
    }

    fn admits(&self, now: Instant) -> bool {
        self.next_start.is_none_or(|deadline| now >= deadline)
    }
}

struct Runtime {
    shutting_down: bool,
    owner_lock: Option<File>,
    child: Option<Child>,
    generation: Option<Arc<Generation>>,
    backoff: RestartBackoff,
    #[cfg(test)]
    injected_transport: bool,
}

pub struct HostSupervisor {
    config: HostLaunchConfig,
    runtime: Mutex<Runtime>,
    read_slots: Arc<Semaphore>,
    shutting_down: AtomicBool,
}

impl HostSupervisor {
    /// Create inert supervision state; does not touch the filesystem or spawn a host.
    /// # Errors
    /// Refuses relative locations, zero deadlines and invalid restart bounds.
    pub fn new(config: HostLaunchConfig) -> Result<Self> {
        if !config.executable.is_absolute()
            || !config.daemon_data_dir.is_absolute()
            || !config.stores_dir.is_absolute()
            || config.startup_timeout.is_zero()
            || config.request_timeout.is_zero()
            || config.initial_backoff.is_zero()
            || config.maximum_backoff < config.initial_backoff
        {
            return Err(HostError::Configuration(
                "absolute paths and bounded nonzero deadlines are required",
            ));
        }
        let runtime = Runtime {
            shutting_down: false,
            owner_lock: None,
            child: None,
            generation: None,
            backoff: RestartBackoff::new(config.initial_backoff, config.maximum_backoff),
            #[cfg(test)]
            injected_transport: false,
        };
        Ok(Self {
            config,
            runtime: Mutex::new(runtime),
            read_slots: Arc::new(Semaphore::new(READ_CONNECTIONS)),
            shutting_down: AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.owner_dir().join("host.sock")
    }

    #[must_use]
    pub fn spool_path(&self) -> PathBuf {
        self.owner_dir().join("spool")
    }

    fn owner_dir(&self) -> PathBuf {
        self.config.daemon_data_dir.join("atomic")
    }

    /// Whether the current connection has completed recovery. This never starts a host.
    pub async fn recovery_ready(&self) -> bool {
        self.runtime
            .lock()
            .await
            .generation
            .as_ref()
            .is_some_and(|generation| generation.ready())
    }

    /// Lazily connect, handshake and reconcile, then send the caller's request once.
    /// A dropped/expired waiter does not kill a running host or release its spool.
    /// # Errors
    /// Reports startup, identity, recovery, transport and typed host errors. A
    /// disconnected or timed-out request is never silently resubmitted.
    pub async fn request(&self, command: Command) -> Result<Reply> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(HostError::ShuttingDown);
        }
        if matches!(command, Command::Handshake { .. }) {
            return Err(HostError::Protocol(
                "handshake is only valid on connection setup",
            ));
        }
        if matches!(command, Command::Shutdown) {
            self.shutdown().await?;
            return Ok(Reply::Shutdown);
        }
        let generation = {
            let mut runtime = self.runtime.lock().await;
            if runtime.shutting_down || self.shutting_down.load(Ordering::Acquire) {
                return Err(HostError::ShuttingDown);
            }
            self.ensure_connected(&mut runtime).await?
        };
        let preserves_known_effect = matches!(
            command,
            Command::AdmitExactRecord { .. }
                | Command::BeginNativeSession { .. }
                | Command::CloseNativeSession { .. }
        );
        let result = if lanes::read_only(&command) {
            self.read_request(&generation, command).await
        } else {
            self.control_request(&generation, command).await
        };
        // A validated record/session response is an immutable physical effect, not
        // a claim that this generation/root/task remains current. Retain it
        // across shutdown or replacement so its owner can persist the fact
        // before independently fencing any later task/source transition.
        if preserves_known_effect
            && matches!(
                result,
                Ok(Reply::ExactRecordAdmitted { .. }
                    | Reply::NativeSessionBegan { .. }
                    | Reply::NativeSessionClosed { .. })
            )
        {
            return result;
        }
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(HostError::ShuttingDown);
        }
        let runtime = self.runtime.lock().await;
        if generation.stopped()
            || !runtime
                .generation
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &generation))
        {
            return Err(HostError::ConnectionUncertain);
        }
        result
    }

    #[cfg(test)]
    pub(crate) async fn with_test_transport(
        config: HostLaunchConfig,
        control: tokio::io::DuplexStream,
        readers: Vec<tokio::io::DuplexStream>,
    ) -> Result<Self> {
        let control = HostClient::connect(WireStream::Duplex(control), &config.identity).await?;
        if readers.len() != READ_CONNECTIONS {
            return Err(HostError::Configuration(
                "test transport requires the complete reader pool",
            ));
        }
        let mut connected = Vec::with_capacity(READ_CONNECTIONS);
        for reader in readers {
            let reader = HostClient::connect(WireStream::Duplex(reader), &config.identity).await?;
            if !reader.recovery_ready() {
                return Err(HostError::RecoveryRequired);
            }
            connected.push(reader);
        }
        let supervisor = Self::new(config)?;
        {
            let mut runtime = supervisor.runtime.lock().await;
            runtime.generation = Some(Arc::new(Generation::new(control, connected)));
            runtime.injected_transport = true;
        }
        Ok(supervisor)
    }

    /// Shut down the daemon-owned host and reap it, retaining all spool files.
    /// # Errors
    /// Returns process wait/kill failures. Uncertain native work is reconciled on restart.
    pub async fn shutdown(&self) -> Result<()> {
        self.shutting_down.store(true, Ordering::Release);
        self.read_slots.close();
        let mut runtime = self.runtime.lock().await;
        runtime.shutting_down = true;
        if let Some(generation) = runtime.generation.take() {
            generation.stop();
            let mut control = generation.control.lock().await;
            if let Some(client) = control.as_mut().filter(|client| client.is_usable()) {
                let _ = tokio::time::timeout(
                    self.config.request_timeout,
                    client.request(Command::Shutdown),
                )
                .await;
            }
            *control = None;
        }
        if let Some(mut child) = runtime.child.take() {
            if let Ok(status) =
                tokio::time::timeout(self.config.request_timeout, child.wait()).await
            {
                status?;
            } else {
                child.kill().await?;
                child.wait().await?;
            }
        }
        runtime.owner_lock = None;
        Ok(())
    }

    async fn ensure_connected(&self, runtime: &mut Runtime) -> Result<Arc<Generation>> {
        if let Some(child) = runtime.child.as_mut() {
            if child.try_wait()?.is_some() {
                runtime.child = None;
                if let Some(generation) = runtime.generation.take() {
                    generation.stop();
                }
                runtime.backoff.failed(Instant::now());
                return Err(HostError::Exited);
            }
        }
        let missing_child = runtime.child.is_none();
        #[cfg(test)]
        let missing_child = missing_child && !runtime.injected_transport;
        if missing_child && runtime.generation.is_some() {
            if let Some(generation) = runtime.generation.take() {
                generation.stop();
            }
            runtime.backoff.failed(Instant::now());
            return Err(HostError::Exited);
        }
        if let Some(generation) = runtime
            .generation
            .as_ref()
            .filter(|generation| !generation.stopped())
        {
            return Ok(generation.clone());
        }
        runtime.generation = None;
        if !runtime.backoff.admits(Instant::now()) {
            return Err(HostError::Backoff);
        }
        if runtime.child.is_none() {
            self.spawn(runtime)?;
        }
        let deadline = Instant::now() + self.config.startup_timeout;
        loop {
            if self.shutting_down.load(Ordering::Acquire) {
                return Err(HostError::ShuttingDown);
            }
            if runtime
                .child
                .as_mut()
                .ok_or(HostError::Exited)?
                .try_wait()?
                .is_some()
            {
                runtime.child = None;
                runtime.backoff.failed(Instant::now());
                return Err(HostError::Exited);
            }
            if Instant::now() >= deadline {
                runtime.backoff.failed(Instant::now());
                return Err(HostError::StartupTimeout);
            }
            match UnixStream::connect(self.socket_path()).await {
                Ok(stream) => {
                    validate_socket(&self.socket_path())?;
                    let attempt =
                        HostClient::connect(WireStream::Unix(stream), &self.config.identity);
                    match tokio::time::timeout_at(deadline, attempt).await {
                        Ok(Ok(client)) => {
                            let readers = if client.recovery_ready() {
                                self.warm_readers(deadline).await?
                            } else {
                                Vec::new()
                            };
                            if self.shutting_down.load(Ordering::Acquire) {
                                return Err(HostError::ShuttingDown);
                            }
                            let generation = Arc::new(Generation::new(client, readers));
                            runtime.generation = Some(generation.clone());
                            runtime.backoff.ready();
                            return Ok(generation);
                        }
                        Ok(Err(error)) => {
                            runtime.backoff.failed(Instant::now());
                            return Err(error);
                        }
                        Err(_) => {
                            runtime.backoff.failed(Instant::now());
                            return Err(HostError::StartupTimeout);
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep_until(
                        (Instant::now() + Duration::from_millis(25)).min(deadline),
                    )
                    .await;
                }
                Err(error) => {
                    runtime.backoff.failed(Instant::now());
                    return Err(error.into());
                }
            }
        }
    }

    async fn connect_client(&self, deadline: Instant) -> Result<Client> {
        let attempt = async {
            let stream = UnixStream::connect(self.socket_path()).await?;
            validate_socket(&self.socket_path())?;
            HostClient::connect(WireStream::Unix(stream), &self.config.identity).await
        };
        tokio::time::timeout_at(deadline, attempt)
            .await
            .map_err(|_| HostError::StartupTimeout)?
    }

    async fn warm_readers(&self, deadline: Instant) -> Result<Vec<Client>> {
        let mut readers = Vec::with_capacity(READ_CONNECTIONS);
        // Host sessions require their own identity handshake and recovery.
        // Warm them while quiescent, never once per ordinary read request.
        for _ in 0..READ_CONNECTIONS {
            let reader = self.connect_client(deadline).await?;
            if !reader.recovery_ready() {
                return Err(HostError::RecoveryRequired);
            }
            readers.push(reader);
        }
        Ok(readers)
    }

    async fn recover_connections(
        &self,
        generation: &Generation,
        control: &mut Option<Client>,
    ) -> Result<()> {
        if generation.stopped() {
            return Err(HostError::ConnectionUncertain);
        }
        generation.reconnect();
        generation.discard_readers();
        let deadline = Instant::now() + self.config.startup_timeout;
        if control.as_ref().is_none_or(|client| !client.is_usable()) {
            *control = None;
            *control = Some(self.connect_client(deadline).await?);
        } else {
            let client = control.as_mut().ok_or(HostError::ConnectionUncertain)?;
            let attempt = ControlAttempt::new(generation);
            let result = self.send_once(client, Command::Reconcile).await;
            attempt.finish(client, &result);
            result?;
        }
        if !control.as_ref().is_some_and(HostClient::recovery_ready) {
            generation.block();
            return Err(HostError::RecoveryRequired);
        }
        let readers = self.warm_readers(deadline).await?;
        generation.install_readers(readers)
    }

    async fn send_once(&self, client: &mut Client, command: Command) -> Result<Reply> {
        tokio::time::timeout(self.config.request_timeout, client.request(command))
            .await
            .unwrap_or(Err(HostError::RequestTimeout))
    }

    async fn read_request(&self, generation: &Arc<Generation>, command: Command) -> Result<Reply> {
        let slot = self
            .read_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| HostError::ShuttingDown)?;
        let mut slot = Some(slot);
        loop {
            if generation.stopped() {
                return Err(HostError::ConnectionUncertain);
            }
            if generation.blocked() {
                return Err(HostError::RecoveryRequired);
            }
            let admission = generation.admission.clone().read_owned().await;
            if generation.ready() {
                if let Some(client) = generation.take_reader()? {
                    let mut lease = ReadLease::new(
                        generation.clone(),
                        client,
                        admission,
                        slot.take().ok_or(HostError::ConnectionUncertain)?,
                    );
                    let client = lease
                        .client
                        .as_mut()
                        .ok_or(HostError::ConnectionUncertain)?;
                    let result = self.send_once(client, command).await;
                    if client.is_usable() && !client.recovery_ready() {
                        generation.block();
                    }
                    if generation.stopped() {
                        return Err(HostError::ConnectionUncertain);
                    }
                    if generation.blocked() {
                        return Err(HostError::RecoveryRequired);
                    }
                    if !generation.ready() {
                        return Err(HostError::ConnectionUncertain);
                    }
                    return result;
                }
            }
            drop(admission);
            // A depleted/poisoned stream is replaced only after the active
            // control operation and reads finish. Healthy warm leases continue
            // to serve alongside that control operation in the meantime.
            let mut control = generation.control.lock().await;
            let _quiescent = generation.admission.write().await;
            if generation.blocked() {
                return Err(HostError::RecoveryRequired);
            }
            if !generation.ready() || generation.idle_count()? == 0 {
                self.recover_connections(generation, &mut control).await?;
            }
        }
    }

    async fn control_request(
        &self,
        generation: &Arc<Generation>,
        command: Command,
    ) -> Result<Reply> {
        let mut control = generation.control.lock().await;
        if matches!(command, Command::Reconcile) {
            let _quiescent = generation.admission.write().await;
            if generation.stopped() {
                return Err(HostError::ConnectionUncertain);
            }
            generation.reconnect();
            generation.discard_readers();
            if control.as_ref().is_none_or(|client| !client.is_usable()) {
                *control = None;
                *control = Some(
                    self.connect_client(Instant::now() + self.config.startup_timeout)
                        .await?,
                );
            }
            let client = control.as_mut().ok_or(HostError::ConnectionUncertain)?;
            let attempt = ControlAttempt::new(generation);
            let result = self.send_once(client, command).await;
            attempt.finish(client, &result);
            if result.is_ok() && client.recovery_ready() {
                let readers = self
                    .warm_readers(Instant::now() + self.config.startup_timeout)
                    .await?;
                generation.install_readers(readers)?;
            }
            return result;
        }
        if generation.blocked() && command.requires_recovery() {
            return Err(HostError::RecoveryRequired);
        }
        if control.as_ref().is_none_or(|client| !client.is_usable())
            || !generation.ready() && !generation.blocked()
        {
            let _quiescent = generation.admission.write().await;
            self.recover_connections(generation, &mut control).await?;
        }
        let _admission = generation.admission.read().await;
        if generation.stopped() {
            return Err(HostError::ConnectionUncertain);
        }
        if command.requires_recovery() && !generation.ready() {
            return Err(HostError::RecoveryRequired);
        }
        let client = control.as_mut().ok_or(HostError::ConnectionUncertain)?;
        let attempt = ControlAttempt::new(generation);
        let result = self.send_once(client, command).await;
        attempt.finish(client, &result);
        result
    }

    fn spawn(&self, runtime: &mut Runtime) -> Result<()> {
        ensure_private_directory(&self.owner_dir())?;
        let config_dir = self.owner_dir().join("config");
        ensure_private_directory(&config_dir)?;
        let _spool = Spool::open(&self.spool_path())?;
        if runtime.owner_lock.is_none() {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.owner_dir().join("host.lock"))?;
            let metadata = lock.metadata()?;
            // SAFETY: geteuid has no arguments; flock is called on this owned descriptor.
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(HostError::Configuration(
                    "host lock must be an owner-private regular file",
                ));
            }
            // SAFETY: the file descriptor remains alive for the supervisor and its child.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(HostError::OwnerBusy);
            }
            runtime.owner_lock = Some(lock);
        }
        let socket_path = self.socket_path();
        if socket_path.try_exists()? {
            validate_socket(&socket_path)?;
            std::fs::remove_file(&socket_path)?;
        }
        let owner_fd = runtime
            .owner_lock
            .as_ref()
            .ok_or(HostError::OwnerBusy)?
            .as_raw_fd();
        let mut command = tokio::process::Command::new(&self.config.executable);
        command
            .env_clear()
            .env("ATOMIC_CONFIG_DIR", &config_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--spool-dir")
            .arg(self.spool_path())
            .arg("--config-dir")
            .arg(&config_dir)
            .arg("--stores-dir")
            .arg(&self.config.stores_dir)
            .arg("--owner-lock-fd")
            .arg(owner_fd.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // SAFETY: pre_exec only invokes async-signal-safe fcntl. Keeping the same
        // flock descriptor alive in the host prevents a second owner after a
        // daemon crash until the old host has actually exited.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(owner_fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        match command.spawn() {
            Ok(child) => {
                runtime.child = Some(child);
                Ok(())
            }
            Err(error) => {
                runtime.backoff.failed(Instant::now());
                Err(error.into())
            }
        }
    }
}

fn validate_socket(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and does not access Rust memory.
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(HostError::Configuration(
            "host socket must be owner-private and not a symlink",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_delays_are_bounded_and_only_success_resets_them() {
        let start = Instant::now();
        let mut backoff = RestartBackoff::new(Duration::from_millis(10), Duration::from_millis(40));
        for milliseconds in [10, 20, 40, 40] {
            backoff.failed(start);
            assert!(!backoff.admits(start + Duration::from_millis(milliseconds - 1)));
            assert!(backoff.admits(start + Duration::from_millis(milliseconds)));
        }
        backoff.ready();
        backoff.failed(start);
        assert!(backoff.admits(start + Duration::from_millis(10)));
    }

    #[tokio::test]
    async fn shutdown_permanently_fences_requests_without_starting_an_inert_host() {
        let temp = tempfile::tempdir().unwrap();
        let supervisor = HostSupervisor::new(HostLaunchConfig::new(
            temp.path().join("not-executed"),
            temp.path().join("data"),
            temp.path().join("stores"),
        ))
        .unwrap();
        supervisor.shutdown().await.unwrap();
        assert!(matches!(
            supervisor.request(Command::Ping).await,
            Err(HostError::ShuttingDown)
        ));
        assert!(!temp.path().join("data").exists());
        assert!(!temp.path().join("stores").exists());
    }

    #[tokio::test]
    async fn construction_is_lazy_and_real_early_exit_backs_off() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = HostLaunchConfig::new(
            PathBuf::from("/usr/bin/false"),
            temp.path().to_owned(),
            temp.path().join("stores"),
        );
        config.initial_backoff = Duration::from_secs(60);
        config.maximum_backoff = Duration::from_secs(60);
        let supervisor = HostSupervisor::new(config.clone()).unwrap();
        assert!(!temp.path().join("atomic").exists());
        // Exercise a real failed child without relying on socket creation,
        // which some development hosts deny even for disposable local paths.
        let mut runtime = supervisor.runtime.lock().await;
        supervisor.spawn(&mut runtime).unwrap();
        assert!(!runtime
            .child
            .as_mut()
            .unwrap()
            .wait()
            .await
            .unwrap()
            .success());
        drop(runtime);
        let second = HostSupervisor::new(config).unwrap();
        let mut second_runtime = second.runtime.lock().await;
        assert!(matches!(
            second.spawn(&mut second_runtime),
            Err(HostError::OwnerBusy)
        ));
        drop(second_runtime);
        assert!(matches!(
            supervisor.request(Command::Ping).await,
            Err(HostError::Exited)
        ));
        assert!(matches!(
            supervisor.request(Command::Ping).await,
            Err(HostError::Backoff)
        ));
        supervisor.shutdown().await.unwrap();
    }
}
