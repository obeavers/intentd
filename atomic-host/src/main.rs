#[cfg(not(unix))]
fn main() {
    eprintln!("intent-atomic-host is available only on qualified Unix hosts");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() {
    if let Err(error) = run() {
        eprintln!("intent-atomic-host: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::Shutdown;
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    };
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use intent_atomic_host::{transport::serve_frame, Host, HostConfig, Session};

    let mut arguments = std::env::args_os().skip(1);
    let (mut socket, mut stores, mut spool, mut config, mut owner_fd) =
        (None, None, None, None, None);
    while let Some(flag) = arguments.next() {
        let value = PathBuf::from(arguments.next().ok_or("missing argument value")?);
        let field = match flag.to_str() {
            Some("--socket") => &mut socket,
            Some("--stores-dir") => &mut stores,
            Some("--spool-dir") => &mut spool,
            Some("--config-dir") => &mut config,
            Some("--owner-lock-fd") => &mut owner_fd,
            _ => return Err("unknown argument".into()),
        };
        if field.replace(value).is_some() {
            return Err("duplicate argument".into());
        }
    }
    let socket = socket.ok_or("--socket is required")?;
    let stores_dir = stores.ok_or("--stores-dir is required")?;
    let spool_dir = spool.ok_or("--spool-dir is required")?;
    let config_dir = config.ok_or("--config-dir is required")?;
    let owner_fd: i32 = owner_fd
        .ok_or("--owner-lock-fd is required; unsupervised launch is refused")?
        .to_str()
        .ok_or("invalid owner descriptor")?
        .parse()?;
    let owner_parent = config_dir
        .parent()
        .ok_or("configuration needs an owner directory")?;
    let _owner = retain_owner(owner_fd, &owner_parent.join("host.lock"))?;
    if socket.parent() != Some(owner_parent) {
        return Err("socket must be inside the daemon-owned Atomic directory".into());
    }
    if !socket.is_absolute() {
        return Err("socket must be absolute".into());
    }
    if std::env::var_os("ATOMIC_CONFIG_DIR").as_deref() != Some(config_dir.as_os_str()) {
        return Err("ATOMIC_CONFIG_DIR must name the daemon-owned configuration directory".into());
    }
    let host = Arc::new(Host::new(HostConfig {
        stores_dir,
        config_dir,
        spool_dir,
    })?);
    // The supervisor owns and validates stale socket cleanup. Never remove an
    // arbitrary pre-existing path merely because bind fails.
    let listener = UnixListener::bind(&socket)
        .map_err(|error| format!("bind private host IPC socket: {error}"))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let socket_identity = std::fs::symlink_metadata(&socket)?;
    let quit = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for stream in listener.incoming() {
        let stream = stream?;
        if quit.load(Ordering::SeqCst) {
            break;
        }
        // Keep only live connection controls. Finished clients must not consume
        // descriptors until the host next shuts down.
        workers.retain(|(_, worker): &(UnixStream, std::thread::JoinHandle<()>)| {
            !worker.is_finished()
        });
        let Ok(control) = stream.try_clone() else {
            continue;
        };
        let host = host.clone();
        let quit = quit.clone();
        let socket = socket.clone();
        workers.push((
            control,
            std::thread::spawn(move || {
                let mut session = Session::default();
                let mut reader = stream;
                let Ok(mut writer) = reader.try_clone() else {
                    return;
                };
                loop {
                    if quit.load(Ordering::SeqCst) {
                        break;
                    }
                    match serve_frame(&host, &mut session, &mut reader, &mut writer) {
                        Ok(Some(false)) => {}
                        Ok(Some(true)) => {
                            quit.store(true, Ordering::SeqCst);
                            let _ = UnixStream::connect(socket);
                            break;
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }),
        ));
    }
    // Connections admitted before Shutdown must finish. No running worker or
    // native handle is released just because a caller detaches its waiter.
    // Wake idle or partially framed readers. Shutting down only their read half
    // does not cancel an admitted handler or prevent its final response.
    for (control, _) in &workers {
        let _ = control.shutdown(Shutdown::Read);
    }
    for (_, worker) in workers {
        let _ = worker.join();
    }
    let current_socket = std::fs::symlink_metadata(&socket)?;
    if !current_socket.file_type().is_socket()
        || current_socket.dev() != socket_identity.dev()
        || current_socket.ino() != socket_identity.ino()
    {
        return Err("host socket changed while it was serving; replacement left intact".into());
    }
    std::fs::remove_file(socket)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn stopping_reads_releases_idle_connections_without_cancelling_response_writes() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let control = server.try_clone().unwrap();
        let (started, ready) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            let mut frame = [0; 4];
            assert_eq!(server.read(&mut frame).unwrap(), 0);
            server.write_all(b"finished").unwrap();
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        control.shutdown(Shutdown::Read).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"finished");
        worker.join().unwrap();
    }
}

#[cfg(unix)]
fn retain_owner(
    fd: i32,
    path: &std::path::Path,
) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use std::os::{fd::FromRawFd, unix::fs::MetadataExt};
    if fd < 3 {
        return Err("invalid inherited owner descriptor".into());
    }
    // SAFETY: fcntl validates the raw OS descriptor before constructing its Rust
    // owner. Startup is single-threaded, so no other worker can close it here.
    if unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the supervisor transferred one inherited descriptor to this
    // process. From this point File owns exactly that descriptor until exit.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let expected = std::fs::symlink_metadata(path)?;
    let actual = file.metadata()?;
    if !expected.is_file()
        || expected.mode() & 0o077 != 0
        || expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
    {
        return Err("owner descriptor does not name the private daemon host lock".into());
    }
    // A flock on the inherited open-file description confirms/acquires the same
    // owner lock; it is never explicitly unlocked while the host is running.
    if unsafe { nix::libc::flock(fd, nix::libc::LOCK_EX | nix::libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let flags = FdFlag::from_bits_truncate(fcntl(&file, FcntlArg::F_GETFD)?);
    fcntl(&file, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(file)
}
