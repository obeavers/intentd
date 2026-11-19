//! Connection ownership for one host process generation. Normal reads and the
//! control lane share admission; connection recovery requires quiescence.

use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use intent_atomic_proto::{Command, FailureCode, Reply};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock};

use crate::{HostClient, HostError, Result};

pub(super) const READ_CONNECTIONS: usize = 4;
const READY: u8 = 0;
const RECONNECT: u8 = 1;
const BLOCKED: u8 = 2;
const STOPPED: u8 = 3;

pub(super) enum WireStream {
    Unix(UnixStream),
    #[cfg(test)]
    Duplex(tokio::io::DuplexStream),
}

impl AsyncRead for WireStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buffer),
            #[cfg(test)]
            Self::Duplex(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for WireStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, bytes),
            #[cfg(test)]
            Self::Duplex(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(test)]
            Self::Duplex(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(test)]
            Self::Duplex(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(super) type Client = HostClient<WireStream>;

pub(super) struct Generation {
    pub(super) control: Mutex<Option<Client>>,
    pub(super) admission: Arc<RwLock<()>>,
    idle: StdMutex<Vec<Client>>,
    readiness: AtomicU8,
}

impl Generation {
    pub(super) fn new(control: Client, readers: Vec<Client>) -> Self {
        let ready = control.recovery_ready() && readers.len() == READ_CONNECTIONS;
        Self {
            control: Mutex::new(Some(control)),
            admission: Arc::new(RwLock::new(())),
            idle: StdMutex::new(readers),
            readiness: AtomicU8::new(if ready { READY } else { BLOCKED }),
        }
    }

    pub(super) fn stopped(&self) -> bool {
        self.readiness.load(Ordering::Acquire) == STOPPED
    }
    pub(super) fn ready(&self) -> bool {
        self.readiness.load(Ordering::Acquire) == READY
    }
    pub(super) fn blocked(&self) -> bool {
        self.readiness.load(Ordering::Acquire) == BLOCKED
    }
    pub(super) fn stop(&self) {
        self.readiness.store(STOPPED, Ordering::Release);
        self.discard_readers();
    }
    fn set(&self, state: u8) {
        let _ = self
            .readiness
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current != STOPPED).then_some(state)
            });
    }
    pub(super) fn block(&self) {
        self.set(BLOCKED);
    }
    pub(super) fn reconnect(&self) {
        self.set(RECONNECT);
    }
    pub(super) fn mark_ready(&self) {
        self.set(READY);
    }
    pub(super) fn idle_count(&self) -> Result<usize> {
        self.idle
            .lock()
            .map(|idle| idle.len())
            .map_err(|_| HostError::Configuration("read pool lock poisoned"))
    }
    pub(super) fn take_reader(&self) -> Result<Option<Client>> {
        Ok(self
            .idle
            .lock()
            .map_err(|_| HostError::Configuration("read pool lock poisoned"))?
            .pop())
    }
    pub(super) fn discard_readers(&self) {
        if let Ok(mut idle) = self.idle.lock() {
            idle.clear();
        }
    }
    pub(super) fn install_readers(&self, readers: Vec<Client>) -> Result<()> {
        if readers.len() != READ_CONNECTIONS
            || readers
                .iter()
                .any(|reader| !reader.is_usable() || !reader.recovery_ready())
        {
            return Err(HostError::RecoveryRequired);
        }
        let mut idle = self
            .idle
            .lock()
            .map_err(|_| HostError::Configuration("read pool lock poisoned"))?;
        if self.stopped() {
            return Err(HostError::ConnectionUncertain);
        }
        *idle = readers;
        self.mark_ready();
        Ok(())
    }

    pub(super) fn observe(&self, client: &Client, result: &Result<Reply>) {
        if matches!(result, Err(HostError::Rejected(failure)) if matches!(failure.code, FailureCode::Uncertain | FailureCode::RecoveryRequired))
            || client.is_usable() && !client.recovery_ready()
        {
            self.block();
        } else if !client.is_usable() {
            self.reconnect();
        }
    }
}

pub(super) fn read_only(command: &Command) -> bool {
    command.is_read_only()
}

/// A cancelled request leaves its client poisoned. Only that stream is dropped;
/// another already-admitted read or control operation keeps its own connection.
pub(super) struct ReadLease {
    generation: Arc<Generation>,
    pub(super) client: Option<Client>,
    _admission: OwnedRwLockReadGuard<()>,
    _slot: OwnedSemaphorePermit,
}

impl ReadLease {
    pub(super) fn new(
        generation: Arc<Generation>,
        client: Client,
        admission: OwnedRwLockReadGuard<()>,
        slot: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            generation,
            client: Some(client),
            _admission: admission,
            _slot: slot,
        }
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        if let Some(client) = self
            .client
            .take()
            .filter(|client| client.is_usable() && client.recovery_ready())
        {
            if let Ok(mut idle) = self.generation.idle.lock() {
                if self.generation.ready() {
                    idle.push(client);
                }
            }
        }
    }
}

pub(super) struct ControlAttempt<'a> {
    generation: &'a Generation,
    completed: bool,
}
impl<'a> ControlAttempt<'a> {
    pub(super) fn new(generation: &'a Generation) -> Self {
        Self {
            generation,
            completed: false,
        }
    }
    pub(super) fn finish(mut self, client: &Client, result: &Result<Reply>) {
        self.generation.observe(client, result);
        self.completed = true;
    }
}
impl Drop for ControlAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.generation.reconnect();
        }
    }
}
