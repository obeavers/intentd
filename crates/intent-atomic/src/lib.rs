//! The daemon side of the isolated Atomic process boundary.
//!
//! Nothing here links Atomic, discovers a user installation, or opens native
//! stores. The engine remains unavailable until native mechanics are qualified.

#[cfg(unix)]
pub mod baselines;
#[cfg(unix)]
pub mod checkpoint;
pub mod client;
#[cfg(unix)]
pub mod closures;
pub mod codec;
#[cfg(unix)]
pub mod composition;
#[cfg(unix)]
pub mod engine;
pub mod execution;
#[cfg(unix)]
pub mod execution_lease;
#[cfg(unix)]
pub mod intents;
#[cfg(unix)]
pub mod knowledge;
#[cfg(unix)]
pub mod native_work;
#[cfg(unix)]
pub mod provenance;
#[cfg(unix)]
pub mod recorded_closures;
#[cfg(unix)]
pub mod recording;
pub mod sealed_record_source;
#[cfg(unix)]
pub mod spool;
#[cfg(unix)]
pub mod supervisor;
#[cfg(unix)]
pub mod triage;

pub use client::HostClient;
#[cfg(unix)]
pub use engine::AtomicWorkspaceEngine;
#[cfg(unix)]
pub use supervisor::{HostLaunchConfig, HostSupervisor};

use intent_atomic_proto::HostFailure;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("Atomic host I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Atomic host JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid Atomic host frame length: {0}")]
    FrameLength(usize),
    #[error("Atomic host identity mismatch")]
    IdentityMismatch,
    #[error("Atomic host protocol violation: {0}")]
    Protocol(&'static str),
    #[error("Atomic host recovery is incomplete")]
    RecoveryRequired,
    #[error("Atomic host connection outcome is uncertain; reconnect and reconcile")]
    ConnectionUncertain,
    #[error("Atomic host rejected the request: {0:?}")]
    Rejected(HostFailure),
    #[error("invalid Atomic spool reference: {0}")]
    InvalidSpool(&'static str),
    #[error("Atomic host restart is backing off")]
    Backoff,
    #[error("Atomic host did not become ready before its deadline")]
    StartupTimeout,
    #[error("Atomic host exited before becoming ready")]
    Exited,
    #[error("Atomic host request timed out; reconcile its outcome before retrying")]
    RequestTimeout,
    #[error("invalid Atomic host configuration: {0}")]
    Configuration(&'static str),
    #[error("another Atomic host owner holds the daemon lock")]
    OwnerBusy,
    #[error("Atomic host supervision is shutting down")]
    ShuttingDown,
}

pub type Result<T> = std::result::Result<T, HostError>;
