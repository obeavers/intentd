//! Portable baseline closure bridge. Intent-store ownership/freshness remains
//! the caller's responsibility after the host returns a durable artifact.

use std::sync::Arc;

use intent_atomic_proto::baselines::BaselineReceipt;
use intent_atomic_proto::closures::{
    BaselineClosure, ClosureProfile, ExportBaselineClosureRequest, RestoreBaselineClosureRequest,
    CLOSURE_FORMAT,
};
use intent_atomic_proto::{Command, HostIdentity, Reply};

use crate::{HostError, HostSupervisor, Result};

pub struct AtomicClosureClient {
    host: Arc<HostSupervisor>,
}

impl AtomicClosureClient {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self { host }
    }

    /// Capture revisions are allocated by the owning Store before this call.
    /// This result is not a committed workspace checkpoint pointer by itself.
    /// # Errors
    /// Returns closure validation, host admission or transport failure.
    pub async fn export(&self, request: ExportBaselineClosureRequest) -> Result<BaselineClosure> {
        let expected = request.clone();
        let Reply::BaselineClosureExported { receipt } = self
            .host
            .request(Command::ExportBaselineClosure { request })
            .await?
        else {
            return Err(HostError::Protocol("expected portable baseline closure"));
        };
        if receipt.format != CLOSURE_FORMAT
            || receipt.profile != ClosureProfile::FrozenBaseline
            || receipt.host != HostIdentity::default()
            || receipt.scope != expected.scope
            || receipt.capture_revision != expected.capture_revision
            || receipt.baseline.baseline != expected.baseline
            || receipt.object_count > 4096
            || receipt.payload.length > 512 * 1024 * 1024
        {
            return Err(HostError::Protocol(
                "portable closure differs from its owner or budget",
            ));
        }
        Ok(receipt)
    }

    /// Restore into a new private native store using retained closure bytes.
    /// # Errors
    /// Refuses a different root epoch, materialization or native state.
    pub async fn restore(&self, request: RestoreBaselineClosureRequest) -> Result<BaselineReceipt> {
        let expected = request.closure.baseline.clone();
        let Reply::BaselineClosureRestored { receipt } = self
            .host
            .request(Command::RestoreBaselineClosure {
                request: Box::new(request),
            })
            .await?
        else {
            return Err(HostError::Protocol(
                "expected restored baseline closure receipt",
            ));
        };
        if receipt != expected {
            return Err(HostError::Protocol(
                "restored baseline differs from captured immutable state",
            ));
        }
        Ok(receipt)
    }
}
