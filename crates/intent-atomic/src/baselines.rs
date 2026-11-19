//! Typed private baseline calls. No Atomic library or native store is opened in
//! the daemon, and host-returned materializations stay inside its configured spool.

use std::path::PathBuf;
use std::sync::Arc;

use intent_atomic_proto::baselines::{
    BaselineMaterialization, BaselineReceipt, BaselineRef, ImportBaselineRequest,
    MaterializeBaselineRequest,
};
use intent_atomic_proto::{Command, HostIdentity, Reply};

use crate::{HostError, HostSupervisor, Result};

pub struct AtomicBaselineClient {
    host: Arc<HostSupervisor>,
    spool_root: PathBuf,
}

impl AtomicBaselineClient {
    /// # Errors
    /// Refuses a nonabsolute owner-supplied spool locator.
    pub fn new(host: Arc<HostSupervisor>, spool_root: PathBuf) -> Result<Self> {
        if !spool_root.is_absolute() {
            return Err(HostError::Configuration(
                "absolute baseline spool is required",
            ));
        }
        Ok(Self { host, spool_root })
    }

    /// # Errors
    /// Returns host refusal/transport errors or a mismatched imported receipt.
    pub async fn import(&self, request: ImportBaselineRequest) -> Result<BaselineReceipt> {
        let expected = request.clone();
        let Reply::BaselineImported { receipt } = self
            .host
            .request(Command::ImportBaseline { request })
            .await?
        else {
            return Err(HostError::Protocol("expected imported baseline receipt"));
        };
        validate_receipt(&receipt)?;
        if receipt.baseline.repository_id != expected.binding.repository_id
            || receipt.baseline.binding_epoch != expected.binding.binding_epoch
            || receipt.source_commit != expected.commit
            || receipt.previous != expected.previous
            || receipt.policy != expected.policy
        {
            return Err(HostError::Protocol(
                "baseline receipt differs from its immutable request",
            ));
        }
        Ok(receipt)
    }

    /// # Errors
    /// Returns changed/missing native state or a mismatched host receipt.
    pub async fn read(&self, baseline: BaselineRef) -> Result<BaselineReceipt> {
        let Reply::Baseline { receipt } = self
            .host
            .request(Command::ReadBaseline {
                baseline: baseline.clone(),
            })
            .await?
        else {
            return Err(HostError::Protocol("expected baseline receipt"));
        };
        validate_receipt(&receipt)?;
        if receipt.baseline != baseline {
            return Err(HostError::Protocol(
                "baseline receipt belongs to another baseline",
            ));
        }
        Ok(receipt)
    }

    /// # Errors
    /// Returns host failure or an output outside the private baseline namespace.
    pub async fn materialize(
        &self,
        request: MaterializeBaselineRequest,
    ) -> Result<BaselineMaterialization> {
        let expected = request.baseline.clone();
        let Reply::BaselineMaterialized { receipt } = self
            .host
            .request(Command::MaterializeBaseline { request })
            .await?
        else {
            return Err(HostError::Protocol(
                "expected private baseline materialization",
            ));
        };
        let parent = receipt.path.parent().ok_or(HostError::Protocol(
            "baseline materialization has no owner namespace",
        ))?;
        if receipt.baseline != expected
            || receipt.path.file_name() != Some(std::ffi::OsStr::new("files"))
            || parent.parent() != Some(self.spool_root.join("baseline-materializations").as_path())
            || !parent
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(hash_valid)
            || !hash_valid(&receipt.materialization_id)
            || !hash_valid(&receipt.manifest_digest)
        {
            return Err(HostError::Protocol(
                "baseline materialization is outside its request or private spool",
            ));
        }
        Ok(receipt)
    }
}

fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn validate_receipt(receipt: &BaselineReceipt) -> Result<()> {
    if receipt.host != HostIdentity::default()
        || receipt.native_state.view.is_empty()
        || receipt.native_state.effective_state.is_empty()
        || receipt.native_state.own_merkle.is_empty()
        || !hash_valid(&receipt.baseline.baseline_id)
        || !hash_valid(&receipt.manifest_digest)
        || !hash_valid(&receipt.materialization_id)
    {
        return Err(HostError::Protocol(
            "baseline receipt has no qualified immutable identity",
        ));
    }
    Ok(())
}
