//! Owned private recorded-view closure exchanges. No Atomic libraries, native
//! store access, automatic request replay or canonical workspace installation.

use std::io::Read;
use std::sync::Arc;

use intent_atomic_proto::recorded_closures::{
    ExportRecordedClosureRequest, RecordedClosure, RecordedClosureProfile, RecordedClosureRestore,
    RestoreRecordedClosureRequest, RECORDED_CLOSURE_FORMAT, RECORDED_CLOSURE_READER,
};
use intent_atomic_proto::{Command, HostIdentity, Reply, SpoolRef};
use sha2::{Digest, Sha256};

use crate::{spool::Spool, HostError, HostSupervisor, Result};

const MAX_PAYLOAD: u64 = 512 * 1024 * 1024;
const MAX_ENVELOPE: u64 = 48 * 1024;

fn digest(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn safe_view(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with("wc/")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./".contains(&byte))
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

#[derive(Clone)]
pub struct OwnedRecordedClosureExport {
    request: ExportRecordedClosureRequest,
    envelope: SpoolRef,
}
impl OwnedRecordedClosureExport {
    #[must_use]
    pub fn request(&self) -> &ExportRecordedClosureRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedRecordedClosureRestore {
    request: RestoreRecordedClosureRequest,
    envelope: SpoolRef,
}
impl OwnedRecordedClosureRestore {
    #[must_use]
    pub fn request(&self) -> &RestoreRecordedClosureRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub struct AtomicRecordedClosureClient {
    host: Arc<HostSupervisor>,
}
impl AtomicRecordedClosureClient {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self { host }
    }

    async fn ensure_spool(&self) -> Result<()> {
        if !matches!(self.host.request(Command::Ping).await?, Reply::Pong) {
            return Err(HostError::Protocol(
                "expected recorded-closure host readiness response",
            ));
        }
        Ok(())
    }

    async fn retain_envelope(&self, bytes: Vec<u8>) -> Result<SpoolRef> {
        if bytes.len() as u64 > MAX_ENVELOPE {
            return Err(HostError::Protocol(
                "recorded closure command exceeds envelope budget",
            ));
        }
        self.ensure_spool().await?;
        let root = self.host.spool_path();
        tokio::task::spawn_blocking(move || Spool::open(&root)?.retain(&bytes))
            .await
            .map_err(|_| HostError::Protocol("recorded closure envelope worker did not finish"))?
    }

    async fn verify_envelope(&self, reference: SpoolRef, expected: Vec<u8>) -> Result<()> {
        let root = self.host.spool_path();
        tokio::task::spawn_blocking(move || {
            let mut file = Spool::open(&root)?.open_verified(&reference, MAX_ENVELOPE)?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(MAX_ENVELOPE + 1)
                .read_to_end(&mut bytes)?;
            if bytes != expected {
                return Err(HostError::Protocol(
                    "recorded closure retained command changed",
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| HostError::Protocol("recorded closure envelope verification did not finish"))?
    }

    /// Retain the original source fence before dispatch; cancellation never
    /// releases these bytes or quietly adopts a later view/root revision.
    /// # Errors
    /// Refuses invalid identities, host ownership and bounded durability failures.
    pub async fn prepare_export(
        &self,
        request: ExportRecordedClosureRequest,
    ) -> Result<OwnedRecordedClosureExport> {
        if !bounded(&request.operation_id)
            || !bounded(&request.scope.workspace_id)
            || !bounded(&request.scope.root_id)
            || request.capture_revision == 0
            || request.scope.binding_epoch == 0
            || !safe_view(&request.view)
            || request.view != request.expected_state.view
            || request.scope.repository_id != request.binding.repository_id
            || request.scope.binding_epoch != request.binding.binding_epoch
            || !request.binding.store_path.is_absolute()
        {
            return Err(HostError::Protocol(
                "recorded closure export source identity differs",
            ));
        }
        let envelope = self.retain_envelope(serde_json::to_vec(&request)?).await?;
        Ok(OwnedRecordedClosureExport { request, envelope })
    }

    /// Export the original retained request, preserving its actual payload.
    /// No current-root/source inference or automatic native replay is performed.
    /// # Errors
    /// Returns host refusal, uncertainty or mismatched source/payload identity.
    pub async fn export(&self, operation: &OwnedRecordedClosureExport) -> Result<RecordedClosure> {
        self.verify_envelope(
            operation.envelope.clone(),
            serde_json::to_vec(&operation.request)?,
        )
        .await?;
        let Reply::RecordedClosureExported { receipt } = self
            .host
            .request(Command::ExportRecordedClosure {
                request: Box::new(operation.request.clone()),
            })
            .await?
        else {
            return Err(HostError::Protocol(
                "expected exact recorded closure export",
            ));
        };
        let receipt = *receipt;
        validate_closure(&receipt)?;
        if receipt.operation_id != operation.request.operation_id
            || receipt.scope != operation.request.scope
            || receipt.capture_revision != operation.request.capture_revision
            || receipt.source_state != operation.request.expected_state
        {
            return Err(HostError::Protocol(
                "recorded closure export differs from original retained source fence",
            ));
        }
        let root = self.host.spool_path();
        let payload = receipt.payload.clone();
        tokio::task::spawn_blocking(move || {
            Spool::open(&root)?
                .open_verified(&payload, MAX_PAYLOAD)
                .map(drop)
        })
        .await
        .map_err(|_| {
            HostError::Protocol("recorded closure payload verification did not finish")
        })??;
        Ok(receipt)
    }

    /// Stage imported closure bytes under their exact immutable digest. Full
    /// native/manifest validation still occurs in the isolated host before restore.
    /// # Errors
    /// Refuses a changed receipt/content hash before starting the host, unsafe
    /// private spool ownership and conflicting existing bytes.
    pub async fn stage_received(
        &self,
        closure: RecordedClosure,
        bytes: Vec<u8>,
    ) -> Result<RecordedClosure> {
        validate_closure(&closure)?;
        let expected = closure.payload.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            if bytes.len() as u64 != expected.length || digest(&bytes) != expected.sha256 {
                return Err(HostError::Protocol(
                    "received recorded closure bytes differ from retained identity",
                ));
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| {
            HostError::Protocol("received closure verification worker did not finish")
        })??;
        self.ensure_spool().await?;
        let root = self.host.spool_path();
        let expected = closure.payload.clone();
        let payload = tokio::task::spawn_blocking(move || {
            Spool::open(&root)?.retain_named(&expected.name, &bytes)
        })
        .await
        .map_err(|_| HostError::Protocol("received closure retention worker did not finish"))??;
        if payload != closure.payload {
            return Err(HostError::Protocol(
                "staged recorded closure identity changed",
            ));
        }
        Ok(closure)
    }

    /// Retain an original scoped restore request. Destination locators are
    /// selected by the host; callers cannot nominate an existing working copy.
    /// # Errors
    /// Refuses unsupported identities/scope or missing/corrupt retained payload.
    pub async fn prepare_restore(
        &self,
        request: RestoreRecordedClosureRequest,
    ) -> Result<OwnedRecordedClosureRestore> {
        validate_closure(&request.closure)?;
        if !bounded(&request.operation_id) || request.expected_scope != request.closure.scope {
            return Err(HostError::Protocol(
                "recorded closure restore scope differs",
            ));
        }
        let root = self.host.spool_path();
        let payload = request.closure.payload.clone();
        tokio::task::spawn_blocking(move || {
            Spool::open(&root)?
                .open_verified(&payload, MAX_PAYLOAD)
                .map(drop)
        })
        .await
        .map_err(|_| {
            HostError::Protocol("recorded closure restore verification did not finish")
        })??;
        let envelope = self.retain_envelope(serde_json::to_vec(&request)?).await?;
        Ok(OwnedRecordedClosureRestore { request, envelope })
    }

    /// Restore into a fresh host-private native store and materialization.
    /// These receipts confer no checkpoint-pointer or workspace-install authority.
    /// # Errors
    /// Returns exact native fidelity/refusal, original-request mismatch or an
    /// output outside the host's recorded-restore namespace.
    pub async fn restore(
        &self,
        operation: &OwnedRecordedClosureRestore,
    ) -> Result<RecordedClosureRestore> {
        self.verify_envelope(
            operation.envelope.clone(),
            serde_json::to_vec(&operation.request)?,
        )
        .await?;
        let Reply::RecordedClosureRestored { receipt } = self
            .host
            .request(Command::RestoreRecordedClosure {
                request: Box::new(operation.request.clone()),
            })
            .await?
        else {
            return Err(HostError::Protocol(
                "expected exact recorded closure restore",
            ));
        };
        let receipt = *receipt;
        validate_restore(&operation.request, &receipt, &self.host.spool_path())?;
        Ok(receipt)
    }
}

fn validate_closure(receipt: &RecordedClosure) -> Result<()> {
    if receipt.format != RECORDED_CLOSURE_FORMAT
        || receipt.reader_version != RECORDED_CLOSURE_READER
        || receipt.profile != RecordedClosureProfile::RecordedViewExact
        || receipt.host != HostIdentity::default()
        || !bounded(&receipt.operation_id)
        || !bounded(&receipt.scope.workspace_id)
        || !bounded(&receipt.scope.root_id)
        || receipt.scope.binding_epoch == 0
        || receipt.capture_revision == 0
        || !safe_view(&receipt.source_state.view)
        || !bounded(&receipt.project_id)
        || !bounded(&receipt.project_identity_hash)
        || !hash_valid(&receipt.view_manifest_digest)
        || !hash_valid(&receipt.materialization_manifest_digest)
        || !hash_valid(&receipt.materialization_id)
        || receipt.object_count > 4096
        || receipt.payload.length > MAX_PAYLOAD
        || !hash_valid(&receipt.payload.sha256)
        || receipt.payload.name != format!("recorded-{}.bin", receipt.payload.sha256)
        || receipt.conflict.as_ref().is_some_and(|conflict| {
            !bounded(&conflict.native_hash)
                || !hash_valid(&conflict.sha256)
                || conflict.length > 16 * 1024 * 1024
                || conflict.file_count == 0
                || conflict.entry_count == 0
        })
    {
        return Err(HostError::Protocol(
            "unsupported or mismatched recorded closure identity",
        ));
    }
    Ok(())
}

fn validate_restore(
    request: &RestoreRecordedClosureRequest,
    receipt: &RecordedClosureRestore,
    spool: &std::path::Path,
) -> Result<()> {
    let closure = &request.closure;
    if receipt.host != HostIdentity::default()
        || receipt.operation_id != request.operation_id
        || receipt.scope != request.expected_scope
        || receipt.capture_revision != closure.capture_revision
        || receipt.source_state != closure.source_state
        || receipt.restored_state.view != closure.source_state.view
        || receipt.restored_state.own_merkle != closure.source_state.own_merkle
        || receipt.project_id != closure.project_id
        || receipt.project_identity_hash != closure.project_identity_hash
        || receipt.view_manifest_digest != closure.view_manifest_digest
        || receipt.materialization_manifest_digest != closure.materialization_manifest_digest
        || receipt.materialization_id != closure.materialization_id
        || receipt.native_conflict_hash
            != closure
                .conflict
                .as_ref()
                .map(|conflict| conflict.native_hash.clone())
        || receipt.object_count != closure.object_count
    {
        return Err(HostError::Protocol(
            "recorded closure private restore differs from original source observation",
        ));
    }
    let parent = receipt.native_path.parent().ok_or(HostError::Protocol(
        "recorded restore has no private parent",
    ))?;
    let operation = spool
        .join("recorded-restores")
        .join(digest(request.operation_id.as_bytes()));
    if receipt.native_path.file_name() != Some(std::ffi::OsStr::new("native"))
        || receipt.path != parent.join("files")
        || parent.parent() != Some(operation.as_path())
        || !parent
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("attempt-"))
            .is_some_and(|name| {
                uuid::Uuid::parse_str(name).is_ok_and(|value| value.to_string() == name)
            })
    {
        return Err(HostError::Protocol(
            "recorded closure restore escaped its private namespace",
        ));
    }
    let mut expected = receipt.clone();
    expected.receipt_digest.clear();
    if digest(&serde_json::to_vec(&expected)?) != receipt.receipt_digest {
        return Err(HostError::Protocol(
            "recorded closure restore receipt digest changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
