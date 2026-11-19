//! Owned private native exchanges. Every retry uses the retained original
//! command; cancellation never releases spool bytes or silently resubmits work.
//! These mechanical receipts grant neither source authority nor task readiness.

use std::{io::Read, sync::Arc};

use intent_atomic_proto::{
    intents::{
        DeclareNativeTurnRequest, FreezeNativeTurnRequest, IntentProjectionReceipt,
        NativeProjectIdentity, NativeTurnDeclaration, ProjectTaskIntentRequest,
    },
    Command, RecoveryReport, Reply, SpoolRef, StoreBinding,
};
use intent_core::{
    vcs::{OperationId, RootBinding},
    work_evidence::{
        native_intent::{TaskNativeBinding, TaskNativeProjection},
        TaskRevision, WorkBinding,
    },
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    intents::{
        prepare_task_projection, retain_projection_receipt, retain_turn_freeze_receipt,
        validate_project_identity, validate_turn_declaration, validate_turn_freeze_request,
        RetainedIntentProjection, RetainedNativeTurnFreeze, TaskProjectionInput,
    },
    spool::Spool,
    HostError, HostSupervisor, Result,
};

mod sessions;
mod working_copies;

pub use sessions::{
    OwnedNativeSessionBegin, OwnedNativeSessionClose, RetainedNativeSession,
    RetainedNativeSessionClose,
};
pub use working_copies::{
    OwnedRegisteredCapture, OwnedWorkingCopyRegistration, RetainedWarmWorkingCopyCapture,
};

pub(crate) const MAX_METADATA: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_RECORD_BYTES: u64 = 512 * 1024 * 1024;

/// Inert client construction performs no installation discovery or native work.
pub struct AtomicNativeWorkClient {
    pub(crate) host: Arc<HostSupervisor>,
}

#[derive(Clone)]
struct ProjectionSource {
    root: RootBinding,
    host_binding: StoreBinding,
    native_binding: TaskNativeBinding,
    source: TaskRevision,
    operation: OperationId,
    projection_revision: u64,
    previous: Option<TaskNativeProjection>,
}

impl ProjectionSource {
    fn capture(input: TaskProjectionInput<'_>) -> Self {
        Self {
            root: input.root.clone(),
            host_binding: input.host_binding.clone(),
            native_binding: input.native_binding.clone(),
            source: input.source.clone(),
            operation: input.operation.clone(),
            projection_revision: input.projection_revision,
            previous: input.previous.cloned(),
        }
    }

    fn input(&self) -> TaskProjectionInput<'_> {
        TaskProjectionInput {
            root: &self.root,
            host_binding: &self.host_binding,
            native_binding: &self.native_binding,
            source: &self.source,
            operation: &self.operation,
            projection_revision: self.projection_revision,
            previous: self.previous.as_ref(),
        }
    }
}

/// A retained original projection request and its local task/reservation cut.
/// Fields are private so later UI/task edits cannot replace an in-flight source.
#[derive(Clone)]
pub struct OwnedTaskProjection {
    source: ProjectionSource,
    request: ProjectTaskIntentRequest,
    envelope: SpoolRef,
}

impl OwnedTaskProjection {
    #[must_use]
    pub fn request(&self) -> &ProjectTaskIntentRequest {
        &self.request
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedTurnDeclaration {
    request: DeclareNativeTurnRequest,
    envelope: SpoolRef,
}

impl OwnedTurnDeclaration {
    #[must_use]
    pub fn request(&self) -> &DeclareNativeTurnRequest {
        &self.request
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

/// Original task/work/native projection retained before the freeze exchange.
#[derive(Clone)]
pub struct OwnedTurnFreeze {
    request: FreezeNativeTurnRequest,
    envelope: SpoolRef,
    work: WorkBinding,
    projection: TaskNativeProjection,
    source_receipt: IntentProjectionReceipt,
}

impl OwnedTurnFreeze {
    #[must_use]
    pub fn request(&self) -> &FreezeNativeTurnRequest {
        &self.request
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

impl AtomicNativeWorkClient {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self { host }
    }

    /// Explicitly initialize only the original daemon-owned native store. An
    /// absent ordinary store is never silently initialized by an observation.
    /// # Errors
    /// Refuses a changed operation/binding or an existing foreign store.
    pub async fn initialize_store(&self, binding: &StoreBinding, operation_id: &str) -> Result<()> {
        if operation_id.is_empty() || operation_id.len() > 256 {
            return Err(invalid(
                "native store initialization requires an exact operation",
            ));
        }
        let command = Command::InitializeStore {
            binding: binding.clone(),
            operation_id: operation_id.into(),
        };
        // Startup creates the private spool before the immutable command is sent.
        if !matches!(self.host.request(Command::Ping).await?, Reply::Pong) {
            return Err(invalid(
                "expected admitted native host before initialization",
            ));
        }
        let envelope = self.retain_command(&command).await?;
        self.verify_command(&envelope, &command).await?;
        let Reply::StoreInitialized {
            binding: initialized,
            operation_id: operation,
        } = self.host.request(command).await?
        else {
            return Err(invalid("expected native store initialization receipt"));
        };
        if initialized != *binding || operation != operation_id {
            return Err(invalid(
                "native store initialization changed its original binding/operation",
            ));
        }
        self.open_store(binding).await
    }

    /// Read only bytes matching a bounded retained reference, using the owner
    /// directory descriptor. The second digest checks the actual returned bytes.
    /// # Errors
    /// Refuses unavailable, replaced, oversized or changed retained files.
    pub async fn read_retained(&self, reference: &SpoolRef, limit: u64) -> Result<Vec<u8>> {
        if limit > MAX_RECORD_BYTES {
            return Err(invalid("retained native read exceeds its maximum budget"));
        }
        let root = self.host.spool_path();
        let reference = reference.clone();
        tokio::task::spawn_blocking(move || read(&Spool::open(&root)?, &reference, limit))
            .await
            .map_err(|_| invalid("retained native read worker failed"))?
    }

    /// # Errors
    /// Refuses another native store, root/epoch or project identity.
    pub async fn project_identity(
        &self,
        root: &RootBinding,
        binding: &StoreBinding,
    ) -> Result<NativeProjectIdentity> {
        self.open_store(binding).await?;
        let Reply::NativeProject { identity } = self
            .host
            .request(Command::ReadNativeProject {
                binding: binding.clone(),
            })
            .await?
        else {
            return Err(invalid("expected actual native project identity"));
        };
        validate_project_identity(root, binding, &identity)?;
        Ok(identity)
    }

    /// Retain the original task/reservation/request before any projection send.
    /// # Errors
    /// Refuses stale identities, invalid predecessors or unavailable spool bytes.
    pub async fn prepare_projection(
        &self,
        input: TaskProjectionInput<'_>,
    ) -> Result<OwnedTaskProjection> {
        let source = ProjectionSource::capture(input);
        self.open_store(&source.host_binding).await?;
        let root = self.host.spool_path();
        tokio::task::spawn_blocking(move || {
            let spool = Spool::open(&root)?;
            let request = prepare_task_projection(&spool, source.input())?;
            let envelope = retain(&spool, &request)?;
            Ok(OwnedTaskProjection {
                source,
                request,
                envelope,
            })
        })
        .await
        .map_err(|_| invalid("native projection preparation worker failed"))?
    }

    /// Send this exact owned projection once. Uncertainty is returned to the
    /// caller; the retained command/source remain available for reconciliation.
    /// # Errors
    /// Refuses altered retained commands, host errors or mismatched receipts.
    pub async fn project(&self, pending: &OwnedTaskProjection) -> Result<RetainedIntentProjection> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let Reply::TaskIntentProjected { receipt } = self
            .host
            .request(Command::ProjectTaskIntent {
                request: Box::new(pending.request.clone()),
            })
            .await?
        else {
            return Err(invalid("expected exact native task projection receipt"));
        };
        let root = self.host.spool_path();
        let pending = pending.clone();
        tokio::task::spawn_blocking(move || {
            retain_projection_receipt(
                &Spool::open(&root)?,
                pending.source.input(),
                &pending.request,
                &receipt,
            )
        })
        .await
        .map_err(|_| invalid("native projection receipt worker failed"))?
    }

    /// # Errors
    /// Refuses empty operation/session/turn identities or unavailable ownership.
    pub async fn retain_declaration(
        &self,
        request: DeclareNativeTurnRequest,
    ) -> Result<OwnedTurnDeclaration> {
        validate_turn_request(
            &request.operation_id,
            &request.session_id,
            request.expected_turn,
        )?;
        self.open_store(&request.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedTurnDeclaration { request, envelope })
    }

    /// A declaration is expressly not a frozen authoring acknowledgement.
    /// # Errors
    /// Returns transport uncertainty, host refusal or a foreign declared turn.
    pub async fn declare(&self, pending: &OwnedTurnDeclaration) -> Result<NativeTurnDeclaration> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let Reply::NativeTurnDeclared { receipt } = self
            .host
            .request(Command::DeclareNativeTurn {
                request: pending.request.clone(),
            })
            .await?
        else {
            return Err(invalid("expected native declared-turn receipt"));
        };
        validate_turn_declaration(&pending.request, &receipt)?;
        self.retain_command(&receipt).await?;
        Ok(receipt)
    }

    /// # Errors
    /// Refuses an incomplete original turn or unavailable owner spool.
    pub async fn retain_freeze(
        &self,
        work: &WorkBinding,
        projection: &TaskNativeProjection,
        source_receipt: &IntentProjectionReceipt,
        request: FreezeNativeTurnRequest,
    ) -> Result<OwnedTurnFreeze> {
        validate_turn_request(
            &request.operation_id,
            &request.session_id,
            request.expected_turn,
        )?;
        validate_turn_freeze_request(work, projection, source_receipt, &request)?;
        self.open_store(&request.binding).await?;
        self.read_retained(&source_receipt.task_source, 1024 * 1024)
            .await?;
        self.read_retained(&source_receipt.artifact, 8 * 1024 * 1024)
            .await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedTurnFreeze {
            request,
            envelope,
            work: work.clone(),
            projection: projection.clone(),
            source_receipt: source_receipt.clone(),
        })
    }

    /// # Errors
    /// Refuses altered original inputs, missing native bytes or a foreign freeze.
    pub async fn freeze(&self, pending: &OwnedTurnFreeze) -> Result<RetainedNativeTurnFreeze> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let Reply::NativeTurnFrozen { receipt } = self
            .host
            .request(Command::FreezeNativeTurn {
                request: pending.request.clone(),
            })
            .await?
        else {
            return Err(invalid("expected exact native frozen-turn receipt"));
        };
        let root = self.host.spool_path();
        let pending = pending.clone();
        tokio::task::spawn_blocking(move || {
            retain_turn_freeze_receipt(
                &Spool::open(&root)?,
                &pending.work,
                &pending.projection,
                &pending.source_receipt,
                &pending.request,
                &receipt,
            )
        })
        .await
        .map_err(|_| invalid("native frozen-turn receipt worker failed"))?
    }

    /// Recovery is separate from a known admitted record fact. Failure here must
    /// not erase a receipt returned by `admit_record` or trigger another record.
    /// # Errors
    /// Returns connection errors or an inconsistent recovery report.
    pub async fn reconcile(&self) -> Result<RecoveryReport> {
        let Reply::Reconciled { recovery } = self.host.request(Command::Reconcile).await? else {
            return Err(invalid("expected native recovery report"));
        };
        if recovery.ready && !recovery.unresolved_operation_ids.is_empty() {
            return Err(invalid(
                "ready native recovery retains unresolved operations",
            ));
        }
        Ok(recovery)
    }

    pub(crate) async fn open_store(&self, binding: &StoreBinding) -> Result<()> {
        let Reply::StoreOpened { binding: opened } = self
            .host
            .request(Command::OpenStore {
                binding: binding.clone(),
            })
            .await?
        else {
            return Err(invalid("expected exact native store admission"));
        };
        if opened != *binding {
            return Err(invalid("native store admission changed its binding"));
        }
        Ok(())
    }

    pub(crate) async fn retain_command(&self, value: &impl Serialize) -> Result<SpoolRef> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > MAX_METADATA {
            return Err(invalid(
                "native command exceeds its retained metadata budget",
            ));
        }
        let root = self.host.spool_path();
        tokio::task::spawn_blocking(move || Spool::open(&root)?.retain(&bytes))
            .await
            .map_err(|_| invalid("native command retention worker failed"))?
    }

    pub(crate) async fn verify_command(
        &self,
        envelope: &SpoolRef,
        value: &impl Serialize,
    ) -> Result<()> {
        let expected = serde_json::to_vec(value)?;
        if self.read_retained(envelope, MAX_METADATA).await? != expected {
            return Err(invalid("retained native command changed before exchange"));
        }
        Ok(())
    }
}

pub(crate) fn invalid(message: &'static str) -> HostError {
    HostError::Protocol(message)
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}

pub(crate) fn sha_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn native_hash(value: &str) -> bool {
    value.len() == 52
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        && matches!(value.as_bytes().last(), Some(b'A' | b'Q'))
}

pub(crate) fn retain(spool: &Spool, value: &impl Serialize) -> Result<SpoolRef> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(invalid("native envelope exceeds its metadata budget"));
    }
    spool.retain(&bytes)
}

pub(crate) fn read(spool: &Spool, reference: &SpoolRef, limit: u64) -> Result<Vec<u8>> {
    let mut file = spool.open_verified(reference, limit)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != reference.length || digest(&bytes) != reference.sha256 {
        return Err(invalid("retained native bytes changed while reading"));
    }
    Ok(bytes)
}

fn validate_turn_request(operation: &str, session: &str, turn: u32) -> Result<()> {
    if operation.is_empty()
        || operation.len() > 256
        || session.is_empty()
        || session.len() > 256
        || turn == 0
    {
        return Err(invalid(
            "native turn requires exact bounded operation/session/turn",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
