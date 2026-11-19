//! Typed source-projection preparation and receipt validation. Private exchanges
//! are owned by `native_work`; normal source activation remains off. `HostFacadeFreezeV1` is a
//! mechanical source witness; authoring still requires separate qualified
//! capture, execution-grant admission and an activated transport owner.

use crate::{spool::Spool, HostError, Result};
use intent_atomic_proto::intents::{
    projection_command_identity, AssignedIntentIdentity, DeclareNativeTurnRequest,
    FreezeNativeTurnRequest, IntentProjectionReceipt, IntentProjectionRef,
    NativeIntentFreezeMethod, NativeIntentPins, NativeProjectIdentity, NativeTurnBindingStage,
    NativeTurnDeclaration, NativeTurnFreezeReceipt, ProjectTaskIntentRequest, TaskRevisionRef,
    INTENT_PROJECTION_VERSION,
};
use intent_atomic_proto::{HostIdentity, SpoolRef, StoreBinding};
use intent_core::vcs::{ContentDigest, OperationId, RootBinding, VcsKind};
use intent_core::work_evidence::native_intent::{TaskNativeBinding, TaskNativeProjection};
use intent_core::work_evidence::{NativeIntentPins as DomainPins, TaskRevision, WorkBinding};
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}
fn projection_command_bytes(request: &ProjectTaskIntentRequest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&projection_command_identity(request))?)
}
fn sha_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn native_hash(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(sha_valid)
}
fn reference(source: &intent_core::work_evidence::TaskRevisionRef) -> TaskRevisionRef {
    TaskRevisionRef {
        workspace_id: source.workspace_id.as_str().into(),
        note_id: source.note_id.as_str().into(),
        rev: source.rev,
        digest: source.digest.as_str().into(),
        projection_schema_version: source.projection_schema_version,
    }
}
fn pins(source: &DomainPins) -> NativeIntentPins {
    NativeIntentPins {
        source_sha256: source.source_digest.as_str().into(),
        parsed_source_hash: source.parsed_source_hash.as_str().into(),
        canonical_content_hash: source.canonical_digest.as_str().into(),
        substance_hash: source.substance_hash.as_str().into(),
    }
}

/// Confirm an actual host identity receipt before creating portable native refs.
/// # Errors
/// Refuses mismatched host/root/epoch/project identity or empty native identity.
pub fn validate_project_identity(
    root: &RootBinding,
    binding: &StoreBinding,
    receipt: &NativeProjectIdentity,
) -> Result<()> {
    if root.kind != VcsKind::Atomic
        || receipt.host != HostIdentity::default()
        || receipt.binding != *binding
        || root.repository_id.as_str() != binding.repository_id
        || root.epoch != binding.binding_epoch
        || receipt.project_id.is_empty()
        || receipt.project_identity_hash.is_empty()
        || receipt.project_id.len() > 256
        || receipt.project_identity_hash.len() > 256
    {
        return Err(HostError::Protocol(
            "native project identity does not match the established host/root",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct TaskProjectionInput<'a> {
    pub root: &'a RootBinding,
    pub host_binding: &'a StoreBinding,
    pub native_binding: &'a TaskNativeBinding,
    pub source: &'a TaskRevision,
    pub operation: &'a OperationId,
    pub projection_revision: u64,
    pub previous: Option<&'a TaskNativeProjection>,
}

/// Retain the exact immutable task JSON before native creation. This prepares a
/// request only; it neither transmits a mutation nor acknowledges a native turn.
/// # Errors
/// Refuses foreign identities, wrong predecessor or source/spool budget failures.
pub fn prepare_task_projection(
    spool: &Spool,
    input: TaskProjectionInput<'_>,
) -> Result<ProjectTaskIntentRequest> {
    let binding = input.native_binding;
    let source = input.source;
    if input.root.kind != VcsKind::Atomic
        || input.root.workspace_id != source.reference.workspace_id
        || binding.workspace_id != source.reference.workspace_id
        || binding.note_id != source.reference.note_id
        || binding.repository_id != input.root.repository_id
        || input.host_binding.repository_id != binding.repository_id.as_str()
        || input.host_binding.binding_epoch != input.root.epoch
        || input.projection_revision == 0
        || binding.canonical_resource != format!("urn:atomic:intent:{}", binding.native_intent_id)
        || input.previous.is_some_and(|previous| {
            previous.binding_id != binding.binding_id
                || previous.root != *input.root
                || previous.projection_revision.checked_add(1) != Some(input.projection_revision)
        })
        || (input.previous.is_none() && input.projection_revision != 1)
    {
        return Err(HostError::Configuration(
            "native projection input does not match its exact task/root/reservation",
        ));
    }
    let bytes = serde_json::to_vec(source)?;
    if bytes.len() > 1024 * 1024 {
        return Err(HostError::Configuration(
            "native task source exceeds qualified projection budget",
        ));
    }
    let source_ref = spool.retain(&bytes)?;
    Ok(ProjectTaskIntentRequest {
        operation_id: input.operation.as_str().into(),
        binding: input.host_binding.clone(),
        root_id: input.root.root_id.clone(),
        identity: AssignedIntentIdentity {
            native_intent_id: binding.native_intent_id.clone(),
            display_key: binding.display_key.clone(),
            project_id: binding.native_project_id.clone(),
            project_identity_hash: binding.native_project_identity_hash.clone(),
            canonical_resource: binding.canonical_resource.clone(),
        },
        projection_revision: input.projection_revision,
        previous: input.previous.map(|previous| IntentProjectionRef {
            operation_id: previous.operation_id.as_str().into(),
            projection_revision: previous.projection_revision,
            task_revision: reference(&previous.task_revision),
            pins: pins(&previous.pins),
        }),
        task_revision: reference(&source.reference),
        source: source_ref,
    })
}

pub struct RetainedIntentProjection {
    pub projection: TaskNativeProjection,
    /// These verified spool bytes must be copied into the durable evidence blob
    /// owner before `Store::retain_task_native_projection` creates references.
    pub task_source: SpoolRef,
    pub artifact: SpoolRef,
    pub native_receipt: SpoolRef,
}

/// Verify the actual host receipt and every returned byte reference, then retain
/// its exact envelope. Native canonical/substance algorithms remain in the host.
/// # Errors
/// Refuses changed source/identity/predecessor, false pins or unavailable bytes.
pub fn retain_projection_receipt(
    spool: &Spool,
    input: TaskProjectionInput<'_>,
    request: &ProjectTaskIntentRequest,
    receipt: &IntentProjectionReceipt,
) -> Result<RetainedIntentProjection> {
    if receipt.host != HostIdentity::default()
        || receipt.binding != request.binding
        || receipt.identity != request.identity
        || receipt.request_digest != sha(&projection_command_bytes(request)?)
        || receipt.projection.operation_id != request.operation_id
        || receipt.projection.projection_revision != request.projection_revision
        || receipt.projection.task_revision != request.task_revision
        || receipt.projection_version != INTENT_PROJECTION_VERSION
        || receipt.control_view != "intent-owner-control"
        || receipt.control_working_copy_id.is_empty()
        || receipt.control_working_copy_id.len() > 256
        || receipt.vault_path != format!("intents/{}/intent.md", request.identity.native_intent_id)
        || receipt.task_source.sha256 != request.source.sha256
        || receipt.task_source.length != request.source.length
        || receipt.task_source.name
            != format!("native-task-{}.json", sha(request.operation_id.as_bytes()))
        || receipt.artifact.name
            != format!("native-intent-{}.md", sha(request.operation_id.as_bytes()))
        || receipt.artifact.sha256 != receipt.projection.pins.source_sha256
        || !sha_valid(&receipt.projection.pins.source_sha256)
        || !native_hash(&receipt.projection.pins.parsed_source_hash)
        || !native_hash(&receipt.projection.pins.canonical_content_hash)
        || !native_hash(&receipt.projection.pins.substance_hash)
        || receipt.observed_unix_seconds < 0
    {
        return Err(HostError::Protocol(
            "native intent projection receipt differs from its exact qualified request",
        ));
    }
    // Revalidate the local authoritative source/reservation rather than trusting
    // the host response to select a different task or root.
    if input.root.kind != VcsKind::Atomic
        || input.root.root_id != request.root_id
        || input.host_binding != &receipt.binding
        || input.root.workspace_id != input.source.reference.workspace_id
        || input.native_binding.workspace_id != input.source.reference.workspace_id
        || input.native_binding.note_id != input.source.reference.note_id
        || input.native_binding.repository_id != input.root.repository_id
        || sha(&serde_json::to_vec(input.source)?) != receipt.task_source.sha256
        || input.native_binding.native_intent_id != receipt.identity.native_intent_id
        || input.native_binding.native_project_id != receipt.identity.project_id
        || input.native_binding.native_project_identity_hash
            != receipt.identity.project_identity_hash
        || input.native_binding.canonical_resource != receipt.identity.canonical_resource
        || reference(&input.source.reference) != receipt.projection.task_revision
        || input.root.repository_id.as_str() != receipt.binding.repository_id
        || input.root.epoch != receipt.binding.binding_epoch
        || input.operation.as_str() != receipt.projection.operation_id
        || input.projection_revision != receipt.projection.projection_revision
    {
        return Err(HostError::Protocol(
            "native intent receipt belongs to another local reservation/task/root",
        ));
    }
    spool.open_verified(&receipt.task_source, 1024 * 1024)?;
    spool.open_verified(&receipt.artifact, 8 * 1024 * 1024)?;
    let envelope = spool.retain(&serde_json::to_vec(receipt)?)?;
    Ok(RetainedIntentProjection {
        projection: TaskNativeProjection {
            binding_id: input.native_binding.binding_id.clone(),
            root: input.root.clone(),
            operation_id: input.operation.clone(),
            task_revision: input.source.reference.clone(),
            projection_revision: receipt.projection.projection_revision,
            projection_version: receipt.projection_version,
            control_working_copy_id: receipt.control_working_copy_id.clone(),
            control_view: receipt.control_view.clone(),
            vault_path: receipt.vault_path.clone(),
            vault_manifest_merkle: receipt.vault_manifest_merkle.clone(),
            pins: DomainPins {
                project_id: receipt.identity.project_id.clone(),
                intent_id: receipt.identity.native_intent_id.clone(),
                canonical_resource: receipt.identity.canonical_resource.clone(),
                source_digest: ContentDigest::from_string(&receipt.projection.pins.source_sha256),
                parsed_source_hash: ContentDigest::from_string(
                    &receipt.projection.pins.parsed_source_hash,
                ),
                canonical_digest: ContentDigest::from_string(
                    &receipt.projection.pins.canonical_content_hash,
                ),
                substance_hash: ContentDigest::from_string(&receipt.projection.pins.substance_hash),
            },
            task_source_digest: ContentDigest::from_string(&receipt.task_source.sha256),
            artifact_digest: ContentDigest::from_string(&receipt.artifact.sha256),
            native_receipt_digest: ContentDigest::from_string(&envelope.sha256),
            projected_at: intent_core::iso_from_unix_secs(receipt.observed_unix_seconds),
        },
        task_source: receipt.task_source.clone(),
        artifact: receipt.artifact.clone(),
        native_receipt: envelope,
    })
}

/// Validate a declared-only observation without converting it to a frozen ack.
/// # Errors
/// Refuses a different turn, native UID, task projection, host or binding epoch.
pub fn validate_turn_declaration(
    request: &DeclareNativeTurnRequest,
    receipt: &NativeTurnDeclaration,
) -> Result<()> {
    if receipt.host != HostIdentity::default()
        || receipt.binding != request.binding
        || receipt.operation_id != request.operation_id
        || receipt.projection != request.projection
        || receipt.session_id != request.session_id
        || receipt.turn != request.expected_turn
        || receipt.native_intent_id != request.native_intent_id
        || receipt.stage != NativeTurnBindingStage::DeclaredOnly
    {
        return Err(HostError::Protocol(
            "native declared-only receipt differs from its exact turn request",
        ));
    }
    Ok(())
}

/// Retained mechanical observation only. This type is not an execution grant,
/// does not acknowledge a Store binding, and cannot authorize native recording.
pub struct RetainedNativeTurnFreeze {
    pub receipt: NativeTurnFreezeReceipt,
    pub envelope: SpoolRef,
}

/// Validate the original local task/work cut before sending a native freeze.
/// This checks request context only and never fabricates a host observation.
/// # Errors
/// Refuses a request assembled from another binding, task or native projection.
pub fn validate_turn_freeze_request(
    work: &WorkBinding,
    projection: &TaskNativeProjection,
    source_receipt: &IntentProjectionReceipt,
    request: &FreezeNativeTurnRequest,
) -> Result<()> {
    if request.work_binding_id != work.admission.binding_id.as_str()
        || work.admission.root.as_ref() != Some(&projection.root)
        || work.task_revision != projection.task_revision
        || work.admission.native_intent.as_ref() != Some(&projection.pins)
        || projection.root.kind != VcsKind::Atomic
        || projection.root.repository_id.as_str() != request.binding.repository_id
        || projection.root.epoch != request.binding.binding_epoch
        || reference(&projection.task_revision) != request.projection.task_revision
        || projection.operation_id.as_str() != request.projection.operation_id
        || projection.projection_revision != request.projection.projection_revision
        || pins(&projection.pins) != request.projection.pins
        || projection.pins.intent_id != request.native_intent_id
        || source_receipt.host != HostIdentity::default()
        || source_receipt.projection != request.projection
        || source_receipt.binding != request.binding
        || sha(&serde_json::to_vec(source_receipt)?) != projection.native_receipt_digest.as_str()
        || source_receipt.task_source.sha256 != projection.task_source_digest.as_str()
        || source_receipt.artifact.sha256 != projection.artifact_digest.as_str()
    {
        return Err(HostError::Protocol(
            "native freeze request differs from its original local task/work cut",
        ));
    }
    Ok(())
}

/// Check an actual host response against retained original task and binding
/// references and retain its envelope. The host must independently validate its
/// journal/marker before using this witness in a native grant producer.
/// # Errors
/// Refuses a foreign operation, declared-only input, changed source or missing bytes.
pub fn retain_turn_freeze_receipt(
    spool: &Spool,
    work: &WorkBinding,
    projection: &TaskNativeProjection,
    source_receipt: &IntentProjectionReceipt,
    request: &FreezeNativeTurnRequest,
    receipt: &NativeTurnFreezeReceipt,
) -> Result<RetainedNativeTurnFreeze> {
    validate_turn_freeze_request(work, projection, source_receipt, request)?;
    if receipt.host != HostIdentity::default()
        || receipt.method != NativeIntentFreezeMethod::HostFacadeFreezeV1
        || receipt.binding != request.binding
        || receipt.operation_id != request.operation_id
        || receipt.work_binding_id != request.work_binding_id
        || receipt.projection != request.projection
        || receipt.native_intent_id != request.native_intent_id
        || receipt.session_id != request.session_id
        || receipt.turn != request.expected_turn
        || receipt.turn == 0
        || receipt.work_binding_id != work.admission.binding_id.as_str()
        || work.admission.root.as_ref() != Some(&projection.root)
        || work.task_revision != projection.task_revision
        || work.admission.native_intent.as_ref() != Some(&projection.pins)
        || projection.root.kind != VcsKind::Atomic
        || projection.root.repository_id.as_str() != receipt.binding.repository_id
        || projection.root.epoch != receipt.binding.binding_epoch
        || reference(&projection.task_revision) != receipt.projection.task_revision
        || projection.operation_id.as_str() != receipt.projection.operation_id
        || projection.projection_revision != receipt.projection.projection_revision
        || pins(&projection.pins) != receipt.projection.pins
        || projection.pins.intent_id != receipt.native_intent_id
        || receipt.projection_receipt_digest != projection.native_receipt_digest.as_str()
        || sha(&serde_json::to_vec(source_receipt)?) != receipt.projection_receipt_digest
        || source_receipt.projection != receipt.projection
        || source_receipt.binding != receipt.binding
        || source_receipt.task_source != receipt.task_source
        || source_receipt.artifact != receipt.artifact
        || receipt.task_source.sha256 != projection.task_source_digest.as_str()
        || receipt.artifact.sha256 != projection.artifact_digest.as_str()
    {
        return Err(HostError::Protocol(
            "native freeze observation differs from the exact original task binding/projection",
        ));
    }
    spool.open_verified(&receipt.task_source, 1024 * 1024)?;
    spool.open_verified(&receipt.artifact, 8 * 1024 * 1024)?;
    let envelope = spool.retain(&serde_json::to_vec(receipt)?)?;
    Ok(RetainedNativeTurnFreeze {
        receipt: receipt.clone(),
        envelope,
    })
}

/// A UID declaration or retained mechanical witness alone is insufficient to
/// activate native authoring. The private host transport and grant/barrier
/// producer must be qualified and composed by their owner first.
/// # Errors
/// Refuses while the native authoring pipeline has no activated admission owner.
pub fn require_qualified_native_freeze() -> Result<()> {
    Err(HostError::Configuration("native frozen-turn transport and execution-grant admission are not activated; a declaration cannot authorize authoring"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declaration_never_satisfies_native_authoring_barrier() {
        assert!(require_qualified_native_freeze().is_err());
        assert!(serde_json::from_value::<NativeTurnFreezeReceipt>(
            serde_json::json!({"stage":"declaredOnly"})
        )
        .is_err());
    }
}
