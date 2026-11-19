//! Exact task-to-native intent bridge. These DTOs confer no task authority.
//! Private transport requests preserve exact native journals and recovery;
//! their receipts never acknowledge source execution or task completion.

use crate::{HostIdentity, SpoolRef, StoreBinding};
use serde::{Deserialize, Serialize};

pub const INTENT_PROJECTION_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRevisionRef {
    pub workspace_id: String,
    pub note_id: String,
    pub rev: i64,
    pub digest: String,
    pub projection_schema_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceCriterion {
    pub criterion_id: String,
    pub index: u32,
    pub text: String,
    pub text_digest: String,
    pub origin: String,
    pub required_kinds: Vec<String>,
}

/// Same retained source representation as Intent's immutable `TaskRevision`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTaskSource {
    pub reference: TaskRevisionRef,
    pub title: String,
    pub content: String,
    pub task_json: String,
    pub criteria: Vec<SourceCriterion>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProjectIdentity {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    /// Actual native project identity and its independently hashed identity record.
    pub project_id: String,
    pub project_identity_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignedIntentIdentity {
    pub native_intent_id: String,
    pub display_key: String,
    pub project_id: String,
    pub project_identity_hash: String,
    pub canonical_resource: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeIntentPins {
    /// SHA-256 of the actual native materialized source bytes.
    pub source_sha256: String,
    /// Native `source_content_hash(frontmatter,body)`, including algorithm prefix.
    pub parsed_source_hash: String,
    /// Native `CanonicalNode.compute_content_hash()`, including algorithm prefix.
    pub canonical_content_hash: String,
    /// Native `intent_substance_hash()`, including algorithm prefix.
    pub substance_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentProjectionRef {
    pub operation_id: String,
    pub projection_revision: u64,
    pub task_revision: TaskRevisionRef,
    pub pins: NativeIntentPins,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectTaskIntentRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    pub root_id: String,
    /// Minted and durably reserved by Intent before native creation, never title lookup.
    pub identity: AssignedIntentIdentity,
    pub projection_revision: u64,
    pub previous: Option<IntentProjectionRef>,
    pub task_revision: TaskRevisionRef,
    /// Exact retained `NativeTaskSource` JSON, verified before parsing.
    pub source: SpoolRef,
}

/// Content-addressed command identity excludes the transient source spool name.
/// Root/project/intent/task/predecessor and exact source bytes remain fixed.
/// The caller chooses its encoding locally; this serde-only protocol crate
/// neither hashes nor opens any source/store. Tuple order is policy-versioned.
#[must_use]
pub fn projection_command_identity(request: &ProjectTaskIntentRequest) -> impl Serialize + '_ {
    (
        INTENT_PROJECTION_VERSION,
        &request.binding,
        &request.root_id,
        &request.identity,
        request.projection_revision,
        &request.previous,
        &request.task_revision,
        request.source.length,
        &request.source.sha256,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentProjectionReceipt {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub identity: AssignedIntentIdentity,
    pub projection: IntentProjectionRef,
    pub request_digest: String,
    pub projection_version: u32,
    pub control_working_copy_id: String,
    pub control_view: String,
    pub vault_path: String,
    pub vault_manifest_merkle: String,
    /// Original task source bytes and generated native artifact remain separate.
    pub task_source: SpoolRef,
    pub artifact: SpoolRef,
    /// First durably retained host observation, not an inferred native write time.
    pub observed_unix_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeclareNativeTurnRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    pub projection: IntentProjectionRef,
    pub native_intent_id: String,
    pub session_id: String,
    pub expected_turn: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeTurnBindingStage {
    /// Actual `SessionStore` declaration only. It is not a frozen record binding
    /// and must never acknowledge Intent's native authoring admission gate.
    DeclaredOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTurnDeclaration {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub operation_id: String,
    pub projection: IntentProjectionRef,
    pub session_id: String,
    pub turn: u32,
    pub native_intent_id: String,
    pub stage: NativeTurnBindingStage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreezeNativeTurnRequest {
    /// The exact record operation that will consume this frozen source snapshot.
    pub operation_id: String,
    pub work_binding_id: String,
    pub binding: StoreBinding,
    pub projection: IntentProjectionRef,
    pub native_intent_id: String,
    pub session_id: String,
    pub expected_turn: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeIntentFreezeMethod {
    HostFacadeFreezeV1,
}

/// A versioned host-facade mechanical witness, not an upstream private call or
/// an Intent task/source authorization grant. Host must validate its journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTurnFreezeReceipt {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub operation_id: String,
    pub work_binding_id: String,
    pub projection: IntentProjectionRef,
    pub session_id: String,
    pub turn: u32,
    pub native_intent_id: String,
    pub method: NativeIntentFreezeMethod,
    pub task_source: SpoolRef,
    pub artifact: SpoolRef,
    pub projection_receipt_digest: String,
}
