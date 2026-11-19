//! Prospective native identity reservation and immutable projection history.
//! A source projection or declared-only native session is never a frozen turn ack.

use super::{NativeIntentPins, TaskRevisionRef};
use crate::vcs::{ContentDigest, OperationId, RepositoryId, RootBinding};
use crate::{NoteId, WorkspaceId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskNativeBinding {
    pub binding_id: OperationId,
    pub workspace_id: WorkspaceId,
    pub note_id: NoteId,
    pub repository_id: RepositoryId,
    /// Actual established native identity, independent of the Intent repository UUID.
    pub native_project_id: String,
    pub native_project_identity_hash: String,
    pub native_intent_id: String,
    pub canonical_resource: String,
    pub display_key: String,
    pub create_operation: OperationId,
    pub create_request_digest: ContentDigest,
    pub reserved_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskNativeProjection {
    pub binding_id: OperationId,
    pub root: RootBinding,
    pub operation_id: OperationId,
    pub task_revision: TaskRevisionRef,
    pub projection_revision: u64,
    pub projection_version: u32,
    pub control_working_copy_id: String,
    pub control_view: String,
    pub vault_path: String,
    pub vault_manifest_merkle: String,
    pub pins: NativeIntentPins,
    pub task_source_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
    pub native_receipt_digest: ContentDigest,
    pub projected_at: String,
}
