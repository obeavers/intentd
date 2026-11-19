//! Immutable task definitions, prospective work bindings and projection delivery.
//!
//! Services retain task/permission authority. These DTOs are evidence identities,
//! not credentials, and native acknowledgements never decide task completion.

use serde::{Deserialize, Serialize};

use crate::vcs::{ContentDigest, NativeStateRef, OperationId, RootBinding};
use crate::{AgentId, NoteId, WorkspaceId};

pub mod atomic_selection;
pub mod candidate;
pub mod composition;
pub mod confirmation;
pub mod confirmation_card;
pub mod execution;
pub mod native_intent;
pub mod planning;

pub const TASK_PROJECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRevisionRef {
    pub workspace_id: WorkspaceId,
    pub note_id: NoteId,
    pub rev: i64,
    pub digest: ContentDigest,
    pub projection_schema_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionCriterion {
    pub criterion_id: ContentDigest,
    pub index: u32,
    pub text: String,
    pub text_digest: ContentDigest,
    pub origin: CriterionOrigin,
    pub required_kinds: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CriterionOrigin {
    ExplicitTaskContent,
    DeterministicParse,
    ModelProposal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRevision {
    pub reference: TaskRevisionRef,
    pub title: String,
    pub content: String,
    /// Exact persisted structured source, before projection/normalization.
    pub task_json: String,
    pub criteria: Vec<RevisionCriterion>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeIntentPins {
    pub project_id: String,
    pub intent_id: String,
    pub canonical_resource: String,
    pub source_digest: ContentDigest,
    pub parsed_source_hash: ContentDigest,
    pub canonical_digest: ContentDigest,
    pub substance_hash: ContentDigest,
}

/// One immutable command to prospectively govern a specific turn attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkBindingAdmission {
    pub binding_id: OperationId,
    pub workspace_id: WorkspaceId,
    pub note_id: NoteId,
    pub expected_task_rev: i64,
    pub root: Option<RootBinding>,
    /// Absent for non-source work or before source capture is qualified. It is
    /// never synthesized from a path, and cannot satisfy source-review readiness.
    pub baseline: Option<NativeStateRef>,
    pub agent_id: AgentId,
    pub session_id: String,
    pub turn_attempt: String,
    pub native_intent: Option<NativeIntentPins>,
    pub delegation_parent: Option<OperationId>,
    pub delegation_group: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeBindingState {
    /// Git has no native turn-intent declaration; no acknowledgement is invented.
    NotRequired,
    Pending,
    Acknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkBinding {
    pub admission: WorkBindingAdmission,
    pub command_digest: ContentDigest,
    pub task_revision: TaskRevisionRef,
    pub native_state: NativeBindingState,
    pub declaration_receipt: Option<ContentDigest>,
    pub active: bool,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewEvidenceOutboxEvent {
    pub event_id: String,
    pub event_kind: String,
    pub schema_version: u32,
    pub source_revision: String,
    /// Exact retained projection bytes; object digest is computed by the store.
    pub payload_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceOutboxEvent {
    pub sequence: u64,
    pub event_id: String,
    pub event_kind: String,
    pub schema_version: u32,
    pub source_revision: String,
    pub object_digest: ContentDigest,
    pub payload_json: String,
    pub created_at: String,
}
