//! Bounded public summaries of an original confirmed first turn. These reads
//! grant no execution authority, prove no complete authorship and never infer
//! check/review/settlement outcomes from a task status or current assignment.

use serde::{Deserialize, Serialize};

use crate::vcs::{ContentDigest, NativeChangeRef, OperationId, RepositoryId, VcsKind};
use crate::work_evidence::planning::TaskWorkPurpose;
use crate::work_evidence::{NativeBindingState, TaskRevisionRef};
use crate::work_explanation::WorkContributionProvenance;
use crate::{AgentId, NoteId, WorkspaceId};

pub const TASK_WORK_EVIDENCE_VERSION: u32 = 1;
pub const TASK_WORK_EVIDENCE_PAGE_LIMIT: u32 = 20;
pub const TASK_WORK_EVIDENCE_BYTE_BUDGET: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskWorkEvidenceQuery {
    Runs {
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    Run {
        agent_id: AgentId,
        #[serde(default)]
        page: Option<TaskEvidenceRunPage>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceRunPage {
    #[serde(default)]
    pub after: TaskEvidenceRunCursor,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceRunCursor {
    pub contributions: Option<String>,
    pub effects: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskEvidenceAdmission {
    AwaitingFirstAdmission,
    Admitted {
        binding_id: OperationId,
        turn_attempt: String,
        admitted_at: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceRun {
    pub agent_id: AgentId,
    pub task_revision: TaskRevisionRef,
    pub confirmed_at: String,
    pub admission: TaskEvidenceAdmission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidencePublicRoot {
    pub repository_id: RepositoryId,
    pub root_id: String,
    pub root_epoch: u64,
    pub kind: VcsKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceBinding {
    pub binding_id: OperationId,
    pub turn_attempt: String,
    pub root: Option<TaskEvidencePublicRoot>,
    pub native_state: NativeBindingState,
    /// Logical admission state only; this does not certify process termination.
    pub admission_active: bool,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceContribution {
    pub operation_id: OperationId,
    pub binding_id: OperationId,
    pub root: TaskEvidencePublicRoot,
    pub change: NativeChangeRef,
    pub provenance: WorkContributionProvenance,
    pub receipt_digest: ContentDigest,
    pub recorded_at: String,
}

/// Exact committed SQL effect identity, not its private callback result and not
/// a task completion or source adoption receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceEffect {
    pub operation_id: OperationId,
    pub grant_id: OperationId,
    pub effect_digest: ContentDigest,
    pub committed_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceCriterion {
    pub index: u32,
    pub text_preview: String,
    pub text_truncated: bool,
    pub text_digest: ContentDigest,
    pub required_kinds: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskEvidenceSourceUnavailable {
    SourceNotRetained,
    SourceByteBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskEvidenceSource {
    Available {
        title_preview: String,
        title_truncated: bool,
        criteria: Vec<TaskEvidenceCriterion>,
        criteria_total: u32,
        criteria_omitted: u32,
        purpose: Option<TaskWorkPurpose>,
    },
    Unavailable {
        reason: TaskEvidenceSourceUnavailable,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskEvidenceUnavailableStatus {
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskEvidenceUnavailableReason {
    NoQualifiedRunLinkage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceUnavailable {
    pub status: TaskEvidenceUnavailableStatus,
    pub reason: TaskEvidenceUnavailableReason,
}

impl Default for TaskEvidenceUnavailable {
    fn default() -> Self {
        Self {
            status: TaskEvidenceUnavailableStatus::Unavailable,
            reason: TaskEvidenceUnavailableReason::NoQualifiedRunLinkage,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceCoverage {
    pub returned_records: u32,
    /// Completeness of this exact retained index page, never unrecorded work.
    pub retained_page_complete: bool,
    pub byte_limited: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceRunCoverage {
    pub contributions: TaskEvidenceCoverage,
    pub effects: TaskEvidenceCoverage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskEvidenceReadScope {
    ConfirmedRuns,
    FirstConfirmedTurnOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskEvidenceReadBasis {
    pub query_version: u32,
    pub source_event_watermark: u64,
    pub scope: TaskEvidenceReadScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TaskWorkEvidenceResult {
    Runs {
        workspace_id: WorkspaceId,
        note_id: NoteId,
        runs: Vec<TaskEvidenceRun>,
        next: Option<String>,
        coverage: TaskEvidenceCoverage,
        read_basis: TaskEvidenceReadBasis,
    },
    Run {
        workspace_id: WorkspaceId,
        note_id: NoteId,
        run: Box<TaskEvidenceRun>,
        source: Box<TaskEvidenceSource>,
        binding: Box<TaskEvidenceBinding>,
        contributions: Vec<TaskEvidenceContribution>,
        effects: Vec<TaskEvidenceEffect>,
        next: TaskEvidenceRunCursor,
        coverage: TaskEvidenceRunCoverage,
        checks: TaskEvidenceUnavailable,
        reviews: TaskEvidenceUnavailable,
        settlement: TaskEvidenceUnavailable,
        read_basis: TaskEvidenceReadBasis,
    },
}
