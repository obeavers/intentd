//! Exact retained lineage for work explanations. Missing links are unavailable,
//! never inferred from overlapping paths, current assignments or rewritten Git history.

use serde::{Deserialize, Serialize};

use crate::vcs::{
    ContentDigest, GitCommitId, NativeChangeRef, NativeStateRef, OperationId, RecordedChange,
    RepositoryId,
};
use crate::work_evidence::confirmation::{
    AdoptionEffectReceipt, ConfirmationReceipt, TaskTransitionReceipt,
};
use crate::work_evidence::{TaskRevision, TaskRevisionRef, WorkBinding};
use crate::WorkspaceId;

pub const WORK_EXPLANATION_VERSION: u32 = 1;

/// Public root identity without a machine-local locator or invented source state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplanationRoot {
    pub repository_id: RepositoryId,
    pub root_id: String,
    pub root_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LedgerReadScope {
    /// Task facts do not imply a code state. This also represents research and
    /// rootless work, without fake repository, root or native hashes.
    TaskLedger { task_revision: TaskRevisionRef },
    CandidateLedger {
        candidate_id: String,
        task_revision: TaskRevisionRef,
        composition_revision: ContentDigest,
    },
    RecordedChange {
        root: ExplanationRoot,
        change: NativeChangeRef,
    },
    RecordedLine {
        root: ExplanationRoot,
        state: NativeStateRef,
        path: String,
        line: u32,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplanationCoverage {
    pub returned_records: u64,
    pub omitted_for_bytes: u64,
    /// True only for the selected retained index page. It never asserts that
    /// unrecorded work, external rewrites or missing provenance do not exist.
    pub retained_page_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExplanationTruncation {
    RecordLimit,
    ByteLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LedgerIgnorePolicy {
    /// These queries read retained ledger facts without walking source files.
    NotAppliedToLedgerFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerReadBasis {
    pub workspace_id: WorkspaceId,
    pub scope: LedgerReadScope,
    /// `MAX(event_outbox.sequence)` observed in the same `SQLite` read snapshot.
    pub source_event_watermark: u64,
    /// No projector completion is inferred from the source watermark.
    pub projector_watermark: Option<u64>,
    pub query_version: u32,
    pub ontology_version: String,
    pub visibility_digest: ContentDigest,
    pub ignore_policy: LedgerIgnorePolicy,
    pub coverage: ExplanationCoverage,
    pub truncation: Vec<ExplanationTruncation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExplanationUnavailable {
    NotRetained,
    NoRecordedAssociation,
    NoRecordedLineMapping,
    AmbiguousLineMapping,
    SourceByteBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Explained<T> {
    Available { value: T },
    Unavailable { reason: ExplanationUnavailable },
}

/// An exact recording request can be governed by an original turn without
/// proving that turn authored every byte in a shared working copy. No complete
/// authorship variant exists until an opaque isolation/capture owner qualifies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkContributionProvenance {
    #[default]
    HistoricalAssociationUnproven,
    RecordingGovernanceOnlySharedWorkingCopy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkContributionReceipt {
    #[serde(default)]
    pub provenance: WorkContributionProvenance,
    pub operation_id: OperationId,
    pub binding_id: OperationId,
    pub task_revision: TaskRevisionRef,
    pub root: ExplanationRoot,
    /// The actual successful primitive result, including post-record warnings.
    pub recording: RecordedChange,
    pub receipt_digest: ContentDigest,
    pub recorded_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedGitSourceRef {
    pub name: String,
    pub expected: GitCommitId,
}

/// An owner-observed ancestry inclusion. Squash/rebase mappings require their
/// own qualified projection owner; ancestry is never relabeled as content proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitMergeObservation {
    pub operation_id: OperationId,
    pub root: ExplanationRoot,
    pub expected_sources: Vec<ExpectedGitSourceRef>,
    pub contribution_ids: Vec<OperationId>,
    pub target_state: NativeStateRef,
    pub included_changes: Vec<NativeChangeRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkMergeReceipt {
    pub observation: GitMergeObservation,
    pub receipt_digest: ContentDigest,
    pub observed_at: String,
}

/// Explicit immutable blame/projection output retained by its execution owner.
/// An inclusion receipt alone never creates one of these line mappings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkLineMapping {
    pub operation_id: OperationId,
    pub merge_operation_id: OperationId,
    pub contribution_id: OperationId,
    pub root: ExplanationRoot,
    pub target_state: NativeStateRef,
    pub path: String,
    pub first_line: u32,
    pub last_line: u32,
    pub blame_receipt_digest: ContentDigest,
}

/// Each category has its own stable keyset cursor. Returning a cursor does not
/// imply coverage beyond the selected workspace and exact task/change scope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplanationCursor {
    pub bindings: Option<String>,
    pub contributions: Option<String>,
    pub decisions: Option<String>,
    pub task_transitions: Option<String>,
    pub adoptions: Option<String>,
    pub merges: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplanationPageRequest {
    pub after: ExplanationCursor,
    /// Per category, at most fifty. All categories share the byte budget.
    pub limit: u32,
    pub max_bytes: u64,
}
impl Default for ExplanationPageRequest {
    fn default() -> Self {
        Self {
            after: ExplanationCursor::default(),
            limit: 20,
            max_bytes: 128 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskExplanation {
    pub task_revision: TaskRevisionRef,
    pub source: Explained<TaskRevision>,
    pub bindings: Vec<WorkBinding>,
    pub contributions: Vec<WorkContributionReceipt>,
    pub decisions: Vec<ConfirmationReceipt>,
    pub task_transitions: Vec<TaskTransitionReceipt>,
    pub adoptions: Vec<AdoptionEffectReceipt>,
    pub next: ExplanationCursor,
    pub read_basis: LedgerReadBasis,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeExplanation {
    pub association: Explained<()>,
    pub contributions: Vec<WorkContributionReceipt>,
    pub merges: Vec<WorkMergeReceipt>,
    pub next: ExplanationCursor,
    pub read_basis: LedgerReadBasis,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LineExplanation {
    pub mapping: Explained<WorkLineMapping>,
    pub contribution: Explained<WorkContributionReceipt>,
    pub read_basis: LedgerReadBasis,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoteId;

    #[test]
    fn rootless_task_basis_does_not_invent_source_identity() {
        let reference = TaskRevisionRef {
            workspace_id: WorkspaceId::from("research"),
            note_id: NoteId::from("task"),
            rev: 4,
            digest: ContentDigest::from_string("source"),
            projection_schema_version: 1,
        };
        let basis = LedgerReadBasis {
            workspace_id: reference.workspace_id.clone(),
            scope: LedgerReadScope::TaskLedger {
                task_revision: reference,
            },
            source_event_watermark: 12,
            projector_watermark: None,
            query_version: 1,
            ontology_version: "intent-work-ledger/v1".into(),
            visibility_digest: ContentDigest::from_string("visibility"),
            ignore_policy: LedgerIgnorePolicy::NotAppliedToLedgerFacts,
            coverage: ExplanationCoverage::default(),
            truncation: vec![],
        };
        let value = serde_json::to_value(&basis).unwrap();
        assert_eq!(value["scope"]["kind"], "taskLedger");
        assert!(value["scope"].get("repositoryId").is_none());
        assert!(value["scope"].get("nativeState").is_none());
        assert!(value["projectorWatermark"].is_null());
        assert_eq!(
            serde_json::from_value::<LedgerReadBasis>(value).unwrap(),
            basis
        );
    }
}
