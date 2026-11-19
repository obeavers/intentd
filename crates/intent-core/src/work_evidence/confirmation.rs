//! Immutable human decisions and separately retained effects. A decision is
//! never itself proof that code adoption or a task transition happened.

use serde::{Deserialize, Serialize};

use super::candidate::EvidenceOrigin;
use super::candidate::WorkCandidate;
use super::TaskRevisionRef;
use crate::vcs::{
    CapturedState, ContentDigest, MaterializationId, NativeChangeRef, NativeStateRef, OperationId,
    RootBinding,
};
use crate::{HostRole, PrincipalId, WorkspaceId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanAuthoritySnapshot {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub host_role: HostRole,
    /// Exact service authority facts and continuity, retained independently of profiles.
    pub facts: serde_json::Value,
    pub digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoSourcePurpose {
    Research,
    Review,
}

/// Retained recorder/capture evidence, supplied by the internal settlement owner.
/// A code-bearing attempt must retain identical exact before/after captures;
/// neither a caller boolean nor an agent's claim of no changes is accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoChangeSettlement {
    pub settlement_id: String,
    pub binding_id: OperationId,
    pub turn_attempt: String,
    pub task_revision: TaskRevisionRef,
    pub purpose: NoSourcePurpose,
    pub before: Option<CapturedState>,
    pub after: Option<CapturedState>,
    pub journal_digest: ContentDigest,
    pub evidence_manifest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConfirmationSubject {
    Source {
        candidate: Box<WorkCandidate>,
        selected_changes: Vec<NativeChangeRef>,
        dependency_changes: Vec<NativeChangeRef>,
        closure_digest: ContentDigest,
    },
    NoSource {
        settlement_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationTarget {
    pub root: RootBinding,
    pub state: NativeStateRef,
    /// Digest of the actual observed working overlay/selection, not just HEAD.
    pub working_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationOfferInputs {
    pub offer_id: String,
    pub task_revision: TaskRevisionRef,
    pub subject: ConfirmationSubject,
    pub expected_target: Option<ConfirmationTarget>,
    pub triage_reference: Option<String>,
    pub report_digest: Option<ContentDigest>,
    /// Retained bytes only; these references do not assert independent review qualification.
    pub review_revisions: Vec<ContentDigest>,
    pub satisfied_criteria: Vec<ContentDigest>,
    pub outstanding_criteria: Vec<ContentDigest>,
}

/// Computed internally at review/decision time. Services observe target bytes
/// under their barrier; storage computes current task/evidence identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationReadBasis {
    pub task_revision: TaskRevisionRef,
    /// Current governing-equivalent note row, separate from original work source.
    pub completion_note_rev: i64,
    pub target: Option<ConfirmationTarget>,
    pub subject_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
    pub check_revisions: Vec<CheckEvidenceRevision>,
    pub review_digest: ContentDigest,
    pub report_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckEvidenceRevision {
    pub run_id: String,
    pub spec_digest: ContentDigest,
    pub observation_digest: Option<ContentDigest>,
    pub origin: EvidenceOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationOffer {
    pub inputs: ConfirmationOfferInputs,
    pub authority: HumanAuthoritySnapshot,
    pub basis: ConfirmationReadBasis,
    pub offer_digest: ContentDigest,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationDecision {
    Accept,
    RequestChanges,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HumanReviewScope {
    ConfirmationOnly,
    IndependentCodeReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationDecisionRequest {
    pub operation_id: OperationId,
    pub offer_id: String,
    pub offer_digest: ContentDigest,
    pub decision: ConfirmationDecision,
    pub reason: Option<String>,
    pub human_review_scope: HumanReviewScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationReceipt {
    pub request: ConfirmationDecisionRequest,
    pub authority: HumanAuthoritySnapshot,
    pub basis: ConfirmationReadBasis,
    pub receipt_digest: ContentDigest,
    pub decided_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionEffectReceipt {
    pub decision_operation_id: OperationId,
    pub adoption_operation_id: OperationId,
    pub before: NativeStateRef,
    pub after: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub native_receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskCompletionKind {
    Confirmed,
    CompletedWithoutConfirmation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanCompletionIntent {
    pub operation_id: OperationId,
    pub task_revision: TaskRevisionRef,
    pub authority: HumanAuthoritySnapshot,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTransitionReceipt {
    pub operation_id: OperationId,
    pub completion_kind: TaskCompletionKind,
    pub task_revision: TaskRevisionRef,
    pub principal_id: PrincipalId,
    pub note_rev_after: i64,
    pub note_version: i64,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationOutcome {
    pub confirmation: ConfirmationReceipt,
    pub task_transition: Option<TaskTransitionReceipt>,
}
