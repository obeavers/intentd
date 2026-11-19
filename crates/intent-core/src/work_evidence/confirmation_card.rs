//! Read-only, source-joined confirmation detail. No field certifies a decision
//! or authorizes a mutation; absent typed result/review/triage remains explicit.

use super::{
    candidate::CandidateCheckRun,
    confirmation::{CheckEvidenceRevision, ConfirmationOffer},
    TaskRevision,
};
use crate::work_explanation::LedgerReadBasis;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfirmationCardUnavailable {
    Missing,
    Changed,
    ByteBudget,
    NotRetainedAsTypedEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConfirmationCardDetail<T> {
    Available { value: T },
    Unavailable { reason: ConfirmationCardUnavailable },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationCheckDetail {
    pub revision: CheckEvidenceRevision,
    pub detail: ConfirmationCardDetail<CandidateCheckRun>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfirmationCardStaleness {
    TaskMissing,
    TaskChanged,
    CheckMissing,
    CheckChanged,
    RootChanged,
    /// An immutable offer target exists; this read did not observe current working source.
    TargetNotReobserved,
    EvidenceUnavailable,
    /// Reading this card does not mint/revalidate a mutation authority credential.
    AuthorityNotRevalidated,
    AuthorityChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnavailableCardStatus {
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnavailableConfirmationSection {
    pub status: UnavailableCardStatus,
    pub reason: ConfirmationCardUnavailable,
}
impl Default for UnavailableConfirmationSection {
    fn default() -> Self {
        Self {
            status: UnavailableCardStatus::Unavailable,
            reason: ConfirmationCardUnavailable::NotRetainedAsTypedEvidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkConfirmationCard {
    pub offer: ConfirmationOffer,
    /// Exact original requested work, including prose and retained criteria.
    pub task: ConfirmationCardDetail<TaskRevision>,
    /// Each detail is joined only through exact retained source digests+origin.
    pub checks: Vec<ConfirmationCheckDetail>,
    pub staleness: Vec<ConfirmationCardStaleness>,
    /// No result is inferred from task status or an agent's idle state.
    pub actual_result: UnavailableConfirmationSection,
    pub reviews: UnavailableConfirmationSection,
    pub triage: UnavailableConfirmationSection,
    pub narrative: UnavailableConfirmationSection,
    pub read_basis: LedgerReadBasis,
}
