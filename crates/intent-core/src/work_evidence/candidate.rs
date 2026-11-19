//! Candidate-bound check records. Claims and observed runner results stay distinct.

use serde::{Deserialize, Serialize};

use super::TaskRevisionRef;
use crate::vcs::{ContentDigest, MaterializationId, NativeStateRef, RootBinding};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkCandidate {
    pub candidate_id: String,
    pub root: RootBinding,
    pub task_revision: TaskRevisionRef,
    pub state: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub selection_revision: ContentDigest,
    pub composition_revision: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateCheckSpec {
    pub run_id: String,
    pub candidate_id: String,
    pub checker_id: String,
    pub configuration_digest: ContentDigest,
    pub environment_digest: ContentDigest,
    pub kind: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOrigin {
    RunnerObservation,
    AgentClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    Passed,
    Failed,
    Cancelled,
    Error,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CriterionCoverage {
    pub criterion_id: ContentDigest,
    pub evidence_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckObservation {
    pub candidate_id: String,
    pub task_revision: TaskRevisionRef,
    pub state: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub outcome: CheckOutcome,
    pub output_digest: ContentDigest,
    pub artifact_digests: Vec<ContentDigest>,
    pub coverage: Vec<CriterionCoverage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateCheckRun {
    pub spec: CandidateCheckSpec,
    pub origin: EvidenceOrigin,
    pub observation: Option<CheckObservation>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

impl CandidateCheckRun {
    /// Stored agent claims never satisfy a required passing runner check.
    #[must_use]
    pub fn is_admissible_pass_for(&self, criterion_id: &ContentDigest, kind: &str) -> bool {
        self.origin == EvidenceOrigin::RunnerObservation
            && self.completed_at.is_some()
            && self.spec.kind == kind
            && self.observation.as_ref().is_some_and(|observation| {
                observation.outcome == CheckOutcome::Passed
                    && observation.coverage.iter().any(|coverage| {
                        coverage.criterion_id == *criterion_id && coverage.evidence_kind == kind
                    })
            })
    }
}
