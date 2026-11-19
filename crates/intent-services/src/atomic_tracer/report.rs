use intent_core::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

use super::{GitSourceIdentity, RetainedAssociation, TaskQueryAssociation, TestObservation};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TracerOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseObservation {
    pub phase: String,
    pub observation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TracerReport {
    pub schema_version: u32,
    pub outcome: TracerOutcome,
    pub phases: Vec<PhaseObservation>,
    pub baseline: Option<GitSourceIdentity>,
    pub baseline_test: Option<TestObservation>,
    pub association: Option<TaskQueryAssociation>,
    pub retained_association: Option<RetainedAssociation>,
    pub sentinel_excluded: bool,
    pub durable_reopen_verified: bool,
    pub error: Option<String>,
    pub limitations: Vec<String>,
}

impl Default for TracerReport {
    fn default() -> Self {
        Self {
            schema_version: 1,
            outcome: TracerOutcome::Failed,
            phases: vec![],
            baseline: None,
            baseline_test: None,
            association: None,
            retained_association: None,
            sentinel_excluded: false,
            durable_reopen_verified: false,
            error: None,
            limitations: vec![
                "Git remains source authority; Atomic supplies an imported recorded-code index.".into(),
                "The test result is an observation, not a qualified independent check receipt.".into(),
                "No exclusive authorship, independent review, source acceptance, task completion, native writing or publication is claimed.".into(),
                "Task-plan confirmation is not source-adoption approval.".into(),
            ],
        }
    }
}

impl TracerReport {
    pub(crate) fn observed(&mut self, phase: &str, observation: &str) {
        self.phases.push(PhaseObservation {
            phase: phase.into(),
            observation: observation.into(),
        });
    }

    /// Render the same retained evidence as a small human-readable report.
    /// # Errors
    /// Returns serialization errors for the embedded machine-readable association.
    pub fn markdown(&self) -> Result<String> {
        let status = match self.outcome {
            TracerOutcome::Passed => "PASS",
            TracerOutcome::Failed => "FAIL",
        };
        let mut text = format!("# Atomic T1 tracer: {status}\n\n");
        if let Some(error) = &self.error {
            let _ = writeln!(text, "Failure: {}\n", escape(error));
        }
        for phase in &self.phases {
            let _ = writeln!(
                text,
                "- {}: {}",
                escape(&phase.phase),
                escape(&phase.observation)
            );
        }
        if let Some(association) = &self.association {
            let run = &association.run;
            text.push_str("\n| Evidence | Identity |\n|---|---|\n");
            for (key, value) in [
                (
                    "Original task",
                    format!(
                        "{} / revision {}",
                        run.task.reference.note_id, run.task.reference.rev
                    ),
                ),
                (
                    "Original admission",
                    run.binding.admission.binding_id.as_str().to_string(),
                ),
                ("Provider", run.provider.adapter_id.clone()),
                ("Changed file", super::SOURCE_PATH.to_string()),
                ("Git commit", run.source.commit.as_str().to_string()),
                ("Git tree", run.source.tree.as_str().to_string()),
                (
                    "Actual test exit",
                    association.test_observation.exit_code.to_string(),
                ),
                (
                    "Test log digest",
                    association.test_observation.log_digest.as_str().to_string(),
                ),
                (
                    "Atomic derived generation",
                    association.preparation.index.generation.clone(),
                ),
                (
                    "Query provenance",
                    "ImportedGitSnapshot; taskRevision remains null".into(),
                ),
            ] {
                let _ = writeln!(text, "| {key} | {} |", escape(&value));
            }
        }
        text.push('\n');
        for limitation in &self.limitations {
            let _ = writeln!(text, "- {}", escape(limitation));
        }
        let evidence_location = match (&self.association, &self.retained_association) {
            (Some(_), Some(_)) => {
                "\nFull typed evidence is retained in report.json and the task association blob.\n"
            }
            (Some(_), None) => {
                "\nObserved typed evidence is included in report.json; task association retention was not confirmed.\n"
            }
            (None, _) => "\nObserved phases and available setup results are retained in report.json.\n",
        };
        text.push_str(evidence_location);
        Ok(text)
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('\n', " ")
}
