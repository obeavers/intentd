//! Bounded observed tool inputs for the pinned deterministic native classifier.
//! A verification classification says what kind of activity was observed; it
//! never establishes that a check passed or ran against a reviewed candidate.

use serde::{Deserialize, Serialize};

pub const MAX_OBSERVATION_BYTES: usize = 32_768;
pub const CLASSIFIER_VERSION: &str = "atomic-tool-rules-1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolObservation {
    pub observation_id: String,
    pub tool_name: String,
    /// Exact JSON input bytes; the host parses them before classification.
    pub input_json: Option<String>,
    pub output: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassifyToolRequest {
    pub observation: ToolObservation,
    /// SHA-256 of the exact serialized `ToolObservation` struct.
    pub input_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ToolClassification {
    Exploration,
    Commitment,
    Verification,
    Execution,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolClassificationReceipt {
    pub observation_id: String,
    pub input_digest: String,
    pub atomic_revision: String,
    pub classifier_version: String,
    pub classification: ToolClassification,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Command, Reply, ATOMIC_REVISION};

    #[test]
    fn classification_receipt_is_bound_to_observation_digest_and_pinned_rules() {
        let request = ClassifyToolRequest {
            observation: ToolObservation {
                observation_id: "event".into(),
                tool_name: "read".into(),
                input_json: None,
                output: None,
                status: None,
            },
            input_digest: "digest".into(),
        };
        let receipt = ToolClassificationReceipt {
            observation_id: "event".into(),
            input_digest: "digest".into(),
            atomic_revision: ATOMIC_REVISION.into(),
            classifier_version: CLASSIFIER_VERSION.into(),
            classification: ToolClassification::Exploration,
        };
        let command = Command::ClassifyTool { request };
        assert!(Reply::ToolClassified {
            receipt: receipt.clone()
        }
        .matches_command(&command));
        for field in ["id", "digest", "pin", "rules"] {
            let mut changed = receipt.clone();
            match field {
                "id" => changed.observation_id = "other".into(),
                "digest" => changed.input_digest = "other".into(),
                "pin" => changed.atomic_revision = "other".into(),
                _ => changed.classifier_version = "other".into(),
            }
            assert!(!Reply::ToolClassified { receipt: changed }.matches_command(&command));
        }
    }
}
