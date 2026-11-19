//! The real native rule classifier, without a model call or source mutation.

use atomic_agent::provenance::{classify::classify_tool_call, types::NodeKind};
use intent_atomic_proto::provenance::{
    ClassifyToolRequest, ToolClassification, ToolClassificationReceipt, CLASSIFIER_VERSION,
    MAX_OBSERVATION_BYTES,
};
use sha2::{Digest, Sha256};

use crate::{HostError, Result};

pub(crate) fn classify(request: &ClassifyToolRequest) -> Result<ToolClassificationReceipt> {
    let observation = &request.observation;
    let bytes = serde_json::to_vec(observation)?;
    if observation.observation_id.is_empty()
        || observation.observation_id.len() > 256
        || observation.tool_name.is_empty()
        || observation.tool_name.len() > 512
        || bytes.len() > MAX_OBSERVATION_BYTES
        || request.input_digest != format!("{:x}", Sha256::digest(&bytes))
    {
        return Err(HostError::Invalid(
            "invalid bounded tool observation or digest",
        ));
    }
    let input = observation
        .input_json
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()?;
    let classification = match classify_tool_call(
        &observation.tool_name,
        input.as_ref(),
        observation.output.as_deref(),
        observation.status.as_deref(),
    ) {
        NodeKind::Exploration => ToolClassification::Exploration,
        NodeKind::Commitment => ToolClassification::Commitment,
        NodeKind::Verification => ToolClassification::Verification,
        NodeKind::Execution => ToolClassification::Execution,
        NodeKind::Error => ToolClassification::Error,
        _ => {
            return Err(HostError::Unsupported(
                "native classifier returned a non-tool activity",
            ));
        }
    };
    Ok(ToolClassificationReceipt {
        observation_id: observation.observation_id.clone(),
        input_digest: request.input_digest.clone(),
        atomic_revision: intent_atomic_proto::ATOMIC_REVISION.into(),
        classifier_version: CLASSIFIER_VERSION.into(),
        classification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_atomic_proto::provenance::ToolObservation;
    use serde_json::json;

    fn fixture_request(
        name: &str,
        input: Option<serde_json::Value>,
        status: Option<&str>,
    ) -> ClassifyToolRequest {
        let observation = ToolObservation {
            observation_id: "observed-tool-event".into(),
            tool_name: name.into(),
            input_json: input.map(|value| value.to_string()),
            output: None,
            status: status.map(str::to_owned),
        };
        let input_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&observation).unwrap())
        );
        ClassifyToolRequest {
            observation,
            input_digest,
        }
    }

    #[test]
    fn pinned_rules_classify_observed_activity_without_certifying_a_pass() {
        for (name, input, status, expected) in [
            (
                "read_file",
                None,
                Some("completed"),
                ToolClassification::Exploration,
            ),
            (
                "apply_patch",
                None,
                Some("completed"),
                ToolClassification::Commitment,
            ),
            (
                "bash",
                Some(json!({"command":"cargo test"})),
                None,
                ToolClassification::Verification,
            ),
            (
                "bash",
                Some(json!({"command":"cargo test"})),
                Some("error"),
                ToolClassification::Error,
            ),
            ("unknown-tool", None, None, ToolClassification::Execution),
        ] {
            let request = fixture_request(name, input, status);
            let receipt = classify(&request).unwrap();
            assert_eq!(receipt.classification, expected);
            assert_eq!(receipt.input_digest, request.input_digest);
            assert!(intent_atomic_proto::Reply::ToolClassified { receipt }
                .matches_command(&intent_atomic_proto::Command::ClassifyTool { request }));
        }
    }

    #[test]
    fn tampered_and_oversized_observations_are_refused_before_classification() {
        let mut request = fixture_request("read", None, None);
        request.observation.tool_name = "write".into();
        assert!(classify(&request).is_err());
        let mut request = fixture_request("read", None, None);
        request.observation.output = Some("x".repeat(MAX_OBSERVATION_BYTES));
        request.input_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&request.observation).unwrap())
        );
        assert!(classify(&request).is_err());
    }
}
