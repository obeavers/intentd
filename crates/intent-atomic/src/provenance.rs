//! Optional native activity classification. Unavailable classification is never
//! substituted with an independent check or a guessed attribution.

use intent_atomic_proto::provenance::{
    ClassifyToolRequest, ToolClassificationReceipt, ToolObservation, MAX_OBSERVATION_BYTES,
};
use intent_atomic_proto::{Command, Reply};
use sha2::{Digest, Sha256};

use crate::{HostError, HostSupervisor, Result};

/// Classify exact observed inputs using the pinned host rules.
/// # Errors
/// Refuses empty identities, oversized payloads, host failures and mismatched receipts.
pub async fn classify_tool(
    host: &HostSupervisor,
    observation: ToolObservation,
) -> Result<ToolClassificationReceipt> {
    let bytes = serde_json::to_vec(&observation)?;
    if observation.observation_id.is_empty()
        || observation.observation_id.len() > 256
        || observation.tool_name.is_empty()
        || observation.tool_name.len() > 512
        || bytes.len() > MAX_OBSERVATION_BYTES
    {
        return Err(HostError::Configuration("invalid bounded tool observation"));
    }
    let request = ClassifyToolRequest {
        observation,
        input_digest: crate::spool::hex(&Sha256::digest(&bytes)),
    };
    match host.request(Command::ClassifyTool { request }).await? {
        Reply::ToolClassified { receipt } => Ok(receipt),
        _ => Err(HostError::Protocol(
            "expected exact tool classification receipt",
        )),
    }
}
