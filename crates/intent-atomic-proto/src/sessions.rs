//! Native authoring-session metadata. These receipts never prove provider exit.

use crate::{HostIdentity, StoreBinding};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginNativeSessionRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    /// Fresh physical native allocation, distinct from a logical ACP agent ID.
    pub session_id: String,
    pub work_binding_id: String,
    pub turn_attempt: String,
    pub agent_id: String,
    pub agent_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSessionReceipt {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub operation_id: String,
    pub session_id: String,
    pub work_binding_id: String,
    pub turn_attempt: String,
    pub agent_id: String,
    pub turn: u32,
    pub command_digest: String,
    pub native_session_sha256: String,
    pub provider_custody_verified: bool,
}

impl NativeSessionReceipt {
    #[must_use]
    pub fn matches_request(&self, request: &BeginNativeSessionRequest) -> bool {
        self.host == HostIdentity::default()
            && self.binding == request.binding
            && self.operation_id == request.operation_id
            && self.session_id == request.session_id
            && self.work_binding_id == request.work_binding_id
            && self.turn_attempt == request.turn_attempt
            && self.agent_id == request.agent_id
            && self.turn == 1
            && !self.provider_custody_verified
            && hash(&self.command_digest)
            && hash(&self.native_session_sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloseNativeSessionRequest {
    pub operation_id: String,
    pub session: NativeSessionReceipt,
}

/// The native turn became idle. This does not assert a process is stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSessionCloseReceipt {
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub operation_id: String,
    pub session_id: String,
    pub begin_operation_id: String,
    pub turn: u32,
    pub command_digest: String,
    pub native_session_sha256: String,
    pub provider_custody_verified: bool,
}

impl NativeSessionCloseReceipt {
    #[must_use]
    pub fn matches_request(&self, request: &CloseNativeSessionRequest) -> bool {
        self.host == HostIdentity::default()
            && self.binding == request.session.binding
            && self.operation_id == request.operation_id
            && self.session_id == request.session.session_id
            && self.begin_operation_id == request.session.operation_id
            && self.turn == request.session.turn
            && self.turn == 1
            && !self.provider_custody_verified
            && hash(&self.command_digest)
            && hash(&self.native_session_sha256)
    }
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
