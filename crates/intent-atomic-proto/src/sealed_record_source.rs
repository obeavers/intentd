//! Private reconstruction of selected bytes over one exact immutable baseline.
//! These messages carry bytes and host observations, never provider-exit proof.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::closures::ClosureScope;
use crate::execution::WarmWorkingCopyCapture;
use crate::recording::SelectedFile;
use crate::{HostIdentity, SpoolRef, StateToken, StoreBinding};

pub const RECORD_SOURCE_PAYLOAD_VERSION: u32 = 1;
pub const MAX_RECORD_SOURCE_FILES: usize = 50_000;
pub const MAX_RECORD_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RECORD_SOURCE_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordSourceFile {
    pub file: SelectedFile,
    pub content_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordSourcePayload {
    pub version: u32,
    pub files: Vec<RecordSourceFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealRecordSourceRequest {
    pub operation_id: String,
    pub scope: ClosureScope,
    pub binding: StoreBinding,
    pub expected_state: StateToken,
    /// The host validates its own retained capture and immutable baseline.
    pub capture: WarmWorkingCopyCapture,
    /// Original SQL selection identity; the host does not mint SQL authority.
    pub selection_digest: String,
    pub files: Vec<SelectedFile>,
    pub payload: SpoolRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedRecordSource {
    pub host: HostIdentity,
    pub operation_id: String,
    pub scope: ClosureScope,
    pub binding: StoreBinding,
    pub expected_state: StateToken,
    /// Actual fresh private native IDs. Only the retained host journal may
    /// translate this token to the original expected canonical Draft token.
    pub sealed_state: StateToken,
    pub capture_operation_id: String,
    pub baseline_manifest_digest: String,
    pub selection_digest: String,
    pub payload: SpoolRef,
    pub sealed_source: PathBuf,
    pub file_count: u64,
    pub total_bytes: u64,
    pub command_digest: String,
}

impl SealedRecordSource {
    #[must_use]
    pub fn matches_request(&self, request: &SealRecordSourceRequest) -> bool {
        self.host == HostIdentity::default()
            && self.operation_id == request.operation_id
            && self.scope == request.scope
            && self.binding == request.binding
            && self.expected_state == request.expected_state
            && self.sealed_state.view == request.expected_state.view
            && self.sealed_state.own_merkle == request.expected_state.own_merkle
            && self.capture_operation_id == request.capture.operation_id
            && self.baseline_manifest_digest == request.capture.baseline_manifest_digest
            && self.selection_digest == request.selection_digest
            && self.payload == request.payload
            && self.file_count == request.files.len() as u64
            && request
                .files
                .iter()
                .try_fold(0u64, |total, file| total.checked_add(file.length))
                == Some(self.total_bytes)
    }
}
