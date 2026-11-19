//! Portable recorded code/view closure, distinct from frozen Git baselines.
//! These DTOs confer no workspace authority or work-evidence completeness.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::closures::ClosureScope;
use crate::{HostIdentity, SpoolRef, StateToken, StoreBinding};

pub const RECORDED_CLOSURE_FORMAT: u32 = 2;
pub const RECORDED_CLOSURE_READER: u32 = 1;
pub const RECORDED_MATERIALIZER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordedClosureProfile {
    RecordedViewExact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportRecordedClosureRequest {
    pub operation_id: String,
    pub scope: ClosureScope,
    /// Allocated by the Store owner before this capture, never by timestamps.
    pub capture_revision: u64,
    pub binding: StoreBinding,
    pub view: String,
    pub expected_state: StateToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedConflictRef {
    pub native_hash: String,
    pub sha256: String,
    pub length: u64,
    pub file_count: u64,
    pub entry_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedClosure {
    pub format: u32,
    pub reader_version: u32,
    pub profile: RecordedClosureProfile,
    pub operation_id: String,
    pub host: HostIdentity,
    pub scope: ClosureScope,
    pub capture_revision: u64,
    /// Original source fence, including its original store-local numeric IDs.
    pub source_state: StateToken,
    pub project_id: String,
    pub project_identity_hash: String,
    pub view_manifest_digest: String,
    pub materialization_manifest_digest: String,
    pub materialization_id: String,
    pub conflict: Option<RecordedConflictRef>,
    pub object_count: u64,
    /// Exact native changes, ordered view hierarchy and canonical conflict object.
    pub payload: SpoolRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRecordedClosureRequest {
    pub operation_id: String,
    pub expected_scope: ClosureScope,
    pub closure: RecordedClosure,
}

/// An actual verified private native restore, not a canonical root install.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedClosureRestore {
    pub operation_id: String,
    pub host: HostIdentity,
    pub scope: ClosureScope,
    pub capture_revision: u64,
    pub source_state: StateToken,
    /// Fresh-store IDs can differ; exact semantic manifests remain unchanged.
    pub restored_state: StateToken,
    pub project_id: String,
    pub project_identity_hash: String,
    pub view_manifest_digest: String,
    pub materialization_manifest_digest: String,
    pub materialization_id: String,
    pub native_conflict_hash: Option<String>,
    pub object_count: u64,
    pub native_path: PathBuf,
    pub path: PathBuf,
    pub receipt_digest: String,
}
