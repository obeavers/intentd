//! Exact native-record qualification. These types are private host protocol,
//! never authority to record a user workspace or to declare a task complete.

use crate::{HostIdentity, SpoolRef, StateToken, StoreBinding};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const RECORD_POLICY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SelectedFileKind {
    Regular,
    Executable,
    Symlink,
    Deletion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedFile {
    pub path: String,
    pub kind: SelectedFileKind,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareRecordRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    /// A pre-created private working copy beneath the host spool. No live
    /// user directory is ever substituted if this sealed source is missing.
    pub sealed_source: PathBuf,
    pub expected_state: StateToken,
    pub files: Vec<SelectedFile>,
    pub message: String,
    pub author_name: String,
    pub author_email: Option<String>,
    pub unix_seconds: i64,
    /// Retained task/work/context references, encoded before native hashing.
    pub context_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedNativeRecord {
    pub operation_id: String,
    pub host: HostIdentity,
    pub binding: StoreBinding,
    pub expected_state: StateToken,
    pub command_digest: String,
    pub selection_digest: String,
    pub metadata_digest: String,
    pub change_hash: String,
    pub bytes: SpoolRef,
    pub recorded_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase", deny_unknown_fields)]
pub enum RecordPreparation {
    Prepared {
        record: Box<PreparedNativeRecord>,
    },
    NoChanges {
        operation_id: String,
        command_digest: String,
        expected_state: StateToken,
        selection_digest: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeRecordReceipt {
    pub operation_id: String,
    pub change_hash: String,
    pub encoding_sha256: String,
    pub encoding_length: u64,
    pub before: StateToken,
    pub after: StateToken,
    pub replayed: bool,
}
