//! Private adapted-binding grant facade. Serialized claims and captures are
//! data; the host must validate its retained freeze/capture proofs and actual
//! native grant registry before any shared-handle read.

use crate::baselines::BaselineRef;
use crate::intents::{NativeTurnFreezeReceipt, TaskRevisionRef};
use crate::{HostIdentity, StateToken, StoreBinding};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const EXECUTION_FACADE_VERSION: u32 = 1;
pub const MAX_GRANTED_READ_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WarmWorkingCopyCapture {
    pub operation_id: String,
    pub repository_id: String,
    pub binding_epoch: u64,
    pub parent_working_copy_id: String,
    pub parent_root: PathBuf,
    pub capture_generation: u64,
    pub selection_digest: Option<String>,
    pub baseline: BaselineRef,
    pub baseline_manifest_digest: String,
    pub working_digest: String,
    pub path: PathBuf,
    pub copied_entries: u64,
    pub copied_bytes: u64,
    pub mechanism: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionCapability {
    Delegate,
    TaskMutation,
    ReadSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionClaim {
    pub grant_id: String,
    pub revision: u64,
    pub work_binding_id: String,
    pub workspace_id: String,
    pub root_id: String,
    pub root_locator: PathBuf,
    pub agent_id: String,
    pub attempt_id: String,
    pub task_revision: TaskRevisionRef,
    pub expires_at_unix_ms: u64,
    pub path_prefixes: Vec<String>,
    pub capabilities: Vec<ExecutionCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueExecutionGrantRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    pub claim: ExecutionClaim,
    pub view: String,
    pub expected_state: StateToken,
    pub freeze: NativeTurnFreezeReceipt,
    pub capture: WarmWorkingCopyCapture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExecutionGrantReceipt {
    pub host: HostIdentity,
    pub facade_version: u32,
    pub binding: StoreBinding,
    pub operation_id: String,
    pub claim: ExecutionClaim,
    pub native_grant_id: String,
    /// Native path-derived sandbox-registry identity, separate from Intent's
    /// persisted repository UUID above. It never replaces the binding identity.
    pub native_repository_id: String,
    pub native_view_id: u64,
    pub native_state: StateToken,
    pub native_capabilities: Vec<String>,
    pub native_expires_at_unix_ms: u64,
    pub freeze_digest: String,
    pub capture: WarmWorkingCopyCapture,
    pub token_sha256: String,
    /// Process incarnation: native grants cannot be reconstructed after restart.
    pub host_generation: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeExecutionGrantIssued {
    pub receipt: NativeExecutionGrantReceipt,
    pub token: String,
}
impl std::fmt::Debug for NativeExecutionGrantIssued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeExecutionGrantIssued")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadGrantedFileRequest {
    pub request_id: String,
    pub grant_id: String,
    pub grant_receipt_digest: String,
    pub token: String,
    pub path: String,
}
impl std::fmt::Debug for ReadGrantedFileRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadGrantedFileRequest")
            .field("request_id", &self.request_id)
            .field("grant_id", &self.grant_id)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedFileReceipt {
    pub request_id: String,
    pub grant_id: String,
    pub grant_receipt_digest: String,
    pub path: String,
    pub grant_state: StateToken,
    pub basis: GrantedReadBasis,
    /// Recorded view bytes only. Working overlays are not inferred or served.
    pub kind: GrantedFileKind,
    pub content_hex: String,
    pub content_sha256: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantedFileKind {
    Regular,
    Executable,
    Symlink,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantedReadBasis {
    /// Exact bytes/mode from the immutable manifest validated at grant issue.
    /// This is not a new atomic observation of the whole current native view.
    PinnedGrantManifest,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloseExecutionGrantRequest {
    pub grant_id: String,
    pub grant_receipt_digest: String,
    pub token: String,
}
impl std::fmt::Debug for CloseExecutionGrantRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloseExecutionGrantRequest")
            .field("grant_id", &self.grant_id)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionGrantClosed {
    pub grant_id: String,
    pub grant_receipt_digest: String,
    pub admitted_reads_drained: bool,
}
