//! Retained execution scope and SQL effect receipts. Serialized scope identifies
//! authority; only a server-owned, non-Serde carrier can exercise it.

use serde::{Deserialize, Serialize};

use super::TaskRevisionRef;
use crate::vcs::{ContentDigest, OperationId, RootBinding};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkExecutionCapability {
    Delegate,
    TaskMutation,
    ReadSource,
    WriteSource,
    RecordSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkExecutionScope {
    pub grant_id: OperationId,
    pub revision: u64,
    pub binding_id: OperationId,
    pub task_revision: TaskRevisionRef,
    pub root: RootBinding,
    pub native_grant_id: String,
    pub native_receipt_digest: ContentDigest,
    pub expires_at_unix_ms: u64,
    /// Canonical relative slash-separated prefixes. A scope never means all
    /// paths implicitly; an explicit `.` denotes the complete bound root.
    pub path_prefixes: Vec<String>,
    pub capabilities: Vec<WorkExecutionCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkSqlEffect {
    pub operation_id: OperationId,
    /// Digest of the exact server-built command, including its target IDs.
    pub command_digest: ContentDigest,
    pub capability: WorkExecutionCapability,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkSqlEffectReceipt {
    pub operation_id: OperationId,
    pub grant_id: OperationId,
    pub grant_revision: u64,
    pub effect_digest: ContentDigest,
    /// Exact committed SQL callback result; replay returns these retained bytes.
    pub result_json: String,
    pub result_digest: ContentDigest,
}
