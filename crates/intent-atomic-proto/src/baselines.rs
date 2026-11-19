//! Private baseline qualification contract. Full imports are deliberate isolated
//! fallbacks, never a claim that an upstream live-parent draft is frozen.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{HostIdentity, StateToken, StoreBinding};

pub const BASELINE_POLICY_VERSION: u32 = 1;
pub const MATERIALIZER_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineRef {
    pub repository_id: String,
    pub binding_epoch: u64,
    pub baseline_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselinePolicy {
    pub version: u32,
    /// Reject case-folding path collisions whenever the destination requires it.
    pub case_sensitive: bool,
    /// Runtime/credential/generated exclusions. A tracked excluded path refuses
    /// the import; it is never silently removed from an "exact" baseline.
    pub excluded_paths: Vec<String>,
}

impl Default for BaselinePolicy {
    fn default() -> Self {
        Self {
            version: BASELINE_POLICY_VERSION,
            case_sensitive: false,
            excluded_paths: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportBaselineRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    pub source_path: PathBuf,
    /// Immutable full SHA-1 commit, never HEAD, a branch name, or a worktree.
    pub commit: String,
    pub previous: Option<BaselineRef>,
    pub policy: BaselinePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BaselineStorage {
    /// Independent full native store per baseline. Incremental parent/delta
    /// storage is not asserted at the current pinned upstream API.
    FullReimport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineReceipt {
    pub baseline: BaselineRef,
    pub host: HostIdentity,
    pub source_commit: String,
    pub source_tree: String,
    pub previous: Option<BaselineRef>,
    pub storage: BaselineStorage,
    pub native_state: StateToken,
    pub manifest_digest: String,
    pub materialization_id: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub policy: BaselinePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterializeBaselineRequest {
    pub operation_id: String,
    pub baseline: BaselineRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineMaterialization {
    pub baseline: BaselineRef,
    pub materialization_id: String,
    /// Host-owned private spool directory, never a caller-selected destination.
    pub path: PathBuf,
    pub manifest_digest: String,
    pub file_count: u64,
    pub total_bytes: u64,
}
