//! History reads carry repository-scoped identities, never live Git handles.

use serde::{Deserialize, Serialize};

use super::NativeChangeRef;

/// Immutable objects captured together for one history walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistorySnapshot {
    pub head: NativeChangeRef,
    pub boundary: Option<NativeChangeRef>,
    pub upstream: Option<NativeChangeRef>,
}

/// Explicit read modes keep ref-based compatibility reads distinct from snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HistoryRead {
    Since {
        base_ref: Option<String>,
        limit: usize,
        include_files: bool,
    },
    Bounded {
        boundary: Option<NativeChangeRef>,
        limit: usize,
        include_older: bool,
        include_files: bool,
    },
    Snapshot {
        snapshot: HistorySnapshot,
        limit: usize,
        include_older: bool,
        include_files: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryEntry {
    pub change: NativeChangeRef,
    pub message: String,
    pub author: String,
    pub author_email: String,
    pub date: String,
    /// `None` means file inspection was deliberately skipped.
    pub files: Option<Vec<String>>,
    pub files_changed: usize,
    pub published: bool,
    pub agent_id: Option<String>,
    pub linked_note_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeFileStat {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeDetails {
    pub change: NativeChangeRef,
    pub author: String,
    pub author_email: String,
    pub date: String,
    pub message: String,
    pub files: Vec<ChangeFileStat>,
}

/// Ref observations certify one history range. Missing candidates retain their
/// positions so a missing remote base differs from a missing local base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryRefreshInputs {
    pub head: NativeChangeRef,
    pub branch: String,
    pub upstream: Option<NativeChangeRef>,
    pub boundary_refs: Vec<Option<NativeChangeRef>>,
    pub fallback: Option<NativeChangeRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryRefreshCapture {
    pub inputs: HistoryRefreshInputs,
    pub history: HistorySnapshot,
}
