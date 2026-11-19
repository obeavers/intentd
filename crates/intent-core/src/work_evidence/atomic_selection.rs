//! Persisted Atomic file/change selection definitions. These values neither
//! seal filesystem payloads nor authorize recording or execution. Store-owned
//! observations and the physical capture barrier remain separate requirements.

use serde::{Deserialize, Serialize};

use crate::vcs::{
    ContentDigest, FrozenSelectionManifest, NativeChangeRef, OperationId, RootBinding, SelectionId,
};

pub const ATOMIC_SELECTION_FORMAT_VERSION: u32 = 1;
pub const MAX_ATOMIC_SELECTION_FILES: usize = 1024;
pub const MAX_ATOMIC_SELECTION_CONTRIBUTIONS: usize = 1024;
pub const MAX_ATOMIC_SELECTION_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicSelectionScope {
    pub root: RootBinding,
    pub working_copy_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicSelection {
    /// Exact selected path/kind/length/digest definitions, not captured bytes.
    pub manifest: FrozenSelectionManifest,
    /// Exact ordered contribution identities. No membership or authorship is
    /// inferred from a label, path, or the order of the selected files.
    pub selected_contributions: Vec<NativeChangeRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "knowledge",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AtomicSelectionKnowledge {
    Unknown,
    Known {
        revision: u64,
        selection_id: SelectionId,
        selection: Box<AtomicSelection>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicSelectionObservation {
    pub scope: AtomicSelectionScope,
    pub knowledge: AtomicSelectionKnowledge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AtomicSelectionWriteDisposition {
    Applied,
    Unchanged,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicSelectionWriteReceipt {
    pub operation_id: OperationId,
    pub request_digest: ContentDigest,
    pub disposition: AtomicSelectionWriteDisposition,
    /// Observation from this operation's original transaction. On replay this
    /// remains historical, rather than claiming to be the current selection.
    pub observation: AtomicSelectionObservation,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicSelectionFreezeReceipt {
    pub operation_id: OperationId,
    pub request_digest: ContentDigest,
    pub scope: AtomicSelectionScope,
    pub revision: u64,
    pub selection_id: SelectionId,
    pub selection: AtomicSelection,
    /// Definition freeze only. A physical source is not sealed by this row.
    pub created_at: String,
}
