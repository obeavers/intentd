//! Engine-neutral repository mechanics and immutable work identities.
//!
//! These values identify work; they do not authorize it. Services own caller
//! authorization, operation admission, capture barriers and durable bindings.
//! Implementations perform blocking repository work and must run off the async
//! event loop. Unsupported operations fail explicitly instead of returning empty
//! snapshots, clean status or successful no-ops.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, GitFileStatus, WorkspaceId};

mod history;
pub use history::*;
mod provision;
pub use provision::*;
mod adoption;
pub use adoption::*;

macro_rules! string_identity {
    ($($(#[$meta:meta])* $name:ident),+ $(,)?) => {$ (
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn from_string(value: impl Into<String>) -> Self { Self(value.into()) }

            #[must_use]
            pub fn as_str(&self) -> &str { &self.0 }
        }
    )+};
}

string_identity! {
    /// Intent-owned repository UUID. Never derive this identity from a path.
    RepositoryId,
    /// Full Git commit object identifier, never an Atomic hash.
    GitCommitId,
    /// Full Git tree object identifier.
    GitTreeId,
    /// A Git object identifier used by a typed object reference.
    GitObjectId,
    /// Hash of the exact stored Atomic change encoding.
    AtomicChangeHash,
    /// Atomic state or Merkle identity, never a Git object identifier.
    AtomicStateHash,
    /// Digest of retained content bytes; its hashing policy belongs to its owner.
    ContentDigest,
    /// Canonical file manifest digest bound to materializer and file-policy versions.
    MaterializationId,
    /// Immutable, content-bound selection identity, not a list of paths.
    SelectionId,
    /// Intent-owned durable attempt identity.
    OperationId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcsKind {
    Git,
    Atomic,
}

/// Persisted repository/root identity and assignment fence. A locator is not authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootBinding {
    pub workspace_id: WorkspaceId,
    pub root_id: String,
    pub repository_id: RepositoryId,
    pub kind: VcsKind,
    pub locator: PathBuf,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeChangeRef {
    Git {
        repository_id: RepositoryId,
        commit: GitCommitId,
    },
    Atomic {
        repository_id: RepositoryId,
        change: AtomicChangeHash,
    },
}

impl NativeChangeRef {
    #[must_use]
    pub const fn kind(&self) -> VcsKind {
        match self {
            Self::Git { .. } => VcsKind::Git,
            Self::Atomic { .. } => VcsKind::Atomic,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> &RepositoryId {
        match self {
            Self::Git { repository_id, .. } | Self::Atomic { repository_id, .. } => repository_id,
        }
    }
}

/// Immutable recorded state. Dirty overlays and index anchors belong to capture,
/// not to the recorded state's semantic commit/tree identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeStateRef {
    Git {
        repository_id: RepositoryId,
        commit: Option<GitCommitId>,
        tree: GitTreeId,
    },
    Atomic {
        repository_id: RepositoryId,
        view: String,
        effective_state: AtomicStateHash,
        own_merkle: AtomicStateHash,
        manifest: ContentDigest,
    },
}

impl NativeStateRef {
    #[must_use]
    pub const fn kind(&self) -> VcsKind {
        match self {
            Self::Git { .. } => VcsKind::Git,
            Self::Atomic { .. } => VcsKind::Atomic,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> &RepositoryId {
        match self {
            Self::Git { repository_id, .. } | Self::Atomic { repository_id, .. } => repository_id,
        }
    }
}

/// Blob identity is separate from change identity: a Git blob is not a commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum NativeObjectRef {
    Git { object: GitObjectId },
    Atomic { digest: ContentDigest },
}

/// Advertise only implemented, qualified operations. Defaults grant no capability.
#[expect(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VcsCapabilities {
    pub staging: bool,
    pub hunk_staging: bool,
    pub turn_records: bool,
    pub exact_record: bool,
    pub composition: bool,
    pub materialization: bool,
    pub closure_export: bool,
    pub closure_restore: bool,
    pub provenance: bool,
    pub triage: bool,
    pub first_class_conflicts: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VcsFileEntry {
    pub path: String,
    /// Existing lexical status values are shared; they contain no backend identity.
    pub status: GitFileStatus,
    pub staged: bool,
    /// `None` when the source observation did not retain conflict information.
    pub conflicted: Option<bool>,
    pub mode: Option<String>,
    pub old_object: Option<NativeObjectRef>,
    pub new_object: Option<NativeObjectRef>,
}

#[expect(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VcsStatus {
    pub kind: VcsKind,
    pub branch: String,
    pub view: Option<String>,
    pub ahead: i64,
    pub behind: i64,
    pub diverged: bool,
    pub files: Vec<VcsFileEntry>,
    pub has_uncommitted_changes: bool,
    pub has_untracked_files: bool,
    pub files_truncated: bool,
    pub total_files: Option<usize>,
    pub has_upstream: bool,
    pub unpushed_count: Option<i64>,
    /// `None` is unknown, not a clean conflict set.
    pub conflicts: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathState {
    Dirty,
    Clean,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffScope {
    Unstaged,
    Staged,
    Working,
}

/// A mutable compatibility ref is explicit and is never represented as an
/// immutable contribution identity. Other engines may refuse Git-specific refs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RevisionSpec {
    Head,
    Index { stage: u8 },
    Change { change: NativeChangeRef },
    GitRef { reference: String },
}

/// Explicit compatibility diff semantics. Missing refs retain the established
/// Git behavior of the selected operation, instead of being silently unified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum DiffRead {
    Unstaged,
    Staged,
    WorkingTracked,
    UnstagedTracked,
    Range { base_ref: String },
    TwoDot { from: String, to: String },
    Commit { revision: RevisionSpec },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffLineKind {
    Context,
    Addition,
    Deletion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    pub content: String,
    pub old_lineno: Option<u32>,
    pub new_lineno: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiffHunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileDiff {
    pub path: String,
    /// File kind and executable permission in portable POSIX tree-entry form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<u32>,
    pub additions: usize,
    pub deletions: usize,
    pub is_binary: bool,
    pub old_object: Option<NativeObjectRef>,
    pub new_object: Option<NativeObjectRef>,
    pub old_is_gitlink: bool,
    pub new_is_gitlink: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileDiffWithHunks {
    pub file: FileDiff,
    pub hunks: Vec<DiffHunk>,
    /// Metadata remains present when one body's serialized bytes exceed budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<DiffOmission>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffOmission {
    FileTooLarge,
}

/// A service attestation of capture admission, not a self-authenticating grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePermit {
    pub operation_id: OperationId,
    pub binding_epoch: u64,
    pub strength: CaptureStrength,
    pub excluded_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStrength {
    Turn,
    Full,
    Write,
}

/// Existing format-1 Git checkpoint anchors. Index/WIP are recovery commits,
/// and are never substituted for the native recorded state's HEAD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitCaptureAnchors {
    pub object_format: String,
    pub head: Option<GitCommitId>,
    pub index: GitCommitId,
    pub wip: Option<GitCommitId>,
    pub branch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CapturedWorkingCopy {
    Git {
        anchors: GitCaptureAnchors,
    },
    /// A new repository has no authored commit to masquerade as a HEAD anchor.
    GitUnborn {
        object_format: String,
        index_tree: GitTreeId,
        working_tree: GitTreeId,
    },
    Atomic {
        overlay_manifest: ContentDigest,
        selection: Option<SelectionId>,
        materialization_id: MaterializationId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedState {
    pub binding: RootBinding,
    pub state: NativeStateRef,
    pub working_copy: CapturedWorkingCopy,
}

/// Git compatibility modes. Native frozen selections use `PreparedRecord`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "paths",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum RecordSelection {
    Explicit(Vec<String>),
    StagedIndex,
    Attributed(Vec<String>),
    /// Missing credible attribution refuses automatic consumption.
    Unattributed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordRequest {
    pub message: String,
    pub selection: RecordSelection,
    pub agent_id: Option<String>,
    pub linked_note_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordSkipReason {
    NoChanges,
    Disabled,
    MergeInProgress,
    MissingAttribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedChange {
    pub change: NativeChangeRef,
    pub files: Vec<String>,
    /// A successful primitive retains its identity when post-commit refresh fails.
    pub index_refresh_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "result",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum RecordOutcome {
    Recorded(RecordedChange),
    Skipped(RecordSkipReason),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixedRecordMetadata {
    pub operation_id: OperationId,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub timestamp_seconds: i64,
    pub timezone_offset_minutes: i32,
    pub attribution_manifest: ContentDigest,
}

/// A sealed source and immutable selection; paths alone are not a frozen selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenSelection {
    pub binding: RootBinding,
    pub selection_id: SelectionId,
    pub source_state: NativeStateRef,
    pub manifest: ContentDigest,
    pub manifest_path: PathBuf,
    pub sealed_source: PathBuf,
}

/// Canonical, whole-file selected bytes. Payloads reside under `sealed_source`;
/// deletion entries name no payload and never follow a filesystem link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenSelectionManifest {
    pub format_version: u32,
    pub source_state: NativeStateRef,
    pub files: Vec<FrozenFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenFile {
    pub path: String,
    pub kind: FrozenFileKind,
    pub digest: Option<ContentDigest>,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FrozenFileKind {
    Regular,
    Executable,
    Symlink,
    Deletion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedRecord {
    pub operation_id: OperationId,
    pub binding: RootBinding,
    pub selection_id: SelectionId,
    pub change: NativeChangeRef,
    pub envelope_digest: ContentDigest,
    pub envelope_length: u64,
    pub spool_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeReceipt {
    pub operation_id: OperationId,
    pub change: NativeChangeRef,
    pub before: NativeStateRef,
    pub after: NativeStateRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_commit_error: Option<String>,
    #[serde(default)]
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiffQuery {
    pub paths: Vec<String>,
    pub max_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiffPage {
    pub before: NativeStateRef,
    pub after: NativeStateRef,
    pub before_capture: ContentDigest,
    pub after_capture: ContentDigest,
    pub files: Vec<FileDiffWithHunks>,
    pub next_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComposeRequest {
    pub operation_id: OperationId,
    pub base: NativeStateRef,
    pub changes: Vec<NativeChangeRef>,
    pub target: NativeStateRef,
}

/// Backend-owned preparation, never deserialized from a caller or RPC. All
/// locators name retained private artifacts; the source binding is unchanged.
#[derive(Clone, Debug)]
pub struct PreparedComposition {
    pub candidate: CompositionCandidate,
    pub materialization: MaterializationReceipt,
    pub closure: NativeClosureManifest,
    pub selection_path: PathBuf,
    pub manifest_path: PathBuf,
    pub receipt: crate::work_evidence::composition::VerifiedCompositionReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionCandidate {
    pub state: NativeStateRef,
    pub selected_changes: Vec<NativeChangeRef>,
    pub required_dependencies: Vec<NativeChangeRef>,
    pub materialization_id: MaterializationId,
    pub conflicts: Vec<ConflictInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConflictInfo {
    pub path: String,
    pub changes: Vec<NativeChangeRef>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ConflictDetails>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConflictDetails {
    Git {
        conflict_kind: GitConflictKind,
        ancestor: Option<GitConflictStage>,
        ours: Option<GitConflictStage>,
        theirs: Option<GitConflictStage>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GitConflictKind {
    Content,
    Binary,
    AddAdd,
    ModifyDelete,
    TypeChange,
    PathConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitConflictStage {
    pub path: String,
    pub object: GitObjectId,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompositionBlock {
    InheritedBaselineRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaterializationReceipt {
    pub state: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub destination: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionGrant {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeClosureManifest {
    pub state: NativeStateRef,
    pub changes: Vec<NativeChangeRef>,
    pub manifest_digest: ContentDigest,
    pub spool_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreReceipt {
    pub state: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub destination: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResetMode {
    Soft,
    Hard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntegrateOutcome {
    pub success: bool,
    pub aborted: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MergeConflicts {
    pub has_conflicts: bool,
    pub conflicted_files: Vec<String>,
    pub cannot_determine: bool,
}

/// Engine errors remain distinct until service policy renders the wire response.
#[derive(Debug, thiserror::Error)]
pub enum VcsError {
    #[error("{operation} is not supported by the {kind:?} engine")]
    Unsupported {
        operation: &'static str,
        kind: VcsKind,
    },
    #[error("repository engine unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("root binding or repository state changed: {reason}")]
    Stale { reason: String },
    #[error("invalid repository operation: {reason}")]
    InvalidInput { reason: String },
    #[error("repository composition blocked: {reason:?}")]
    PolicyBlocked {
        reason: CompositionBlock,
        changes: Vec<NativeChangeRef>,
    },
    #[error("repository operation outcome is uncertain: {reason}")]
    Uncertain {
        operation_id: OperationId,
        reason: String,
    },
    /// Preserve established Git error categories and payloads without re-prefixing.
    #[error(transparent)]
    Backend(#[from] Error),
}

pub type VcsResult<T> = std::result::Result<T, VcsError>;

/// Synchronous repository mechanics. The caller schedules blocking work and owns
/// authorization, admission and the lifetime of every supplied capture barrier.
/// Defaults deliberately refuse operations until an engine implements them.
pub trait WorkspaceEngine: Send + Sync {
    /// Inspect and retain the exact target under its actual live write barrier.
    /// # Errors
    /// Refuses unavailable barriers, dirty/unsupported targets and unstable bytes.
    fn capture_target(
        &self,
        _root: &RootBinding,
        _barrier: &WriteBarrierPermit,
        _spool_directory: &Path,
    ) -> VcsResult<PreparedTargetCapture> {
        Err(self.unsupported("captureTarget"))
    }
    /// Reinspect the complete retained capture artifact after process restart.
    /// # Errors
    /// Refuses missing or altered artifacts; never reconstructs proof from JSON alone.
    fn reopen_target_capture(
        &self,
        _root: &RootBinding,
        _manifest_path: &Path,
    ) -> VcsResult<PreparedTargetCapture> {
        Err(self.unsupported("reopenTargetCapture"))
    }
    /// Prepare an exact adoption from a retained target and inspected candidate.
    /// # Errors
    /// Refuses conflicts, changed identities or an invalid immutable preparation.
    fn prepare_adoption(
        &self,
        _root: &RootBinding,
        _capture: &PreparedTargetCapture,
        _candidate: &PreparedComposition,
        _operation_id: &OperationId,
        _spool_directory: &Path,
    ) -> VcsResult<PreparedAdoption> {
        Err(self.unsupported("prepareAdoption"))
    }
    /// Reinspect an immutable prepared adoption and its retained native objects.
    /// # Errors
    /// Refuses missing or altered objects/manifests.
    fn reopen_adoption(
        &self,
        _root: &RootBinding,
        _manifest_path: &Path,
    ) -> VcsResult<PreparedAdoption> {
        Err(self.unsupported("reopenAdoption"))
    }
    /// Reinspect a retained complete composition bundle after process restart.
    /// # Errors
    /// Refuses missing objects, altered manifests or incompatible identities.
    fn reopen_composition(
        &self,
        _root: &RootBinding,
        _bundle_directory: &Path,
    ) -> VcsResult<PreparedComposition> {
        Err(self.unsupported("reopenComposition"))
    }
    /// Retain a complete inspected composition in another private directory.
    /// # Errors
    /// Refuses altered source, unsupported file kinds or an existing destination.
    fn copy_composition(
        &self,
        _prepared: &PreparedComposition,
        _private_destination: &Path,
    ) -> VcsResult<PreparedComposition> {
        Err(self.unsupported("copyComposition"))
    }
    /// Apply only the retained command under the actual barrier and Store permit.
    /// # Errors
    /// Refuses stale/foreign authorization or returns a typed uncertain effect.
    fn apply_adoption(
        &self,
        _root: &RootBinding,
        _barrier: &WriteBarrierPermit,
        _prepared: &PreparedAdoption,
        _authorization: &AdoptionAuthorization,
    ) -> VcsResult<VerifiedAdoptionReceipt> {
        Err(self.unsupported("applyAdoption"))
    }
    /// Recover the same exact command; never recreate it from live source bytes.
    /// # Errors
    /// Refuses an inconsistent journal or an unprovable partial native effect.
    fn reconcile_adoption(
        &self,
        _root: &RootBinding,
        _barrier: &WriteBarrierPermit,
        _prepared: &PreparedAdoption,
        _authorization: &AdoptionAuthorization,
    ) -> VcsResult<VerifiedAdoptionReceipt> {
        Err(self.unsupported("reconcileAdoption"))
    }
    /// Read only an already retained terminal native effect, independently of
    /// the current checkout/barrier. This never begins or finishes an effect.
    /// # Errors
    /// Returns uncertain when no terminal proof is retained or artifacts differ.
    fn read_adoption_receipt(
        &self,
        _root: &RootBinding,
        _prepared: &PreparedAdoption,
        _authorization: &AdoptionAuthorization,
    ) -> VcsResult<VerifiedAdoptionReceipt> {
        Err(self.unsupported("readAdoptionReceipt"))
    }
    /// Read a retained known native CAS effect independently of complete-task
    /// readiness. This is historical progress, never permission to apply again.
    /// # Errors
    /// Returns uncertain when an exact native effect fact is not retained.
    fn read_adoption_progress(
        &self,
        _root: &RootBinding,
        _prepared: &PreparedAdoption,
        _authorization: &AdoptionAuthorization,
    ) -> VcsResult<VerifiedAdoptionProgress> {
        Err(self.unsupported("readAdoptionProgress"))
    }
    fn kind(&self) -> VcsKind;
    fn capabilities(&self) -> VcsCapabilities;

    fn unsupported(&self, operation: &'static str) -> VcsError {
        VcsError::Unsupported {
            operation,
            kind: self.kind(),
        }
    }

    /// Observe a bound working copy without replacing an unreadable root with clean state.
    /// # Errors
    /// Returns unsupported, stale binding or the backend's scan error.
    fn status(&self, _root: &RootBinding) -> VcsResult<VcsStatus> {
        Err(self.unsupported("status"))
    }
    /// Observe file rows with explicit rename detection for attribution recovery.
    /// # Errors
    /// Returns unsupported or the backend's status-read error.
    fn files_without_renames(&self, _root: &RootBinding) -> VcsResult<Vec<VcsFileEntry>> {
        Err(self.unsupported("filesWithoutRenames"))
    }
    /// Read the immutable recorded baseline without scanning a working overlay.
    /// # Errors
    /// Returns unsupported, unavailable/unborn HEAD or a backend object-read error.
    fn recorded_state(&self, _root: &RootBinding) -> VcsResult<NativeStateRef> {
        Err(self.unsupported("recordedState"))
    }
    /// Compare the requested working-copy layer.
    /// # Errors
    /// Returns unsupported, stale binding or the backend's diff error.
    fn diff_working(
        &self,
        _root: &RootBinding,
        _scope: DiffScope,
        _paths: Option<&[String]>,
    ) -> VcsResult<Vec<FileDiffWithHunks>> {
        Err(self.unsupported("diffWorking"))
    }
    /// Read one repository-scoped immutable contribution.
    /// # Errors
    /// Returns unsupported, an identity mismatch or the backend's read error.
    fn diff_change(
        &self,
        _root: &RootBinding,
        _change: &NativeChangeRef,
    ) -> VcsResult<Vec<FileDiffWithHunks>> {
        Err(self.unsupported("diffChange"))
    }
    /// Enumerate summaries before loading bodies for a bounded page.
    /// # Errors
    /// Returns unsupported or the selected backend operation's established error.
    fn diff_summaries(&self, _root: &RootBinding, _read: &DiffRead) -> VcsResult<Vec<FileDiff>> {
        Err(self.unsupported("diffSummaries"))
    }
    /// Load text hunks for typed content identities without another status walk.
    /// # Errors
    /// Returns unsupported, an identity mismatch or a missing-object error.
    fn hunks_between(
        &self,
        _root: &RootBinding,
        _old: Option<&NativeObjectRef>,
        _new: Option<&NativeObjectRef>,
    ) -> VcsResult<Vec<DiffHunk>> {
        Err(self.unsupported("hunksBetween"))
    }
    /// Hydrate one enumerated file, preserving binary and gitlink semantics.
    /// # Errors
    /// Returns unsupported, invalid object identities or missing-object errors.
    fn hunks_for_diff(&self, _root: &RootBinding, _file: &FileDiff) -> VcsResult<Vec<DiffHunk>> {
        Err(self.unsupported("hunksForDiff"))
    }
    /// Read file bytes at an explicit mutable ref or immutable contribution.
    /// # Errors
    /// Returns unsupported, an invalid revision or the backend's file-read error.
    fn show_file_bytes(
        &self,
        _root: &RootBinding,
        _revision: &RevisionSpec,
        _path: &str,
    ) -> VcsResult<Vec<u8>> {
        Err(self.unsupported("showFile"))
    }
    /// Resolve a compatibility ref to its typed object identity.
    /// # Errors
    /// Returns unsupported or the backend's unresolved-ref error.
    fn resolve_ref(&self, _root: &RootBinding, _reference: &str) -> VcsResult<NativeObjectRef> {
        Err(self.unsupported("resolveRef"))
    }
    /// Read the currently checked-out branch when the repository is readable.
    /// # Errors
    /// Returns unsupported or a backend failure; absent branch remains explicit.
    fn current_branch(&self, _root: &RootBinding) -> VcsResult<Option<String>> {
        Err(self.unsupported("currentBranch"))
    }
    /// Detect the backend's local default branch using its existing policy.
    /// # Errors
    /// Returns unsupported or a backend repository-read error.
    fn detect_default_branch(&self, _root: &RootBinding) -> VcsResult<Option<String>> {
        Err(self.unsupported("detectDefaultBranch"))
    }
    /// Probe a merge without altering the working copy or index.
    /// # Errors
    /// Returns unsupported or a backend merge-analysis error.
    fn merge_conflicts(
        &self,
        _root: &RootBinding,
        _from: &str,
        _target: &str,
    ) -> VcsResult<MergeConflicts> {
        Err(self.unsupported("mergeConflicts"))
    }
    /// Test ancestry under explicit compatibility revision syntax.
    /// # Errors
    /// Returns unsupported or a backend ref/graph error.
    fn is_ancestor(
        &self,
        _root: &RootBinding,
        _ancestor: &str,
        _descendant: &str,
    ) -> VcsResult<bool> {
        Err(self.unsupported("isAncestor"))
    }
    /// Count graph divergence against an explicit compatibility base.
    /// # Errors
    /// Returns unsupported or a backend repository-read error.
    fn ahead_behind(&self, _root: &RootBinding, _base: &str) -> VcsResult<(i64, i64)> {
        Err(self.unsupported("aheadBehind"))
    }
    /// Resolve the legacy branch boundary using the backend's existing rules.
    /// # Errors
    /// Returns unsupported or a backend repository-read error.
    fn resolve_branch_boundary(
        &self,
        _root: &RootBinding,
        _base_ref: Option<&str>,
        _base_sha: Option<&str>,
        _target: &str,
    ) -> VcsResult<Option<NativeChangeRef>> {
        Err(self.unsupported("resolveBranchBoundary"))
    }
    /// Read bounded change metadata with explicit boundary semantics.
    /// # Errors
    /// Returns unsupported, invalid identity or a backend history error.
    fn history(&self, _root: &RootBinding, _read: &HistoryRead) -> VcsResult<Vec<HistoryEntry>> {
        Err(self.unsupported("history"))
    }
    /// Read one resolved change and per-file statistics.
    /// # Errors
    /// Returns unsupported or the backend's established not-found/read error.
    fn change_details(
        &self,
        _root: &RootBinding,
        _revision: &RevisionSpec,
    ) -> VcsResult<ChangeDetails> {
        Err(self.unsupported("changeDetails"))
    }
    /// Freeze history inputs and reject a moving ref set.
    /// # Errors
    /// Returns unsupported or a backend history-capture error.
    fn capture_history_refresh(
        &self,
        _root: &RootBinding,
        _base_ref: Option<&str>,
        _base_sha: Option<&str>,
    ) -> VcsResult<Option<HistoryRefreshCapture>> {
        Err(self.unsupported("captureHistoryRefresh"))
    }
    /// Resolve a workspace history boundary, retaining its native identity.
    /// # Errors
    /// Returns unsupported or a backend boundary-read error.
    fn resolve_workspace_boundary(
        &self,
        _root: &RootBinding,
        _base_ref: Option<&str>,
        _base_sha: Option<&str>,
    ) -> VcsResult<Option<NativeChangeRef>> {
        Err(self.unsupported("resolveWorkspaceBoundary"))
    }
    /// Retain immutable recovery anchors under a caller-owned capture barrier.
    /// # Errors
    /// Returns unsupported, stale admission, unstable input or capture failure.
    fn capture(&self, _root: &RootBinding, _permit: &CapturePermit) -> VcsResult<CapturedState> {
        Err(self.unsupported("capture"))
    }
    /// Compare retained snapshots with paging tied to their immutable identities.
    /// # Errors
    /// Returns unsupported, an invalid cursor or unavailable snapshot data.
    fn compare(
        &self,
        _before: &CapturedState,
        _after: &CapturedState,
        _query: &DiffQuery,
        _page_token: Option<&str>,
    ) -> VcsResult<DiffPage> {
        Err(self.unsupported("compare"))
    }
    /// Prepare exact immutable bytes without changing authored membership.
    /// # Errors
    /// Returns unsupported, invalid selection or a preparation/durability error.
    fn prepare_record(
        &self,
        _selection: &FrozenSelection,
        _metadata: &FixedRecordMetadata,
        _spool_directory: &Path,
    ) -> VcsResult<PreparedRecord> {
        Err(self.unsupported("prepareRecord"))
    }
    /// Import the retained bytes and fence membership on the expected state.
    /// # Errors
    /// Returns unsupported, stale state, invalid bytes or an uncertain effect.
    fn admit_record(
        &self,
        _root: &RootBinding,
        _record: &PreparedRecord,
        _expected_state: &NativeStateRef,
    ) -> VcsResult<NativeReceipt> {
        Err(self.unsupported("admitRecord"))
    }
    /// Compose privately in an existing owner-controlled spool outside the
    /// source checkout, retaining conflicts as data in the candidate.
    /// # Errors
    /// Returns unsupported, unavailable dependencies or policy/preparation failure.
    fn compose(
        &self,
        _root: &RootBinding,
        _request: &ComposeRequest,
        _spool_directory: &Path,
    ) -> VcsResult<PreparedComposition> {
        Err(self.unsupported("compose"))
    }
    /// Page a retained private composition against its exact target snapshot.
    /// # Errors
    /// Returns unsupported, stale scope, unavailable artifacts or an invalid cursor.
    fn compare_composition(
        &self,
        _root: &RootBinding,
        _composition: &PreparedComposition,
        _query: &DiffQuery,
        _page_token: Option<&str>,
    ) -> VcsResult<DiffPage> {
        Err(self.unsupported("compareComposition"))
    }
    /// Materialize immutable state into a private destination and verify its manifest.
    /// # Errors
    /// Returns unsupported, unavailable state or a fidelity/write error.
    fn materialize(
        &self,
        _root: &RootBinding,
        _state: &NativeStateRef,
        _private_destination: &Path,
    ) -> VcsResult<MaterializationReceipt> {
        Err(self.unsupported("materialize"))
    }
    /// Verify a private retained tree, excluding only declared generated roots
    /// that contain no authored path. The receipt is data, never authority.
    /// # Errors
    /// Returns unsupported, mismatched content/state or an invalid output policy.
    fn verify_materialization(
        &self,
        _receipt: &MaterializationReceipt,
        _generated: &[String],
    ) -> VcsResult<()> {
        Err(self.unsupported("verifyMaterialization"))
    }
    /// Create another private copy of an exact retained materialization.
    /// # Errors
    /// Returns unsupported, altered source or an existing/invalid destination.
    fn copy_materialization(
        &self,
        _source: &MaterializationReceipt,
        _destination: &Path,
    ) -> VcsResult<MaterializationReceipt> {
        Err(self.unsupported("copyMaterialization"))
    }
    /// Export all required immutable changes under retained service admission.
    /// # Errors
    /// Returns unsupported, incomplete closure or an export/durability error.
    fn export_closure(
        &self,
        _root: &RootBinding,
        _state: &NativeStateRef,
        _grant: &RetentionGrant,
        _spool_directory: &Path,
    ) -> VcsResult<NativeClosureManifest> {
        Err(self.unsupported("exportClosure"))
    }
    /// Restore and verify an exact closure in a private destination.
    /// # Errors
    /// Returns unsupported, incompatible data or restoration/verification failure.
    fn restore_closure(
        &self,
        _manifest: &NativeClosureManifest,
        _private_destination: &Path,
    ) -> VcsResult<RestoreReceipt> {
        Err(self.unsupported("restoreClosure"))
    }

    // Attribution is a non-durable observation. Legacy Git workspaces can use
    // it before repository identity and binding persistence have been added.
    /// Observe status for an explicitly selected engine before durable binding.
    /// # Errors
    /// Returns unsupported or the backend's status-read error.
    fn observe_status(&self, _root: &Path) -> VcsResult<VcsStatus> {
        Err(self.unsupported("observeStatus"))
    }
    /// Pull a pre-workspace Git checkout through the explicitly selected engine.
    /// # Errors
    /// Returns unsupported or the established Git pull/authorization failure.
    fn pull_branch(
        &self,
        _root: &Path,
        _branch: &str,
        _token: Option<&str>,
        _classify_authorization: bool,
    ) -> VcsResult<crate::GitPullResult> {
        Err(self.unsupported("pullBranch"))
    }
    /// Observe the owning repository's ignore policy for an untracked path.
    /// # Errors
    /// Returns unsupported or an unreadable repository instead of asserting clean state.
    fn is_ignored(&self, _root: &Path, _path: &str) -> VcsResult<bool> {
        Err(self.unsupported("isIgnored"))
    }
    /// Classify paths in input order, preserving unknown ownership.
    /// # Errors
    /// Returns unsupported or a failure to scan the top-level repository.
    fn classify_paths(&self, _root: &Path, _paths: &[String]) -> VcsResult<Vec<PathState>> {
        Err(self.unsupported("classifyPaths"))
    }
    /// Keep advisory lock candidates consistent with a previously observed status.
    /// # Errors
    /// Returns unsupported or backend failure; callers preserve candidates on uncertainty.
    fn lockable_paths(
        &self,
        _root: &Path,
        _status: &[VcsFileEntry],
        _paths: &[String],
    ) -> VcsResult<Vec<String>> {
        Err(self.unsupported("lockablePaths"))
    }

    // Compatibility mechanics preserve existing Git selection modes; they do
    // not claim to implement native immutable preparation/admission.
    /// Apply the engine's compatibility recording mode without claiming native preparation.
    /// # Errors
    /// Returns unsupported, invalid input or backend failure; completed receipts are retained.
    fn record(&self, _root: &RootBinding, _request: &RecordRequest) -> VcsResult<RecordOutcome> {
        Err(self.unsupported("record"))
    }
    /// Select paths using an engine's existing staging mechanism.
    /// # Errors
    /// Returns unsupported, invalid input or a staging error.
    fn stage(&self, _root: &RootBinding, _paths: &[String]) -> VcsResult<()> {
        Err(self.unsupported("stage"))
    }
    /// Stage one caller-selected hunk using the backend index semantics.
    /// # Errors
    /// Returns unsupported or a backend patch/path error.
    fn stage_hunk(&self, _root: &RootBinding, _path: &str, _patch: &str) -> VcsResult<()> {
        Err(self.unsupported("stageHunk"))
    }
    /// Unstage one caller-selected hunk without discarding working bytes.
    /// # Errors
    /// Returns unsupported or a backend patch/path error.
    fn unstage_hunk(&self, _root: &RootBinding, _path: &str, _patch: &str) -> VcsResult<()> {
        Err(self.unsupported("unstageHunk"))
    }
    /// List the backend's distinct changed paths, preserving rename sides.
    /// # Errors
    /// Returns unsupported or the backend's status-read error.
    fn changed_paths(&self, _root: &RootBinding, _staged_only: bool) -> VcsResult<Vec<String>> {
        Err(self.unsupported("changedPaths"))
    }
    /// Check for pending merge ancestry before choosing a recording mode.
    /// # Errors
    /// Returns unsupported or a backend merge-state read error.
    fn has_pending_merge(&self, _root: &RootBinding) -> VcsResult<bool> {
        Err(self.unsupported("hasPendingMerge"))
    }
    /// Remove an explicitly requested stale backend index lock.
    /// # Errors
    /// Returns unsupported or the backend's lock-file removal error.
    fn remove_index_lock(&self, _root: &RootBinding) -> VcsResult<bool> {
        Err(self.unsupported("removeIndexLock"))
    }
    /// Remove paths from the engine's staging mechanism.
    /// # Errors
    /// Returns unsupported, invalid input or a staging error.
    fn unstage(&self, _root: &RootBinding, _paths: &[String]) -> VcsResult<()> {
        Err(self.unsupported("unstage"))
    }
    /// Restore explicitly requested paths according to the engine's selection semantics.
    /// # Errors
    /// Returns unsupported, invalid input or restoration failure.
    fn discard(&self, _root: &RootBinding, _paths: &[String]) -> VcsResult<()> {
        Err(self.unsupported("discard"))
    }
    /// Create a compatibility branch, optionally checking it out.
    /// # Errors
    /// Returns unsupported or the backend's branch-creation error.
    fn create_branch(&self, _root: &RootBinding, _name: &str, _checkout: bool) -> VcsResult<()> {
        Err(self.unsupported("createBranch"))
    }
    /// Check out a compatibility branch through the selected backend.
    /// # Errors
    /// Returns unsupported or the backend's checkout error.
    fn checkout_branch(&self, _root: &RootBinding, _name: &str) -> VcsResult<()> {
        Err(self.unsupported("checkoutBranch"))
    }
    /// Rename a compatibility branch through the selected backend.
    /// # Errors
    /// Returns unsupported or the backend's rename error.
    fn rename_branch(&self, _root: &RootBinding, _old: &str, _new: &str) -> VcsResult<()> {
        Err(self.unsupported("renameBranch"))
    }
    /// Build a compatibility squash commit from the current tree without moving refs.
    /// # Errors
    /// Returns unsupported or the backend's commit construction error.
    fn commit_tree(
        &self,
        _root: &RootBinding,
        _parent: &str,
        _message: &str,
    ) -> VcsResult<NativeChangeRef> {
        Err(self.unsupported("commitTree"))
    }
    /// Apply a compatibility ref update for a repository-scoped contribution.
    /// # Errors
    /// Returns unsupported, mismatched identity or the backend's ref-write error.
    fn update_ref(
        &self,
        _root: &RootBinding,
        _reference: &str,
        _change: &NativeChangeRef,
    ) -> VcsResult<()> {
        Err(self.unsupported("updateRef"))
    }
    /// Integrate an engine-supported base while retaining conflict/recovery outcomes.
    /// # Errors
    /// Returns unsupported, invalid input or failure before integration can be classified.
    fn rebase(&self, _root: &RootBinding, _target: &str) -> VcsResult<IntegrateOutcome> {
        Err(self.unsupported("rebase"))
    }
    /// Reset to a repository-scoped immutable change using explicit semantics.
    /// # Errors
    /// Returns unsupported, an identity mismatch or backend reset failure.
    fn reset(
        &self,
        _root: &RootBinding,
        _target: &NativeChangeRef,
        _mode: ResetMode,
    ) -> VcsResult<()> {
        Err(self.unsupported("reset"))
    }
    /// Reset a compatibility revision without relabeling it as immutable state.
    /// # Errors
    /// Returns unsupported or the backend's original revision/reset error.
    fn reset_revision(
        &self,
        _root: &RootBinding,
        _target: &RevisionSpec,
        _mode: ResetMode,
    ) -> VcsResult<()> {
        Err(self.unsupported("resetRevision"))
    }
}
