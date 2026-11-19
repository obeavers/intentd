//! Local format-2 aggregate recovery: native code closure, raw working overlay,
//! exact selection and a separately versioned work-evidence closure.
//!
//! A retained archive or private restore is data, not source admission, task
//! completion, reviewer independence or a committed Store checkpoint pointer.
//! Frozen baselines and exact recorded-view/conflict closures are separate code
//! profiles. Native export/restore eligibility still applies to each profile.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use intent_atomic_proto::baselines::{
    BaselineReceipt, MaterializeBaselineRequest, BASELINE_POLICY_VERSION, MATERIALIZER_VERSION,
};
use intent_atomic_proto::closures::{
    BaselineClosure, ClosureProfile, ClosureScope, ExportBaselineClosureRequest,
    RestoreBaselineClosureRequest, CLOSURE_FORMAT,
};
use intent_atomic_proto::intents::{IntentProjectionRef, TaskRevisionRef};
use intent_atomic_proto::recorded_closures::{
    ExportRecordedClosureRequest, RecordedClosure, RecordedClosureProfile, RecordedClosureRestore,
    RestoreRecordedClosureRequest, RECORDED_CLOSURE_FORMAT, RECORDED_CLOSURE_READER,
    RECORDED_MATERIALIZER_VERSION,
};
use intent_atomic_proto::recording::{SelectedFile, SelectedFileKind};
use intent_atomic_proto::{Command, HostIdentity, SpoolRef, StateToken};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::baselines::AtomicBaselineClient;
use crate::closures::AtomicClosureClient;
use crate::recorded_closures::AtomicRecordedClosureClient;
use crate::spool::Spool;
use crate::{HostError, HostSupervisor, Result};

mod fs;
#[cfg(test)]
mod tests;

pub const AGGREGATE_CHECKPOINT_FORMAT: u32 = 2;
pub const AGGREGATE_READER_VERSION: u32 = 2;
pub const WORK_EVIDENCE_FORMAT: u32 = 1;
const MAGIC: &[u8] = b"INTENT-ATOMIC-AGGREGATE-2\n";
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_HEADER: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 50_000;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_EVIDENCE: usize = 1024;

fn invalid(message: &'static str) -> HostError {
    HostError::Protocol(message)
}
fn digest(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.is_ascii()
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value.split('/').count() <= 64
        && value.split('/').all(|part| {
            !matches!(
                part.to_ascii_lowercase().as_str(),
                "" | "." | ".." | ".git" | ".atomic" | ".atomic-sandbox"
            )
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckpointProfile {
    FrozenBaselineOverlay,
    RecordedView,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "profile", rename_all = "camelCase", deny_unknown_fields)]
pub enum CheckpointCode {
    FrozenBaseline { closure: BaselineClosure },
    RecordedView { closure: RecordedClosure },
}

impl CheckpointCode {
    #[must_use]
    pub fn frozen_baseline(&self) -> Option<&BaselineClosure> {
        match self {
            Self::FrozenBaseline { closure } => Some(closure),
            Self::RecordedView { .. } => None,
        }
    }
    #[must_use]
    pub fn recorded_view(&self) -> Option<&RecordedClosure> {
        match self {
            Self::RecordedView { closure } => Some(closure),
            Self::FrozenBaseline { .. } => None,
        }
    }
    fn payload(&self) -> &SpoolRef {
        match self {
            Self::FrozenBaseline { closure } => &closure.payload,
            Self::RecordedView { closure } => &closure.payload,
        }
    }
    fn scope(&self) -> &ClosureScope {
        match self {
            Self::FrozenBaseline { closure } => &closure.scope,
            Self::RecordedView { closure } => &closure.scope,
        }
    }
    fn capture_revision(&self) -> u64 {
        match self {
            Self::FrozenBaseline { closure } => closure.capture_revision,
            Self::RecordedView { closure } => closure.capture_revision,
        }
    }
    fn case_sensitive(&self) -> bool {
        match self {
            Self::FrozenBaseline { closure } => closure.baseline.policy.case_sensitive,
            Self::RecordedView { .. } => false,
        }
    }
}

/// Actual private native result; it carries no workspace installation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedCheckpointCode {
    FrozenBaseline {
        receipt: Box<BaselineReceipt>,
    },
    RecordedView {
        receipt: Box<RecordedClosureRestore>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileKind {
    Directory,
    Regular,
    Executable,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub kind: FileKind,
    pub mode: u32,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrackingKind {
    Tracked,
    Untracked,
    Ignored,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OverlayEntry {
    pub file: FileEntry,
    pub tracking: TrackingKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingOverlayManifest {
    /// Exact observed native code materialization, independent of Git HEAD/index.
    pub baseline: Vec<FileEntry>,
    pub upserts: Vec<OverlayEntry>,
    pub deletions: Vec<String>,
    pub final_manifest_digest: String,
    pub ignored_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub enum CheckpointSelection {
    Unknown,
    Known {
        selection_id: String,
        /// Complete kind/length/content pins, including selected deletions.
        files: Vec<SelectedFile>,
    },
}

/// Original frozen selection bytes, independent of later working-copy edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedContent {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskIntentLink {
    pub work_binding_id: String,
    pub task_revision: TaskRevisionRef,
    pub native_intent_id: String,
    pub projection: IntentProjectionRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorshipCompleteness {
    Unknown,
    Partial,
    Complete,
}

/// Retained declarations; restoring them grants no authorship or review authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorshipBoundary {
    pub paths: Vec<String>,
    pub authors: Vec<String>,
    pub completeness: AuthorshipCompleteness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectRef {
    pub sha256: String,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDocumentRef {
    /// Versioned ledger/source/provenance/context/review bytes remain independent.
    pub kind: String,
    pub logical_id: String,
    pub object: ObjectRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceDocument {
    pub kind: String,
    pub logical_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkEvidenceManifest {
    pub format: u32,
    pub workspace_id: String,
    pub task_intent_links: Vec<TaskIntentLink>,
    pub documents: Vec<EvidenceDocumentRef>,
    pub authorship_boundaries: Vec<AuthorshipBoundary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InheritedCheckpointRef {
    pub scope: ClosureScope,
    pub capture_revision: u64,
    pub archive_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateManifest {
    pub format: u32,
    pub reader_version: u32,
    pub profile: CheckpointProfile,
    pub operation_id: String,
    pub scope: ClosureScope,
    pub capture_revision: u64,
    pub native_closure: CheckpointCode,
    pub overlay: WorkingOverlayManifest,
    pub selection: CheckpointSelection,
    pub evidence: WorkEvidenceManifest,
    pub inherited: Vec<InheritedCheckpointRef>,
    pub objects: Vec<ObjectRef>,
}

/// This reference is committed by the Store owner after complete durable capture.
/// Deserializing it is not proof of that transaction or capture admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateCheckpointRef {
    pub format: u32,
    pub reader_version: u32,
    pub scope: ClosureScope,
    pub capture_revision: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct AggregateCaptureRequest {
    pub profile: CheckpointProfile,
    pub export: ExportBaselineClosureRequest,
    /// An already closed/drained, privately sealed source owned by the caller.
    /// This owner verifies stable bytes; it does not mint execution admission.
    pub sealed_source: PathBuf,
    /// Content digest observed while the caller owns the closed capture barrier.
    pub expected_working_manifest: String,
    pub expected_state: StateToken,
    pub selection: CheckpointSelection,
    /// Required when frozen selected bytes are no longer the working bytes.
    /// Matching current bytes may be retained directly from the sealed source.
    pub selection_contents: Vec<SelectedContent>,
    pub ignored_paths: Vec<String>,
    pub task_intent_links: Vec<TaskIntentLink>,
    pub authorship_boundaries: Vec<AuthorshipBoundary>,
    pub evidence_documents: Vec<EvidenceDocument>,
    pub inherited: Vec<InheritedCheckpointRef>,
}

#[derive(Clone, Debug)]
pub struct RecordedAggregateCaptureRequest {
    pub export: ExportRecordedClosureRequest,
    pub sealed_source: PathBuf,
    pub expected_working_manifest: String,
    pub selection: CheckpointSelection,
    pub selection_contents: Vec<SelectedContent>,
    pub ignored_paths: Vec<String>,
    pub task_intent_links: Vec<TaskIntentLink>,
    pub authorship_boundaries: Vec<AuthorshipBoundary>,
    pub evidence_documents: Vec<EvidenceDocument>,
    pub inherited: Vec<InheritedCheckpointRef>,
}

#[derive(Clone, Debug)]
pub struct CapturedCheckpoint {
    pub reference: AggregateCheckpointRef,
    pub payload: SpoolRef,
    pub manifest: AggregateManifest,
}

/// Only a private, verified restore. The Store must still commit ownership and
/// freshness before exposing it, repairing aliases or emitting completion.
#[derive(Clone, Debug)]
pub struct PreparedCheckpointRestore {
    /// Retained exact native graph/conflicts, independent of working overlay.
    pub native_code: PreparedCheckpointCode,
    pub path: PathBuf,
    /// Durable aggregate bytes retained beside the verified private files.
    pub archive_path: PathBuf,
    pub reference: AggregateCheckpointRef,
    pub selection: CheckpointSelection,
    pub selection_contents: Vec<SelectedContent>,
    pub evidence: WorkEvidenceManifest,
    pub evidence_documents: Vec<EvidenceDocument>,
}

/// Validated archive bytes, not native source authority. Native restore still
/// verifies the code closure before these working files may be reconstructed.
pub struct ValidatedCheckpoint {
    manifest: AggregateManifest,
    objects: BTreeMap<String, Vec<u8>>,
    final_entries: Vec<FileEntry>,
    reference: AggregateCheckpointRef,
}

impl ValidatedCheckpoint {
    /// Validate all formats, scope, manifests, object content and selected bytes.
    /// No host or destination is accessed.
    /// # Errors
    /// Refuses unsupported, stale, malformed, oversized or corrupt archives.
    pub fn read(
        bytes: &[u8],
        reference: &AggregateCheckpointRef,
        expected_scope: &ClosureScope,
    ) -> Result<Self> {
        decode(bytes, reference, expected_scope)
    }

    #[must_use]
    pub fn native_closure(&self) -> &CheckpointCode {
        &self.manifest.native_closure
    }

    #[must_use]
    pub fn native_closure_bytes(&self) -> &[u8] {
        &self.objects[&self.manifest.native_closure.payload().sha256]
    }

    /// Verify the actual restored baseline materialization and reconstruct only
    /// a private working directory; no Store commit or workspace replacement.
    /// # Errors
    /// Refuses another native receipt, corrupt/replaced source, conflicting
    /// operation replay and incomplete or changed private reconstruction.
    pub fn restore_files(
        self,
        operation_id: String,
        restored: &intent_atomic_proto::baselines::BaselineReceipt,
        baseline_root: impl AsRef<std::path::Path>,
        restore_root: &std::path::Path,
    ) -> Result<PreparedCheckpointRestore> {
        if !bounded(&operation_id)
            || self
                .manifest
                .native_closure
                .frozen_baseline()
                .is_none_or(|closure| restored != &closure.baseline)
        {
            return Err(invalid(
                "native restore receipt differs from aggregate code closure",
            ));
        }
        let reference = self.reference.clone();
        restore_private(
            operation_id,
            reference,
            self,
            baseline_root.as_ref(),
            restore_root,
            PreparedCheckpointCode::FrozenBaseline {
                receipt: Box::new(restored.clone()),
            },
        )
    }

    /// Reconstruct working data only after an actual exact recorded native
    /// restore. Fresh numeric state IDs are independent of the original fence.
    /// # Errors
    /// Refuses another native result, changed files, conflicting replay or I/O.
    pub fn restore_recorded_files(
        self,
        operation_id: String,
        restored: &RecordedClosureRestore,
        restore_root: &std::path::Path,
    ) -> Result<PreparedCheckpointRestore> {
        let closure = self.manifest.native_closure.recorded_view().ok_or(invalid(
            "recorded restore requires a recorded code component",
        ))?;
        verify_recorded_restore(closure, restored)?;
        if !bounded(&operation_id) {
            return Err(invalid("invalid aggregate restore operation"));
        }
        let reference = self.reference.clone();
        let baseline_root = restored.path.clone();
        restore_private(
            operation_id,
            reference,
            self,
            &baseline_root,
            restore_root,
            PreparedCheckpointCode::RecordedView {
                receipt: Box::new(restored.clone()),
            },
        )
    }
}

fn file_digest(entries: &[FileEntry]) -> Result<String> {
    let mut bytes = b"intent-atomic-working-overlay-v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(entries)?);
    Ok(digest(&bytes))
}

/// Observe exact raw working bytes for an already closed/drained source. This
/// creates no source admission; the caller must retain that original barrier.
/// # Errors
/// Refuses unsafe/special paths, changing bytes and bounded snapshot failures.
pub fn observe_closed_working_manifest(root: &std::path::Path) -> Result<String> {
    let before = fs::snapshot(root)?;
    if before != fs::snapshot(root)? {
        return Err(invalid(
            "checkpoint source changed while observing its manifest",
        ));
    }
    file_digest(&before.entries)
}

fn validate_entries(entries: &[FileEntry], case_sensitive: bool) -> Result<()> {
    if entries.len() > MAX_ENTRIES {
        return Err(invalid("checkpoint file inventory exceeds budget"));
    }
    let mut previous = None;
    let mut paths = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    for entry in entries {
        if !safe_path(&entry.path)
            || previous.is_some_and(|value| value >= entry.path.as_str())
            || !hash_valid(&entry.sha256)
            || entry.length > MAX_FILE
            || entry.mode > 0o777
            || (!case_sensitive && !folded.insert(entry.path.to_ascii_lowercase()))
        {
            return Err(invalid("invalid, duplicate or unordered checkpoint path"));
        }
        let expected = match entry.kind {
            FileKind::Directory => entry.length == 0 && entry.sha256 == digest(&[]),
            FileKind::Regular => entry.mode & 0o111 == 0,
            FileKind::Executable => entry.mode & 0o111 != 0,
            FileKind::Symlink => entry.length > 0,
        };
        if !expected {
            return Err(invalid("checkpoint file kind/mode/content disagree"));
        }
        let mut parent = entry.path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if paths.get(prefix) != Some(&FileKind::Directory) {
                return Err(invalid("checkpoint parent is absent or is not a directory"));
            }
            parent = prefix;
        }
        total = total
            .checked_add(entry.length)
            .ok_or(invalid("checkpoint length overflow"))?;
        if total > MAX_ARCHIVE {
            return Err(invalid("checkpoint working bytes exceed budget"));
        }
        previous = Some(entry.path.as_str());
        paths.insert(entry.path.as_str(), entry.kind);
    }
    Ok(())
}

fn final_entries(manifest: &AggregateManifest) -> Result<Vec<FileEntry>> {
    let case_sensitive = manifest.native_closure.case_sensitive();
    validate_entries(&manifest.overlay.baseline, case_sensitive)?;
    let mut files: BTreeMap<_, _> = manifest
        .overlay
        .baseline
        .iter()
        .map(|file| (file.path.clone(), file.clone()))
        .collect();
    let tracked_paths: BTreeSet<_> = manifest
        .overlay
        .baseline
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut removed = BTreeSet::new();
    for path in &manifest.overlay.deletions {
        if !safe_path(path) || !removed.insert(path.as_str()) || files.remove(path).is_none() {
            return Err(invalid("invalid or repeated checkpoint deletion"));
        }
    }
    let mut changed = BTreeSet::new();
    for entry in &manifest.overlay.upserts {
        if !changed.insert(entry.file.path.as_str()) || removed.contains(entry.file.path.as_str()) {
            return Err(invalid("duplicate or deleted checkpoint upsert"));
        }
        let tracked = tracked_paths.contains(entry.file.path.as_str());
        if tracked != (entry.tracking == TrackingKind::Tracked) {
            return Err(invalid(
                "checkpoint tracking class differs from baseline membership",
            ));
        }
        files.insert(entry.file.path.clone(), entry.file.clone());
    }
    let result: Vec<_> = files.into_values().collect();
    validate_entries(&result, case_sensitive)?;
    if file_digest(&result)? != manifest.overlay.final_manifest_digest {
        return Err(invalid(
            "checkpoint overlay has another final materialization",
        ));
    }
    Ok(result)
}

fn validate_selection(selection: &CheckpointSelection, baseline: &[FileEntry]) -> Result<()> {
    let CheckpointSelection::Known {
        selection_id,
        files,
    } = selection
    else {
        return Ok(());
    };
    if !bounded(selection_id) || files.len() > MAX_ENTRIES {
        return Err(invalid("invalid checkpoint selection identity or budget"));
    }
    let mut paths = BTreeSet::new();
    let original: BTreeMap<_, _> = baseline
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    for selected in files {
        if !safe_path(&selected.path)
            || !paths.insert(selected.path.as_str())
            || !hash_valid(&selected.sha256)
            || selected.length > MAX_FILE
        {
            return Err(invalid("invalid or duplicate checkpoint selection path"));
        }
        if selected.kind == SelectedFileKind::Deletion {
            if !original
                .get(selected.path.as_str())
                .is_some_and(|entry| entry.kind != FileKind::Directory)
                || selected.length != 0
                || selected.sha256 != digest(&[])
            {
                return Err(invalid(
                    "selected checkpoint deletion differs from captured bytes",
                ));
            }
        } else if selected.kind == SelectedFileKind::Symlink
            && (selected.length == 0 || selected.length > 4096)
        {
            return Err(invalid("invalid frozen selected symlink length"));
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeBaselineEntry<'a> {
    path: &'a str,
    kind: FileKind,
    mode: u32,
    length: u64,
    sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeBaselineManifest<'a> {
    policy_version: u32,
    materializer_version: u32,
    entries: Vec<NativeBaselineEntry<'a>>,
}

fn native_manifest_digest(entries: &[FileEntry]) -> Result<String> {
    let mut native = Vec::new();
    let mut directories = BTreeSet::new();
    let mut expected_directories = BTreeSet::new();
    for file in entries {
        if file.kind == FileKind::Directory {
            if file.mode != 0o700 {
                return Err(invalid(
                    "native baseline directory mode differs from materializer policy",
                ));
            }
            directories.insert(file.path.as_str());
            continue;
        }
        let mode = match file.kind {
            FileKind::Regular if file.mode == 0o644 => 0o100_644,
            FileKind::Executable if file.mode == 0o755 => 0o100_755,
            FileKind::Symlink if file.mode == 0o777 => 0o120_000,
            _ => {
                return Err(invalid(
                    "native baseline file mode differs from materializer policy",
                ))
            }
        };
        let mut parent = file.path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            expected_directories.insert(prefix);
            parent = prefix;
        }
        native.push(NativeBaselineEntry {
            path: &file.path,
            kind: file.kind,
            mode,
            length: file.length,
            sha256: &file.sha256,
        });
    }
    if directories != expected_directories {
        return Err(invalid(
            "native baseline contains a missing or extra directory",
        ));
    }
    Ok(digest(&serde_json::to_vec(&NativeBaselineManifest {
        policy_version: BASELINE_POLICY_VERSION,
        materializer_version: MATERIALIZER_VERSION,
        entries: native,
    })?))
}

fn verify_baseline_entries(entries: &[FileEntry], receipt: &BaselineReceipt) -> Result<()> {
    validate_entries(entries, receipt.policy.case_sensitive)?;
    let manifest_digest = native_manifest_digest(entries)?;
    if receipt.policy.version != BASELINE_POLICY_VERSION
        || manifest_digest != receipt.manifest_digest
        || digest(&serde_json::to_vec(&(
            MATERIALIZER_VERSION,
            &manifest_digest,
        ))?) != receipt.materialization_id
        || entries
            .iter()
            .filter(|entry| entry.kind != FileKind::Directory)
            .count() as u64
            != receipt.file_count
        || entries.iter().map(|entry| entry.length).sum::<u64>() != receipt.total_bytes
    {
        return Err(invalid(
            "observed baseline differs from native manifest/materialization identity",
        ));
    }
    Ok(())
}

fn native_baseline_snapshot(
    root: &std::path::Path,
    receipt: &BaselineReceipt,
) -> Result<fs::Snapshot> {
    let mut snapshot = fs::snapshot(root)?;
    // Git/Atomic's recorded symlink mode is 120000. Filesystem symlink permission
    // bits are not part of that native manifest and differ under Darwin umasks.
    // Keep the native baseline semantic here; the working overlay separately
    // retains and restores its actual raw symlink mode.
    for entry in &mut snapshot.entries {
        if entry.kind == FileKind::Symlink {
            entry.mode = 0o777;
        }
    }
    verify_baseline_entries(&snapshot.entries, receipt)?;
    Ok(snapshot)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeRecordedDirectory<'a> {
    path: &'a str,
    mode: u32,
}

fn recorded_manifest_digest(entries: &[FileEntry]) -> Result<String> {
    validate_entries(entries, false)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for entry in entries {
        if entry.kind == FileKind::Directory {
            if entry.mode != 0o755 {
                return Err(invalid(
                    "recorded native directory mode differs from exact materializer",
                ));
            }
            directories.push(NativeRecordedDirectory {
                path: &entry.path,
                mode: entry.mode,
            });
            continue;
        }
        let mode = match entry.kind {
            FileKind::Regular if entry.mode == 0o644 => 0o100_644,
            FileKind::Executable if entry.mode == 0o755 => 0o100_755,
            FileKind::Symlink if entry.mode == 0o777 => 0o120_000,
            _ => {
                return Err(invalid(
                    "recorded native file mode differs from exact materializer",
                ))
            }
        };
        files.push(NativeBaselineEntry {
            path: &entry.path,
            kind: entry.kind,
            mode,
            length: entry.length,
            sha256: &entry.sha256,
        });
    }
    let files = NativeBaselineManifest {
        policy_version: 1,
        materializer_version: RECORDED_MATERIALIZER_VERSION,
        entries: files,
    };
    Ok(digest(&serde_json::to_vec(&(files, directories))?))
}

fn verify_recorded_entries(entries: &[FileEntry], closure: &RecordedClosure) -> Result<()> {
    let manifest = recorded_manifest_digest(entries)?;
    if manifest != closure.materialization_manifest_digest
        || digest(&serde_json::to_vec(&(
            "intent-recorded-materialization",
            RECORDED_MATERIALIZER_VERSION,
            &manifest,
        ))?) != closure.materialization_id
    {
        return Err(invalid(
            "recorded native inventory differs from exact native materialization",
        ));
    }
    Ok(())
}

fn native_code_snapshot(root: &std::path::Path, code: &CheckpointCode) -> Result<fs::Snapshot> {
    match code {
        CheckpointCode::FrozenBaseline { closure } => {
            native_baseline_snapshot(root, &closure.baseline)
        }
        CheckpointCode::RecordedView { closure } => {
            let mut snapshot = fs::snapshot(root)?;
            for entry in &mut snapshot.entries {
                if entry.kind == FileKind::Symlink {
                    entry.mode = 0o777;
                }
            }
            verify_recorded_entries(&snapshot.entries, closure)?;
            Ok(snapshot)
        }
    }
}

fn verify_recorded_restore(
    closure: &RecordedClosure,
    restored: &RecordedClosureRestore,
) -> Result<()> {
    if restored.host != HostIdentity::default()
        || restored.scope != closure.scope
        || restored.capture_revision != closure.capture_revision
        || restored.source_state != closure.source_state
        || restored.restored_state.view != closure.source_state.view
        || restored.restored_state.own_merkle != closure.source_state.own_merkle
        || restored.project_id != closure.project_id
        || restored.project_identity_hash != closure.project_identity_hash
        || restored.view_manifest_digest != closure.view_manifest_digest
        || restored.materialization_manifest_digest != closure.materialization_manifest_digest
        || restored.materialization_id != closure.materialization_id
        || restored.native_conflict_hash
            != closure
                .conflict
                .as_ref()
                .map(|conflict| conflict.native_hash.clone())
        || restored.object_count != closure.object_count
        || !restored.path.is_absolute()
        || !restored.native_path.is_absolute()
        || !hash_valid(&restored.receipt_digest)
    {
        return Err(invalid(
            "recorded native result differs from original aggregate code closure",
        ));
    }
    Ok(())
}

fn validate_manifest(manifest: &AggregateManifest) -> Result<Vec<FileEntry>> {
    if manifest.format != AGGREGATE_CHECKPOINT_FORMAT
        || manifest.reader_version != AGGREGATE_READER_VERSION
    {
        return Err(invalid(
            "unsupported aggregate checkpoint format or reader version",
        ));
    }
    if !bounded(&manifest.operation_id)
        || !bounded(&manifest.scope.workspace_id)
        || !bounded(&manifest.scope.root_id)
        || !bounded(&manifest.scope.repository_id)
        || manifest.scope.binding_epoch == 0
        || manifest.capture_revision == 0
        || manifest.native_closure.scope() != &manifest.scope
        || manifest.native_closure.capture_revision() != manifest.capture_revision
        || !hash_valid(&manifest.native_closure.payload().sha256)
        || manifest.native_closure.payload().length > MAX_ARCHIVE
    {
        return Err(invalid(
            "aggregate checkpoint native closure or scope differs",
        ));
    }
    match (&manifest.native_closure, manifest.profile) {
        (CheckpointCode::FrozenBaseline { closure }, CheckpointProfile::FrozenBaselineOverlay) => {
            if closure.format != CLOSURE_FORMAT
                || closure.profile != ClosureProfile::FrozenBaseline
                || closure.host != HostIdentity::default()
                || closure.baseline.host != HostIdentity::default()
                || closure.baseline.baseline.repository_id != manifest.scope.repository_id
                || closure.baseline.baseline.binding_epoch != manifest.scope.binding_epoch
                || closure.baseline.native_state.view.starts_with("wc/")
                || closure.payload.name != format!("closure-{}.bin", closure.payload.sha256)
            {
                return Err(invalid("aggregate frozen-baseline code component differs"));
            }
            verify_baseline_entries(&manifest.overlay.baseline, &closure.baseline)?;
        }
        (CheckpointCode::RecordedView { closure }, CheckpointProfile::RecordedView) => {
            if closure.format != RECORDED_CLOSURE_FORMAT
                || closure.reader_version != RECORDED_CLOSURE_READER
                || closure.profile != RecordedClosureProfile::RecordedViewExact
                || closure.host != HostIdentity::default()
                || closure.source_state.view.starts_with("wc/")
                || !bounded(&closure.source_state.view)
                || !bounded(&closure.source_state.own_merkle)
                || !bounded(&closure.source_state.effective_state)
                || !bounded(&closure.project_id)
                || !bounded(&closure.project_identity_hash)
                || !hash_valid(&closure.view_manifest_digest)
                || !hash_valid(&closure.materialization_manifest_digest)
                || !hash_valid(&closure.materialization_id)
                || closure.object_count > 4096
                || closure.payload.name != format!("recorded-{}.bin", closure.payload.sha256)
                || closure.conflict.as_ref().is_some_and(|conflict| {
                    !bounded(&conflict.native_hash)
                        || !hash_valid(&conflict.sha256)
                        || conflict.length > 16 * 1024 * 1024
                        || conflict.file_count == 0
                        || conflict.entry_count == 0
                })
            {
                return Err(invalid("aggregate recorded-view code component differs"));
            }
            verify_recorded_entries(&manifest.overlay.baseline, closure)?;
        }
        _ => {
            return Err(invalid(
                "aggregate checkpoint profile disagrees with native code component",
            ))
        }
    }
    if manifest.evidence.format != WORK_EVIDENCE_FORMAT
        || manifest.evidence.workspace_id != manifest.scope.workspace_id
        || manifest.evidence.documents.len() > MAX_EVIDENCE
        || manifest.evidence.task_intent_links.len() > MAX_EVIDENCE
        || manifest.evidence.authorship_boundaries.len() > MAX_EVIDENCE
        || manifest.inherited.len() > MAX_EVIDENCE
    {
        return Err(invalid("invalid work-evidence format, scope or budget"));
    }
    let mut documents = BTreeSet::new();
    for document in &manifest.evidence.documents {
        if !bounded(&document.kind)
            || !bounded(&document.logical_id)
            || !documents.insert((&document.kind, &document.logical_id))
        {
            return Err(invalid("invalid or duplicate work-evidence document"));
        }
    }
    for link in &manifest.evidence.task_intent_links {
        if !bounded(&link.work_binding_id)
            || !bounded(&link.native_intent_id)
            || link.task_revision.workspace_id != manifest.scope.workspace_id
            || link.projection.task_revision != link.task_revision
        {
            return Err(invalid(
                "task/intent evidence link differs from checkpoint owner",
            ));
        }
    }
    for boundary in &manifest.evidence.authorship_boundaries {
        if boundary.paths.len() > MAX_ENTRIES
            || boundary.authors.len() > MAX_EVIDENCE
            || boundary.paths.iter().any(|path| !safe_path(path))
            || boundary.authors.iter().any(|author| !bounded(author))
        {
            return Err(invalid("invalid retained authorship boundary"));
        }
    }
    for inherited in &manifest.inherited {
        if !bounded(&inherited.scope.repository_id)
            || inherited.scope.binding_epoch == 0
            || inherited.capture_revision == 0
            || !hash_valid(&inherited.archive_sha256)
        {
            return Err(invalid("invalid inherited checkpoint reference"));
        }
    }
    let mut ignored = BTreeSet::new();
    if manifest.overlay.ignored_paths.len() > MAX_ENTRIES
        || manifest
            .overlay
            .ignored_paths
            .iter()
            .any(|path| !safe_path(path) || !ignored.insert(path))
    {
        return Err(invalid("invalid ignored-path classifications"));
    }
    let entries = final_entries(manifest)?;
    validate_selection(&manifest.selection, &manifest.overlay.baseline)?;
    Ok(entries)
}

fn referenced_objects(manifest: &AggregateManifest) -> Result<BTreeMap<String, u64>> {
    let mut objects = BTreeMap::new();
    let mut add = |sha256: &str, length: u64| -> Result<()> {
        if !hash_valid(sha256)
            || length > MAX_ARCHIVE
            || objects
                .insert(sha256.to_owned(), length)
                .is_some_and(|old| old != length)
        {
            return Err(invalid(
                "invalid or conflicting checkpoint object reference",
            ));
        }
        Ok(())
    };
    add(
        &manifest.native_closure.payload().sha256,
        manifest.native_closure.payload().length,
    )?;
    for entry in &manifest.overlay.upserts {
        if entry.file.kind != FileKind::Directory {
            add(&entry.file.sha256, entry.file.length)?;
        }
    }
    if let CheckpointSelection::Known { files, .. } = &manifest.selection {
        for file in files {
            if file.kind != SelectedFileKind::Deletion {
                add(&file.sha256, file.length)?;
            }
        }
    }
    for document in &manifest.evidence.documents {
        if document.object.length > MAX_FILE {
            return Err(invalid("checkpoint evidence document exceeds budget"));
        }
        add(&document.object.sha256, document.object.length)?;
    }
    Ok(objects)
}

fn encode(manifest: &AggregateManifest, objects: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    validate_manifest(manifest)?;
    let expected = referenced_objects(manifest)?;
    let descriptors: Vec<_> = objects
        .iter()
        .map(|(sha256, bytes)| ObjectRef {
            sha256: sha256.clone(),
            length: bytes.len() as u64,
        })
        .collect();
    if descriptors != manifest.objects
        || expected.len() != objects.len()
        || objects.iter().any(|(sha256, bytes)| {
            expected.get(sha256) != Some(&(bytes.len() as u64)) || digest(bytes) != *sha256
        })
    {
        return Err(invalid(
            "checkpoint object bytes differ from exact references",
        ));
    }
    let header = serde_json::to_vec(manifest)?;
    let length = objects
        .values()
        .try_fold(MAGIC.len() + 8 + header.len(), |length, bytes| {
            length.checked_add(bytes.len())
        })
        .ok_or(invalid("checkpoint length overflow"))?;
    if header.len() > MAX_HEADER || length as u64 > MAX_ARCHIVE {
        return Err(invalid("aggregate checkpoint exceeds budget"));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&header);
    for object in objects.values() {
        bytes.extend_from_slice(object);
    }
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
    reference: &AggregateCheckpointRef,
    expected_scope: &ClosureScope,
) -> Result<ValidatedCheckpoint> {
    if reference.format != AGGREGATE_CHECKPOINT_FORMAT
        || reference.reader_version != AGGREGATE_READER_VERSION
        || reference.scope != *expected_scope
        || reference.capture_revision == 0
        || reference.length > MAX_ARCHIVE
        || reference.length != bytes.len() as u64
        || reference.sha256 != digest(bytes)
        || !bytes.starts_with(MAGIC)
    {
        return Err(invalid(
            "checkpoint reference, format, scope or bytes differ",
        ));
    }
    let prefix = MAGIC.len() + 8;
    let size: [u8; 8] = bytes
        .get(MAGIC.len()..prefix)
        .ok_or(invalid("short checkpoint header"))?
        .try_into()
        .map_err(|_| invalid("short checkpoint header"))?;
    let length = usize::try_from(u64::from_be_bytes(size))
        .map_err(|_| invalid("checkpoint header overflow"))?;
    if length > MAX_HEADER {
        return Err(invalid("checkpoint header exceeds budget"));
    }
    let end = prefix
        .checked_add(length)
        .ok_or(invalid("checkpoint header overflow"))?;
    let manifest: AggregateManifest = serde_json::from_slice(
        bytes
            .get(prefix..end)
            .ok_or(invalid("short checkpoint manifest"))?,
    )?;
    if serde_json::to_vec(&manifest)? != bytes[prefix..end] {
        return Err(invalid(
            "noncanonical aggregate checkpoint manifest encoding",
        ));
    }
    if manifest.scope != reference.scope || manifest.capture_revision != reference.capture_revision
    {
        return Err(invalid(
            "checkpoint manifest differs from its committed reference",
        ));
    }
    let final_entries = validate_manifest(&manifest)?;
    let expected = referenced_objects(&manifest)?;
    if manifest.objects.len() != expected.len() {
        return Err(invalid("checkpoint object inventory is incomplete"));
    }
    let mut offset = end;
    let mut objects = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for object in &manifest.objects {
        if previous.is_some_and(|value| value >= object.sha256.as_str())
            || expected.get(&object.sha256) != Some(&object.length)
        {
            return Err(invalid(
                "checkpoint object inventory is unordered or inconsistent",
            ));
        }
        let length = usize::try_from(object.length)
            .map_err(|_| invalid("checkpoint object length overflow"))?;
        let next = offset
            .checked_add(length)
            .ok_or(invalid("checkpoint object length overflow"))?;
        let content = bytes
            .get(offset..next)
            .ok_or(invalid("short checkpoint object"))?;
        if digest(content) != object.sha256 {
            return Err(invalid("checkpoint object content hash differs"));
        }
        objects.insert(object.sha256.clone(), content.to_vec());
        offset = next;
        previous = Some(&object.sha256);
    }
    if offset != bytes.len() {
        return Err(invalid("unreferenced checkpoint bytes"));
    }
    for entry in &manifest.overlay.upserts {
        if entry.file.kind == FileKind::Symlink {
            let target = &objects[&entry.file.sha256];
            if target.is_empty() || target.len() > 4096 || target.contains(&0) {
                return Err(invalid("invalid checkpoint symlink target bytes"));
            }
        }
    }
    if let CheckpointSelection::Known { files, .. } = &manifest.selection {
        for file in files
            .iter()
            .filter(|file| file.kind == SelectedFileKind::Symlink)
        {
            let target = &objects[&file.sha256];
            if target.is_empty() || target.len() > 4096 || target.contains(&0) {
                return Err(invalid("invalid frozen selected symlink bytes"));
            }
        }
    }
    Ok(ValidatedCheckpoint {
        manifest,
        objects,
        final_entries,
        reference: reference.clone(),
    })
}

pub struct AtomicCheckpointClient {
    host: Arc<HostSupervisor>,
    restore_root: PathBuf,
}

impl AtomicCheckpointClient {
    /// Construct an inert owner. No host, store or directory is opened.
    /// # Errors
    /// Refuses a relative private restore root.
    pub fn new(host: Arc<HostSupervisor>, restore_root: PathBuf) -> Result<Self> {
        if !restore_root.is_absolute() {
            return Err(HostError::Configuration(
                "absolute aggregate restore root is required",
            ));
        }
        Ok(Self { host, restore_root })
    }

    /// Export native bytes, capture the closed source twice, and durably retain
    /// the aggregate before returning. The caller commits Store freshness later.
    /// # Errors
    /// Refuses unsupported profiles, changing sources, invalid selections/evidence,
    /// host receipts, path/file types and bounded archive or durability failures.
    pub async fn capture(&self, request: AggregateCaptureRequest) -> Result<CapturedCheckpoint> {
        if request.profile != CheckpointProfile::FrozenBaselineOverlay {
            return Err(HostError::Configuration(
                "recorded-view capture requires the exact recorded closure owner",
            ));
        }
        if !request.sealed_source.is_absolute() || !bounded(&request.export.operation_id) {
            return Err(invalid(
                "checkpoint capture requires an owned absolute sealed source",
            ));
        }
        let closure = AtomicClosureClient::new(Arc::clone(&self.host))
            .export(request.export.clone())
            .await?;
        if request.expected_state != closure.baseline.native_state {
            return Err(invalid(
                "checkpoint capture native state differs from frozen baseline",
            ));
        }
        let baseline = AtomicBaselineClient::new(Arc::clone(&self.host), self.host.spool_path())?
            .materialize(MaterializeBaselineRequest {
                operation_id: format!(
                    "aggregate-base-{}",
                    digest(request.export.operation_id.as_bytes())
                ),
                baseline: closure.baseline.baseline.clone(),
            })
            .await?;
        let spool = self.host.spool_path();
        tokio::task::spawn_blocking(move || {
            capture_frozen_components(request, closure, baseline.path, &spool)
        })
        .await
        .map_err(|_| invalid("checkpoint capture worker did not finish"))?
    }

    /// Capture an actual named recorded view and complete native conflict
    /// object, then retain its independently frozen working and work state.
    /// # Errors
    /// Refuses native eligibility limits, stale source fences, changing closed
    /// files, invalid selection/evidence or incomplete durable capture.
    pub async fn capture_recorded(
        &self,
        request: RecordedAggregateCaptureRequest,
    ) -> Result<CapturedCheckpoint> {
        if !request.sealed_source.is_absolute() {
            return Err(invalid(
                "checkpoint capture requires an owned absolute sealed source",
            ));
        }
        let client = AtomicRecordedClosureClient::new(Arc::clone(&self.host));
        let export = client.prepare_export(request.export.clone()).await?;
        let closure = client.export(&export).await?;
        // Materialize the immutable exported closure privately. The source
        // canonical native root remains code-free throughout capture.
        let operation = client
            .prepare_restore(RestoreRecordedClosureRequest {
                operation_id: format!(
                    "aggregate-recorded-base-{}",
                    digest(request.export.operation_id.as_bytes())
                ),
                expected_scope: closure.scope.clone(),
                closure: closure.clone(),
            })
            .await?;
        let restored = client.restore(&operation).await?;
        let spool = self.host.spool_path();
        tokio::task::spawn_blocking(move || {
            capture_recorded_components(request, closure, &restored, &spool)
        })
        .await
        .map_err(|_| invalid("recorded checkpoint capture worker did not finish"))?
    }

    /// Validate every archive object before any host request or destination write,
    /// restore the actual native closure, then verify a private overlay/selection.
    /// No workspace root or committed checkpoint pointer is modified.
    /// # Errors
    /// Refuses unsupported/corrupt/stale data, conflicting replay, native restore,
    /// changed baseline bytes and incomplete private filesystem reconstruction.
    pub async fn restore(
        &self,
        operation_id: String,
        reference: AggregateCheckpointRef,
        expected_scope: ClosureScope,
        bytes: Vec<u8>,
    ) -> Result<PreparedCheckpointRestore> {
        if !bounded(&operation_id) {
            return Err(invalid("invalid aggregate restore operation"));
        }
        let archive = tokio::task::spawn_blocking(move || {
            decode(&bytes, &reference, &expected_scope).map(|archive| (archive, reference))
        })
        .await
        .map_err(|_| invalid("checkpoint validation worker did not finish"))??;
        let (archive, reference) = archive;
        // Starting the owner is intentionally after complete archive validation.
        self.host.request(Command::Ping).await?;
        let spool_path = self.host.spool_path();
        let code = archive.objects[&archive.manifest.native_closure.payload().sha256].clone();
        let (native_code, baseline_root) = match archive.manifest.native_closure.clone() {
            CheckpointCode::FrozenBaseline { mut closure } => {
                closure.payload = tokio::task::spawn_blocking(move || {
                    Spool::open(&spool_path)?.retain_closure(&code)
                })
                .await
                .map_err(|_| invalid("checkpoint staging worker did not finish"))??;
                let baseline = AtomicClosureClient::new(Arc::clone(&self.host))
                    .restore(RestoreBaselineClosureRequest {
                        operation_id: format!(
                            "aggregate-native-{}",
                            digest(operation_id.as_bytes())
                        ),
                        expected_scope: archive.manifest.scope.clone(),
                        closure,
                    })
                    .await?;
                let materialized =
                    AtomicBaselineClient::new(Arc::clone(&self.host), self.host.spool_path())?
                        .materialize(MaterializeBaselineRequest {
                            operation_id: format!(
                                "aggregate-files-{}",
                                digest(operation_id.as_bytes())
                            ),
                            baseline: baseline.baseline.clone(),
                        })
                        .await?;
                (
                    PreparedCheckpointCode::FrozenBaseline {
                        receipt: Box::new(baseline),
                    },
                    materialized.path,
                )
            }
            CheckpointCode::RecordedView { closure } => {
                let client = AtomicRecordedClosureClient::new(Arc::clone(&self.host));
                let closure = client.stage_received(closure, code).await?;
                let operation = client
                    .prepare_restore(RestoreRecordedClosureRequest {
                        operation_id: format!(
                            "aggregate-native-{}",
                            digest(operation_id.as_bytes())
                        ),
                        expected_scope: archive.manifest.scope.clone(),
                        closure,
                    })
                    .await?;
                let restored = client.restore(&operation).await?;
                let path = restored.path.clone();
                (
                    PreparedCheckpointCode::RecordedView {
                        receipt: Box::new(restored),
                    },
                    path,
                )
            }
        };
        let restore_root = self.restore_root.clone();
        tokio::task::spawn_blocking(move || {
            restore_private(
                operation_id,
                reference,
                archive,
                &baseline_root,
                &restore_root,
                native_code,
            )
        })
        .await
        .map_err(|_| invalid("checkpoint restore worker did not finish"))?
    }
}

/// Capture components from an actual frozen-closure export/materialization.
/// Used by the typed client and native host conformance tests. It verifies data
/// fidelity but does not commit checkpoint ownership or grant source admission.
/// # Errors
/// Refuses changed bytes, invalid scope/selection, unsupported profiles and I/O.
pub fn capture_frozen_components(
    request: AggregateCaptureRequest,
    closure: BaselineClosure,
    baseline_root: impl AsRef<std::path::Path>,
    spool_root: &std::path::Path,
) -> Result<CapturedCheckpoint> {
    if request.profile != CheckpointProfile::FrozenBaselineOverlay {
        return Err(HostError::Configuration(
            "recorded-view capture requires the exact recorded closure owner",
        ));
    }
    if request.export.scope != closure.scope
        || request.export.capture_revision != closure.capture_revision
        || request.export.baseline != closure.baseline.baseline
        || request.expected_state != closure.baseline.native_state
        || !request.sealed_source.is_absolute()
        || !bounded(&request.export.operation_id)
        || !hash_valid(&request.expected_working_manifest)
    {
        return Err(invalid(
            "aggregate components differ from original capture identity",
        ));
    }
    let baseline = native_baseline_snapshot(baseline_root.as_ref(), &closure.baseline)?;
    capture_components(
        CaptureParts {
            profile: request.profile,
            operation_id: request.export.operation_id,
            sealed_source: request.sealed_source,
            expected_working_manifest: request.expected_working_manifest,
            selection: request.selection,
            selection_contents: request.selection_contents,
            ignored_paths: request.ignored_paths,
            task_intent_links: request.task_intent_links,
            authorship_boundaries: request.authorship_boundaries,
            evidence_documents: request.evidence_documents,
            inherited: request.inherited,
        },
        CheckpointCode::FrozenBaseline { closure },
        baseline,
        spool_root,
    )
}

/// Capture actual recorded native components plus an independently frozen raw
/// overlay/selection/evidence. The native receipt is data; no Store pointer or
/// source-admission grant is created here.
/// # Errors
/// Refuses another original source fence, native materialization, source race,
/// invalid selection/evidence, unsupported paths and durability failures.
pub fn capture_recorded_components(
    request: RecordedAggregateCaptureRequest,
    closure: RecordedClosure,
    restored: &RecordedClosureRestore,
    spool_root: &std::path::Path,
) -> Result<CapturedCheckpoint> {
    if request.export.operation_id != closure.operation_id
        || request.export.scope != closure.scope
        || request.export.capture_revision != closure.capture_revision
        || request.export.expected_state != closure.source_state
        || request.export.view != closure.source_state.view
        || request.export.binding.repository_id != closure.scope.repository_id
        || request.export.binding.binding_epoch != closure.scope.binding_epoch
        || !request.sealed_source.is_absolute()
        || !bounded(&request.export.operation_id)
        || !hash_valid(&request.expected_working_manifest)
    {
        return Err(invalid(
            "recorded aggregate components differ from original capture identity",
        ));
    }
    verify_recorded_restore(&closure, restored)?;
    let code = CheckpointCode::RecordedView { closure };
    let baseline = native_code_snapshot(&restored.path, &code)?;
    capture_components(
        CaptureParts {
            profile: CheckpointProfile::RecordedView,
            operation_id: request.export.operation_id,
            sealed_source: request.sealed_source,
            expected_working_manifest: request.expected_working_manifest,
            selection: request.selection,
            selection_contents: request.selection_contents,
            ignored_paths: request.ignored_paths,
            task_intent_links: request.task_intent_links,
            authorship_boundaries: request.authorship_boundaries,
            evidence_documents: request.evidence_documents,
            inherited: request.inherited,
        },
        code,
        baseline,
        spool_root,
    )
}

struct CaptureParts {
    profile: CheckpointProfile,
    operation_id: String,
    sealed_source: PathBuf,
    expected_working_manifest: String,
    selection: CheckpointSelection,
    selection_contents: Vec<SelectedContent>,
    ignored_paths: Vec<String>,
    task_intent_links: Vec<TaskIntentLink>,
    authorship_boundaries: Vec<AuthorshipBoundary>,
    evidence_documents: Vec<EvidenceDocument>,
    inherited: Vec<InheritedCheckpointRef>,
}

fn capture_components(
    request: CaptureParts,
    closure: CheckpointCode,
    baseline: fs::Snapshot,
    spool_root: &std::path::Path,
) -> Result<CapturedCheckpoint> {
    let working = fs::snapshot(&request.sealed_source)?;
    let repeated = fs::snapshot(&request.sealed_source)?;
    if working != repeated || file_digest(&working.entries)? != request.expected_working_manifest {
        return Err(invalid(
            "checkpoint source changed during immutable capture",
        ));
    }
    let spool = Spool::open(spool_root)?;
    let mut payload = spool.open_verified(closure.payload(), MAX_ARCHIVE)?;
    let mut code = Vec::new();
    Read::by_ref(&mut payload)
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut code)?;
    if code.len() as u64 != closure.payload().length || digest(&code) != closure.payload().sha256 {
        return Err(invalid("native closure changed while capturing"));
    }
    let mut objects = BTreeMap::from([(closure.payload().sha256.clone(), code)]);
    let base: BTreeMap<_, _> = baseline
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let current: BTreeSet<_> = working
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let mut upserts = Vec::new();
    for file in &working.entries {
        if base
            .get(file.path.as_str())
            .is_some_and(|old| **old == *file)
        {
            continue;
        }
        if file.kind != FileKind::Directory {
            objects.insert(file.sha256.clone(), working.contents[&file.path].clone());
        }
        let tracking = if base.contains_key(file.path.as_str()) {
            TrackingKind::Tracked
        } else if request.ignored_paths.iter().any(|path| {
            file.path == *path
                || file
                    .path
                    .strip_prefix(path)
                    .is_some_and(|tail| tail.starts_with('/'))
        }) {
            TrackingKind::Ignored
        } else {
            TrackingKind::Untracked
        };
        upserts.push(OverlayEntry {
            file: file.clone(),
            tracking,
        });
    }
    let deletions = base
        .keys()
        .filter(|path| !current.contains(**path))
        .map(|path| (*path).to_owned())
        .collect();
    retain_selection_objects(
        &request.selection,
        &request.selection_contents,
        &working,
        &baseline,
        &mut objects,
    )?;
    let mut documents = Vec::new();
    for document in request.evidence_documents {
        let sha256 = digest(&document.bytes);
        let object = ObjectRef {
            sha256: sha256.clone(),
            length: document.bytes.len() as u64,
        };
        objects.insert(sha256, document.bytes);
        documents.push(EvidenceDocumentRef {
            kind: document.kind,
            logical_id: document.logical_id,
            object,
        });
    }
    let manifest = AggregateManifest {
        format: AGGREGATE_CHECKPOINT_FORMAT,
        reader_version: AGGREGATE_READER_VERSION,
        profile: request.profile,
        operation_id: request.operation_id,
        scope: closure.scope().clone(),
        capture_revision: closure.capture_revision(),
        overlay: WorkingOverlayManifest {
            baseline: baseline.entries,
            upserts,
            deletions,
            final_manifest_digest: file_digest(&working.entries)?,
            ignored_paths: request.ignored_paths,
        },
        selection: request.selection,
        evidence: WorkEvidenceManifest {
            format: WORK_EVIDENCE_FORMAT,
            workspace_id: closure.scope().workspace_id.clone(),
            task_intent_links: request.task_intent_links,
            documents,
            authorship_boundaries: request.authorship_boundaries,
        },
        inherited: request.inherited,
        native_closure: closure,
        objects: objects
            .iter()
            .map(|(sha256, bytes)| ObjectRef {
                sha256: sha256.clone(),
                length: bytes.len() as u64,
            })
            .collect(),
    };
    let bytes = encode(&manifest, &objects)?;
    let reference = AggregateCheckpointRef {
        format: manifest.format,
        reader_version: manifest.reader_version,
        scope: manifest.scope.clone(),
        capture_revision: manifest.capture_revision,
        length: bytes.len() as u64,
        sha256: digest(&bytes),
    };
    let operation_key = digest(manifest.operation_id.as_bytes());
    let payload = spool.retain_named(&format!("aggregate-{operation_key}.payload"), &bytes)?;
    Ok(CapturedCheckpoint {
        reference,
        payload,
        manifest,
    })
}

fn restore_private(
    operation_id: String,
    reference: AggregateCheckpointRef,
    archive: ValidatedCheckpoint,
    baseline_root: &std::path::Path,
    restore_root: &std::path::Path,
    native_code: PreparedCheckpointCode,
) -> Result<PreparedCheckpointRestore> {
    match (&archive.manifest.native_closure, &native_code) {
        (
            CheckpointCode::FrozenBaseline { closure },
            PreparedCheckpointCode::FrozenBaseline { receipt },
        ) if &closure.baseline == receipt.as_ref() => {}
        (
            CheckpointCode::RecordedView { closure },
            PreparedCheckpointCode::RecordedView { receipt },
        ) => verify_recorded_restore(closure, receipt)?,
        _ => return Err(invalid("prepared native code profile or identity differs")),
    }
    let baseline = native_code_snapshot(baseline_root, &archive.manifest.native_closure)?;
    if baseline.entries != archive.manifest.overlay.baseline {
        return Err(invalid(
            "restored native baseline differs from aggregate inventory",
        ));
    }
    let mut contents = baseline.contents;
    for path in &archive.manifest.overlay.deletions {
        contents.remove(path);
    }
    for entry in &archive.manifest.overlay.upserts {
        if entry.file.kind == FileKind::Directory {
            contents.remove(&entry.file.path);
        } else {
            contents.insert(
                entry.file.path.clone(),
                archive.objects[&entry.file.sha256].clone(),
            );
        }
    }
    let expected = fs::Snapshot {
        entries: archive.final_entries,
        contents,
    };
    let command_payload = (operation_id, &reference);
    let command = digest(&serde_json::to_vec(&command_payload)?);
    let encoded = encode(&archive.manifest, &archive.objects)?;
    if encoded.len() as u64 != reference.length || digest(&encoded) != reference.sha256 {
        return Err(invalid(
            "validated checkpoint cannot be reconstructed exactly",
        ));
    }
    let path = fs::install_private(
        restore_root,
        &command_payload.0,
        &command,
        &expected,
        &archive.manifest,
        &encoded,
        &archive.objects,
    )?;
    let evidence_documents = archive
        .manifest
        .evidence
        .documents
        .iter()
        .map(|document| EvidenceDocument {
            kind: document.kind.clone(),
            logical_id: document.logical_id.clone(),
            bytes: archive.objects[&document.object.sha256].clone(),
        })
        .collect();
    let selection_contents = match &archive.manifest.selection {
        CheckpointSelection::Unknown => Vec::new(),
        CheckpointSelection::Known { files, .. } => files
            .iter()
            .filter(|file| file.kind != SelectedFileKind::Deletion)
            .map(|file| SelectedContent {
                path: file.path.clone(),
                bytes: archive.objects[&file.sha256].clone(),
            })
            .collect(),
    };
    Ok(PreparedCheckpointRestore {
        native_code,
        archive_path: path
            .parent()
            .ok_or(invalid("private restore owner is missing"))?
            .join("checkpoint.payload"),
        path,
        reference,
        selection: archive.manifest.selection,
        selection_contents,
        evidence: archive.manifest.evidence,
        evidence_documents,
    })
}

fn retain_selection_objects(
    selection: &CheckpointSelection,
    supplied: &[SelectedContent],
    working: &fs::Snapshot,
    baseline: &fs::Snapshot,
    objects: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if supplied.len() > MAX_ENTRIES {
        return Err(invalid("frozen selection content exceeds budget"));
    }
    let mut contents = BTreeMap::new();
    for content in supplied {
        if !safe_path(&content.path)
            || content.bytes.len() as u64 > MAX_FILE
            || contents
                .insert(content.path.as_str(), content.bytes.as_slice())
                .is_some()
        {
            return Err(invalid("invalid or duplicate frozen selection content"));
        }
    }
    let CheckpointSelection::Known { files, .. } = selection else {
        return if supplied.is_empty() {
            Ok(())
        } else {
            Err(invalid(
                "unknown selection cannot carry invented selected content",
            ))
        };
    };
    for file in files {
        if file.kind == SelectedFileKind::Deletion {
            if contents.contains_key(file.path.as_str()) {
                return Err(invalid("selected deletion has unexpected content"));
            }
            continue;
        }
        let expected_kind = match file.kind {
            SelectedFileKind::Regular => FileKind::Regular,
            SelectedFileKind::Executable => FileKind::Executable,
            SelectedFileKind::Symlink => FileKind::Symlink,
            SelectedFileKind::Deletion => unreachable!(),
        };
        let matches =
            |bytes: &[u8]| bytes.len() as u64 == file.length && digest(bytes) == file.sha256;
        let content = if let Some(content) = contents.remove(file.path.as_str()) {
            if !matches(content) {
                return Err(invalid(
                    "original frozen selection bytes differ from their pins",
                ));
            }
            content
        } else {
            [working, baseline]
                .into_iter()
                .find_map(|snapshot| {
                    let entry = snapshot
                        .entries
                        .iter()
                        .find(|entry| entry.path == file.path)?;
                    let bytes = snapshot.contents.get(&file.path)?;
                    (entry.kind == expected_kind && matches(bytes)).then_some(bytes.as_slice())
                })
                .ok_or(invalid("original frozen selection bytes are unavailable"))?
        };
        if file.kind == SelectedFileKind::Symlink
            && (content.is_empty() || content.len() > 4096 || content.contains(&0))
        {
            return Err(invalid("invalid frozen selection link target"));
        }
        objects.insert(file.sha256.clone(), content.to_vec());
    }
    if !contents.is_empty() {
        return Err(invalid("unselected frozen content was supplied"));
    }
    Ok(())
}
