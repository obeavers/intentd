//! Immutable Git-object input and raw native assembly. No checkout, attribute
//! filter, user working file or credential helper supplies imported bytes.
//! The upstream renderer may probe Git configuration; with no physical tracked
//! attributes in this isolated root, it cannot select a source filter driver.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::time::{Duration, UNIX_EPOCH};

use atomic_core::change::{ChangeHeader, InodeAttr, InodeKind};
use atomic_core::output::memory::Memory;
use atomic_core::pristine::{CachedGraphTxn, ViewGraph, ViewTxnT};
use atomic_core::record::workflow::assembly::{assemble_change, AssemblyOptions};
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use atomic_core::Base32;
use atomic_repository::{InsertOptions, Repository, ViewEntryKind};
use intent_atomic_proto::baselines::BaselinePolicy;
use intent_atomic_proto::StateToken;
use serde::{Deserialize, Serialize};

use crate::{durable, HostError, Result};

use super::{digest, native};

pub(crate) const MAX_FILES: usize = 50_000;
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SnapshotKind {
    Regular,
    Executable,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SnapshotEntry {
    pub path: String,
    pub kind: SnapshotKind,
    pub mode: u32,
    pub length: u64,
    pub sha256: String,
}

pub(super) struct GitSnapshot {
    pub tree: String,
    pub timestamp: i64,
    pub entries: Vec<SnapshotEntry>,
    pub contents: BTreeMap<String, Vec<u8>>,
}

pub(crate) fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
}

pub(crate) fn excluded(path: &str, policy: &BaselinePolicy) -> bool {
    let components: Vec<_> = path.split('/').map(str::to_ascii_lowercase).collect();
    components.iter().any(|part| {
        matches!(
            part.as_str(),
            ".git"
                | ".atomic"
                | ".atomic-sandbox"
                | ".vault"
                | ".intent"
                | ".ssh"
                | ".aws"
                | "node_modules"
                | "tool-outputs"
        ) || part == ".env"
            || part.starts_with(".env.")
            || matches!(
                part.as_str(),
                ".npmrc" | ".pypirc" | "credentials.json" | "id_rsa" | "id_ed25519"
            )
    }) || components.windows(2).any(|pair| {
        matches!(
            (pair[0].as_str(), pair[1].as_str()),
            (".codex", "auth.json")
                | (".claude", ".credentials.json")
                | (".gemini", "oauth_creds.json")
        )
    }) || Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pem" | "key" | "p12"
            )
        })
        || policy.excluded_paths.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
}

pub(super) fn read_git(
    source: &Path,
    commit: &str,
    policy: &BaselinePolicy,
) -> Result<GitSnapshot> {
    let git = git2::Repository::open(source).map_err(native)?;
    let oid = git2::Oid::from_str(commit).map_err(native)?;
    let commit = git.find_commit(oid).map_err(native)?;
    let tree = commit.tree().map_err(native)?;
    let mut objects = BTreeMap::new();
    let mut failure = None;
    let mut folded_paths = BTreeMap::new();
    tree.walk(git2::TreeWalkMode::PreOrder, |parent, entry| {
        let Ok(name) = entry.name() else {
            failure = Some(HostError::Invalid("baseline path is not UTF-8"));
            return git2::TreeWalkResult::Abort;
        };
        let path = format!("{parent}{name}");
        if !safe_path(&path) || excluded(&path, policy) {
            failure = Some(HostError::Invalid(
                "tracked baseline path is excluded or reserved",
            ));
            return git2::TreeWalkResult::Abort;
        }
        if !policy.case_sensitive && !path.is_ascii() {
            failure = Some(HostError::Unsupported(
                "non-ASCII case-folding destination policy is unqualified",
            ));
            return git2::TreeWalkResult::Abort;
        }
        if !policy.case_sensitive
            && folded_paths
                .insert(path.to_ascii_lowercase(), path.clone())
                .is_some_and(|earlier| earlier != path)
        {
            failure = Some(HostError::Invalid(
                "baseline paths collide on the destination",
            ));
            return git2::TreeWalkResult::Abort;
        }
        if entry.kind() != Some(git2::ObjectType::Tree) {
            objects.insert(path, (entry.id(), entry.filemode()));
        }
        if objects.len() > MAX_FILES {
            failure = Some(HostError::Invalid("baseline file count exceeds budget"));
            return git2::TreeWalkResult::Abort;
        }
        git2::TreeWalkResult::Ok
    })
    .map_err(native)
    .map_err(|error| failure.take().unwrap_or(error))?;
    if let Some(error) = failure {
        return Err(error);
    }
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    let mut contents = BTreeMap::new();
    let mut total = 0usize;
    for (path, (oid, mode)) in objects {
        if !policy.case_sensitive && !names.insert(path.to_ascii_lowercase()) {
            return Err(HostError::Invalid(
                "baseline paths collide on the destination",
            ));
        }
        let kind = match mode {
            0o100_644 => SnapshotKind::Regular,
            0o100_755 => SnapshotKind::Executable,
            0o120_000 => SnapshotKind::Symlink,
            _ => {
                return Err(HostError::Unsupported(
                    "baseline file kind is not qualified",
                ));
            }
        };
        let blob = git.find_blob(oid).map_err(native)?;
        if blob.size() > MAX_FILE_BYTES
            || total
                .checked_add(blob.size())
                .is_none_or(|bytes| bytes > MAX_SOURCE_BYTES)
        {
            return Err(HostError::Invalid("baseline byte count exceeds budget"));
        }
        total += blob.size();
        let bytes = blob.content().to_vec();
        if kind == SnapshotKind::Symlink && (bytes.is_empty() || bytes.contains(&0)) {
            return Err(HostError::Invalid("invalid baseline symlink target"));
        }
        entries.push(SnapshotEntry {
            path: path.clone(),
            kind,
            mode: u32::try_from(mode).map_err(native)?,
            length: u64::try_from(bytes.len()).map_err(native)?,
            sha256: digest(&bytes),
        });
        contents.insert(path, bytes);
    }
    Ok(GitSnapshot {
        tree: tree.id().to_string(),
        timestamp: commit.time().seconds(),
        entries,
        contents,
    })
}

fn qualification_phase(files: usize, phase: &str, started: std::time::Instant) {
    #[cfg(test)]
    if files >= 20_000 {
        eprintln!(
            "native baseline qualification phase={phase}, files={files}, elapsed={:?}",
            started.elapsed()
        );
    }
    #[cfg(not(test))]
    let _ = (files, phase, started);
}

pub(super) fn import_native(
    root: &Path,
    snapshot: &GitSnapshot,
    source_commit: &str,
) -> Result<Repository> {
    let started = std::time::Instant::now();
    let repository = Repository::init(root).map_err(native)?;
    qualification_phase(snapshot.entries.len(), "native initialized", started);
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .map_err(native)?;
    if !snapshot.entries.is_empty() {
        let memory = Memory::new();
        let options = RecordingOptions::new()
            .max_file_size(MAX_FILE_BYTES)
            .skip_binary(false)
            .record_empty_files(true);
        let mut recorded = Vec::with_capacity(snapshot.entries.len());
        for (offset, entry) in snapshot.entries.iter().enumerate() {
            memory.add_file(&entry.path, &snapshot.contents[&entry.path]);
            let mut file =
                record_added_file(&memory, &DetectedFile::added(entry.path.clone()), &options)
                    .map_err(native)?;
            file.set_attr(InodeAttr::Mode(match entry.kind {
                SnapshotKind::Regular => 0o644,
                SnapshotKind::Executable => 0o755,
                SnapshotKind::Symlink => 0o777,
            }));
            file.set_attr(InodeAttr::Kind(if entry.kind == SnapshotKind::Symlink {
                InodeKind::Symlink
            } else {
                InodeKind::Regular
            }));
            recorded.push(file);
            if (offset + 1) % 5000 == 0 {
                qualification_phase(
                    snapshot.entries.len(),
                    &format!(
                        "file records prepared ({}/{})",
                        offset + 1,
                        snapshot.entries.len()
                    ),
                    started,
                );
            }
        }
        qualification_phase(snapshot.entries.len(), "assembling exact change", started);
        let mut header = ChangeHeader::new(format!("Imported Git baseline {source_commit}"));
        header.timestamp = if snapshot.timestamp >= 0 {
            UNIX_EPOCH.checked_add(Duration::from_secs(snapshot.timestamp.unsigned_abs()))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(snapshot.timestamp.unsigned_abs()))
        }
        .ok_or(HostError::Invalid(
            "source timestamp is outside the host range",
        ))?
        .into();
        // The repository facade hardcodes AssemblyOptions::default(), which
        // omits empty FileAdd operations. Use the same public view-scoped core
        // assembly with explicit empty-file support, including its attributes.
        let mut change = {
            let transaction = repository.pristine().read_txn().map_err(native)?;
            let view = transaction
                .get_view(repository.current_view())
                .map_err(native)?
                .ok_or(HostError::Invalid("baseline root view is unavailable"))?;
            let visibility =
                atomic_repository::graph_visibility_closure(&transaction, &view).map_err(native)?;
            let cached = CachedGraphTxn::new(&transaction).map_err(native)?;
            let graph = ViewGraph::new(&cached, visibility);
            assemble_change(
                &graph,
                &recorded,
                header,
                &AssemblyOptions::new().include_empty_files(true),
            )
            .map_err(native)?
            .into_change()
        };
        qualification_phase(snapshot.entries.len(), "change assembled", started);
        change.hashed.metadata = serde_json::to_vec(&serde_json::json!({
            "origin":"importedGitBaseline",
            "sourceCommit":source_commit,
            "sourceTree":snapshot.tree,
            "authority":"importedOnly"
        }))?;
        // This serialization's bytes and hash stay together. No reconstructed
        // object is handed to save_change, which might serialize differently.
        let mut bytes = Vec::new();
        let hash = change.serialize(&mut bytes).map_err(native)?;
        qualification_phase(snapshot.entries.len(), "change serialized", started);
        qualification_phase(snapshot.entries.len(), "importing exact object", started);
        repository
            .import_change_bytes(&hash, &bytes)
            .map_err(native)?;
        qualification_phase(
            snapshot.entries.len(),
            "exact object imported; flushing metadata",
            started,
        );
        durable::sync_tree(&root.join(".atomic"))?;
        qualification_phase(
            snapshot.entries.len(),
            "exact object durable; inserting graph",
            started,
        );
        repository
            .insert_change(&hash, InsertOptions::default())
            .map_err(native)?;
    }
    qualification_phase(
        snapshot.entries.len(),
        "native graph inserted; verifying files",
        started,
    );
    verify_native(&repository, &snapshot.entries)?;
    qualification_phase(snapshot.entries.len(), "native files verified", started);
    durable::sync_tree(&root.join(".atomic"))?;
    durable::sync_parent(root)?;
    Ok(repository)
}

pub(crate) fn native_state(repository: &Repository) -> Result<StateToken> {
    let view = repository.current_view();
    Ok(StateToken {
        view: view.into(),
        effective_state: repository
            .sandbox_effective_state(view)
            .map_err(native)?
            .to_base32(),
        own_merkle: repository
            .get_view_info(view)
            .map_err(native)?
            .state_base32(),
    })
}

pub(crate) fn verify_native(
    repository: &Repository,
    expected: &[SnapshotEntry],
) -> Result<BTreeMap<String, Vec<u8>>> {
    verify_native_on_view(repository, repository.current_view(), expected)
}

pub(crate) fn verify_native_on_view(
    repository: &Repository,
    view: &str,
    expected: &[SnapshotEntry],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let started = std::time::Instant::now();
    let mut files = BTreeMap::new();
    let mut actual = Vec::new();
    repository
        .materialize_view_entries(view, |entry| {
            if entry.kind == ViewEntryKind::Directory {
                return Ok::<_, HostError>(());
            }
            if !safe_path(&entry.path) {
                return Err(HostError::Invalid(
                    "native baseline contains an unsafe path",
                ));
            }
            let (kind, mode) = match entry.kind {
                ViewEntryKind::Symlink => (SnapshotKind::Symlink, 0o120_000),
                ViewEntryKind::File if entry.mode == 0o644 => (SnapshotKind::Regular, 0o100_644),
                ViewEntryKind::File if entry.mode == 0o755 => (SnapshotKind::Executable, 0o100_755),
                _ => {
                    return Err(HostError::Unsupported(
                        "native baseline mode is unqualified",
                    ));
                }
            };
            // Conflict-marker-looking bytes from Git are legitimate source bytes;
            // only exact manifest equality decides imported fidelity here.
            actual.push(SnapshotEntry {
                path: entry.path.clone(),
                kind,
                mode,
                length: u64::try_from(entry.content.len()).map_err(native)?,
                sha256: digest(&entry.content),
            });
            if actual.len() % 5000 == 0 {
                qualification_phase(
                    expected.len(),
                    &format!(
                        "verified native render ({}/{})",
                        actual.len(),
                        expected.len()
                    ),
                    started,
                );
            }
            if files.insert(entry.path, entry.content).is_some() {
                return Err(HostError::Invalid(
                    "native baseline contains duplicate paths",
                ));
            }
            Ok(())
        })
        .map_err(native)??;
    actual.sort_by(|left, right| left.path.cmp(&right.path));
    if actual != expected {
        return Err(HostError::Invalid(
            "native baseline differs from immutable Git bytes or attributes",
        ));
    }
    Ok(files)
}
