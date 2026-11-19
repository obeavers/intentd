//! Private Git merge candidates. Original commits retain their identities and
//! parent graph; derived preview commits are explicitly composition-only.

use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use git2::{Index, IndexEntry, IndexTime, Oid, Repository};
use intent_core::work_evidence::composition::{
    NativeCompositionReceipt, VerifiedCompositionReceipt,
};
use serde::{Deserialize, Serialize};

use super::{change_ref, content_digest, empty_tree_id, git_root, json_bytes, storage, vcs};

const VERSION: u32 = 1;
const MAX_GRAPH: usize = 65_536;
const MAX_INPUTS: usize = 1_024;
const MAX_METADATA: u64 = 8 * 1024 * 1024;
const MAX_CONFLICT_BLOB: usize = 64 * 1024 * 1024;
const MAX_RETAINED_COPY: u64 = 1024 * 1024 * 1024;

pub(super) fn reopen(
    root: &vcs::RootBinding,
    directory: &Path,
) -> vcs::VcsResult<vcs::PreparedComposition> {
    git_root(root, "reopenComposition")?;
    let directory = storage::canonical_directory(directory)?;
    let bytes = read(&directory.join("command.json"))?;
    let command: Command =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if command.format_version != VERSION || command.root != *root || json_bytes(&command)? != bytes
    {
        return Err(invalid("retained composition command has changed"));
    }
    load(root, &command.request, &directory, &bytes)
}

pub(super) fn copy(
    prepared: &vcs::PreparedComposition,
    destination: &Path,
) -> vcs::VcsResult<vcs::PreparedComposition> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "copyComposition",
            kind: vcs::VcsKind::Git,
        });
    }
    let root = &prepared.receipt.receipt().root;
    let directory = prepared
        .manifest_path
        .parent()
        .ok_or_else(|| invalid("composition has no retained bundle"))?;
    let source = reopen(root, directory)?;
    if source.receipt.receipt() != prepared.receipt.receipt() {
        return Err(invalid(
            "composition copy source differs from its inspected receipt",
        ));
    }
    let parent = storage::canonical_directory(
        destination
            .parent()
            .ok_or_else(|| invalid("composition destination has no parent"))?,
    )?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| invalid("composition destination has no name"))?,
    );
    if destination.symlink_metadata().is_ok() || destination.starts_with(directory) {
        return Err(invalid(
            "composition copy must create another private destination",
        ));
    }
    let mut staging_builder = tempfile::Builder::new();
    staging_builder.prefix("composition-copy-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staging_builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let staged = staging_builder
        .tempdir_in(&parent)
        .map_err(|error| io(&error))?;
    let mut pending = vec![(directory.to_path_buf(), staged.path().to_path_buf())];
    let mut synced = Vec::new();
    let mut copied = 0_u64;
    while let Some((from, to)) = pending.pop() {
        synced.push(to.clone());
        for entry in std::fs::read_dir(&from).map_err(|error| io(&error))? {
            let entry = entry.map_err(|error| io(&error))?;
            let path = entry.path();
            let target = to.join(entry.file_name());
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| io(&error))?;
            if metadata.is_dir() {
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&target).map_err(|error| io(&error))?;
                pending.push((path, target));
            } else if metadata.file_type().is_symlink() {
                if !path.starts_with(&source.materialization.destination)
                    || path.starts_with(source.materialization.destination.join(".git"))
                {
                    return Err(invalid(
                        "only authored materialization symlinks can be retained",
                    ));
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(
                    std::fs::read_link(&path).map_err(|error| io(&error))?,
                    &target,
                )
                .map_err(|error| io(&error))?;
                #[cfg(not(unix))]
                return Err(invalid("composition symlink retention is unavailable"));
            } else if metadata.is_file() {
                let mut input = storage::read_file(&path)?;
                let mut output = storage::create_file(&target)?;
                let length = std::io::copy(
                    &mut std::io::Read::by_ref(&mut input)
                        .take(MAX_RETAINED_COPY.saturating_sub(copied).saturating_add(1)),
                    &mut output,
                )
                .map_err(|error| io(&error))?;
                copied = copied.saturating_add(length);
                if copied > MAX_RETAINED_COPY {
                    return Err(invalid("composition retention exceeds its byte budget"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o111 != 0 {
                        output
                            .set_permissions(std::fs::Permissions::from_mode(0o700))
                            .map_err(|error| io(&error))?;
                    }
                }
                output.sync_all().map_err(|error| io(&error))?;
            } else {
                return Err(invalid("unsupported file in retained composition"));
            }
        }
    }
    for directory in synced.into_iter().rev() {
        storage::sync_directory(&directory)?;
    }
    let copied = reopen(root, staged.path())?;
    if copied.receipt.receipt() != source.receipt.receipt() {
        return Err(invalid("retained composition differs from its source"));
    }
    let _ = reopen(root, directory)?;
    if destination.symlink_metadata().is_ok() {
        return Err(invalid("composition destination appeared during retention"));
    }
    std::fs::rename(staged.keep(), &destination).map_err(|error| io(&error))?;
    storage::sync_directory(&parent)?;
    reopen(root, &destination)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Command {
    format_version: u32,
    root: vcs::RootBinding,
    request: vcs::ComposeRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    format_version: u32,
    base: vcs::NativeStateRef,
    changes: Vec<vcs::NativeChangeRef>,
    dependency_only_changes: Vec<vcs::NativeChangeRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    incoming: vcs::NativeChangeRef,
    before: vcs::NativeStateRef,
    after: vcs::NativeStateRef,
    preview_commit: Option<vcs::NativeChangeRef>,
    conflicts: Vec<vcs::ConflictInfo>,
    omitted_preview_paths: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    format_version: u32,
    merger: String,
    command_digest: vcs::ContentDigest,
    candidate: vcs::CompositionCandidate,
    steps: Vec<Step>,
    selection_revision: vcs::ContentDigest,
    closure_manifest_digest: vcs::ContentDigest,
    closure_directory: String,
    #[serde(rename = "conflictManifest")]
    conflicts_digest: Option<vcs::ContentDigest>,
}

fn invalid(reason: impl Into<String>) -> vcs::VcsError {
    storage::invalid(reason)
}
fn io(error: &std::io::Error) -> vcs::VcsError {
    storage::io(error)
}
fn oid(value: &str) -> vcs::VcsResult<Oid> {
    storage::object_id(value)
}

fn write(path: &Path, bytes: &[u8]) -> vcs::VcsResult<()> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_METADATA {
        return Err(invalid(
            "composition metadata exceeds its retained byte budget",
        ));
    }
    let mut file = storage::create_file(path)?;
    file.write_all(bytes).map_err(|error| io(&error))?;
    file.sync_all().map_err(|error| io(&error))?;
    storage::sync_directory(
        path.parent()
            .ok_or_else(|| invalid("composition artifact has no parent"))?,
    )
}

fn read(path: &Path) -> vcs::VcsResult<Vec<u8>> {
    let mut file = storage::read_file(path)?;
    if file.metadata().map_err(|error| io(&error))?.len() > MAX_METADATA {
        return Err(invalid("retained composition metadata is oversized"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io(&error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_METADATA {
        return Err(invalid("composition metadata grew beyond its budget"));
    }
    Ok(bytes)
}

fn input_state(
    repo: &Repository,
    root: &vcs::RootBinding,
    state: &vcs::NativeStateRef,
) -> vcs::VcsResult<(Option<Oid>, Oid)> {
    if let vcs::NativeStateRef::Git {
        repository_id,
        commit: None,
        tree,
    } = state
    {
        if repository_id != &root.repository_id || oid(tree.as_str())? != empty_tree_id()? {
            return Err(invalid("invalid empty Git composition state"));
        }
        // Verifying a conceptual empty state must not write the source ODB.
        return Ok((None, empty_tree_id()?));
    }
    storage::verify_state(repo, &root.repository_id, state)
}

fn state(
    root: &vcs::RootBinding,
    repo: &Repository,
    head: Option<Oid>,
) -> vcs::VcsResult<vcs::NativeStateRef> {
    let tree = match head {
        Some(id) => repo.find_commit(id).map_err(crate::map_git_err)?.tree_id(),
        None => empty_tree_id()?,
    };
    Ok(vcs::NativeStateRef::Git {
        repository_id: root.repository_id.clone(),
        commit: head.map(|id| vcs::GitCommitId::from_string(id.to_string())),
        tree: vcs::GitTreeId::from_string(tree.to_string()),
    })
}

fn closure(
    repo: &Repository,
    heads: impl IntoIterator<Item = Oid>,
) -> vcs::VcsResult<HashSet<Oid>> {
    let mut pending: Vec<_> = heads.into_iter().collect();
    let mut seen = HashSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_GRAPH {
            return Err(invalid(
                "composition dependency graph exceeds its qualification budget",
            ));
        }
        let commit = repo.find_commit(id).map_err(crate::map_git_err)?;
        pending.extend(commit.parent_ids());
    }
    Ok(seen)
}

fn refs(root: &vcs::RootBinding, ids: impl IntoIterator<Item = Oid>) -> Vec<vcs::NativeChangeRef> {
    let mut ids: Vec<_> = ids.into_iter().collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .map(|id| change_ref(root, id.to_string()))
        .collect()
}

fn selected(
    root: &vcs::RootBinding,
    repo: &Repository,
    request: &vcs::ComposeRequest,
) -> vcs::VcsResult<Vec<Oid>> {
    if request.operation_id.as_str().is_empty()
        || request.operation_id.as_str().len() > 256
        || request.changes.len() > MAX_INPUTS
    {
        return Err(invalid("invalid or oversized composition request"));
    }
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for change in &request.changes {
        let vcs::NativeChangeRef::Git {
            repository_id,
            commit,
        } = change
        else {
            return Err(invalid("Git composition received a non-Git contribution"));
        };
        if repository_id != &root.repository_id {
            return Err(invalid(
                "composition contribution belongs to another repository",
            ));
        }
        let id = oid(commit.as_str())?;
        if !seen.insert(id) {
            return Err(invalid("composition selected the same contribution twice"));
        }
        repo.find_commit(id).map_err(crate::map_git_err)?;
        ids.push(id);
    }
    Ok(ids)
}

fn frontier(repo: &Repository, selected: &[Oid]) -> vcs::VcsResult<Vec<Oid>> {
    let selected_set: HashSet<_> = selected.iter().copied().collect();
    let mut non_frontier = HashSet::new();
    let mut visited = HashSet::new();
    let mut pending = Vec::new();
    for id in selected {
        pending.extend(
            repo.find_commit(*id)
                .map_err(crate::map_git_err)?
                .parent_ids(),
        );
    }
    while let Some(id) = pending.pop() {
        if selected_set.contains(&id) {
            non_frontier.insert(id);
        }
        if !visited.insert(id) {
            continue;
        }
        if visited.len() > MAX_GRAPH {
            return Err(invalid("composition frontier exceeds its graph budget"));
        }
        pending.extend(
            repo.find_commit(id)
                .map_err(crate::map_git_err)?
                .parent_ids(),
        );
    }
    Ok(selected
        .iter()
        .copied()
        .filter(|id| !non_frontier.contains(id))
        .collect())
}

fn stage(entry: Option<&IndexEntry>) -> vcs::VcsResult<Option<vcs::GitConflictStage>> {
    entry
        .map(|entry| {
            Ok(vcs::GitConflictStage {
                path: std::str::from_utf8(&entry.path)
                    .map_err(|_| invalid("composition conflict path is not UTF-8"))?
                    .into(),
                object: vcs::GitObjectId::from_string(entry.id.to_string()),
                mode: entry.mode,
            })
        })
        .transpose()
}

fn normal_entry(path: Vec<u8>, id: Oid, mode: u32) -> IndexEntry {
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode,
        uid: 0,
        gid: 0,
        file_size: 0,
        id,
        flags: 0,
        flags_extended: 0,
        path,
    }
}

fn conflict_kind(
    repo: &Repository,
    conflict: &git2::IndexConflict,
) -> vcs::VcsResult<vcs::GitConflictKind> {
    use vcs::GitConflictKind as K;
    let (Some(ours), Some(theirs)) = (&conflict.our, &conflict.their) else {
        return Ok(K::ModifyDelete);
    };
    if ours.path != theirs.path {
        return Ok(K::PathConflict);
    }
    if ours.mode & 0o170_000 != theirs.mode & 0o170_000 {
        return Ok(K::TypeChange);
    }
    for entry in [&conflict.ancestor, &conflict.our, &conflict.their]
        .into_iter()
        .flatten()
    {
        if entry.mode == 0o160_000 {
            return Ok(K::TypeChange);
        }
        let blob = repo.find_blob(entry.id).map_err(crate::map_git_err)?;
        if blob.size() > MAX_CONFLICT_BLOB {
            return Err(invalid("conflict blob exceeds the rendering byte budget"));
        }
        if blob.is_binary() {
            return Ok(K::Binary);
        }
    }
    if conflict.ancestor.is_none() {
        Ok(K::AddAdd)
    } else {
        Ok(K::Content)
    }
}

fn render_index(
    repo: &Repository,
    index: &Index,
    root: &vcs::RootBinding,
    ours: Oid,
    theirs: Oid,
) -> vcs::VcsResult<(Oid, Vec<vcs::ConflictInfo>, Vec<String>)> {
    let mut entries: BTreeMap<Vec<u8>, IndexEntry> = index
        .iter()
        .filter(|entry| entry.flags & 0x3000 == 0)
        .map(|entry| {
            (
                entry.path.clone(),
                normal_entry(entry.path, entry.id, entry.mode),
            )
        })
        .collect();
    let mut conflicts = Vec::new();
    for item in index.conflicts().map_err(crate::map_git_err)? {
        let conflict = item.map_err(crate::map_git_err)?;
        let kind = conflict_kind(repo, &conflict)?;
        let chosen = conflict
            .our
            .as_ref()
            .or(conflict.their.as_ref())
            .or(conflict.ancestor.as_ref())
            .ok_or_else(|| invalid("native conflict has no retained stages"))?;
        let path = std::str::from_utf8(&chosen.path)
            .map_err(|_| invalid("conflict path is not UTF-8"))?
            .to_string();
        let mut rendered = normal_entry(chosen.path.clone(), chosen.id, chosen.mode);
        if matches!(
            kind,
            vcs::GitConflictKind::Content | vcs::GitConflictKind::AddAdd
        ) {
            if let (Some(ours), Some(theirs)) = (&conflict.our, &conflict.their) {
                if ours.mode & 0o170_000 == 0o100_000 && theirs.mode & 0o170_000 == 0o100_000 {
                    let empty = normal_entry(
                        chosen.path.clone(),
                        repo.blob(&[]).map_err(crate::map_git_err)?,
                        chosen.mode,
                    );
                    let ancestor = conflict.ancestor.as_ref().unwrap_or(&empty);
                    let mut options = git2::MergeFileOptions::new();
                    options
                        .ancestor_label("base")
                        .our_label("target")
                        .their_label("selected")
                        .style_diff3(true);
                    let merged = repo
                        .merge_file_from_index(ancestor, ours, theirs, Some(&mut options))
                        .map_err(crate::map_git_err)?;
                    rendered.id = repo.blob(merged.content()).map_err(crate::map_git_err)?;
                }
            }
        }
        conflicts.push(vcs::ConflictInfo {
            path,
            changes: vec![
                change_ref(root, ours.to_string()),
                change_ref(root, theirs.to_string()),
            ],
            reason: format!("Git {kind:?} conflict; preview rendering does not resolve it"),
            details: Some(vcs::ConflictDetails::Git {
                conflict_kind: kind,
                ancestor: stage(conflict.ancestor.as_ref())?,
                ours: stage(conflict.our.as_ref())?,
                theirs: stage(conflict.their.as_ref())?,
            }),
        });
        entries.insert(rendered.path.clone(), rendered);
    }
    let mut clean = Index::new().map_err(crate::map_git_err)?;
    let mut retained_paths: HashSet<Vec<u8>> = HashSet::new();
    let mut omitted = Vec::new();
    for (path, entry) in entries {
        if path
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
            .any(|(position, _)| retained_paths.contains(&path[..position]))
        {
            if conflicts.is_empty() {
                return Err(invalid(
                    "native clean merge produced incompatible file paths",
                ));
            }
            omitted.push(
                String::from_utf8(path)
                    .map_err(|_| invalid("omitted conflict path is not UTF-8"))?,
            );
            continue;
        }
        clean.add(&entry).map_err(crate::map_git_err)?;
        retained_paths.insert(path);
    }
    let tree = clean.write_tree_to(repo).map_err(crate::map_git_err)?;
    Ok((tree, conflicts, omitted))
}

fn merge(
    repo: &Repository,
    root: &vcs::RootBinding,
    request: &vcs::ComposeRequest,
    selected: &[Oid],
    target: Option<Oid>,
) -> vcs::VcsResult<(Option<Oid>, Vec<Step>, Vec<Oid>)> {
    let mut current = target;
    let mut steps = Vec::new();
    let mut previews = Vec::new();
    for incoming in frontier(repo, selected)? {
        let before = state(root, repo, current)?;
        let mut conflicts = Vec::new();
        let mut omitted = Vec::new();
        let mut preview = None;
        let next = match current {
            None => incoming,
            Some(ours)
                if ours == incoming
                    || repo
                        .graph_descendant_of(ours, incoming)
                        .map_err(crate::map_git_err)? =>
            {
                ours
            }
            Some(ours)
                if repo
                    .graph_descendant_of(incoming, ours)
                    .map_err(crate::map_git_err)? =>
            {
                incoming
            }
            Some(ours) => {
                let ours_commit = repo.find_commit(ours).map_err(crate::map_git_err)?;
                let their_commit = repo.find_commit(incoming).map_err(crate::map_git_err)?;
                let index = repo
                    .merge_commits(&ours_commit, &their_commit, None)
                    .map_err(crate::map_git_err)?;
                let (tree, found, pruned) = render_index(repo, &index, root, ours, incoming)?;
                conflicts = found;
                omitted = pruned;
                let message = json_bytes(
                    &serde_json::json!({"kind":"intent-composition-preview-v1","operationId":request.operation_id,
                    "repositoryId":root.repository_id,"rootId":root.root_id,"rootEpoch":root.epoch,"step":steps.len(),"incoming":incoming.to_string(),
                    "before":ours.to_string(),"tree":tree.to_string(),"conflicts":conflicts,"omittedPreviewPaths":omitted}),
                )?;
                let signature = git2::Signature::new(
                    "Intent composition preview",
                    "preview@intent.invalid",
                    &git2::Time::new(0, 0),
                )
                .map_err(crate::map_git_err)?;
                let commit = repo
                    .commit(
                        None,
                        &signature,
                        &signature,
                        std::str::from_utf8(&message)
                            .map_err(|_| invalid("preview metadata is not UTF-8"))?,
                        &repo.find_tree(tree).map_err(crate::map_git_err)?,
                        &[&ours_commit, &their_commit],
                    )
                    .map_err(crate::map_git_err)?;
                previews.push(commit);
                preview = Some(change_ref(root, commit.to_string()));
                commit
            }
        };
        current = Some(next);
        steps.push(Step {
            incoming: change_ref(root, incoming.to_string()),
            before,
            after: state(root, repo, current)?,
            preview_commit: preview,
            conflicts,
            omitted_preview_paths: omitted,
        });
    }
    Ok((current, steps, previews))
}

fn receipt_digest(receipt: &NativeCompositionReceipt) -> vcs::VcsResult<vcs::ContentDigest> {
    let mut body = serde_json::to_value(receipt).map_err(|error| invalid(error.to_string()))?;
    body.as_object_mut()
        .ok_or_else(|| invalid("composition receipt is not an object"))?
        .remove("receiptDigest");
    Ok(content_digest(&json_bytes(&body)?))
}

#[cfg(unix)]
type CompositionLease = nix::fcntl::Flock<File>;
#[cfg(not(unix))]
type CompositionLease = File;

fn open_lock(path: &Path) -> vcs::VcsResult<CompositionLease> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let file = options.open(path).map_err(|error| io(&error))?;
    if !file.metadata().map_err(|error| io(&error))?.is_file() {
        return Err(invalid("composition lease must be a regular file"));
    }
    #[cfg(unix)]
    let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| io(&error.into()))?;
    #[cfg(not(any(unix, windows)))]
    return Err(invalid("composition OS locking is unsupported"));
    #[cfg(any(unix, windows))]
    Ok(file)
}

fn load(
    root: &vcs::RootBinding,
    request: &vcs::ComposeRequest,
    directory: &Path,
    command: &[u8],
) -> vcs::VcsResult<vcs::PreparedComposition> {
    if storage::canonical_directory(directory)? != directory {
        return Err(invalid("composition bundle locator is not canonical"));
    }
    if read(&directory.join("command.json"))? != command {
        return Err(invalid("conflicting replay of immutable Git composition"));
    }
    let manifest_bytes = read(&directory.join("composition.json"))?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| invalid(error.to_string()))?;
    if manifest.format_version != VERSION
        || json_bytes(&manifest)? != manifest_bytes
        || manifest.command_digest != content_digest(command)
    {
        return Err(invalid(
            "retained composition manifest differs from its command",
        ));
    }
    let receipt_bytes = read(&directory.join("receipt.json"))?;
    let receipt: NativeCompositionReceipt =
        serde_json::from_slice(&receipt_bytes).map_err(|error| invalid(error.to_string()))?;
    if json_bytes(&receipt)? != receipt_bytes
        || receipt.root != *root
        || receipt.operation_id != request.operation_id
        || receipt.base_state != request.base
        || receipt.target_state != request.target
        || receipt.candidate_state != manifest.candidate.state
        || receipt.materialization_id != manifest.candidate.materialization_id
        || receipt.selected_changes != request.changes
        || receipt.selection_revision != content_digest(&read(&directory.join("selection.json"))?)
        || receipt.selection_revision != manifest.selection_revision
        || receipt.composition_revision != content_digest(&manifest_bytes)
        || receipt.conflict_manifest != manifest.conflicts_digest
        || receipt.receipt_digest != receipt_digest(&receipt)?
    {
        return Err(invalid("retained Git composition receipt is inconsistent"));
    }
    let conflicts: Vec<_> = manifest
        .steps
        .iter()
        .flat_map(|step| step.conflicts.iter().cloned())
        .collect();
    if conflicts != manifest.candidate.conflicts
        || conflicts.is_empty() != receipt.conflict_manifest.is_none()
    {
        return Err(invalid(
            "conflict manifest cannot assert an unproved clean candidate",
        ));
    }
    if let Some(expected) = &receipt.conflict_manifest {
        if content_digest(&read(&directory.join("conflicts.json"))?) != *expected {
            return Err(invalid("retained conflict stages changed"));
        }
    }
    let materialization = vcs::MaterializationReceipt {
        state: receipt.candidate_state.clone(),
        materialization_id: receipt.materialization_id.clone(),
        destination: directory.join("materialization"),
    };
    storage::verify_materialization(&materialization, &[])?;
    let repo = Repository::open(&materialization.destination).map_err(crate::map_git_err)?;
    let (head, _) = input_state(&repo, root, &receipt.candidate_state)?;
    if refs(root, closure(&repo, head)?) != receipt.full_closed_changes {
        return Err(invalid(
            "retained composition has incomplete original ancestry",
        ));
    }
    let (base, _) = input_state(&repo, root, &request.base)?;
    let selected_ids = selected(root, &repo, request)?;
    let selected_set: HashSet<_> = selected_ids.iter().copied().collect();
    let inherited = closure(&repo, base)?;
    let (target, _) = input_state(&repo, root, &request.target)?;
    if refs(root, closure(&repo, target)?) != receipt.target_context_changes {
        return Err(invalid(
            "retained target context differs from the exact original target ancestry",
        ));
    }
    let selected_closure = closure(&repo, selected_ids)?;
    let dependencies = refs(
        root,
        selected_closure
            .difference(&inherited)
            .copied()
            .filter(|id| !selected_set.contains(id)),
    );
    if dependencies != receipt.dependency_only_changes
        || dependencies != manifest.candidate.required_dependencies
    {
        return Err(invalid(
            "retained dependencies do not match the original commit parent graph",
        ));
    }
    let selection_bytes = read(&directory.join("selection.json"))?;
    let selection: Selection =
        serde_json::from_slice(&selection_bytes).map_err(|error| invalid(error.to_string()))?;
    if selection.format_version != VERSION
        || selection.base != request.base
        || selection.changes != request.changes
        || selection.dependency_only_changes != dependencies
        || json_bytes(&selection)? != selection_bytes
    {
        return Err(invalid(
            "retained selection metadata differs from actual selected ancestry",
        ));
    }
    if refs(
        root,
        inherited
            .iter()
            .copied()
            .filter(|id| !selected_set.contains(id)),
    ) != receipt.inherited_baseline_changes
    {
        return Err(invalid(
            "retained inherited membership differs from the exact baseline ancestry",
        ));
    }
    for (position, step) in manifest.steps.iter().enumerate() {
        if let Some(vcs::NativeChangeRef::Git { commit, .. }) = &step.preview_commit {
            let preview = repo
                .find_commit(oid(commit.as_str())?)
                .map_err(crate::map_git_err)?;
            let (Some(before), _) = input_state(&repo, root, &step.before)? else {
                return Err(invalid("derived merge anchor has no actual target parent"));
            };
            let vcs::NativeChangeRef::Git {
                commit: incoming, ..
            } = &step.incoming
            else {
                return Err(invalid("derived merge mapped a foreign input"));
            };
            let (Some(after), after_tree) = input_state(&repo, root, &step.after)? else {
                return Err(invalid("derived merge has no actual result anchor"));
            };
            let message = json_bytes(
                &serde_json::json!({"kind":"intent-composition-preview-v1","operationId":request.operation_id,
                "repositoryId":root.repository_id,"rootId":root.root_id,"rootEpoch":root.epoch,"step":position,"incoming":incoming.as_str(),
                "before":before.to_string(),"tree":after_tree.to_string(),"conflicts":step.conflicts,"omittedPreviewPaths":step.omitted_preview_paths}),
            )?;
            if after != preview.id()
                || preview.parent_ids().collect::<Vec<_>>() != [before, oid(incoming.as_str())?]
                || preview.message_bytes() != message
            {
                return Err(invalid(
                    "derived preview no longer preserves its explicit original parent mapping",
                ));
            }
        }
    }
    let previews: Vec<_> = manifest
        .steps
        .iter()
        .filter_map(|step| step.preview_commit.clone())
        .collect();
    if refs(
        root,
        previews
            .iter()
            .map(|change| match change {
                vcs::NativeChangeRef::Git { commit, .. } => oid(commit.as_str()),
                vcs::NativeChangeRef::Atomic { .. } => Err(invalid("foreign preview")),
            })
            .collect::<vcs::VcsResult<Vec<_>>>()?,
    ) != receipt.composition_only_changes
    {
        return Err(invalid(
            "derived preview anchors do not match their explicit mapping",
        ));
    }
    if manifest.closure_directory.is_empty()
        || manifest.closure_directory.contains(['/', '\\'])
        || manifest.closure_directory.starts_with('.')
    {
        return Err(invalid("portable composition closure escaped its bundle"));
    }
    let closure = vcs::NativeClosureManifest {
        state: receipt.candidate_state.clone(),
        changes: receipt.full_closed_changes.clone(),
        manifest_digest: manifest.closure_manifest_digest,
        spool_path: directory
            .join(&manifest.closure_directory)
            .join("closure.json"),
    };
    storage::verify_closure(&closure)?;
    let receipt = VerifiedCompositionReceipt::from_verified_backend(receipt)
        .map_err(vcs::VcsError::Backend)?;
    Ok(vcs::PreparedComposition {
        candidate: manifest.candidate,
        materialization,
        closure,
        selection_path: directory.join("selection.json"),
        manifest_path: directory.join("composition.json"),
        receipt,
    })
}

pub(super) fn compose(
    root: &vcs::RootBinding,
    request: &vcs::ComposeRequest,
    spool: &Path,
) -> vcs::VcsResult<vcs::PreparedComposition> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "compose",
            kind: vcs::VcsKind::Git,
        });
    }
    git_root(root, "compose")?;
    let parent = storage::canonical_directory(spool)?;
    let command = json_bytes(&Command {
        format_version: VERSION,
        root: root.clone(),
        request: request.clone(),
    })?;
    if command.len() > usize::try_from(MAX_METADATA).unwrap_or(usize::MAX) {
        return Err(invalid("composition command exceeds metadata budget"));
    }
    let key = content_digest(&json_bytes(&(root, &request.operation_id))?);
    let _lease = open_lock(&parent.join(format!("git-composition-{}.lock", key.as_str())))?;
    let destination = parent.join(format!("git-composition-{}", key.as_str()));
    if destination.symlink_metadata().is_ok() {
        return load(root, request, &destination, &command);
    }
    let source = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    let source_dir = std::fs::canonicalize(source.workdir().unwrap_or(source.path()))
        .map_err(|error| io(&error))?;
    let source_admin = std::fs::canonicalize(source.commondir()).map_err(|error| io(&error))?;
    if parent.starts_with(&source_dir) || parent.starts_with(&source_admin) {
        return Err(invalid(
            "composition spool must be outside the source checkout and Git administration",
        ));
    }
    let (base, _) = input_state(&source, root, &request.base)?;
    let (target, _) = input_state(&source, root, &request.target)?;
    let selected_ids = selected(root, &source, request)?;
    if let Some(base) = base {
        let target_contains_base = match target {
            Some(target) if target == base => true,
            Some(target) => source
                .graph_descendant_of(target, base)
                .map_err(crate::map_git_err)?,
            None => false,
        };
        if !target_contains_base {
            return Err(vcs::VcsError::PolicyBlocked {
                reason: vcs::CompositionBlock::InheritedBaselineRequired,
                changes: vec![change_ref(root, base.to_string())],
            });
        }
        for id in &selected_ids {
            if *id != base
                && !source
                    .graph_descendant_of(*id, base)
                    .map_err(crate::map_git_err)?
            {
                return Err(invalid("selected Git contribution does not descend from the declared inherited baseline"));
            }
        }
    }
    let inherited = closure(&source, base)?;
    let source_changes = closure(&source, selected_ids.iter().copied())?;
    let selected_set: HashSet<_> = selected_ids.iter().copied().collect();
    let dependencies = refs(
        root,
        source_changes
            .difference(&inherited)
            .copied()
            .filter(|id| !selected_set.contains(id)),
    );
    let mut all = inherited.clone();
    all.extend(source_changes);
    all.extend(closure(&source, target)?);
    if all.len().saturating_add(selected_ids.len()) > MAX_GRAPH {
        return Err(invalid(
            "combined composition graph exceeds its qualification budget",
        ));
    }
    // The first private merge policy never executes user or global drivers.
    // Attribute-aware merge semantics need a separately qualified policy.
    let mut trees = HashSet::new();
    trees.extend(
        base.map(|id| source.find_commit(id).map(|commit| commit.tree_id()))
            .transpose()
            .map_err(crate::map_git_err)?,
    );
    trees.extend(
        target
            .map(|id| source.find_commit(id).map(|commit| commit.tree_id()))
            .transpose()
            .map_err(crate::map_git_err)?,
    );
    for id in &selected_ids {
        trees.insert(
            source
                .find_commit(*id)
                .map_err(crate::map_git_err)?
                .tree_id(),
        );
    }
    for id in trees {
        let mut index = Index::new().map_err(crate::map_git_err)?;
        index
            .read_tree(&source.find_tree(id).map_err(crate::map_git_err)?)
            .map_err(crate::map_git_err)?;
        if index.iter().any(|entry| {
            entry.path == b".gitattributes" || entry.path.ends_with(b"/.gitattributes")
        }) {
            return Err(vcs::VcsError::Unsupported {
                operation: "composeGitAttributes",
                kind: vcs::VcsKind::Git,
            });
        }
    }
    let staging = tempfile::Builder::new()
        .prefix(".git-composition-pending-")
        .tempdir_in(&parent)
        .map_err(|error| io(&error))?;
    write(&staging.path().join("command.json"), &command)?;
    let repo = storage::initialize(&staging.path().join("repository"))?;
    // Pin only the private local config; global custom drivers never execute.
    let config = git2::Config::open(&repo.path().join("config")).map_err(crate::map_git_err)?;
    repo.set_config(&config).map_err(crate::map_git_err)?;
    let mut roots = selected_ids.clone();
    roots.extend(base);
    roots.extend(target);
    crate::checkpoint::copy_objects(&source, &repo, &roots)?;
    repo.odb()
        .map_err(crate::map_git_err)?
        .write(git2::ObjectType::Tree, &[])
        .map_err(crate::map_git_err)?;
    let (head, steps, previews) = merge(&repo, root, request, &selected_ids, target)?;
    let candidate_state = state(root, &repo, head)?;
    let (_, tree) = input_state(&repo, root, &candidate_state)?;
    let materialization = storage::materialize_objects(
        &repo,
        head,
        tree,
        &candidate_state,
        &staging.path().join("materialization"),
    )?;
    let conflicts: Vec<_> = steps
        .iter()
        .flat_map(|step| step.conflicts.iter().cloned())
        .collect();
    let conflict_manifest = if conflicts.is_empty() {
        None
    } else {
        let bytes = json_bytes(&conflicts)?;
        write(&staging.path().join("conflicts.json"), &bytes)?;
        Some(content_digest(&bytes))
    };
    let selection = json_bytes(&Selection {
        format_version: VERSION,
        base: request.base.clone(),
        changes: request.changes.clone(),
        dependency_only_changes: dependencies.clone(),
    })?;
    write(&staging.path().join("selection.json"), &selection)?;
    let selection_revision = content_digest(&selection);
    let grant = vcs::RetentionGrant {
        operation_id: request.operation_id.clone(),
        repository_id: root.repository_id.clone(),
        binding_epoch: root.epoch,
    };
    let exported_closure = storage::export_objects(
        &repo,
        root,
        &candidate_state,
        head,
        tree,
        &grant,
        staging.path(),
    )?;
    let closure_directory = exported_closure
        .spool_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("closure directory is not portable UTF-8"))?
        .to_string();
    let candidate = vcs::CompositionCandidate {
        state: candidate_state.clone(),
        selected_changes: request.changes.clone(),
        required_dependencies: dependencies.clone(),
        materialization_id: materialization.materialization_id.clone(),
        conflicts,
    };
    let manifest = Manifest {
        format_version: VERSION,
        merger: format!(
            "libgit2/{:?}/three-way-v1",
            git2::Version::get().libgit2_version()
        ),
        command_digest: content_digest(&command),
        candidate,
        steps,
        selection_revision: selection_revision.clone(),
        closure_manifest_digest: exported_closure.manifest_digest,
        closure_directory,
        conflicts_digest: conflict_manifest.clone(),
    };
    let manifest_bytes = json_bytes(&manifest)?;
    write(&staging.path().join("composition.json"), &manifest_bytes)?;
    let mut receipt = NativeCompositionReceipt {
        operation_id: request.operation_id.clone(),
        root: root.clone(),
        base_state: request.base.clone(),
        target_state: request.target.clone(),
        candidate_state,
        materialization_id: materialization.materialization_id,
        selected_changes: request.changes.clone(),
        dependency_only_changes: dependencies,
        full_closed_changes: exported_closure.changes,
        inherited_baseline_changes: refs(
            root,
            inherited
                .into_iter()
                .filter(|id| !selected_set.contains(id)),
        ),
        target_context_changes: refs(root, closure(&repo, target)?),
        composition_only_changes: refs(root, previews),
        selection_revision,
        composition_revision: content_digest(&manifest_bytes),
        conflict_manifest,
        receipt_digest: vcs::ContentDigest::from_string("0".repeat(64)),
    };
    receipt.receipt_digest = receipt_digest(&receipt)?;
    write(&staging.path().join("receipt.json"), &json_bytes(&receipt)?)?;
    drop(repo);
    drop(source);
    std::fs::remove_dir_all(staging.path().join("repository")).map_err(|error| io(&error))?;
    storage::sync_directory(staging.path())?;
    // The per-operation lock serializes publication; existing artifacts are
    // always verified, never overwritten by a new checkout.
    if destination.symlink_metadata().is_ok() {
        return Err(invalid(
            "composition destination appeared during preparation",
        ));
    }
    let staging_path = staging.keep();
    std::fs::rename(&staging_path, &destination).map_err(|error| io(&error))?;
    storage::sync_directory(&parent)?;
    load(root, request, &destination, &command)
}

pub(super) fn comparison(
    root: &vcs::RootBinding,
    prepared: &vcs::PreparedComposition,
) -> vcs::VcsResult<super::ComparisonBasis> {
    git_root(root, "compareComposition")?;
    let receipt = prepared.receipt.receipt();
    if &receipt.root != root
        || receipt.candidate_state != prepared.materialization.state
        || receipt.materialization_id != prepared.materialization.materialization_id
        || receipt.materialization_id != prepared.candidate.materialization_id
        || receipt.candidate_state != prepared.candidate.state
    {
        return Err(vcs::VcsError::Stale {
            reason: "composition comparison has a different root, epoch or immutable candidate"
                .into(),
        });
    }
    Ok(super::ComparisonBasis {
        method: "intent-git-composition-compare-v1",
        source: prepared.materialization.destination.clone(),
        before: receipt.target_state.clone(),
        after: receipt.candidate_state.clone(),
        before_capture: content_digest(&json_bytes(&(
            root,
            &receipt.target_state,
            &receipt.composition_revision,
        ))?),
        after_capture: content_digest(&json_bytes(&(
            root,
            &receipt.candidate_state,
            &receipt.receipt_digest,
        ))?),
    })
}

#[cfg(all(test, unix))]
mod tests;
