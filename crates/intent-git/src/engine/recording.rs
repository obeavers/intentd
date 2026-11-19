//! Exact Git preparation and fenced admission. Preparation retains immutable
//! bytes without moving refs; admission never recreates a commit from live files.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use git2::{Index, IndexEntry, IndexTime, ObjectType, Oid, Repository};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::storage::{
    canonical_directory, create_file, digest_reader, invalid, io, object_id, read_file,
    sync_directory, verify_state,
};
use super::{
    content_digest, git_change, git_root, hex_digest, json_bytes, vcs, GitWorkspaceEngine,
};
use vcs::WorkspaceEngine;

const VERSION: u32 = 1;
const MAX_MANIFEST: u64 = 8 * 1024 * 1024;
const ENVELOPE: &str = "record.json";
const PACK: &str = "objects.pack";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexBefore {
    path: String,
    object: Option<String>,
    mode: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    format_version: u32,
    binding: vcs::RootBinding,
    metadata: vcs::FixedRecordMetadata,
    selection_id: vcs::SelectionId,
    selection_manifest: vcs::ContentDigest,
    before: vcs::NativeStateRef,
    reference: String,
    commit: vcs::GitCommitId,
    tree: vcs::GitTreeId,
    commit_bytes: String,
    objects: Vec<vcs::GitObjectId>,
    index_before: Vec<IndexBefore>,
    pack_digest: vcs::ContentDigest,
    pack_length: u64,
}

fn bounded_read(path: &Path) -> vcs::VcsResult<Vec<u8>> {
    let mut file = read_file(path)?;
    if file.metadata().map_err(|error| io(&error))?.len() > MAX_MANIFEST {
        return Err(invalid("immutable record manifest exceeds its byte budget"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io(&error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST {
        return Err(invalid("immutable record manifest exceeds its byte budget"));
    }
    Ok(bytes)
}

fn reference(repo: &Repository) -> vcs::VcsResult<String> {
    let head = repo.find_reference("HEAD").map_err(crate::map_git_err)?;
    let reference = head
        .symbolic_target()
        .map_err(crate::map_git_err)?
        .unwrap_or("HEAD");
    if reference != "HEAD"
        && (!reference.starts_with("refs/heads/") || !git2::Reference::is_valid_name(reference))
    {
        return Err(invalid(
            "native recording requires a local branch or detached HEAD",
        ));
    }
    Ok(reference.into())
}

fn safe_value(value: &str) -> bool {
    !value.is_empty() && !value.contains(['\0', '\r', '\n'])
}

fn commit_message(
    selection: &vcs::FrozenSelection,
    metadata: &vcs::FixedRecordMetadata,
) -> vcs::VcsResult<String> {
    if !safe_value(metadata.operation_id.as_str())
        || !safe_value(selection.selection_id.as_str())
        || !safe_value(selection.manifest.as_str())
        || !safe_value(metadata.attribution_manifest.as_str())
    {
        return Err(invalid(
            "record metadata identifiers must be nonempty single-line values",
        ));
    }
    Ok(format!("{}\n\nIntent-Operation-Id: {}\nIntent-Selection-Id: {}\nIntent-Selection-Manifest: {}\nIntent-Attribution-Manifest: {}\n", metadata.message.trim_end(), metadata.operation_id.as_str(), selection.selection_id.as_str(), selection.manifest.as_str(), metadata.attribution_manifest.as_str()))
}

fn source_path(base: &Path, relative: &str) -> vcs::VcsResult<PathBuf> {
    if !crate::checkpoint::safe_relative_path(relative)
        || crate::checkpoint::excluded(
            Path::new(relative),
            &crate::checkpoint::CaptureOptions::default(),
        )
    {
        return Err(invalid("selected path is unsafe or runtime-owned"));
    }
    let mut path = base.to_path_buf();
    let components: Vec<_> = Path::new(relative).components().collect();
    for (position, component) in components.iter().enumerate() {
        path.push(component.as_os_str());
        if position + 1 < components.len() {
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| io(&error))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid(
                    "selected payload parent must be a real directory within the sealed source",
                ));
            }
        }
    }
    Ok(path)
}

fn selected_blob(
    repo: &Repository,
    base: &Path,
    selected: &vcs::FrozenFile,
) -> vcs::VcsResult<Option<(Oid, u32)>> {
    if selected.kind == vcs::FrozenFileKind::Deletion {
        if !crate::checkpoint::safe_relative_path(&selected.path)
            || crate::checkpoint::excluded(
                Path::new(&selected.path),
                &crate::checkpoint::CaptureOptions::default(),
            )
        {
            return Err(invalid("selected deletion path is unsafe or runtime-owned"));
        }
        if selected.digest.is_some() || selected.length != 0 {
            return Err(invalid("selected deletion cannot carry payload bytes"));
        }
        return Ok(None);
    }
    let path = source_path(base, &selected.path)?;
    let expected = selected
        .digest
        .as_ref()
        .ok_or_else(|| invalid("selected file lacks its exact payload digest"))?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| io(&error))?;
    let (id, digest, length, mode) = match selected.kind {
        vcs::FrozenFileKind::Symlink => {
            if !metadata.file_type().is_symlink() {
                return Err(invalid("selected symlink payload changed kind"));
            }
            let target = std::fs::read_link(&path).map_err(|error| io(&error))?;
            let bytes = target.as_os_str().as_encoded_bytes();
            (
                repo.blob(bytes).map_err(crate::map_git_err)?,
                content_digest(bytes),
                u64::try_from(bytes.len())
                    .map_err(|_| invalid("selected symlink length overflow"))?,
                0o120_000,
            )
        }
        vcs::FrozenFileKind::Regular | vcs::FrozenFileKind::Executable => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid("selected regular payload changed kind"));
            }
            let mode = if selected.kind == vcs::FrozenFileKind::Executable {
                0o100_755
            } else {
                0o100_644
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (metadata.permissions().mode() & 0o111 != 0) != (mode == 0o100_755) {
                    return Err(invalid("selected executable mode changed"));
                }
            }
            let mut source = read_file(&path)?;
            let mut writer = repo.blob_writer(None).map_err(crate::map_git_err)?;
            let mut hash = Sha256::new();
            let mut length = 0u64;
            let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
            loop {
                let count = source.read(&mut buffer).map_err(|error| io(&error))?;
                if count == 0 {
                    break;
                }
                writer
                    .write_all(&buffer[..count])
                    .map_err(|error| io(&error))?;
                hash.update(&buffer[..count]);
                length = length
                    .checked_add(
                        u64::try_from(count)
                            .map_err(|_| invalid("selected payload length overflow"))?,
                    )
                    .ok_or_else(|| invalid("selected payload length overflow"))?;
            }
            (
                writer.commit().map_err(crate::map_git_err)?,
                hex_digest(&hash.finalize()),
                length,
                mode,
            )
        }
        vcs::FrozenFileKind::Deletion => unreachable!(),
    };
    if &digest != expected || length != selected.length {
        return Err(invalid(
            "selected payload no longer matches its frozen digest and length",
        ));
    }
    Ok(Some((id, mode)))
}

fn index_entry(path: &str, object: Oid, mode: u32, length: u64) -> IndexEntry {
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode,
        uid: 0,
        gid: 0,
        file_size: u32::try_from(length).unwrap_or(u32::MAX),
        id: object,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

fn changed_objects(
    repo: &Repository,
    before: Option<Oid>,
    after: Oid,
    objects: &mut BTreeSet<Oid>,
) -> vcs::VcsResult<()> {
    if before == Some(after) {
        return Ok(());
    }
    objects.insert(after);
    let after = repo.find_tree(after).map_err(crate::map_git_err)?;
    let before = before
        .map(|id| repo.find_tree(id))
        .transpose()
        .map_err(crate::map_git_err)?;
    for entry in &after {
        let old = before
            .as_ref()
            .and_then(|tree| tree.get_name_bytes(entry.name_bytes()));
        let old = old
            .filter(|old| old.kind() == entry.kind())
            .map(|old| old.id());
        if entry.kind() == Some(ObjectType::Tree) {
            changed_objects(repo, old, entry.id(), objects)?;
        } else if entry.kind() == Some(ObjectType::Blob) && old != Some(entry.id()) {
            objects.insert(entry.id());
        }
    }
    Ok(())
}

pub(super) fn prepare_record(
    selection: &vcs::FrozenSelection,
    metadata: &vcs::FixedRecordMetadata,
    spool_directory: &Path,
) -> vcs::VcsResult<vcs::PreparedRecord> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "prepareRecord",
            kind: vcs::VcsKind::Git,
        });
    }
    let source = git_root(&selection.binding, "prepareRecord")?;
    let repo = Repository::open(source).map_err(crate::map_git_err)?;
    if crate::commit::has_pending_merge(source)? {
        return Err(invalid(
            "native preparation cannot discard pending merge ancestry",
        ));
    }
    let target_reference = reference(&repo)?;
    let current = GitWorkspaceEngine::default().recorded_state(&selection.binding)?;
    if current != selection.source_state || reference(&repo)? != target_reference {
        return Err(vcs::VcsError::Stale {
            reason: "selection baseline or active reference changed before preparation".into(),
        });
    }
    let (parent, parent_tree) = verify_state(
        &repo,
        &selection.binding.repository_id,
        &selection.source_state,
    )?;
    let bytes = bounded_read(&selection.manifest_path)?;
    if content_digest(&bytes) != selection.manifest {
        return Err(invalid("selection manifest digest mismatch"));
    }
    let manifest: vcs::FrozenSelectionManifest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid selection manifest: {error}")))?;
    if manifest.format_version != VERSION
        || manifest.source_state != selection.source_state
        || json_bytes(&manifest)? != bytes
        || manifest.files.is_empty()
    {
        return Err(invalid(
            "selection manifest version, baseline or canonical encoding mismatch",
        ));
    }
    if manifest
        .files
        .windows(2)
        .any(|pair| pair[0].path.as_bytes() >= pair[1].path.as_bytes())
    {
        return Err(invalid(
            "selection manifest paths must be unique and sorted by bytes",
        ));
    }
    crate::submodule::reject_submodule_internal_paths(
        &repo,
        &manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>(),
    )?;
    let sealed = canonical_directory(&selection.sealed_source)?;
    let live_index = repo.index().map_err(crate::map_git_err)?;
    if live_index.has_conflicts() {
        return Err(invalid("native preparation requires a resolved index"));
    }
    let mut index_before = Vec::new();
    let mut index = Index::new().map_err(crate::map_git_err)?;
    index
        .read_tree(&repo.find_tree(parent_tree).map_err(crate::map_git_err)?)
        .map_err(crate::map_git_err)?;
    for file in &manifest.files {
        let prior = live_index.get_path(Path::new(&file.path), 0);
        index_before.push(IndexBefore {
            path: file.path.clone(),
            object: prior.as_ref().map(|entry| entry.id.to_string()),
            mode: prior.map(|entry| entry.mode),
        });
        if let Some((object, mode)) = selected_blob(&repo, &sealed, file)? {
            index
                .add(&index_entry(&file.path, object, mode, file.length))
                .map_err(crate::map_git_err)?;
        } else if index.get_path(Path::new(&file.path), 0).is_some() {
            index
                .remove_path(Path::new(&file.path))
                .map_err(crate::map_git_err)?;
        }
    }
    let tree = index.write_tree_to(&repo).map_err(crate::map_git_err)?;
    let mut names = BTreeSet::new();
    for entry in index.iter() {
        let path = std::str::from_utf8(&entry.path)
            .map_err(|_| invalid("native record paths must be UTF-8"))?;
        if !crate::checkpoint::safe_relative_path(path) {
            return Err(invalid("native record has an unsafe path"));
        }
        if cfg!(any(target_os = "macos", windows)) && !names.insert(path.to_lowercase()) {
            return Err(invalid("native record has case-colliding paths"));
        }
    }
    if tree == parent_tree {
        return Err(invalid("frozen selection has no authored changes"));
    }
    let author = git2::Signature::new(
        &metadata.author_name,
        &metadata.author_email,
        &git2::Time::new(metadata.timestamp_seconds, metadata.timezone_offset_minutes),
    )
    .map_err(crate::map_git_err)?;
    let parent_commit = parent
        .map(|id| repo.find_commit(id))
        .transpose()
        .map_err(crate::map_git_err)?;
    let raw = repo
        .commit_create_buffer(
            &author,
            &author,
            &commit_message(selection, metadata)?,
            &repo.find_tree(tree).map_err(crate::map_git_err)?,
            &parent_commit.iter().collect::<Vec<_>>(),
        )
        .map_err(crate::map_git_err)?;
    let commit = Oid::hash_object(ObjectType::Commit, &raw).map_err(crate::map_git_err)?;
    let commit_bytes = std::str::from_utf8(&raw)
        .map_err(|_| invalid("prepared Git commit encoding is not UTF-8"))?
        .to_string();
    let mut objects = BTreeSet::new();
    changed_objects(&repo, Some(parent_tree), tree, &mut objects)?;
    let base = canonical_directory(spool_directory)?;
    let spool = tempfile::Builder::new()
        .prefix("git-record-")
        .tempdir_in(&base)
        .map_err(|error| io(&error))?;
    let mut builder = repo.packbuilder().map_err(crate::map_git_err)?;
    builder.set_threads(1);
    for object in &objects {
        builder
            .insert_object(*object, None)
            .map_err(crate::map_git_err)?;
    }
    let mut pack = create_file(&spool.path().join(PACK))?;
    let mut write_error = None;
    let streamed = builder.foreach(|chunk| match pack.write_all(chunk) {
        Ok(()) => true,
        Err(error) => {
            write_error = Some(error);
            false
        }
    });
    if let Some(error) = write_error {
        return Err(io(&error));
    }
    streamed.map_err(crate::map_git_err)?;
    pack.sync_all().map_err(|error| io(&error))?;
    drop(pack);
    let (pack_digest, pack_length) = digest_reader(&mut read_file(&spool.path().join(PACK))?)?;
    let envelope = Envelope {
        format_version: VERSION,
        binding: selection.binding.clone(),
        metadata: metadata.clone(),
        selection_id: selection.selection_id.clone(),
        selection_manifest: selection.manifest.clone(),
        before: selection.source_state.clone(),
        reference: target_reference,
        commit: vcs::GitCommitId::from_string(commit.to_string()),
        tree: vcs::GitTreeId::from_string(tree.to_string()),
        commit_bytes,
        objects: objects
            .into_iter()
            .map(|id| vcs::GitObjectId::from_string(id.to_string()))
            .collect(),
        index_before,
        pack_digest,
        pack_length,
    };
    let bytes = json_bytes(&envelope)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST {
        return Err(invalid(
            "prepared record envelope exceeds its retained byte budget",
        ));
    }
    let mut output = create_file(&spool.path().join(ENVELOPE))?;
    output.write_all(&bytes).map_err(|error| io(&error))?;
    output.sync_all().map_err(|error| io(&error))?;
    sync_directory(spool.path())?;
    let path = spool.keep();
    sync_directory(&base)?;
    Ok(vcs::PreparedRecord {
        operation_id: metadata.operation_id.clone(),
        binding: selection.binding.clone(),
        selection_id: selection.selection_id.clone(),
        change: super::change_ref(&selection.binding, commit.to_string()),
        envelope_digest: content_digest(&bytes),
        envelope_length: u64::try_from(bytes.len())
            .map_err(|_| invalid("record envelope length overflow"))?,
        spool_path: path.join(ENVELOPE),
    })
}

fn sync_objects(
    repo: &Repository,
    pack: Oid,
    objects: impl IntoIterator<Item = Oid>,
) -> vcs::VcsResult<()> {
    let object_root = repo.commondir().join("objects");
    let mut directories = BTreeSet::new();
    for object in objects {
        let object = object.to_string();
        let directory = object_root.join(&object[..2]);
        let path = directory.join(&object[2..]);
        if path.try_exists().map_err(|error| io(&error))? {
            read_file(&path)?.sync_all().map_err(|error| io(&error))?;
            directories.insert(directory);
        }
    }
    let pack_directory = object_root.join("pack");
    for extension in ["pack", "idx"] {
        let path = pack_directory.join(format!("pack-{pack}.{extension}"));
        if path.try_exists().map_err(|error| io(&error))? {
            read_file(&path)?.sync_all().map_err(|error| io(&error))?;
            directories.insert(pack_directory.clone());
        }
    }
    for directory in directories {
        sync_directory(&directory)?;
    }
    sync_directory(&object_root)
}

fn import_objects(repo: &Repository, envelope: &Envelope, pack_path: &Path) -> vcs::VcsResult<Oid> {
    let mut pack = read_file(pack_path)?;
    let (digest, length) = digest_reader(&mut pack)?;
    if digest != envelope.pack_digest || length != envelope.pack_length || length < 32 {
        return Err(invalid(
            "prepared object pack no longer matches retained bytes",
        ));
    }
    pack.seek(SeekFrom::End(-20)).map_err(|error| io(&error))?;
    let mut trailer = [0u8; 20];
    pack.read_exact(&mut trailer).map_err(|error| io(&error))?;
    let pack_id = Oid::from_bytes(&trailer).map_err(crate::map_git_err)?;
    pack.rewind().map_err(|error| io(&error))?;
    let odb = repo.odb().map_err(crate::map_git_err)?;
    let mut writer = odb.packwriter().map_err(crate::map_git_err)?;
    let mut hash = Sha256::new();
    let mut actual_length = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = pack.read(&mut buffer).map_err(|error| io(&error))?;
        if count == 0 {
            break;
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| io(&error))?;
        hash.update(&buffer[..count]);
        actual_length = actual_length
            .checked_add(u64::try_from(count).map_err(|_| invalid("object pack length overflow"))?)
            .ok_or_else(|| invalid("object pack length overflow"))?;
    }
    let actual_digest = hex_digest(&hash.finalize());
    if actual_digest != envelope.pack_digest || actual_length != length {
        return Err(invalid("prepared object pack changed during admission"));
    }
    writer.commit().map_err(crate::map_git_err)?;
    let commit = odb
        .write(ObjectType::Commit, envelope.commit_bytes.as_bytes())
        .map_err(crate::map_git_err)?;
    if commit != object_id(envelope.commit.as_str())? {
        return Err(invalid(
            "prepared commit bytes have a different Git identity",
        ));
    }
    let objects = envelope
        .objects
        .iter()
        .map(|object| object_id(object.as_str()))
        .collect::<vcs::VcsResult<Vec<_>>>()?;
    for object in &objects {
        if !odb.exists(*object) {
            return Err(invalid("prepared object closure is incomplete"));
        }
    }
    sync_objects(repo, pack_id, objects.into_iter().chain([commit]))?;
    Ok(commit)
}

fn refresh_index(
    repo: &Repository,
    tree: Oid,
    before: &[IndexBefore],
) -> vcs::VcsResult<Option<String>> {
    let mut index = repo.index().map_err(crate::map_git_err)?;
    let tree = repo.find_tree(tree).map_err(crate::map_git_err)?;
    let mut changed = false;
    let mut retained = Vec::new();
    for prior in before {
        let path = Path::new(&prior.path);
        let current = index.get_path(path, 0);
        let desired = match tree.get_path(path) {
            Ok(entry) => Some((entry.id(), entry.filemode().cast_unsigned())),
            Err(error) if error.code() == git2::ErrorCode::NotFound => None,
            Err(error) => return Err(crate::map_git_err(error).into()),
        };
        let current_id = current.as_ref().map(|entry| (entry.id, entry.mode));
        if current_id == desired {
            continue;
        }
        let prior_id = prior
            .object
            .as_ref()
            .zip(prior.mode)
            .map(|(id, mode)| object_id(id).map(|id| (id, mode)))
            .transpose()?;
        if current_id != prior_id {
            retained.push(prior.path.clone());
            continue;
        }
        match desired {
            Some((object, mode)) => index
                .add(&index_entry(&prior.path, object, mode, 0))
                .map_err(crate::map_git_err)?,
            None if current.is_some() => index.remove_path(path).map_err(crate::map_git_err)?,
            None => {}
        }
        changed = true;
    }
    if changed {
        index.write().map_err(crate::map_git_err)?;
        if let Some(path) = index.path() {
            read_file(path)?.sync_all().map_err(|error| io(&error))?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
        }
    }
    Ok((!retained.is_empty()).then(|| {
        format!(
            "current selections were retained for paths changed after preparation: {}",
            retained.join(", ")
        )
    }))
}

pub(super) fn sync_reference(repo: &Repository, reference: &str) -> vcs::VcsResult<()> {
    let base = if reference == "HEAD" {
        repo.path()
    } else {
        repo.commondir()
    };
    let path = base.join(reference);
    read_file(&path)?.sync_all().map_err(|error| io(&error))?;
    let mut directory = path.parent();
    while let Some(current) = directory {
        sync_directory(current)?;
        if current == base {
            break;
        }
        directory = current.parent();
    }
    Ok(())
}

pub(super) fn admit_record(
    root: &vcs::RootBinding,
    record: &vcs::PreparedRecord,
    expected_state: &vcs::NativeStateRef,
) -> vcs::VcsResult<vcs::NativeReceipt> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "admitRecord",
            kind: vcs::VcsKind::Git,
        });
    }
    if root != &record.binding {
        return Err(vcs::VcsError::Stale {
            reason: "prepared record belongs to a replaced root binding".into(),
        });
    }
    let source = git_root(root, "admitRecord")?;
    let expected_commit = git_change(root, &record.change, "admitRecord")?;
    let bytes = bounded_read(&record.spool_path)?;
    if content_digest(&bytes) != record.envelope_digest
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != record.envelope_length
    {
        return Err(invalid("prepared envelope digest or length changed"));
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid prepared envelope: {error}")))?;
    if envelope.format_version != VERSION
        || envelope.binding != *root
        || envelope.metadata.operation_id != record.operation_id
        || envelope.selection_id != record.selection_id
        || envelope.before != *expected_state
        || envelope.commit.as_str() != expected_commit
        || json_bytes(&envelope)? != bytes
    {
        return Err(invalid(
            "prepared envelope does not match its retained command identity",
        ));
    }
    if envelope.reference != "HEAD"
        && (!envelope.reference.starts_with("refs/heads/")
            || !git2::Reference::is_valid_name(&envelope.reference))
    {
        return Err(invalid("prepared target reference is invalid"));
    }
    let repo = Repository::open(source).map_err(crate::map_git_err)?;
    let (parent, _) = verify_state(&repo, &root.repository_id, expected_state)?;
    let spool = canonical_directory(
        record
            .spool_path
            .parent()
            .ok_or_else(|| invalid("prepared envelope has no spool directory"))?,
    )?;
    let commit = import_objects(&repo, &envelope, &spool.join(PACK))?;
    let object = repo.find_commit(commit).map_err(crate::map_git_err)?;
    let tree = object_id(envelope.tree.as_str())?;
    if object.tree_id() != tree
        || object.parent_count() != usize::from(parent.is_some())
        || parent.is_some_and(|parent| object.parent_id(0).ok() != Some(parent))
    {
        return Err(invalid(
            "prepared commit does not preserve the exact parent and tree",
        ));
    }
    let after = vcs::NativeStateRef::Git {
        repository_id: root.repository_id.clone(),
        commit: Some(envelope.commit.clone()),
        tree: envelope.tree.clone(),
    };
    let mut transaction = repo.transaction().map_err(crate::map_git_err)?;
    transaction.lock_ref("HEAD").map_err(crate::map_git_err)?;
    if envelope.reference != "HEAD" {
        transaction
            .lock_ref(&envelope.reference)
            .map_err(crate::map_git_err)?;
    }
    let already_applied = repo
        .find_reference(&envelope.reference)
        .ok()
        .and_then(|reference| reference.target())
        == Some(commit);
    let active_reference = reference(&repo)?;
    if !already_applied
        && (active_reference != envelope.reference
            || GitWorkspaceEngine::default().recorded_state(root)? != *expected_state)
    {
        return Err(vcs::VcsError::Stale {
            reason: "recorded state or active reference advanced before admission".into(),
        });
    }
    let mut post_commit_errors = Vec::new();
    if already_applied {
        drop(transaction);
    } else {
        let signature = git2::Signature::new(
            &envelope.metadata.author_name,
            &envelope.metadata.author_email,
            &git2::Time::new(
                envelope.metadata.timestamp_seconds,
                envelope.metadata.timezone_offset_minutes,
            ),
        )
        .map_err(crate::map_git_err)?;
        transaction
            .set_target(
                &envelope.reference,
                commit,
                Some(&signature),
                "Intent: admit exact prepared record",
            )
            .map_err(crate::map_git_err)?;
        if let Err(error) = transaction.commit() {
            if repo
                .find_reference(&envelope.reference)
                .ok()
                .and_then(|reference| reference.target())
                != Some(commit)
            {
                return Err(vcs::VcsError::Uncertain {
                    operation_id: record.operation_id.clone(),
                    reason: format!("reference write outcome requires reconciliation: {error}"),
                });
            }
            post_commit_errors.push(format!(
                "reference advanced but the write reported an error: {error}"
            ));
        }
    }
    if let Err(error) = sync_reference(&repo, &envelope.reference) {
        post_commit_errors.push(error.to_string());
    }
    if active_reference == envelope.reference {
        match refresh_index(&repo, tree, &envelope.index_before) {
            Ok(Some(error)) => post_commit_errors.push(error),
            Ok(None) => {}
            Err(error) => post_commit_errors.push(error.to_string()),
        }
    } else {
        post_commit_errors.push("record already landed; active reference changed, so the current index was left untouched".into());
    }
    Ok(vcs::NativeReceipt {
        operation_id: record.operation_id.clone(),
        change: record.change.clone(),
        before: expected_state.clone(),
        after,
        target_reference: Some(envelope.reference),
        post_commit_error: (!post_commit_errors.is_empty()).then(|| post_commit_errors.join("; ")),
        replayed: already_applied,
    })
}
