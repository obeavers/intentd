//! Verified Git object closure and private materialization. Receipts contain
//! content identities, never a claim inferred from the presence of a directory.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid, Repository};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{content_digest, empty_tree_id, git_root, hex_digest, json_bytes, vcs};

const FORMAT_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const PACK_FILE: &str = "objects.pack";
const MANIFEST_FILE: &str = "closure.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileEntry {
    path: String,
    mode: u32,
    digest: vcs::ContentDigest,
    length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Materialization {
    format_version: u32,
    materializer: String,
    file_policy_version: u32,
    files: Vec<FileEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Closure {
    format_version: u32,
    operation_id: vcs::OperationId,
    state: vcs::NativeStateRef,
    changes: Vec<vcs::NativeChangeRef>,
    materialization: Materialization,
    pack_digest: vcs::ContentDigest,
    pack_length: u64,
}

pub(super) fn invalid(reason: impl Into<String>) -> vcs::VcsError {
    vcs::VcsError::InvalidInput {
        reason: reason.into(),
    }
}

pub(super) fn io(error: &std::io::Error) -> vcs::VcsError {
    intent_core::Error::Internal(format!("Git immutable storage: {error}")).into()
}

pub(super) fn object_id(value: &str) -> vcs::VcsResult<Oid> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "immutable Git state requires canonical full SHA-1 identifiers",
        ));
    }
    Oid::from_str(value)
        .map_err(crate::map_git_err)
        .map_err(Into::into)
}

fn state_objects(
    root: &vcs::RootBinding,
    state: &vcs::NativeStateRef,
) -> vcs::VcsResult<(Repository, Option<Oid>, Oid)> {
    let source = git_root(root, "immutableStorage")?;
    let repo = Repository::open(source).map_err(crate::map_git_err)?;
    let (commit, tree) = verify_state(&repo, &root.repository_id, state)?;
    Ok((repo, commit, tree))
}

pub(super) fn verify_state(
    repo: &Repository,
    expected_repository: &vcs::RepositoryId,
    state: &vcs::NativeStateRef,
) -> vcs::VcsResult<(Option<Oid>, Oid)> {
    let vcs::NativeStateRef::Git {
        repository_id,
        commit,
        tree,
    } = state
    else {
        return Err(invalid("Git operation received a non-Git state"));
    };
    if repository_id != expected_repository {
        return Err(invalid("native state belongs to another repository"));
    }
    let tree = object_id(tree.as_str())?;
    let commit = match commit {
        Some(commit) => {
            let id = object_id(commit.as_str())?;
            if repo.find_commit(id).map_err(crate::map_git_err)?.tree_id() != tree {
                return Err(invalid("Git state commit and tree do not match"));
            }
            Some(id)
        }
        None if tree == empty_tree_id()? => {
            // recorded_state does not mutate the ODB. Bulk operations may retain
            // this immutable object without creating an authored commit.
            repo.odb()
                .map_err(crate::map_git_err)?
                .write(ObjectType::Tree, &[])
                .map_err(crate::map_git_err)?;
            None
        }
        None => {
            return Err(invalid(
                "unborn Git state must name the canonical empty tree",
            ))
        }
    };
    repo.find_tree(tree).map_err(crate::map_git_err)?;
    Ok((commit, tree))
}

fn file_manifest(repo: &Repository, tree: Oid) -> vcs::VcsResult<Materialization> {
    let mut index = git2::Index::new().map_err(crate::map_git_err)?;
    index
        .read_tree(&repo.find_tree(tree).map_err(crate::map_git_err)?)
        .map_err(crate::map_git_err)?;
    let mut files = Vec::new();
    let mut folded = HashSet::new();
    for entry in index.iter() {
        let path = std::str::from_utf8(&entry.path)
            .map_err(|_| invalid("materialization paths must be UTF-8"))?;
        if !crate::checkpoint::safe_relative_path(path)
            || crate::checkpoint::excluded(
                Path::new(path),
                &crate::checkpoint::CaptureOptions::default(),
            )
        {
            return Err(invalid("unsafe or runtime-owned path in materialization"));
        }
        if cfg!(any(target_os = "macos", windows)) && !folded.insert(path.to_lowercase()) {
            return Err(invalid("case-colliding materialization paths"));
        }
        if !matches!(entry.mode, 0o100_644 | 0o100_755 | 0o120_000) {
            return Err(invalid("materialization requires separately retained submodule roots or a supported file kind"));
        }
        let blob = repo.find_blob(entry.id).map_err(crate::map_git_err)?;
        files.push(FileEntry {
            path: path.into(),
            mode: entry.mode,
            digest: content_digest(blob.content()),
            length: u64::try_from(blob.size())
                .map_err(|_| invalid("blob length exceeds the manifest format"))?,
        });
    }
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    Ok(Materialization {
        format_version: FORMAT_VERSION,
        materializer: "intent-git-v1".into(),
        file_policy_version: 1,
        files,
    })
}

pub(super) fn canonical_directory(path: &Path) -> vcs::VcsResult<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io(&error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("storage parent must be a real directory"));
    }
    std::fs::canonicalize(path).map_err(|error| io(&error))
}

fn new_destination(path: &Path) -> vcs::VcsResult<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("private destination needs a final directory name"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("private destination needs a parent directory"))?;
    Ok(canonical_directory(parent)?.join(name))
}

fn create_directory(path: &Path) -> vcs::VcsResult<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| io(&error))
}

pub(super) fn create_file(path: &Path) -> vcs::VcsResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| io(&error))
}

pub(super) fn read_file(path: &Path) -> vcs::VcsResult<File> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io(&error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "immutable storage file must be regular and not a symlink",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|error| io(&error))
}

pub(super) fn sync_directory(path: &Path) -> vcs::VcsResult<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    options
        .open(path)
        .map_err(|error| io(&error))?
        .sync_all()
        .map_err(|error| io(&error))
}

pub(super) fn sync_tree(root: &Path) -> vcs::VcsResult<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        for entry in std::fs::read_dir(&directories[cursor]).map_err(|error| io(&error))? {
            let entry = entry.map_err(|error| io(&error))?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| io(&error))?;
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                read_file(&entry.path())?
                    .sync_all()
                    .map_err(|error| io(&error))?;
            } else if !metadata.file_type().is_symlink() {
                return Err(invalid("unsupported file in private checkout"));
            }
        }
        cursor += 1;
    }
    for directory in directories.into_iter().rev() {
        sync_directory(&directory)?;
    }
    Ok(())
}

pub(super) fn initialize(destination: &Path) -> vcs::VcsResult<Repository> {
    let mut options = git2::RepositoryInitOptions::new();
    options.external_template(false).no_reinit(true);
    Repository::init_opts(destination, &options)
        .map_err(crate::map_git_err)
        .map_err(Into::into)
}

pub(super) fn commit_closure(repo: &Repository, head: Option<Oid>) -> vcs::VcsResult<Vec<Oid>> {
    let mut pending: Vec<_> = head.into_iter().collect();
    let mut seen = HashSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let commit = repo.find_commit(id).map_err(crate::map_git_err)?;
        pending.extend(commit.parent_ids());
    }
    let mut commits: Vec<_> = seen.into_iter().collect();
    commits.sort();
    Ok(commits)
}

pub(super) fn digest_reader(reader: &mut impl Read) -> vcs::VcsResult<(vcs::ContentDigest, u64)> {
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = reader.read(&mut buffer).map_err(|error| io(&error))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        length = length
            .checked_add(u64::try_from(count).map_err(|_| invalid("file length overflow"))?)
            .ok_or_else(|| invalid("file length overflow"))?;
    }
    Ok((hex_digest(&hash.finalize()), length))
}

fn verify_working_files(
    destination: &Path,
    expected: &Materialization,
    generated: &[String],
) -> vcs::VcsResult<()> {
    if generated.len() > 256 {
        return Err(invalid("too many generated output roots"));
    }
    let normalized = |value: &str| {
        if cfg!(any(target_os = "macos", windows)) {
            value.to_lowercase()
        } else {
            value.to_string()
        }
    };
    for path in generated {
        if !path.is_ascii()
            || !crate::checkpoint::safe_relative_path(path)
            || expected.files.iter().any(|file| {
                let file = normalized(&file.path);
                let path = normalized(path);
                file == path || file.starts_with(&(path + "/"))
            })
        {
            return Err(invalid("generated output roots must be canonical ASCII paths outside the authored file tree"));
        }
    }
    let mut actual = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let directory = destination.join(&relative);
        for entry in std::fs::read_dir(&directory).map_err(|error| io(&error))? {
            let entry = entry.map_err(|error| io(&error))?;
            if relative.as_os_str().is_empty() && entry.file_name() == ".git" {
                continue;
            }
            let path = relative.join(entry.file_name());
            let relative_name = path
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 materialized path"))?
                .replace('\\', "/");
            if generated.iter().any(|root| {
                let path = normalized(&relative_name);
                let root = normalized(root);
                path == root || path.starts_with(&(root + "/"))
            }) {
                continue;
            }
            let full = destination.join(&path);
            let metadata = std::fs::symlink_metadata(&full).map_err(|error| io(&error))?;
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            let path = path
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 materialized path"))?
                .replace('\\', "/");
            let (mode, digest, length) = if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(&full).map_err(|error| io(&error))?;
                let bytes = target.as_os_str().as_encoded_bytes();
                (
                    0o120_000,
                    content_digest(bytes),
                    u64::try_from(bytes.len()).map_err(|_| invalid("symlink length overflow"))?,
                )
            } else if metadata.is_file() {
                let mut file = read_file(&full)?;
                let (digest, length) = digest_reader(&mut file)?;
                file.sync_all().map_err(|error| io(&error))?;
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o111 == 0 {
                        0o100_644
                    } else {
                        0o100_755
                    }
                };
                #[cfg(not(unix))]
                let mode = expected
                    .files
                    .iter()
                    .find(|entry| entry.path == path)
                    .map_or(0o100_644, |entry| entry.mode);
                (mode, digest, length)
            } else {
                return Err(invalid("unsupported materialized file kind"));
            };
            actual.push(FileEntry {
                path,
                mode,
                digest,
                length,
            });
        }
        sync_directory(&directory)?;
    }
    actual.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    if actual != expected.files {
        return Err(invalid(
            "materialized file tree does not match its canonical manifest",
        ));
    }
    Ok(())
}

fn checkout(repo: &Repository, head: Option<Oid>, tree: Oid) -> vcs::VcsResult<()> {
    let tree = repo.find_tree(tree).map_err(crate::map_git_err)?;
    let mut options = git2::build::CheckoutBuilder::new();
    options.force().disable_filters(true);
    repo.checkout_tree(tree.as_object(), Some(&mut options))
        .map_err(crate::map_git_err)?;
    let mut index = repo.index().map_err(crate::map_git_err)?;
    index.read_tree(&tree).map_err(crate::map_git_err)?;
    index.write().map_err(crate::map_git_err)?;
    if let Some(head) = head {
        repo.set_head_detached(head).map_err(crate::map_git_err)?;
    }
    Ok(())
}

pub(super) fn materialize(
    root: &vcs::RootBinding,
    state: &vcs::NativeStateRef,
    destination: &Path,
) -> vcs::VcsResult<vcs::MaterializationReceipt> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "materialize",
            kind: vcs::VcsKind::Git,
        });
    }
    let (source, head, tree) = state_objects(root, state)?;
    materialize_objects(&source, head, tree, state, destination)
}

pub(super) fn materialize_objects(
    source: &Repository,
    head: Option<Oid>,
    tree: Oid,
    state: &vcs::NativeStateRef,
    destination: &Path,
) -> vcs::VcsResult<vcs::MaterializationReceipt> {
    let manifest = file_manifest(source, tree)?;
    let materialization_id =
        vcs::MaterializationId::from_string(content_digest(&json_bytes(&manifest)?).as_str());
    let destination = new_destination(destination)?;
    create_directory(&destination)?;
    let result = (|| {
        let target = initialize(&destination)?;
        crate::checkpoint::copy_objects(source, &target, &[head.unwrap_or(tree)])?;
        checkout(&target, head, tree)?;
        verify_working_files(&destination, &manifest, &[])?;
        sync_tree(&destination)?;
        sync_directory(
            destination
                .parent()
                .ok_or_else(|| invalid("destination parent disappeared"))?,
        )?;
        Ok(vcs::MaterializationReceipt {
            state: state.clone(),
            materialization_id,
            destination: destination.clone(),
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&destination);
    }
    result
}

pub(super) fn verify_materialization(
    receipt: &vcs::MaterializationReceipt,
    generated: &[String],
) -> vcs::VcsResult<()> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "verifyMaterialization",
            kind: vcs::VcsKind::Git,
        });
    }
    let path = canonical_directory(&receipt.destination)?;
    let administration = canonical_directory(&path.join(".git"))?;
    let repo = Repository::open(&path).map_err(crate::map_git_err)?;
    if canonical_directory(repo.path())? != administration
        || canonical_directory(repo.commondir())? != administration
    {
        return Err(invalid(
            "private materialization cannot redirect Git administration outside its owned checkout",
        ));
    }
    let (head, tree) = verify_state(&repo, receipt.state.repository_id(), &receipt.state)?;
    match repo.head() {
        Ok(reference)
            if Some(reference.peel_to_commit().map_err(crate::map_git_err)?.id()) == head => {}
        Err(error) if head.is_none() && error.code() == git2::ErrorCode::UnbornBranch => {}
        _ => return Err(invalid("private materialization's recorded HEAD changed")),
    }
    let mut index = repo.index().map_err(crate::map_git_err)?;
    if index.has_conflicts() || index.write_tree().map_err(crate::map_git_err)? != tree {
        return Err(invalid("private materialization's selection/index changed"));
    }
    let manifest = file_manifest(&repo, tree)?;
    if vcs::MaterializationId::from_string(content_digest(&json_bytes(&manifest)?).as_str())
        != receipt.materialization_id
    {
        return Err(invalid(
            "private materialization identity differs from its receipt",
        ));
    }
    verify_working_files(&path, &manifest, generated)
}

pub(super) fn copy_materialization(
    receipt: &vcs::MaterializationReceipt,
    destination: &Path,
) -> vcs::VcsResult<vcs::MaterializationReceipt> {
    verify_materialization(receipt, &[])?;
    let repo = Repository::open(&receipt.destination).map_err(crate::map_git_err)?;
    let (head, tree) = verify_state(&repo, receipt.state.repository_id(), &receipt.state)?;
    let copied = materialize_objects(&repo, head, tree, &receipt.state, destination)?;
    if copied.materialization_id != receipt.materialization_id {
        return Err(invalid("copied materialization changed identity"));
    }
    Ok(copied)
}

pub(super) fn export_closure(
    root: &vcs::RootBinding,
    state: &vcs::NativeStateRef,
    grant: &vcs::RetentionGrant,
    spool_directory: &Path,
) -> vcs::VcsResult<vcs::NativeClosureManifest> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "exportClosure",
            kind: vcs::VcsKind::Git,
        });
    }
    if grant.repository_id != root.repository_id || grant.binding_epoch != root.epoch {
        return Err(vcs::VcsError::Stale {
            reason: "closure retention grant belongs to another repository or root epoch".into(),
        });
    }
    let (repo, head, tree) = state_objects(root, state)?;
    export_objects(&repo, root, state, head, tree, grant, spool_directory)
}

/// Export an explicitly supplied backend-owned private repository without
/// fabricating a durable `RootBinding` for its temporary locator.
pub(super) fn export_objects(
    repo: &Repository,
    root: &vcs::RootBinding,
    state: &vcs::NativeStateRef,
    head: Option<Oid>,
    tree: Oid,
    grant: &vcs::RetentionGrant,
    spool_directory: &Path,
) -> vcs::VcsResult<vcs::NativeClosureManifest> {
    if grant.repository_id != root.repository_id || grant.binding_epoch != root.epoch {
        return Err(vcs::VcsError::Stale {
            reason: "private export belongs to another root epoch".into(),
        });
    }
    if verify_state(repo, &root.repository_id, state)? != (head, tree) {
        return Err(invalid(
            "private export state differs from its actual objects",
        ));
    }
    let materialization = file_manifest(repo, tree)?;
    let base = canonical_directory(spool_directory)?;
    let spool = tempfile::Builder::new()
        .prefix("git-closure-")
        .tempdir_in(&base)
        .map_err(|error| io(&error))?;
    let mut builder = repo.packbuilder().map_err(crate::map_git_err)?;
    builder.set_threads(1);
    let mut changes = Vec::new();
    if head.is_some() {
        for id in commit_closure(repo, head)? {
            builder.insert_commit(id).map_err(crate::map_git_err)?;
            changes.push(super::change_ref(root, id.to_string()));
        }
    } else {
        builder.insert_tree(tree).map_err(crate::map_git_err)?;
    }
    let mut pack = create_file(&spool.path().join(PACK_FILE))?;
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
    let (pack_digest, pack_length) = digest_reader(&mut read_file(&spool.path().join(PACK_FILE))?)?;
    let closure = Closure {
        format_version: FORMAT_VERSION,
        operation_id: grant.operation_id.clone(),
        state: state.clone(),
        changes: changes.clone(),
        materialization,
        pack_digest,
        pack_length,
    };
    let bytes = json_bytes(&closure)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "closure manifest exceeds the retained manifest budget",
        ));
    }
    let mut manifest = create_file(&spool.path().join(MANIFEST_FILE))?;
    manifest.write_all(&bytes).map_err(|error| io(&error))?;
    manifest.sync_all().map_err(|error| io(&error))?;
    sync_directory(spool.path())?;
    let retained = spool.keep();
    sync_directory(&base)?;
    Ok(vcs::NativeClosureManifest {
        state: state.clone(),
        changes,
        manifest_digest: content_digest(&bytes),
        spool_path: retained.join(MANIFEST_FILE),
    })
}

fn read_closure(manifest: &vcs::NativeClosureManifest) -> vcs::VcsResult<(Closure, File)> {
    let mut input = read_file(&manifest.spool_path)?;
    if input.metadata().map_err(|error| io(&error))?.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "closure manifest exceeds the retained manifest budget",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io(&error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "closure manifest grew beyond its retained byte budget",
        ));
    }
    if content_digest(&bytes) != manifest.manifest_digest {
        return Err(invalid(
            "closure manifest digest does not match retained bytes",
        ));
    }
    let closure: Closure = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid closure manifest: {error}")))?;
    if closure.format_version != FORMAT_VERSION
        || closure.state != manifest.state
        || closure.changes != manifest.changes
        || json_bytes(&closure)? != bytes
    {
        return Err(invalid(
            "closure manifest identity or canonical encoding mismatch",
        ));
    }
    let parent = manifest
        .spool_path
        .parent()
        .ok_or_else(|| invalid("closure manifest has no spool directory"))?;
    let parent = canonical_directory(parent)?;
    let mut pack = read_file(&parent.join(PACK_FILE))?;
    let (digest, length) = digest_reader(&mut pack)?;
    if digest != closure.pack_digest || length != closure.pack_length {
        return Err(invalid("closure object pack digest or length mismatch"));
    }
    pack.rewind().map_err(|error| io(&error))?;
    Ok((closure, pack))
}

pub(super) fn verify_closure(manifest: &vcs::NativeClosureManifest) -> vcs::VcsResult<()> {
    read_closure(manifest).map(|_| ())
}

pub(super) fn restore_closure(
    manifest: &vcs::NativeClosureManifest,
    destination: &Path,
) -> vcs::VcsResult<vcs::RestoreReceipt> {
    if !cfg!(unix) {
        return Err(vcs::VcsError::Unsupported {
            operation: "restoreClosure",
            kind: vcs::VcsKind::Git,
        });
    }
    let (closure, mut pack) = read_closure(manifest)?;
    let vcs::NativeStateRef::Git {
        repository_id,
        commit,
        tree,
    } = &closure.state
    else {
        return Err(invalid("cannot restore a non-Git closure"));
    };
    let head = commit
        .as_ref()
        .map(|commit| object_id(commit.as_str()))
        .transpose()?;
    let tree = object_id(tree.as_str())?;
    if head.is_none() && tree != empty_tree_id()? {
        return Err(invalid("unborn closure has a nonempty recorded state"));
    }
    let destination = new_destination(destination)?;
    create_directory(&destination)?;
    let result = (|| {
        let target = initialize(&destination)?;
        let odb = target.odb().map_err(crate::map_git_err)?;
        let mut writer = odb.packwriter().map_err(crate::map_git_err)?;
        let mut hash = Sha256::new();
        let mut imported_length = 0u64;
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
            imported_length = imported_length
                .checked_add(u64::try_from(count).map_err(|_| invalid("pack length overflow"))?)
                .ok_or_else(|| invalid("pack length overflow"))?;
        }
        let imported_digest = hex_digest(&hash.finalize());
        if imported_length != closure.pack_length || imported_digest != closure.pack_digest {
            return Err(invalid("closure pack changed during restore"));
        }
        writer.commit().map_err(crate::map_git_err)?;
        let (verified_head, verified_tree) = verify_state(&target, repository_id, &closure.state)?;
        if verified_head != head
            || verified_tree != tree
            || file_manifest(&target, tree)? != closure.materialization
        {
            return Err(invalid(
                "restored object graph does not match the materialization manifest",
            ));
        }
        let mut actual_changes = Vec::new();
        if head.is_some() {
            for id in commit_closure(&target, head)? {
                actual_changes.push(vcs::NativeChangeRef::Git {
                    repository_id: repository_id.clone(),
                    commit: vcs::GitCommitId::from_string(id.to_string()),
                });
            }
        }
        if actual_changes != closure.changes {
            return Err(invalid("restored commit closure membership mismatch"));
        }
        checkout(&target, head, tree)?;
        verify_working_files(&destination, &closure.materialization, &[])?;
        sync_tree(&destination)?;
        sync_directory(
            destination
                .parent()
                .ok_or_else(|| invalid("destination parent disappeared"))?,
        )?;
        Ok(vcs::RestoreReceipt {
            state: closure.state.clone(),
            materialization_id: vcs::MaterializationId::from_string(
                content_digest(&json_bytes(&closure.materialization)?).as_str(),
            ),
            destination: destination.clone(),
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&destination);
    }
    result
}
