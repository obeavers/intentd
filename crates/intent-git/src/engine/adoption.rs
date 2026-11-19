//! Journaled clean-target Git adoption. The actual service barrier and accepted
//! Store decision are mandatory. Existing file inodes remain retained after an
//! atomic exchange; unexpected concurrent bytes produce uncertainty, not rollback.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use git2::{Oid, Repository};
use serde::{Deserialize, Serialize};

use super::{
    composition, content_digest, empty_tree_id, git_root, json_bytes, recording, storage, vcs,
};
use vcs::WorkspaceEngine;

mod fs;
mod observation;
#[cfg(test)]
mod tests;

const VERSION: u32 = 1;
const MAX_METADATA: u64 = 8 * 1024 * 1024;
const MAX_BLOB: usize = 64 * 1024 * 1024;
const MAX_FILES: usize = 20_000;

fn invalid(reason: impl Into<String>) -> vcs::VcsError {
    storage::invalid(reason)
}
fn io(error: &std::io::Error) -> vcs::VcsError {
    storage::io(error)
}
fn uncertain(operation: &vcs::OperationId, reason: impl Into<String>) -> vcs::VcsError {
    vcs::VcsError::Uncertain {
        operation_id: operation.clone(),
        reason: reason.into(),
    }
}
fn stale(reason: impl Into<String>) -> vcs::VcsError {
    vcs::VcsError::Stale {
        reason: reason.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Image {
    mode: u32,
    digest: vcs::ContentDigest,
    length: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Node {
    object: vcs::GitObjectId,
    image: Image,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Physical {
    root_device: u64,
    root_inode: u64,
    git_path: PathBuf,
    git_device: u64,
    git_inode: u64,
    common_path: PathBuf,
    common_device: u64,
    common_inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    version: u32,
    exclusions: String,
    config: BTreeMap<String, Option<String>>,
    local_excludes: Option<vcs::ContentDigest>,
    global_excludes: Option<vcs::ContentDigest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    receipt: vcs::TargetCaptureReceipt,
    physical: Physical,
    policy: Policy,
    ignore_digest: vcs::ContentDigest,
    index_present: bool,
    index_digest: vcs::ContentDigest,
    index_length: u64,
    index_tree: vcs::GitTreeId,
    working_tree: vcs::GitTreeId,
    untracked: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Change {
    path: String,
    before: Option<Node>,
    after: Option<Node>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Preparation {
    receipt: vcs::AdoptionPreparationReceipt,
    capture: Capture,
    changes: Vec<Change>,
    index_after_digest: vcs::ContentDigest,
    index_after_length: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Admitted,
    Paths,
    Index,
    Reference,
    Applied,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    version: u32,
    authorization: vcs::AdoptionAuthorizationReceipt,
    phase: Phase,
    completed_paths: Vec<String>,
}

fn read(path: &Path) -> vcs::VcsResult<Vec<u8>> {
    let mut file = storage::read_file(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io(&error))?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(invalid("adoption metadata exceeds its byte budget"));
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(path: &Path) -> vcs::VcsResult<T> {
    let bytes = read(path)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if json_bytes(&value)? != bytes {
        return Err(invalid("retained adoption data is not canonical"));
    }
    Ok(value)
}
fn write(path: &Path, bytes: &[u8]) -> vcs::VcsResult<()> {
    let mut file = storage::create_file(path)?;
    file.write_all(bytes).map_err(|error| io(&error))?;
    file.sync_all().map_err(|error| io(&error))?;
    storage::sync_directory(
        path.parent()
            .ok_or_else(|| invalid("artifact has no parent"))?,
    )
}
fn replace(path: &Path, bytes: &[u8]) -> vcs::VcsResult<()> {
    if path.symlink_metadata().is_ok() {
        let _ = storage::read_file(path)?;
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("journal has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| io(&error))?;
    temporary.write_all(bytes).map_err(|error| io(&error))?;
    temporary.as_file().sync_all().map_err(|error| io(&error))?;
    temporary.persist(path).map_err(|error| io(&error.error))?;
    storage::sync_directory(parent)
}
fn private_directory(path: &Path) -> vcs::VcsResult<()> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| io(&error))
}
fn base(root: &vcs::RootBinding, path: &Path, same_device: bool) -> vcs::VcsResult<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("adoption storage must be absolute"));
    }
    if !path.try_exists().map_err(|error| io(&error))? {
        private_directory(path)?;
    }
    let path = storage::canonical_directory(path)?;
    let source = storage::canonical_directory(git_root(root, "adoption")?)?;
    let repo = Repository::open(&source).map_err(crate::map_git_err)?;
    if path.starts_with(&source)
        || path.starts_with(storage::canonical_directory(repo.commondir())?)
        || std::fs::metadata(&path)
            .map_err(|error| io(&error))?
            .permissions()
            .mode()
            & 0o077
            != 0
    {
        return Err(invalid(
            "adoption storage must be private and outside source/Git administration",
        ));
    }
    if same_device
        && std::fs::metadata(&path).map_err(|error| io(&error))?.dev()
            != std::fs::metadata(&source)
                .map_err(|error| io(&error))?
                .dev()
    {
        return Err(invalid(
            "atomic adoption requires retained preimages on the target filesystem",
        ));
    }
    Ok(path)
}
fn lock(base: &Path, key: &str) -> vcs::VcsResult<nix::fcntl::Flock<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(base.join(format!("{key}.lock")))
        .map_err(|error| io(&error))?;
    if !file.metadata().map_err(|error| io(&error))?.is_file() {
        return Err(invalid("operation lock is not regular"));
    }
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| invalid(error.to_string()))
}
fn key(
    kind: &str,
    root: &vcs::RootBinding,
    operation: &vcs::OperationId,
) -> vcs::VcsResult<String> {
    Ok(format!(
        "{kind}-{}",
        content_digest(&json_bytes(&(kind, root, operation))?).as_str()
    ))
}
fn barrier(root: &vcs::RootBinding, permit: &vcs::WriteBarrierPermit) -> vcs::VcsResult<()> {
    git_root(root, "adoption")?;
    if permit.root() != root || !permit.is_live() {
        return Err(stale("actual target write barrier is closed or foreign"));
    }
    Ok(())
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
        return Err(invalid("adoption requires local branch or detached HEAD"));
    }
    Ok(reference.into())
}
fn physical(root: &vcs::RootBinding, repo: &Repository) -> vcs::VcsResult<Physical> {
    let working = fs::directory(&root.locator)?
        .metadata()
        .map_err(|error| io(&error))?;
    let git_path = storage::canonical_directory(repo.path())?;
    let common_path = storage::canonical_directory(repo.commondir())?;
    let git = fs::directory(&git_path)?
        .metadata()
        .map_err(|error| io(&error))?;
    let common = fs::directory(&common_path)?
        .metadata()
        .map_err(|error| io(&error))?;
    Ok(Physical {
        root_device: working.dev(),
        root_inode: working.ino(),
        git_device: git.dev(),
        git_inode: git.ino(),
        git_path,
        common_device: common.dev(),
        common_inode: common.ino(),
        common_path,
    })
}
fn optional_digest(path: &Path) -> vcs::VcsResult<Option<vcs::ContentDigest>> {
    match path.symlink_metadata() {
        Ok(_) => Ok(Some(content_digest(&read(path)?))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io(&error)),
    }
}
fn policy(repo: &Repository) -> vcs::VcsResult<Policy> {
    let config = repo.config().map_err(crate::map_git_err)?;
    let mut values = BTreeMap::new();
    for name in [
        "core.ignorecase",
        "core.filemode",
        "core.symlinks",
        "core.autocrlf",
        "core.eol",
        "core.attributesfile",
        "core.excludesfile",
        "extensions.objectformat",
    ] {
        let value = match config.get_string(name) {
            Ok(value) => Some(value),
            Err(error) if error.code() == git2::ErrorCode::NotFound => None,
            Err(error) => return Err(crate::map_git_err(error).into()),
        };
        values.insert(name.to_string(), value);
    }
    if values["extensions.objectformat"]
        .as_deref()
        .is_some_and(|value| value != "sha1")
        || values["core.attributesfile"]
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || optional_digest(&repo.commondir().join("info/attributes"))?.is_some()
    {
        return Err(invalid(
            "adoption file policy does not execute attributes or alternate object formats",
        ));
    }
    let global_excludes = match values["core.excludesfile"].as_deref() {
        None | Some("") => None,
        Some(path) => {
            let path = Path::new(path);
            if !path.is_absolute() {
                return Err(invalid(
                    "relative/global-expanded ignore policy is unqualified",
                ));
            }
            optional_digest(path)?
        }
    };
    Ok(Policy {
        version: VERSION,
        exclusions:
            "checkpoint-default-exclusions-v1/safe-fd-frozen-ignore-v2/raw-bytes-no-drivers-v1"
                .into(),
        config: values,
        local_excludes: optional_digest(&repo.commondir().join("info/exclude"))?,
        global_excludes,
    })
}
fn tree_files(repo: &Repository, tree: Oid) -> vcs::VcsResult<BTreeMap<String, Node>> {
    let mut index = git2::Index::new().map_err(crate::map_git_err)?;
    index
        .read_tree(&repo.find_tree(tree).map_err(crate::map_git_err)?)
        .map_err(crate::map_git_err)?;
    if index.len() > MAX_FILES {
        return Err(invalid(
            "adoption file inventory exceeds its qualification budget",
        ));
    }
    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    for entry in index.iter() {
        let path = std::str::from_utf8(&entry.path)
            .map_err(|_| invalid("adoption paths require UTF-8"))?;
        if !crate::checkpoint::safe_relative_path(path)
            || crate::checkpoint::excluded(
                Path::new(path),
                &crate::checkpoint::CaptureOptions::default(),
            )
            || !matches!(entry.mode, 0o100_644 | 0o100_755 | 0o120_000)
            || path == ".gitattributes"
            || path.ends_with("/.gitattributes")
            || (cfg!(target_os = "macos") && !folded.insert(path.to_lowercase()))
        {
            return Err(invalid(
                "unsupported/colliding adoption path, attributes or separately owned submodule",
            ));
        }
        let blob = repo.find_blob(entry.id).map_err(crate::map_git_err)?;
        if blob.size() > MAX_BLOB {
            return Err(invalid("adoption blob exceeds its byte budget"));
        }
        files.insert(
            path.to_string(),
            Node {
                object: vcs::GitObjectId(entry.id.to_string()),
                image: Image {
                    mode: entry.mode,
                    digest: content_digest(blob.content()),
                    length: blob.size() as u64,
                },
            },
        );
    }
    Ok(files)
}
fn state(
    root: &vcs::RootBinding,
    repo: &Repository,
    head: Option<Oid>,
) -> vcs::VcsResult<vcs::NativeStateRef> {
    let tree = head
        .map(|id| repo.find_commit(id).map(|commit| commit.tree_id()))
        .transpose()
        .map_err(crate::map_git_err)?
        .unwrap_or(empty_tree_id()?);
    Ok(vcs::NativeStateRef::Git {
        repository_id: root.repository_id.clone(),
        commit: head.map(|id| vcs::GitCommitId(id.to_string())),
        tree: vcs::GitTreeId(tree.to_string()),
    })
}
fn git_ids(state: &vcs::NativeStateRef) -> vcs::VcsResult<(Option<Oid>, Oid)> {
    let vcs::NativeStateRef::Git { commit, tree, .. } = state else {
        return Err(invalid("adoption state is not Git"));
    };
    Ok((
        commit
            .as_ref()
            .map(|id| storage::object_id(id.as_str()))
            .transpose()?,
        storage::object_id(tree.as_str())?,
    ))
}
fn capture_digest(capture: &Capture) -> vcs::VcsResult<vcs::ContentDigest> {
    Ok(content_digest(&json_bytes(&(
        &capture.receipt.root,
        &capture.receipt.state,
        &capture.receipt.reference,
        &capture.physical,
        &capture.receipt.selection_digest,
        &capture.receipt.working_digest,
        &capture.receipt.policy_digest,
        &capture.untracked,
        capture.receipt.clean,
    ))?))
}
fn observe(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
) -> vcs::VcsResult<(Capture, Option<Vec<u8>>)> {
    barrier(root, permit)?;
    let repo = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    let first_physical = physical(root, &repo)?;
    let first_policy = policy(&repo)?;
    let first_reference = reference(&repo)?;
    let observation = observation::read_target(&repo, root, &first_policy)?;
    let head = observation
        .head
        .as_deref()
        .map(storage::object_id)
        .transpose()?;
    let native = state(root, &repo, head)?;
    let (_, head_tree) = git_ids(&native)?;
    let index_tree = storage::object_id(&observation.index_tree)?;
    let working_tree = storage::object_id(&observation.working_tree)?;
    let _ = tree_files(&repo, head_tree)?;
    let _ = tree_files(&repo, index_tree)?;
    let working_files = tree_files(&repo, working_tree)?;
    let untracked = observation.untracked.clone();
    let index_present = observation.index_bytes.is_some();
    let raw = observation.index_bytes.as_deref().unwrap_or_default();
    let index_digest = content_digest(raw);
    let selection_digest = content_digest(&json_bytes(&(
        index_present,
        &index_digest,
        &observation.index_tree,
    ))?);
    let mut capture = Capture {
        receipt: vcs::TargetCaptureReceipt {
            format_version: VERSION,
            operation_id: permit.operation_id().clone(),
            root: root.clone(),
            state: native,
            reference: Some(first_reference),
            selection_digest,
            working_digest: content_digest(&json_bytes(&working_files)?),
            policy_digest: content_digest(&json_bytes(&(
                &first_policy,
                &observation.ignore_digest,
            ))?),
            capture_digest: content_digest(b"pending"),
            clean: index_tree == head_tree && working_tree == head_tree && untracked.is_empty(),
        },
        physical: first_physical,
        policy: first_policy,
        ignore_digest: observation.ignore_digest,
        index_present,
        index_digest,
        index_length: raw.len() as u64,
        index_tree: vcs::GitTreeId(observation.index_tree),
        working_tree: vcs::GitTreeId(observation.working_tree),
        untracked,
    };
    capture.receipt.capture_digest = capture_digest(&capture)?;
    if physical(root, &repo)? != capture.physical
        || policy(&repo)? != capture.policy
        || Some(reference(&repo)?) != capture.receipt.reference
        || GitState::read(root)? != capture.receipt.state
    {
        return Err(stale("target changed during its capture"));
    }
    barrier(root, permit)?;
    Ok((capture, observation.index_bytes))
}
struct GitState;
impl GitState {
    fn read(root: &vcs::RootBinding) -> vcs::VcsResult<vcs::NativeStateRef> {
        super::GitWorkspaceEngine::default().recorded_state(root)
    }
}

fn captured_repo(directory: &Path) -> vcs::VcsResult<Repository> {
    let path = storage::canonical_directory(&directory.join("repository"))?;
    let repo = Repository::open(&path).map_err(crate::map_git_err)?;
    if storage::canonical_directory(repo.path())? != path.join(".git")
        || storage::canonical_directory(repo.commondir())? != path.join(".git")
    {
        return Err(invalid(
            "retained capture redirects repository administration",
        ));
    }
    Ok(repo)
}
pub(super) fn reopen_capture(
    root: &vcs::RootBinding,
    path: &Path,
) -> vcs::VcsResult<vcs::PreparedTargetCapture> {
    let directory = storage::canonical_directory(
        path.parent()
            .ok_or_else(|| invalid("capture artifact has no parent"))?,
    )?;
    let capture: Capture = decode(&directory.join("capture.json"))?;
    if capture.receipt.root != *root
        || capture.receipt.capture_digest != capture_digest(&capture)?
        || capture.receipt.policy_digest
            != content_digest(&json_bytes(&(&capture.policy, &capture.ignore_digest))?)
    {
        return Err(invalid("capture receipt/assumptions changed"));
    }
    let index = read(&directory.join("index.before"))?;
    if index.len() as u64 != capture.index_length
        || content_digest(&index) != capture.index_digest
        || capture.receipt.selection_digest
            != content_digest(&json_bytes(&(
                capture.index_present,
                &capture.index_digest,
                capture.index_tree.as_str(),
            ))?)
    {
        return Err(invalid("retained exact index bytes changed"));
    }
    let repo = captured_repo(&directory)?;
    let (_, tree) = storage::verify_state(&repo, &root.repository_id, &capture.receipt.state)?;
    let index_tree = storage::object_id(capture.index_tree.as_str())?;
    let work_tree = storage::object_id(capture.working_tree.as_str())?;
    let _ = tree_files(&repo, tree)?;
    let _ = tree_files(&repo, index_tree)?;
    if capture.receipt.working_digest
        != content_digest(&json_bytes(&tree_files(&repo, work_tree)?)?)
        || capture.receipt.clean
            != (tree == index_tree && tree == work_tree && capture.untracked.is_empty())
    {
        return Err(invalid(
            "retained working overlay or clean-target policy changed",
        ));
    }
    vcs::PreparedTargetCapture::from_captured_target(
        capture.receipt,
        directory.join("capture.json"),
    )
    .map_err(Into::into)
}
pub(super) fn capture_target(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    spool: &Path,
) -> vcs::VcsResult<vcs::PreparedTargetCapture> {
    barrier(root, permit)?;
    let base = base(root, spool, false)?;
    let key = key("capture", root, permit.operation_id())?;
    let _lock = lock(&base, &key)?;
    let destination = base.join(&key);
    if destination.symlink_metadata().is_ok() {
        let retained = reopen_capture(root, &destination.join("capture.json"))?;
        let (current, _) = observe(root, permit)?;
        if current.receipt.capture_digest != retained.receipt().capture_digest {
            return Err(stale(
                "capture operation cannot be rebound to changed source",
            ));
        }
        return Ok(retained);
    }
    let (capture, index) = observe(root, permit)?;
    let staged = tempfile::Builder::new()
        .prefix("capture-preparing-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&base)
        .map_err(|error| io(&error))?;
    let source = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    let target = storage::initialize(&staged.path().join("repository"))?;
    let (head, _) = git_ids(&capture.receipt.state)?;
    let mut roots = vec![
        storage::object_id(capture.index_tree.as_str())?,
        storage::object_id(capture.working_tree.as_str())?,
    ];
    roots.extend(head);
    crate::checkpoint::copy_objects(&source, &target, &roots)?;
    storage::sync_tree(&staged.path().join("repository"))?;
    write(
        &staged.path().join("index.before"),
        &index.unwrap_or_default(),
    )?;
    write(&staged.path().join("capture.json"), &json_bytes(&capture)?)?;
    let (current, _) = observe(root, permit)?;
    if current.receipt.capture_digest != capture.receipt.capture_digest {
        return Err(stale("target changed before capture retention"));
    }
    drop(target);
    drop(source);
    storage::sync_directory(staged.path())?;
    std::fs::rename(staged.keep(), &destination).map_err(|error| io(&error))?;
    storage::sync_directory(&base)?;
    reopen_capture(root, &destination.join("capture.json"))
}

fn prepared_digest(preparation: &Preparation) -> vcs::VcsResult<vcs::ContentDigest> {
    let mut value =
        serde_json::to_value(preparation).map_err(|error| invalid(error.to_string()))?;
    value
        .get_mut("receipt")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| invalid("missing preparation receipt"))?
        .remove("preparedDigest");
    Ok(content_digest(&json_bytes(&value)?))
}
fn plan(repo: &Repository, before: Oid, after: Oid) -> vcs::VcsResult<Vec<Change>> {
    let before = tree_files(repo, before)?;
    let after = tree_files(repo, after)?;
    let paths: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    // Prefix/type swaps need a separately qualified directory preimage policy.
    for path in before.keys() {
        if after
            .keys()
            .any(|other| other.starts_with(&format!("{path}/")))
        {
            return Err(invalid(
                "file/directory adoption transitions are unqualified",
            ));
        }
    }
    for path in after.keys() {
        if before
            .keys()
            .any(|other| other.starts_with(&format!("{path}/")))
        {
            return Err(invalid(
                "directory/file adoption transitions are unqualified",
            ));
        }
    }
    Ok(paths
        .into_iter()
        .filter_map(|path| {
            let old = before.get(&path);
            let new = after.get(&path);
            (old != new).then(|| Change {
                path,
                before: old.cloned(),
                after: new.cloned(),
            })
        })
        .collect())
}
pub(super) fn reopen_preparation(
    root: &vcs::RootBinding,
    path: &Path,
) -> vcs::VcsResult<vcs::PreparedAdoption> {
    let directory = storage::canonical_directory(
        path.parent()
            .ok_or_else(|| invalid("preparation artifact has no parent"))?,
    )?;
    let preparation: Preparation = decode(&directory.join("adoption.json"))?;
    if preparation.receipt.root != *root
        || preparation.receipt.capture_digest != preparation.capture.receipt.capture_digest
        || preparation.receipt.before != preparation.capture.receipt.state
        || prepared_digest(&preparation)? != preparation.receipt.prepared_digest
        || !preparation.capture.receipt.clean
    {
        return Err(invalid(
            "adoption preparation changed or has a dirty target",
        ));
    }
    let candidate = composition::reopen(root, &directory.join("composition"))?;
    let receipt = candidate.receipt.receipt();
    if receipt.conflict_manifest.is_some()
        || receipt.target_state != preparation.receipt.before
        || receipt.candidate_state != preparation.receipt.after
        || receipt.receipt_digest != preparation.receipt.composition_receipt_digest
        || receipt.materialization_id != preparation.receipt.materialization_id
        || receipt.selection_revision != preparation.receipt.selection_revision
        || receipt.composition_revision != preparation.receipt.composition_revision
        || candidate.closure.manifest_digest != preparation.receipt.closure_digest
    {
        return Err(invalid(
            "adoption candidate differs from exact retained composition",
        ));
    }
    let repo =
        Repository::open(&candidate.materialization.destination).map_err(crate::map_git_err)?;
    let (_, before) = git_ids(&preparation.receipt.before)?;
    let (_, after) = git_ids(&preparation.receipt.after)?;
    if plan(&repo, before, after)? != preparation.changes
        || content_digest(&json_bytes(&preparation.changes)?)
            != preparation.receipt.write_manifest_digest
    {
        return Err(invalid("adoption path manifest changed"));
    }
    let index = read(&directory.join("index.after"))?;
    if content_digest(&index) != preparation.index_after_digest
        || index.len() as u64 != preparation.index_after_length
    {
        return Err(invalid("prepared post-adoption index changed"));
    }
    let before_index = read(&directory.join("index.before"))?;
    if content_digest(&before_index) != preparation.capture.index_digest
        || before_index.len() as u64 != preparation.capture.index_length
    {
        return Err(invalid("prepared source index changed"));
    }
    vcs::PreparedAdoption::from_prepared_adoption(
        preparation.receipt,
        directory.join("adoption.json"),
    )
    .map_err(Into::into)
}
pub(super) fn prepare(
    root: &vcs::RootBinding,
    capture: &vcs::PreparedTargetCapture,
    candidate: &vcs::PreparedComposition,
    operation: &vcs::OperationId,
    spool: &Path,
) -> vcs::VcsResult<vcs::PreparedAdoption> {
    git_root(root, "prepareAdoption")?;
    let inspected = reopen_capture(root, capture.manifest_path())?;
    if inspected.receipt() != capture.receipt() || !capture.receipt().clean {
        return Err(stale("dirty target/active index selection blocks adoption"));
    }
    let source = composition::reopen(
        root,
        candidate
            .manifest_path
            .parent()
            .ok_or_else(|| invalid("candidate has no bundle"))?,
    )?;
    if source.receipt.receipt() != candidate.receipt.receipt()
        || source.receipt.receipt().target_state != capture.receipt().state
        || source.receipt.receipt().conflict_manifest.is_some()
    {
        return Err(invalid(
            "candidate is conflicted or names a different target",
        ));
    }
    let base = base(root, spool, true)?;
    let key = key("adoption", root, operation)?;
    let _lock = lock(&base, &key)?;
    let destination = base.join(&key);
    if destination.symlink_metadata().is_ok() {
        let retained = reopen_preparation(root, &destination.join("adoption.json"))?;
        if retained.receipt().capture_digest != capture.receipt().capture_digest
            || retained.receipt().composition_receipt_digest
                != candidate.receipt.receipt().receipt_digest
        {
            return Err(invalid("conflicting replay of adoption preparation"));
        }
        return Ok(retained);
    }
    let staged = tempfile::Builder::new()
        .prefix("adoption-preparing-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&base)
        .map_err(|error| io(&error))?;
    let retained = composition::copy(&source, &staged.path().join("composition"))?;
    let repo =
        Repository::open(&retained.materialization.destination).map_err(crate::map_git_err)?;
    let (before_commit, before_tree) = git_ids(&capture.receipt().state)?;
    let (after_commit, after_tree) = git_ids(&retained.candidate.state)?;
    let after_commit = after_commit
        .ok_or_else(|| invalid("an adopted candidate requires an actual Git commit"))?;
    if before_commit.is_some_and(|before| {
        before != after_commit
            && !repo
                .graph_descendant_of(after_commit, before)
                .unwrap_or(false)
    }) {
        return Err(invalid(
            "adoption candidate does not preserve original target ancestry",
        ));
    }
    let changes = plan(&repo, before_tree, after_tree)?;
    let capture_doc: Capture = decode(capture.manifest_path())?;
    write(
        &staged.path().join("index.before"),
        &read(
            &capture
                .manifest_path()
                .parent()
                .ok_or_else(|| invalid("capture has no parent"))?
                .join("index.before"),
        )?,
    )?;
    let mut index =
        git2::Index::open(&staged.path().join("index.after")).map_err(crate::map_git_err)?;
    index
        .read_tree(&repo.find_tree(after_tree).map_err(crate::map_git_err)?)
        .map_err(crate::map_git_err)?;
    index.write().map_err(crate::map_git_err)?;
    let index_bytes = read(&staged.path().join("index.after"))?;
    storage::read_file(&staged.path().join("index.after"))?
        .sync_all()
        .map_err(|error| io(&error))?;
    let proof = retained.receipt.receipt();
    let mut preparation = Preparation {
        receipt: vcs::AdoptionPreparationReceipt {
            format_version: VERSION,
            operation_id: operation.clone(),
            root: root.clone(),
            before: capture.receipt().state.clone(),
            after: proof.candidate_state.clone(),
            capture_digest: capture.receipt().capture_digest.clone(),
            composition_receipt_digest: proof.receipt_digest.clone(),
            materialization_id: proof.materialization_id.clone(),
            selection_revision: proof.selection_revision.clone(),
            composition_revision: proof.composition_revision.clone(),
            closure_digest: retained.closure.manifest_digest.clone(),
            write_manifest_digest: content_digest(&json_bytes(&changes)?),
            prepared_digest: content_digest(b"pending"),
        },
        capture: capture_doc,
        changes,
        index_after_digest: content_digest(&index_bytes),
        index_after_length: index_bytes.len() as u64,
    };
    preparation.receipt.prepared_digest = prepared_digest(&preparation)?;
    write(
        &staged.path().join("adoption.json"),
        &json_bytes(&preparation)?,
    )?;
    let _ = reopen_preparation(root, &staged.path().join("adoption.json"))?;
    drop(index);
    drop(repo);
    storage::sync_directory(staged.path())?;
    std::fs::rename(staged.keep(), &destination).map_err(|error| io(&error))?;
    storage::sync_directory(&base)?;
    reopen_preparation(root, &destination.join("adoption.json"))
}

fn receipt_digest(receipt: &vcs::ObservedAdoptionReceipt) -> vcs::VcsResult<vcs::ContentDigest> {
    let mut value = serde_json::to_value(receipt).map_err(|error| invalid(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("invalid adoption receipt"))?
        .remove("receiptDigest");
    Ok(content_digest(&json_bytes(&value)?))
}
fn checked_command(
    root: &vcs::RootBinding,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<(PathBuf, Preparation)> {
    let inspected = reopen_preparation(root, prepared.manifest_path())?;
    if inspected.receipt() != prepared.receipt()
        || authorization.receipt().preparation != *prepared.receipt()
    {
        return Err(invalid(
            "adoption authorization differs from its exact inspected command",
        ));
    }
    let directory = storage::canonical_directory(
        prepared
            .manifest_path()
            .parent()
            .ok_or_else(|| invalid("adoption has no retained directory"))?,
    )?;
    let document = decode(&directory.join("adoption.json"))?;
    Ok((directory, document))
}
fn terminal(
    root: &vcs::RootBinding,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    let (directory, preparation) = checked_command(root, prepared, authorization)?;
    let path = directory.join("receipt.json");
    if path.symlink_metadata().is_err() {
        return Err(uncertain(
            &prepared.receipt().operation_id,
            "no retained terminal adoption receipt",
        ));
    }
    let receipt: vcs::ObservedAdoptionReceipt = decode(&path)?;
    let journal: Journal = decode(&directory.join("journal.json"))?;
    if receipt.authorization != *authorization.receipt()
        || journal.authorization != *authorization.receipt()
        || !matches!(
            journal.phase,
            Phase::Reference | Phase::Applied | Phase::Complete
        )
        || receipt.format_version != VERSION
        || receipt.preimages_digest != preimages_digest(&preparation)?
        || journal.completed_paths
            != preparation
                .changes
                .iter()
                .map(|change| change.path.clone())
                .collect::<Vec<_>>()
        || receipt.receipt_digest != receipt_digest(&receipt)?
        || receipt.target_reference != preparation.capture.receipt.reference
    {
        return Err(invalid(
            "terminal adoption receipt/journal/authorization changed",
        ));
    }
    vcs::VerifiedAdoptionReceipt::from_observed_adoption(receipt, path, true).map_err(Into::into)
}
pub(super) fn read_receipt(
    root: &vcs::RootBinding,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    terminal(root, prepared, authorization)
}

fn progress_digest(receipt: &vcs::AdoptionProgressReceipt) -> vcs::VcsResult<vcs::ContentDigest> {
    let mut value = serde_json::to_value(receipt).map_err(|error| invalid(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("invalid native adoption progress"))?
        .remove("effectDigest");
    Ok(content_digest(&json_bytes(&value)?))
}

fn save_progress(
    directory: &Path,
    authorization: &vcs::AdoptionAuthorization,
    target: &str,
    observation: vcs::AdoptionProgressObservation,
) -> vcs::VcsResult<()> {
    let mut receipt = vcs::AdoptionProgressReceipt {
        format_version: VERSION,
        authorization: authorization.receipt().clone(),
        target_reference: Some(target.into()),
        observation,
        effect_digest: content_digest(b"pending"),
    };
    receipt.effect_digest = progress_digest(&receipt)?;
    let path = directory.join("native-effect.json");
    if path.symlink_metadata().is_ok() {
        let prior: vcs::AdoptionProgressReceipt = decode(&path)?;
        if prior != receipt {
            return Err(invalid("conflicting native effect progress"));
        }
        Ok(())
    } else {
        write(&path, &json_bytes(&receipt)?)
    }
}

pub(super) fn read_progress(
    root: &vcs::RootBinding,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<vcs::VerifiedAdoptionProgress> {
    let (directory, preparation) = checked_command(root, prepared, authorization)?;
    let path = directory.join("native-effect.json");
    if path.symlink_metadata().is_err() {
        return Err(uncertain(
            &prepared.receipt().operation_id,
            "no retained native CAS fact",
        ));
    }
    let receipt: vcs::AdoptionProgressReceipt = decode(&path)?;
    let journal: Journal = decode(&directory.join("journal.json"))?;
    if receipt.format_version != VERSION
        || receipt.authorization != *authorization.receipt()
        || journal.authorization != *authorization.receipt()
        || !matches!(
            journal.phase,
            Phase::Reference | Phase::Applied | Phase::Complete
        )
        || receipt.target_reference != preparation.capture.receipt.reference
        || receipt.effect_digest != progress_digest(&receipt)?
    {
        return Err(invalid(
            "native CAS progress differs from exact retained operation",
        ));
    }
    vcs::VerifiedAdoptionProgress::from_observed_adoption_progress(receipt, path)
        .map_err(Into::into)
}

fn copy_objects_durable(
    source: &Repository,
    target: &Repository,
    roots: &[Oid],
) -> vcs::VcsResult<()> {
    let source_odb = source.odb().map_err(crate::map_git_err)?;
    let target_odb = target.odb().map_err(crate::map_git_err)?;
    let mut seen = BTreeSet::new();
    let mut pending = roots.to_vec();
    let mut directories = BTreeSet::new();
    let mut total = 0_u64;
    let object_root = target.commondir().join("objects");
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > 200_000 {
            return Err(invalid("adoption object closure exceeds its object budget"));
        }
        let object = source_odb.read(id).map_err(crate::map_git_err)?;
        total = total.saturating_add(object.data().len() as u64);
        if total > 1024 * 1024 * 1024 {
            return Err(invalid("adoption object closure exceeds its byte budget"));
        }
        match object.kind() {
            git2::ObjectType::Commit => {
                let commit = source.find_commit(id).map_err(crate::map_git_err)?;
                pending.push(commit.tree_id());
                pending.extend(commit.parent_ids());
            }
            git2::ObjectType::Tree => pending.extend(
                source
                    .find_tree(id)
                    .map_err(crate::map_git_err)?
                    .iter()
                    .filter(|entry| entry.filemode() != 0o160_000)
                    .map(|entry| entry.id()),
            ),
            git2::ObjectType::Blob => {}
            _ => return Err(invalid("unsupported object in adoption closure")),
        }
        if target_odb
            .write(object.kind(), object.data())
            .map_err(crate::map_git_err)?
            != id
        {
            return Err(invalid("adoption object import changed native identity"));
        }
        let hash = id.to_string();
        let parent = object_root.join(&hash[..2]);
        let path = parent.join(&hash[2..]);
        if path.try_exists().map_err(|error| io(&error))? {
            storage::read_file(&path)?
                .sync_all()
                .map_err(|error| io(&error))?;
            directories.insert(parent);
        }
    }
    for directory in directories {
        storage::sync_directory(&directory)?;
    }
    storage::sync_directory(&object_root)?;
    storage::sync_directory(target.commondir())
}

struct IndexLease {
    path: PathBuf,
    file: File,
}
impl IndexLease {
    fn acquire(repo: &Repository) -> vcs::VcsResult<Self> {
        // Git names this index.lock, including non-default index filenames.
        let index = repo.index().map_err(crate::map_git_err)?;
        let index_path = index
            .path()
            .ok_or_else(|| invalid("repository index has no path"))?;
        let path = index_path.with_file_name(format!(
            "{}.lock",
            index_path
                .file_name()
                .ok_or_else(|| invalid("index has no name"))?
                .to_string_lossy()
        ));
        let file = storage::create_file(&path)?;
        file.sync_all().map_err(|error| io(&error))?;
        storage::sync_directory(
            path.parent()
                .ok_or_else(|| invalid("index lock has no parent"))?,
        )?;
        Ok(Self { path, file })
    }
}
impl Drop for IndexLease {
    fn drop(&mut self) {
        if let (Ok(current), Ok(owned)) =
            (std::fs::symlink_metadata(&self.path), self.file.metadata())
        {
            if current.is_file() && current.dev() == owned.dev() && current.ino() == owned.ino() {
                let _ = std::fs::remove_file(&self.path);
                if let Some(parent) = self.path.parent() {
                    let _ = storage::sync_directory(parent);
                }
            }
        }
    }
}
fn save_journal(directory: &Path, journal: &Journal) -> vcs::VcsResult<()> {
    replace(&directory.join("journal.json"), &json_bytes(journal)?)
}
fn preimages_digest(preparation: &Preparation) -> vcs::VcsResult<vcs::ContentDigest> {
    // Immutable expected before objects remain in the retained original graph;
    // exchanged old inodes also remain in live-preimages for later fd writes.
    Ok(content_digest(&json_bytes(&(
        &preparation.capture.index_digest,
        preparation
            .changes
            .iter()
            .map(|change| (&change.path, &change.before))
            .collect::<Vec<_>>(),
        "immutable-before-plus-retained-live-inode-v1",
    ))?))
}
fn postconditions(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    preparation: &Preparation,
    directory: &Path,
) -> vcs::VcsResult<()> {
    barrier(root, permit)?;
    let repo = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    if physical(root, &repo)? != preparation.capture.physical
        || policy(&repo)? != preparation.capture.policy
        || Some(reference(&repo)?) != preparation.capture.receipt.reference
        || GitState::read(root)? != preparation.receipt.after
    {
        return Err(stale(
            "adoption recorded state/reference/policy/physical root is not its exact postcondition",
        ));
    }
    let index = repo.index().map_err(crate::map_git_err)?;
    let index_path = index.path().ok_or_else(|| invalid("index has no path"))?;
    let index_bytes = read(index_path)?;
    if content_digest(&index_bytes) != preparation.index_after_digest
        || index_bytes.len() as u64 != preparation.index_after_length
    {
        return Err(stale("adoption index is not its exact postcondition"));
    }
    let observation = observation::read_target(&repo, root, &preparation.capture.policy)?;
    let (_, after) = git_ids(&preparation.receipt.after)?;
    if storage::object_id(&observation.working_tree)? != after || !observation.untracked.is_empty()
    {
        return Err(stale(
            "adoption working files changed before terminal observation",
        ));
    }
    let retained = composition::reopen(root, &directory.join("composition"))?;
    let native =
        Repository::open(&retained.materialization.destination).map_err(crate::map_git_err)?;
    let opened = fs::directory(&root.locator)?;
    for (path, node) in tree_files(&native, after)? {
        if fs::image(&opened, &path)?.as_ref() != Some(&node.image) {
            return Err(stale(
                "post-adoption raw file bytes/mode differ from candidate",
            ));
        }
    }
    barrier(root, permit)
}
fn seal_terminal(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    authorization: &vcs::AdoptionAuthorization,
    directory: &Path,
    preparation: &Preparation,
    journal: &mut Journal,
    replayed: bool,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    postconditions(root, permit, preparation, directory)?;
    let repo = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    let target = preparation.capture.receipt.reference.clone();
    recording::sync_reference(
        &repo,
        target
            .as_deref()
            .ok_or_else(|| invalid("missing target reference"))?,
    )?;
    storage::read_file(
        repo.index()
            .map_err(crate::map_git_err)?
            .path()
            .ok_or_else(|| invalid("index has no path"))?,
    )?
    .sync_all()
    .map_err(|error| io(&error))?;
    storage::sync_directory(repo.path())?;
    storage::sync_directory(&root.locator)?;
    let mut receipt = vcs::ObservedAdoptionReceipt {
        format_version: VERSION,
        authorization: authorization.receipt().clone(),
        target_reference: target,
        preimages_digest: preimages_digest(preparation)?,
        receipt_digest: content_digest(b"pending"),
        post_effect_errors: Vec::new(),
    };
    receipt.receipt_digest = receipt_digest(&receipt)?;
    let receipt_path = directory.join("receipt.json");
    if receipt_path.symlink_metadata().is_ok() {
        let prior: vcs::ObservedAdoptionReceipt = decode(&receipt_path)?;
        if prior != receipt {
            return Err(invalid("conflicting terminal adoption receipt"));
        }
    } else {
        write(&receipt_path, &json_bytes(&receipt)?)?;
    }
    journal.phase = Phase::Complete;
    save_journal(directory, journal)?;
    vcs::VerifiedAdoptionReceipt::from_observed_adoption(receipt, receipt_path, replayed)
        .map_err(Into::into)
}
pub(super) fn reconcile(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    if let Ok(receipt) = terminal(root, prepared, authorization) {
        return Ok(receipt);
    }
    barrier(root, permit)?;
    let (directory, preparation) = checked_command(root, prepared, authorization)?;
    let _lock = lock(&directory, "effect")?;
    let path = directory.join("journal.json");
    if path.symlink_metadata().is_err() {
        return Err(uncertain(
            &preparation.receipt.operation_id,
            "adoption has no admitted native journal; inspection cannot begin it",
        ));
    }
    let mut journal: Journal = decode(&path)?;
    if journal.authorization != *authorization.receipt() || journal.version != VERSION {
        return Err(invalid("adoption recovery command changed"));
    }
    if !matches!(
        journal.phase,
        Phase::Reference | Phase::Applied | Phase::Complete
    ) {
        return Err(uncertain(
            &preparation.receipt.operation_id,
            "adoption remains incomplete; inspection never resumes native writes",
        ));
    }
    seal_terminal(
        root,
        permit,
        authorization,
        &directory,
        &preparation,
        &mut journal,
        true,
    )
    .map_err(|error| {
        uncertain(
            &preparation.receipt.operation_id,
            format!("completed adoption is not yet provable: {error}"),
        )
    })
}
pub(super) fn apply(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    apply_checked(root, permit, prepared, authorization, |_| Ok(()))
}
fn apply_checked(
    root: &vcs::RootBinding,
    permit: &vcs::WriteBarrierPermit,
    prepared: &vcs::PreparedAdoption,
    authorization: &vcs::AdoptionAuthorization,
    mut observed: impl FnMut(&str) -> vcs::VcsResult<()>,
) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
    if !authorization.allows_apply() {
        return Err(invalid(
            "reconciliation authorization cannot begin native adoption",
        ));
    }
    barrier(root, permit)?;
    if permit.operation_id() != &prepared.receipt().operation_id {
        return Err(stale("write barrier belongs to another adoption operation"));
    }
    let (directory, preparation) = checked_command(root, prepared, authorization)?;
    let _lock = lock(&directory, "effect")?;
    if directory.join("receipt.json").symlink_metadata().is_ok() {
        return terminal(root, prepared, authorization);
    }
    if directory.join("journal.json").symlink_metadata().is_ok() {
        return Err(uncertain(
            &preparation.receipt.operation_id,
            "an earlier native admission exists; a fresh apply cannot resume it",
        ));
    }
    let repo = Repository::open(&root.locator).map_err(crate::map_git_err)?;
    if std::fs::metadata(&directory)
        .map_err(|error| io(&error))?
        .dev()
        != std::fs::metadata(&root.locator)
            .map_err(|error| io(&error))?
            .dev()
    {
        return Err(invalid(
            "retained preimage storage is no longer on target filesystem",
        ));
    }
    let mut transaction = repo.transaction().map_err(crate::map_git_err)?;
    transaction.lock_ref("HEAD").map_err(crate::map_git_err)?;
    let target = preparation
        .capture
        .receipt
        .reference
        .as_deref()
        .ok_or_else(|| invalid("missing target reference"))?;
    if target != "HEAD" {
        transaction.lock_ref(target).map_err(crate::map_git_err)?;
    }
    let _index_lease = IndexLease::acquire(&repo)?;
    let (current, _) = observe(root, permit)?;
    if current.receipt.capture_digest != preparation.receipt.capture_digest
        || !current.receipt.clean
    {
        return Err(stale("target HEAD/index/working bytes/physical binding/policy changed; prepare a new candidate"));
    }
    let working = fs::directory(&root.locator)?;
    for change in &preparation.changes {
        if fs::image(&working, &change.path)?.as_ref()
            != change.before.as_ref().map(|node| &node.image)
        {
            return Err(stale(
                "changed target path no longer matches its captured preimage",
            ));
        }
    }
    let mut journal = Journal {
        version: VERSION,
        authorization: authorization.receipt().clone(),
        phase: Phase::Admitted,
        completed_paths: Vec::new(),
    };
    write(&directory.join("journal.json"), &json_bytes(&journal)?)?;
    let result = (|| {
        observed("admitted")?;
        barrier(root, permit)?;
        let candidate = composition::reopen(root, &directory.join("composition"))?;
        let native =
            Repository::open(&candidate.materialization.destination).map_err(crate::map_git_err)?;
        let (head, tree) = git_ids(&preparation.receipt.after)?;
        copy_objects_durable(&native, &repo, &[head.unwrap_or(tree)])?;
        let saved = directory.join("live-preimages");
        private_directory(&saved)?;
        storage::sync_directory(&directory)?;
        let saved_directory = fs::directory(&saved)?;
        journal.phase = Phase::Paths;
        save_journal(&directory, &journal)?;
        for (number, change) in preparation.changes.iter().enumerate() {
            barrier(root, permit)?;
            let saved_name = format!("path-{number:06}");
            let named = fs::name(&saved_name)?;
            if let Some(after) = &change.after {
                let blob = native
                    .find_blob(storage::object_id(after.object.as_str())?)
                    .map_err(crate::map_git_err)?;
                if content_digest(blob.content()) != after.image.digest {
                    return Err(invalid("candidate payload changed before path write"));
                }
                fs::stage(&saved.join(&saved_name), after.image.mode, blob.content())?;
            }
            let (parent, name) = fs::parent(&working, &change.path, change.after.is_some())?;
            if fs::image_at(&parent, &name)?.as_ref()
                != change.before.as_ref().map(|node| &node.image)
            {
                return Err(stale("path changed immediately before atomic replacement"));
            }
            observed("before-path-exchange")?;
            barrier(root, permit)?;
            match (&change.before, &change.after) {
                (Some(before), Some(_)) => {
                    fs::exchange(&saved_directory, &named, &parent, &name)?;
                    parent.sync_all().map_err(|error| io(&error))?;
                    saved_directory.sync_all().map_err(|error| io(&error))?;
                    if fs::image_at(&saved_directory, &named)?.as_ref() != Some(&before.image) {
                        return Err(stale(
                            "racing replacement preimage retained; target is uncertain",
                        ));
                    }
                }
                (Some(before), None) => {
                    fs::move_preimage(&parent, &name, &saved_directory, &named)?;
                    if fs::image_at(&saved_directory, &named)?.as_ref() != Some(&before.image) {
                        return Err(stale(
                            "racing deletion preimage retained; target is uncertain",
                        ));
                    }
                }
                (None, Some(_)) => fs::publish_new(&saved_directory, &named, &parent, &name)?,
                (None, None) => return Err(invalid("empty path operation")),
            }
            if fs::image_at(&parent, &name)?.as_ref()
                != change.after.as_ref().map(|node| &node.image)
            {
                return Err(stale("path changed immediately after atomic replacement"));
            }
            journal.completed_paths.push(change.path.clone());
            save_journal(&directory, &journal)?;
            observed("path-complete")?;
        }
        barrier(root, permit)?;
        journal.phase = Phase::Index;
        save_journal(&directory, &journal)?;
        let index = repo.index().map_err(crate::map_git_err)?;
        let index_path = index.path().ok_or_else(|| invalid("index has no path"))?;
        let parent = fs::directory(
            index_path
                .parent()
                .ok_or_else(|| invalid("index has no parent"))?,
        )?;
        let current = if index_path.symlink_metadata().is_ok() {
            Some(read(index_path)?)
        } else {
            None
        };
        if current.is_some() != preparation.capture.index_present
            || content_digest(current.as_deref().unwrap_or_default())
                != preparation.capture.index_digest
        {
            return Err(stale("index changed despite retained native lock"));
        }
        let saved_index_name = format!(
            "index.intent-adoption-{}",
            preparation.receipt.prepared_digest.as_str()
        );
        let staged_index = index_path.with_file_name(&saved_index_name);
        write(&staged_index, &read(&directory.join("index.after"))?)?;
        let index_name = fs::name(
            index_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("index name is not UTF-8"))?,
        )?;
        let staged_name = fs::name(&saved_index_name)?;
        if preparation.capture.index_present {
            fs::exchange(&parent, &staged_name, &parent, &index_name)?;
            if content_digest(&read(&staged_index)?) != preparation.capture.index_digest {
                return Err(stale("racing index preimage retained"));
            }
        } else {
            fs::publish_new(&parent, &staged_name, &parent, &index_name)?;
        }
        parent.sync_all().map_err(|error| io(&error))?;
        observed("index-complete")?;
        barrier(root, permit)?;
        journal.phase = Phase::Reference;
        save_journal(&directory, &journal)?;
        if Some(reference(&repo)?) != preparation.capture.receipt.reference
            || GitState::read(root)? != preparation.receipt.before
        {
            return Err(stale(
                "recorded target/reference advanced before exact adoption CAS",
            ));
        }
        transaction
            .set_target(
                target,
                head.ok_or_else(|| invalid("adoption has no commit"))?,
                None,
                "Intent: adopt exact verified candidate",
            )
            .map_err(crate::map_git_err)?;
        match transaction.commit() {
            Ok(()) => save_progress(
                &directory,
                authorization,
                target,
                vcs::AdoptionProgressObservation::CasReturnedSuccess,
            )?,
            Err(error) => {
                if preparation.receipt.before != preparation.receipt.after
                    && repo
                        .find_reference(target)
                        .ok()
                        .and_then(|reference| reference.target())
                        == head
                {
                    save_progress(
                        &directory,
                        authorization,
                        target,
                        vcs::AdoptionProgressObservation::ObservedAfterFailedCas,
                    )?;
                }
                return Err(crate::map_git_err(error).into());
            }
        }
        // This fact precedes every later live-state/durability observation. A
        // completed CAS is never erased by drift or a failed completion tail.
        journal.phase = Phase::Applied;
        save_journal(&directory, &journal)?;
        observed("cas-fact-retained")?;
        recording::sync_reference(&repo, target)?;
        observed("reference-complete")?;
        seal_terminal(
            root,
            permit,
            authorization,
            &directory,
            &preparation,
            &mut journal,
            false,
        )
    })();
    result.map_err(|error|uncertain(&preparation.receipt.operation_id,format!("retained adoption requires inspection; native bytes/preimages were not rolled back: {error}")))
}
