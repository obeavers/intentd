//! Exact recorded-view closure with graph-backed native conflict objects.
//! Restores are disposable private repositories, never canonical-root installs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use atomic_core::change::Change;
use atomic_core::kg::project_id::{MintReason, ProjectIdentityRecord};
use atomic_core::pristine::ViewTxnT;
use atomic_core::{Base32, Hash};
use atomic_repository::{ConflictSetObject, Repository, ViewEntryKind, ViewManifest};
use intent_atomic_proto::composition::CaptureCompositionTargetRequest;
use intent_atomic_proto::recorded_closures::{
    ExportRecordedClosureRequest, RecordedClosure, RecordedClosureProfile, RecordedClosureRestore,
    RecordedConflictRef, RestoreRecordedClosureRequest, RECORDED_CLOSURE_FORMAT,
    RECORDED_CLOSURE_READER, RECORDED_MATERIALIZER_VERSION,
};
use intent_atomic_proto::{HostIdentity, SpoolRef, StateToken};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::baselines::{Manifest, SnapshotEntry, SnapshotKind};
use crate::{baselines, composition, durable, Host, HostError, Result};

const MAGIC: &[u8] = b"INTENT-ATOMIC-RECORDED-CLOSURE-2\n";
const MAX_PAYLOAD: u64 = 512 * 1024 * 1024;
const MAX_HEADER: usize = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;
const MAX_FILES: usize = 50_000;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CONFLICT_BYTES: u64 = 16 * 1024 * 1024;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn invalid(message: &'static str) -> HostError {
    HostError::Invalid(message)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn sha_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_view(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with("wc/")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_. /".contains(&byte))
        && !value.contains(' ')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}
fn safe_file(value: &str) -> bool {
    baselines::source::safe_path(value)
        && value.is_ascii()
        && value.split('/').count() <= 64
        && value.split('/').all(|part| {
            !matches!(
                part.to_ascii_lowercase().as_str(),
                ".atomic" | ".atomic-sandbox" | ".git"
            )
        })
}
fn parse_hash(value: &str) -> Result<Hash> {
    let hash = Hash::from_base32(value.as_bytes())
        .ok_or(invalid("malformed recorded closure native hash"))?;
    if hash == Hash::NONE || hash.to_base32() != value {
        return Err(invalid("noncanonical recorded closure native hash"));
    }
    Ok(hash)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Object {
    hash: String,
    sha256: String,
    length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DirectoryEntry {
    path: String,
    mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    format: u32,
    reader_version: u32,
    profile: RecordedClosureProfile,
    operation_id: String,
    host: HostIdentity,
    scope: intent_atomic_proto::closures::ClosureScope,
    capture_revision: u64,
    source_state: StateToken,
    project: ProjectIdentityRecord,
    views: Vec<String>,
    files: Manifest,
    directories: Vec<DirectoryEntry>,
    conflict: Option<RecordedConflictRef>,
    objects: Vec<Object>,
}

type NativeObjects = Vec<(Hash, Vec<u8>)>;
struct Decoded {
    header: Header,
    views: Vec<ViewManifest>,
    objects: NativeObjects,
    conflict: Option<ConflictSetObject>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportJournal {
    request: ExportRecordedClosureRequest,
    command_digest: String,
    receipt: Option<RecordedClosure>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreJournal {
    request: RestoreRecordedClosureRequest,
    command_digest: String,
    receipt: Option<RecordedClosureRestore>,
    owner: Option<RestoreFileOwner>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttemptOwner {
    command_digest: String,
    directory: durable::FileIdentity,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreFileOwner {
    attempt: durable::FileIdentity,
    native: durable::FileIdentity,
    database: durable::FileIdentity,
    dot_directory: durable::FileIdentity,
    files: durable::FileIdentity,
}

fn materialization_id(files_digest: &str) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(
        "intent-recorded-materialization",
        RECORDED_MATERIALIZER_VERSION,
        files_digest,
    ))?))
}

fn validate_files(files: &Manifest) -> Result<()> {
    if files.policy_version != 1
        || files.materializer_version != RECORDED_MATERIALIZER_VERSION
        || files.entries.len() > MAX_FILES
    {
        return Err(invalid("unsupported recorded materialization manifest"));
    }
    let mut previous: Option<&str> = None;
    let mut names = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let mut folded_components = BTreeMap::new();
    let mut total = 0u64;
    for file in &files.entries {
        if !safe_file(&file.path)
            || previous.is_some_and(|old| old >= file.path.as_str())
            || !folded.insert(file.path.to_ascii_lowercase())
            || !sha_valid(&file.sha256)
            || file.length > MAX_FILE_BYTES
            || !names.insert(file.path.as_str())
        {
            return Err(invalid(
                "recorded materialization has unsafe, duplicate or oversized paths",
            ));
        }
        if Path::new(&file.path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(".gitattributes"))
        {
            return Err(HostError::Unsupported(
                "recorded conflict-safe materialization of attributes awaits a no-filter native primitive",
            ));
        }
        let expected_mode = match file.kind {
            SnapshotKind::Regular => 0o100_644,
            SnapshotKind::Executable => 0o100_755,
            SnapshotKind::Symlink => 0o120_000,
        };
        if file.mode != expected_mode
            || (file.kind == SnapshotKind::Symlink && (file.length == 0 || file.length > 4096))
        {
            return Err(invalid("recorded materialization kind or mode differs"));
        }
        let mut parent = file.path.as_str();
        let mut component = String::new();
        for part in file.path.split('/') {
            if !component.is_empty() {
                component.push('/');
            }
            component.push_str(part);
            if folded_components
                .insert(component.to_ascii_lowercase(), component.clone())
                .is_some_and(|previous| previous != component)
            {
                return Err(HostError::Unsupported(
                    "recorded path components collide on case-insensitive filesystems",
                ));
            }
        }
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if names.contains(prefix) {
                return Err(invalid("a recorded file is another file's parent"));
            }
            parent = prefix;
        }
        total = total
            .checked_add(file.length)
            .filter(|total| *total <= MAX_FILES_BYTES)
            .ok_or(invalid("recorded materialization exceeds byte budget"))?;
        previous = Some(&file.path);
    }
    Ok(())
}

fn validate_directories(files: &Manifest, directories: &[DirectoryEntry]) -> Result<()> {
    if files.entries.len().saturating_add(directories.len()) > MAX_FILES {
        return Err(invalid("recorded directory inventory exceeds budget"));
    }
    let file_names: BTreeSet<_> = files
        .entries
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut names = BTreeSet::new();
    let mut folded = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for directory in directories {
        if !safe_file(&directory.path)
            || directory.mode != 0o755
            || previous.is_some_and(|old| old >= directory.path.as_str())
            || file_names.contains(directory.path.as_str())
            || !names.insert(directory.path.as_str())
        {
            return Err(HostError::Unsupported(
                "recorded directory path or mode is unqualified",
            ));
        }
        previous = Some(&directory.path);
    }
    for path in file_names.iter().copied().chain(names.iter().copied()) {
        let mut component = String::new();
        for part in path.split('/') {
            if !component.is_empty() {
                component.push('/');
            }
            component.push_str(part);
            if folded
                .insert(component.to_ascii_lowercase(), component.clone())
                .is_some_and(|previous| previous != component)
            {
                return Err(HostError::Unsupported(
                    "recorded directory components collide by case",
                ));
            }
        }
        let mut parent = path;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if !names.contains(prefix) {
                return Err(invalid("recorded directory manifest omits a parent"));
            }
            parent = prefix;
        }
    }
    Ok(())
}

fn files_digest(files: &Manifest, directories: &[DirectoryEntry]) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(files, directories))?))
}

fn verify_repository_location(repository: &Repository, root: &Path) -> Result<()> {
    if repository.root() != root
        || repository.dot_dir() != root.join(".atomic")
        || repository.database_path() != root.join(".atomic/atomic.redb")
    {
        return Err(invalid(
            "recorded repository resolved a foreign common store",
        ));
    }
    Ok(())
}

fn require_code_free(root: &Path) -> Result<()> {
    durable::identity(root, true)?;
    for entry in std::fs::read_dir(root)? {
        if entry?.file_name() != std::ffi::OsStr::new(".atomic") {
            return Err(invalid(
                "recorded native owner is no longer code-free; no repair attempted",
            ));
        }
    }
    durable::identity(&root.join(".atomic"), true)?;
    if root.join(".atomic/repository").symlink_metadata().is_ok()
        || root.join(".atomic-sandbox").symlink_metadata().is_ok()
    {
        return Err(invalid(
            "recorded canonical restore contains an unowned repository pointer",
        ));
    }
    Ok(())
}

fn validate_views(header: &Header) -> Result<Vec<ViewManifest>> {
    if header.views.is_empty()
        || header.views.len() > 128
        || !safe_view(&header.source_state.view)
        || [
            &header.source_state.own_merkle,
            &header.source_state.effective_state,
        ]
        .iter()
        .any(|value| {
            Hash::from_base32(value.as_bytes()).is_none_or(|hash| hash.to_base32() != **value)
        })
    {
        return Err(invalid(
            "recorded closure has no bounded safe view hierarchy or state",
        ));
    }
    let mut views = Vec::with_capacity(header.views.len());
    let mut names = BTreeSet::new();
    for text in &header.views {
        let view = ViewManifest::parse(text).map_err(native)?;
        view.verify().map_err(native)?;
        if !safe_view(&view.name)
            || !names.insert(view.name.clone())
            || view.parent.as_deref().is_some_and(|name| !safe_view(name))
            || view.to_text() != *text
        {
            return Err(invalid(
                "recorded view names or manifest encoding are unsafe",
            ));
        }
        if view.parent.as_deref()
            != views
                .last()
                .map(|previous: &ViewManifest| previous.name.as_str())
        {
            return Err(invalid("recorded view hierarchy is not exact root-to-leaf"));
        }
        views.push(view);
    }
    let leaf = views
        .last()
        .ok_or(invalid("recorded view hierarchy is empty"))?;
    if leaf.name != header.source_state.view
        || leaf.state.to_base32() != header.source_state.own_merkle
    {
        return Err(invalid(
            "recorded source state differs from exact view hierarchy",
        ));
    }
    Ok(views)
}

fn validate_conflict(
    bytes: &[u8],
    expected: &RecordedConflictRef,
    objects: &BTreeSet<Hash>,
) -> Result<ConflictSetObject> {
    if expected.length != bytes.len() as u64
        || expected.length > MAX_CONFLICT_BYTES
        || digest(bytes) != expected.sha256
    {
        return Err(invalid("recorded conflict object bytes differ"));
    }
    let conflict = ConflictSetObject::decode(bytes).map_err(native)?;
    conflict.validate().map_err(native)?;
    if conflict.is_empty()
        || conflict.canonical_bytes().map_err(native)? != bytes
        || conflict.hash().map_err(native)?.to_base32() != expected.native_hash
        || conflict.files.len() as u64 != expected.file_count
        || conflict.entry_count() as u64 != expected.entry_count
    {
        return Err(invalid(
            "recorded conflict object identity or counts differ",
        ));
    }
    parse_hash(&expected.native_hash)?;
    for file in &conflict.files {
        let path = std::str::from_utf8(&file.path).map_err(native)?;
        if !safe_file(path) || file.entries.len() > MAX_FILES {
            return Err(invalid("unsafe or oversized recorded conflict paths"));
        }
        for entry in &file.entries {
            for claimant in &entry.claimants {
                if !safe_file(std::str::from_utf8(&claimant.path).map_err(native)?) {
                    return Err(invalid("unsafe recorded conflict claimant"));
                }
            }
            for side in entry.sides.iter().chain(entry.base.iter()) {
                if side.end < side.start || side.end.saturating_sub(side.start) > MAX_FILE_BYTES {
                    return Err(invalid("recorded conflict side exceeds bounds"));
                }
            }
        }
    }
    if conflict
        .side_changes()
        .iter()
        .any(|hash| *hash != Hash::NONE && !objects.contains(hash))
    {
        return Err(invalid(
            "recorded conflict side is missing from exact object closure",
        ));
    }
    Ok(conflict)
}

fn encode(header: &Header, objects: &NativeObjects, conflicts: &[u8]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(header)?;
    let length = objects
        .iter()
        .try_fold(MAGIC.len() + 8 + json.len(), |length, (_, bytes)| {
            length.checked_add(bytes.len())
        })
        .and_then(|length| length.checked_add(conflicts.len()))
        .ok_or(invalid("recorded closure length overflow"))?;
    if json.len() > MAX_HEADER || length as u64 > MAX_PAYLOAD {
        return Err(invalid("recorded closure exceeds payload budget"));
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(json.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&json);
    for (_, object) in objects {
        bytes.extend_from_slice(object);
    }
    bytes.extend_from_slice(conflicts);
    Ok(bytes)
}

fn decode(bytes: &[u8], expected: &RecordedClosure) -> Result<Decoded> {
    if expected.format != RECORDED_CLOSURE_FORMAT
        || expected.reader_version != RECORDED_CLOSURE_READER
        || expected.profile != RecordedClosureProfile::RecordedViewExact
        || expected.host != HostIdentity::default()
        || !bounded(&expected.operation_id)
        || !bounded(&expected.scope.workspace_id)
        || !bounded(&expected.scope.root_id)
        || uuid::Uuid::parse_str(&expected.scope.repository_id)
            .map_or(true, |id| id.to_string() != expected.scope.repository_id)
        || expected.scope.binding_epoch == 0
        || expected.capture_revision == 0
        || expected.object_count > MAX_OBJECTS as u64
        || expected.payload.length != bytes.len() as u64
        || expected.payload.length > MAX_PAYLOAD
        || expected.payload.sha256 != digest(bytes)
        || expected.payload.name != format!("recorded-{}.bin", expected.payload.sha256)
        || !bytes.starts_with(MAGIC)
        || bytes.len() < MAGIC.len() + 8
    {
        return Err(invalid(
            "unsupported or mismatched recorded closure receipt",
        ));
    }
    let prefix = MAGIC.len() + 8;
    let size: [u8; 8] = bytes[MAGIC.len()..prefix].try_into().map_err(native)?;
    let length = usize::try_from(u64::from_be_bytes(size)).map_err(native)?;
    let mut offset = prefix
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(invalid("truncated recorded closure header"))?;
    if length > MAX_HEADER {
        return Err(invalid("recorded closure header exceeds budget"));
    }
    let header: Header = serde_json::from_slice(&bytes[prefix..offset])?;
    if serde_json::to_vec(&header)? != bytes[prefix..offset]
        || header.format != expected.format
        || header.reader_version != expected.reader_version
        || header.profile != expected.profile
        || header.operation_id != expected.operation_id
        || header.host != expected.host
        || header.scope != expected.scope
        || header.capture_revision != expected.capture_revision
        || header.source_state != expected.source_state
        || header.objects.len() as u64 != expected.object_count
        || header.conflict != expected.conflict
        || digest(&serde_json::to_vec(&header.views)?) != expected.view_manifest_digest
        || files_digest(&header.files, &header.directories)?
            != expected.materialization_manifest_digest
        || materialization_id(&expected.materialization_manifest_digest)?
            != expected.materialization_id
        || header.project.project_id().map_err(native)?.to_base32() != expected.project_id
        || header.project.hash.to_base32() != expected.project_identity_hash
    {
        return Err(invalid(
            "recorded closure manifest differs from retained source observation",
        ));
    }
    atomic_repository::verify_project_identity(&header.project, None).map_err(native)?;
    let views = validate_views(&header)?;
    validate_files(&header.files)?;
    validate_directories(&header.files, &header.directories)?;
    let mut objects = Vec::with_capacity(header.objects.len());
    let mut seen = BTreeSet::new();
    let mut dependencies = BTreeMap::new();
    for object in &header.objects {
        let hash = parse_hash(&object.hash)?;
        let length = usize::try_from(object.length).map_err(native)?;
        let next = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(invalid("truncated recorded native object"))?;
        let content = &bytes[offset..next];
        let (change, actual) =
            Change::deserialize(&mut std::io::Cursor::new(content)).map_err(native)?;
        if actual != hash
            || digest(content) != object.sha256
            || change.kind().is_snapshot()
            || seen.contains(&hash)
            || change
                .dependencies()
                .iter()
                .any(|dependency| *dependency != Hash::NONE && !seen.contains(dependency))
        {
            return Err(invalid(
                "recorded native object is private, mismatched or dependency-incomplete",
            ));
        }
        seen.insert(hash);
        if change
            .hashed
            .extra_known
            .iter()
            .chain(change.causal_frontier().roots())
            .any(|hash| *hash != Hash::NONE && (!seen.contains(hash) || *hash == actual))
        {
            return Err(HostError::Unsupported(
                "recorded closure has external or unordered causal/context knowledge",
            ));
        }
        dependencies.insert(hash, change.dependencies().to_vec());
        objects.push((hash, content.to_vec()));
        offset = next;
    }
    let mut reachable = BTreeSet::new();
    let mut pending: Vec<_> = views
        .iter()
        .flat_map(|view| view.changes.iter().copied())
        .collect();
    while let Some(hash) = pending.pop() {
        if hash == Hash::NONE || !reachable.insert(hash) {
            continue;
        }
        let children = dependencies
            .get(&hash)
            .ok_or(invalid("view membership names an absent recorded object"))?;
        pending.extend(children.iter().copied());
    }
    if reachable != seen {
        return Err(invalid(
            "recorded closure contains foreign or omitted native objects",
        ));
    }
    let conflict = if let Some(reference) = &header.conflict {
        let length = usize::try_from(reference.length).map_err(native)?;
        let next = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(invalid("truncated recorded conflict object"))?;
        let conflict = validate_conflict(&bytes[offset..next], reference, &seen)?;
        offset = next;
        Some(conflict)
    } else {
        None
    };
    if offset != bytes.len() {
        return Err(invalid("unexpected recorded closure trailing bytes"));
    }
    Ok(Decoded {
        header,
        views,
        objects,
        conflict,
    })
}

fn read_payload(host: &Host, reference: &SpoolRef) -> Result<Vec<u8>> {
    composition::read_spool(host, reference, MAX_PAYLOAD)
}
fn retain(host: &Host, bytes: &[u8]) -> Result<SpoolRef> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    let sha256 = digest(bytes);
    let reference = SpoolRef {
        name: format!("recorded-{sha256}.bin"),
        length: bytes.len() as u64,
        sha256,
    };
    let path = host.config.spool_dir.join(&reference.name);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            File::open(&host.config.spool_dir)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_payload(host, &reference)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(reference)
}

fn project_matches(repository: &Repository, expected: &ProjectIdentityRecord) -> Result<()> {
    let actual = repository
        .project_identity()
        .map_err(native)?
        .ok_or(invalid("restored recorded project identity is absent"))?;
    if actual.object != expected.object
        || actual.hash != expected.hash
        || actual.project_id().map_err(native)? != expected.project_id().map_err(native)?
    {
        return Err(invalid(
            "recorded project identity changed during private replay",
        ));
    }
    Ok(())
}

fn instantiate(decoded: &Decoded, root: &Path) -> Result<Repository> {
    let first = decoded
        .views
        .first()
        .ok_or(invalid("recorded closure has no root view"))?;
    durable::private_dir(root)?;
    let mut repository = Repository::init_with_view(root, &first.name).map_err(native)?;
    verify_repository_location(&repository, root)?;
    repository
        .ensure_project_identity(MintReason::Upgrade)
        .map_err(native)?;
    repository
        .adopt_remote_project_identity(&decoded.header.project)
        .map_err(native)?;
    project_matches(&repository, &decoded.header.project)?;
    repository
        .set_view_scope(&first.name, first.scope)
        .map_err(native)?;
    for (hash, bytes) in &decoded.objects {
        repository
            .import_change_bytes(hash, bytes)
            .map_err(native)?;
        crate::recording::sync_imported_object(&repository, &hash.to_base32())?;
    }
    for view in &decoded.views {
        repository.apply_view_manifest(view).map_err(native)?;
    }
    let working_copy = repository.require_working_copy_id().map_err(native)?;
    repository
        .set_current_view(working_copy, &decoded.header.source_state.view)
        .map_err(native)?;
    verify_semantics(&repository, decoded)?;
    Ok(repository)
}

fn verify_semantics(repository: &Repository, decoded: &Decoded) -> Result<StateToken> {
    project_matches(repository, &decoded.header.project)?;
    let (state, views, objects) =
        crate::native::snapshot_views(repository, &decoded.header.source_state.view)?;
    if state.own_merkle != decoded.header.source_state.own_merkle
        || views.iter().map(ViewManifest::to_text).collect::<Vec<_>>() != decoded.header.views
        || objects.iter().copied().collect::<BTreeSet<_>>()
            != decoded.objects.iter().map(|(hash, _)| *hash).collect()
    {
        return Err(invalid(
            "restored recorded semantic state differs from exact source closure",
        ));
    }
    Ok(state)
}

type RenderedFiles = (Manifest, BTreeMap<String, Vec<u8>>, Vec<DirectoryEntry>);

fn collect_files(repository: &Repository) -> Result<RenderedFiles> {
    collect_files_on(repository, repository.current_view())
}

fn collect_files_on(repository: &Repository, view: &str) -> Result<RenderedFiles> {
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    let mut directories = Vec::new();
    repository
        .materialize_view_entries(view, |entry| {
            if !safe_file(&entry.path) {
                return Err(invalid("recorded materialization path is unsafe"));
            }
            if entry.kind == ViewEntryKind::Directory {
                if entry.mode != 0o755 || !entry.content.is_empty() {
                    return Err(HostError::Unsupported(
                        "recorded native directory mode is unqualified",
                    ));
                }
                directories.push(DirectoryEntry {
                    path: entry.path,
                    mode: u32::from(entry.mode),
                });
                return Ok(());
            }
            let (kind, mode) = match entry.kind {
                ViewEntryKind::File if entry.mode == 0o644 => (SnapshotKind::Regular, 0o100_644),
                ViewEntryKind::File if entry.mode == 0o755 => (SnapshotKind::Executable, 0o100_755),
                ViewEntryKind::Symlink => (SnapshotKind::Symlink, 0o120_000),
                _ => {
                    return Err(HostError::Unsupported(
                        "recorded native mode or file kind is unqualified",
                    ));
                }
            };
            if entry.content.len() as u64 > MAX_FILE_BYTES
                || entries.len() >= MAX_FILES
                || (kind == SnapshotKind::Symlink
                    && (entry.content.is_empty()
                        || entry.content.len() > 4096
                        || entry.content.contains(&0)))
            {
                return Err(invalid("recorded materialization exceeds file bounds"));
            }
            entries.push(SnapshotEntry {
                path: entry.path.clone(),
                kind,
                mode,
                length: entry.content.len() as u64,
                sha256: digest(&entry.content),
            });
            if files.insert(entry.path, entry.content).is_some() {
                return Err(HostError::Unsupported(
                    "recorded paths have no unambiguous materialization",
                ));
            }
            Ok(())
        })
        .map_err(native)??;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = Manifest {
        policy_version: 1,
        materializer_version: RECORDED_MATERIALIZER_VERSION,
        entries,
    };
    validate_files(&manifest)?;
    directories.sort_by(|left, right| left.path.cmp(&right.path));
    validate_directories(&manifest, &directories)?;
    Ok((manifest, files, directories))
}

fn verify_conflict_row_coverage(
    repository: &Repository,
    view: &str,
    conflict: Option<&ConflictSetObject>,
) -> Result<()> {
    // Native capture deliberately omits marker-only rows without graph sides
    // or claimants. Such a row must not disappear behind another capturable
    // conflict. Match each persisted path/kind once, without relying on local
    // inode IDs or requiring marker positions on an unmaterialized source.
    let mut represented: BTreeMap<Vec<u8>, Vec<_>> = conflict
        .into_iter()
        .flat_map(|conflict| &conflict.files)
        .map(|file| {
            (
                file.path.clone(),
                file.entries
                    .iter()
                    .map(|entry| entry.kind.to_stored())
                    .collect(),
            )
        })
        .collect();
    let transaction = repository.pristine().read_txn().map_err(native)?;
    let view = transaction
        .get_view(view)
        .map_err(native)?
        .ok_or(invalid("recorded conflict view disappeared"))?;
    for (_, rows) in transaction.iter_conflicts(view.id).map_err(native)? {
        for row in rows {
            let represented_kind = represented.get_mut(row.path.as_bytes()).and_then(|kinds| {
                kinds
                    .iter()
                    .position(|kind| *kind == row.kind)
                    .map(|index| kinds.swap_remove(index))
            });
            if represented_kind.is_none() {
                return Err(HostError::Unsupported(
                    "persisted native conflict row has no complete graph-backed representation",
                ));
            }
        }
    }
    // An unmaterialized source may have no cached rows. The independently
    // replayed graph object remains authoritative for the archived conflicts.
    Ok(())
}

fn materialize_and_conflicts(
    repository: &Repository,
    expected: Option<&ConflictSetObject>,
) -> Result<Option<ConflictSetObject>> {
    // Pure inspection rejects attributes before the full native materializer can
    // write them and choose a filter policy. Source directories are never used.
    collect_files(repository)?;
    let working_copy = repository.require_working_copy_id().map_err(native)?;
    let result = repository.materialize(working_copy).map_err(native)?;
    if result.files_truncated != 0 {
        return Err(HostError::Unsupported(
            "recorded native output was truncated",
        ));
    }
    let conflict = repository
        .capture_view_conflict_set(repository.current_view())
        .map_err(native)?;
    verify_conflict_row_coverage(repository, repository.current_view(), conflict.as_ref())?;
    if result.has_conflicts() && conflict.is_none() {
        return Err(HostError::Unsupported(
            "native conflict rows have no complete graph-backed conflict object",
        ));
    }
    match (expected, &conflict) {
        (Some(expected), Some(actual)) if actual.normalized() == expected.normalized() => {
            repository
                .verify_restored_conflict_state(repository.current_view(), expected)
                .map_err(native)?;
        }
        (Some(_), _) => return Err(invalid("restored native conflicts lost sides or claimants")),
        (None, _) => {}
    }
    Ok(conflict)
}

fn directory_inventory(root: &Path, current: &Path) -> Result<BTreeMap<String, u32>> {
    let mut result = BTreeMap::new();
    for child in std::fs::read_dir(current)? {
        let child = child?;
        if current == root && child.file_name() == std::ffi::OsStr::new(".atomic") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(child.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let path = child
                .path()
                .strip_prefix(root)
                .map_err(native)?
                .to_str()
                .ok_or(invalid("non-UTF8 recorded directory"))?
                .to_owned();
            if !safe_file(&path) || result.len() >= MAX_FILES {
                return Err(invalid("unsafe or oversized recorded directory inventory"));
            }
            result.insert(path, metadata.permissions().mode() & 0o777);
            result.extend(directory_inventory(root, &child.path())?);
        }
    }
    Ok(result)
}

fn verify_files_directory(
    root: &Path,
    files: &Manifest,
    directories: &[DirectoryEntry],
) -> Result<()> {
    baselines::verify_materialization(root, &files.entries)?;
    let expected: BTreeMap<_, _> = directories
        .iter()
        .map(|directory| (directory.path.clone(), directory.mode))
        .collect();
    if directory_inventory(root, root)? != expected {
        return Err(invalid("recorded materialization directory state differs"));
    }
    Ok(())
}

fn verify_materialized_output(
    repository: &Repository,
    files: &Manifest,
    directories: &[DirectoryEntry],
) -> Result<()> {
    let expected: BTreeSet<_> = files.entries.iter().map(|file| file.path.clone()).collect();
    if composition::native_inventory(repository.root(), repository.root())? != expected {
        return Err(invalid(
            "recorded native materialization contains omitted or unexpected files",
        ));
    }
    baselines::verify_materialized_entries(repository.root(), &files.entries)?;
    let expected: BTreeMap<_, _> = directories
        .iter()
        .map(|directory| (directory.path.clone(), directory.mode))
        .collect();
    if directory_inventory(repository.root(), repository.root())? != expected {
        return Err(invalid("native recorded directory materialization differs"));
    }
    Ok(())
}

fn copy_materialization(
    repository: &Repository,
    target: &Path,
    manifest: &Manifest,
    contents: &BTreeMap<String, Vec<u8>>,
    directories: &[DirectoryEntry],
) -> Result<()> {
    durable::private_dir(target)?;
    for directory in directories {
        let path = target.join(&directory.path);
        durable::private_dir(&path)?;
    }
    for entry in &manifest.entries {
        let path = target.join(&entry.path);
        let mut parent = target.to_owned();
        for component in Path::new(&entry.path)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .components()
        {
            parent.push(component);
            durable::private_dir(&parent)?;
        }
        if entry.kind == SnapshotKind::Symlink {
            use std::os::unix::ffi::OsStringExt;
            std::os::unix::fs::symlink(
                std::ffi::OsString::from_vec(contents[&entry.path].clone()),
                &path,
            )?;
        } else {
            let mode = if entry.kind == SnapshotKind::Executable {
                0o755
            } else {
                0o644
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&path)?;
            file.write_all(&contents[&entry.path])?;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
        }
        File::open(parent)?.sync_all()?;
    }
    for directory in directories.iter().rev() {
        let path = target.join(&directory.path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(directory.mode))?;
        File::open(path)?.sync_all()?;
    }
    verify_files_directory(target, manifest, directories)?;
    // Keep the independent native graph code-free. Conflict rows are retained
    // in its private database; replay observes this graph without writing.
    for entry in &manifest.entries {
        std::fs::remove_file(repository.root().join(&entry.path))?;
    }
    for directory in directories.iter().rev() {
        std::fs::remove_dir(repository.root().join(&directory.path))?;
    }
    require_code_free(repository.root())?;
    Ok(())
}

fn operation_directory(
    host: &Host,
    namespace: &str,
    operation: &str,
    command_digest: &str,
) -> Result<PathBuf> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    let parent = host.config.spool_dir.join(namespace);
    durable::private_dir(&parent)?;
    let root = parent.join(digest(operation.as_bytes()));
    let exists = root.symlink_metadata().is_ok();
    durable::private_dir(&root)?;
    let owner_path = root.join("owner.json");
    if exists {
        let owner: AttemptOwner = durable::read_json(&owner_path)?;
        if owner.command_digest != command_digest
            || owner.directory != durable::identity(&root, true)?
        {
            return Err(invalid(
                "recorded closure operation directory was replaced or reused",
            ));
        }
    } else {
        durable::write_json(
            &owner_path,
            &AttemptOwner {
                command_digest: command_digest.to_owned(),
                directory: durable::identity(&root, true)?,
            },
            false,
        )?;
    }
    let attempt = root.join(format!("attempt-{}", uuid::Uuid::new_v4()));
    durable::private_dir(&attempt)?;
    Ok(attempt)
}

impl Host {
    /// Export exact recorded view membership and complete native conflict state
    /// without materializing into the canonical store or user working directory.
    /// # Errors
    /// Refuses stale bindings, unsafe views, private snapshots, missing knowledge
    /// closure, unrepresentable output, filters, conflicting replay and budgets.
    pub fn export_recorded_closure(
        &self,
        request: &ExportRecordedClosureRequest,
    ) -> Result<RecordedClosure> {
        crate::embedding_policy::refuse_ambient_embedding()?;
        if !bounded(&request.operation_id)
            || !bounded(&request.scope.workspace_id)
            || !bounded(&request.scope.root_id)
            || request.capture_revision == 0
            || request.scope.repository_id != request.binding.repository_id
            || request.scope.binding_epoch != request.binding.binding_epoch
            || request.view != request.expected_state.view
            || !safe_view(&request.view)
        {
            return Err(HostError::StaleBinding);
        }
        // This existing owner retains a real original capture, not a DTO echo.
        let captured = self.capture_composition_target(&CaptureCompositionTargetRequest {
            operation_id: format!("recorded-{}", digest(request.operation_id.as_bytes())),
            scope: request.scope.clone(),
            binding: request.binding.clone(),
            view: request.view.clone(),
            expected_state: request.expected_state.clone(),
        })?;
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        let journals = self.config.config_dir.join("recorded-closure-operations");
        durable::private_dir(&journals)?;
        let path = journals.join(format!(
            "export-{}.json",
            digest(request.operation_id.as_bytes())
        ));
        let command_digest = digest(&serde_json::to_vec(request)?);
        let mut journal = if path.symlink_metadata().is_ok() {
            let journal: ExportJournal = durable::read_json(&path)?;
            if journal.request != *request || journal.command_digest != command_digest {
                return Err(invalid("conflicting recorded closure export replay"));
            }
            if let Some(receipt) = &journal.receipt {
                decode(&read_payload(self, &receipt.payload)?, receipt)?;
                return Ok(receipt.clone());
            }
            journal
        } else {
            let journal = ExportJournal {
                request: request.clone(),
                command_digest: command_digest.clone(),
                receipt: None,
            };
            durable::write_json(&path, &journal, false)?;
            journal
        };
        let capture = self.load_composition_capture(&captured)?;
        let store = self.cached_store(&request.binding)?;
        verify_repository_location(store.repository(), &request.binding.store_path)?;
        require_code_free(&request.binding.store_path)?;
        let (state, views, hashes) =
            crate::native::snapshot_views(store.repository(), &request.view)?;
        if state != request.expected_state
            || views.iter().map(ViewManifest::to_text).collect::<Vec<_>>() != capture.views
        {
            return Err(HostError::StaleBinding);
        }
        let project = store
            .repository()
            .project_identity()
            .map_err(native)?
            .ok_or(invalid("recorded source has no project identity"))?;
        atomic_repository::verify_project_identity(&project, None).map_err(native)?;
        let (original_files, _, original_directories) =
            collect_files_on(store.repository(), &request.view)?;
        let mut objects = Vec::with_capacity(capture.objects.len());
        for object in &capture.objects {
            objects.push((
                parse_hash(&object.hash)?,
                composition::read_spool(self, &object.bytes, MAX_PAYLOAD)?,
            ));
        }
        let attempt = operation_directory(
            self,
            "recorded-exports",
            &request.operation_id,
            &command_digest,
        )?;
        let provisional_files = Manifest {
            policy_version: 1,
            materializer_version: RECORDED_MATERIALIZER_VERSION,
            entries: vec![],
        };
        let mut header = Header {
            format: RECORDED_CLOSURE_FORMAT,
            reader_version: RECORDED_CLOSURE_READER,
            profile: RecordedClosureProfile::RecordedViewExact,
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            scope: request.scope.clone(),
            capture_revision: request.capture_revision,
            source_state: state.clone(),
            project,
            views: capture.views.clone(),
            files: provisional_files,
            directories: vec![],
            conflict: None,
            objects: objects
                .iter()
                .map(|(hash, bytes)| Object {
                    hash: hash.to_base32(),
                    sha256: digest(bytes),
                    length: bytes.len() as u64,
                })
                .collect(),
        };
        validate_views(&header)?;
        // Pure object/manifest validation precedes Repository::init: even the
        // provisional archive is never allowed to smuggle private snapshots.
        let mut receipt = receipt_for(request, &header, &objects, &[])?;
        let provisional = encode(&header, &objects, &[])?;
        receipt.payload = SpoolRef {
            name: format!("recorded-{}.bin", digest(&provisional)),
            length: provisional.len() as u64,
            sha256: digest(&provisional),
        };
        let decoded = decode(&provisional, &receipt)?;
        let repository = instantiate(&decoded, &attempt.join("native"))?;
        let conflict = materialize_and_conflicts(&repository, None)?;
        verify_conflict_row_coverage(store.repository(), &request.view, conflict.as_ref())?;
        let (files, _, directories) = collect_files(&repository)?;
        verify_materialized_output(&repository, &files, &directories)?;
        if files_digest(&files, &directories)?
            != files_digest(&original_files, &original_directories)?
        {
            return Err(HostError::Unsupported(
                "private native replay changes original named-view materialization",
            ));
        }
        let conflict_bytes = conflict
            .as_ref()
            .map(|conflict| conflict.canonical_bytes().map_err(native))
            .transpose()?
            .unwrap_or_default();
        header.files = files;
        header.directories = directories;
        header.conflict = conflict
            .as_ref()
            .map(|conflict| -> Result<RecordedConflictRef> {
                Ok(RecordedConflictRef {
                    native_hash: conflict.hash().map_err(native)?.to_base32(),
                    sha256: digest(&conflict_bytes),
                    length: conflict_bytes.len() as u64,
                    file_count: conflict.files.len() as u64,
                    entry_count: conflict.entry_count() as u64,
                })
            })
            .transpose()?;
        let bytes = encode(&header, &objects, &conflict_bytes)?;
        let mut receipt = receipt_for(request, &header, &objects, &conflict_bytes)?;
        receipt.payload = retain(self, &bytes)?;
        decode(&bytes, &receipt)?;
        let current = crate::native::snapshot_views(store.repository(), &request.view)?;
        if current.0 != state
            || current.1 != views
            || current.2 != hashes
            || store
                .repository()
                .project_identity()
                .map_err(native)?
                .as_ref()
                .map(|project| project.hash)
                != Some(header.project.hash)
        {
            return Err(HostError::StaleBinding);
        }
        journal.receipt = Some(receipt.clone());
        durable::write_json(&path, &journal, true)?;
        Ok(receipt)
    }

    /// Restore exact recorded graph, source project and native conflicts into a
    /// new private namespace. No old store, Git root or current source is read.
    /// # Errors
    /// Refuses corrupt/unsupported input before destination creation, stale
    /// scopes, incomplete conflict sides and changed semantic/materialized state.
    pub fn restore_recorded_closure(
        &self,
        request: &RestoreRecordedClosureRequest,
    ) -> Result<RecordedClosureRestore> {
        crate::embedding_policy::refuse_ambient_embedding()?;
        if !bounded(&request.operation_id) || request.expected_scope != request.closure.scope {
            return Err(HostError::StaleBinding);
        }
        let bytes = read_payload(self, &request.closure.payload)?;
        let decoded = decode(&bytes, &request.closure)?;
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        let journals = self.config.config_dir.join("recorded-closure-operations");
        durable::private_dir(&journals)?;
        let path = journals.join(format!(
            "restore-{}.json",
            digest(request.operation_id.as_bytes())
        ));
        let command_digest = digest(&serde_json::to_vec(request)?);
        let mut journal = if path.symlink_metadata().is_ok() {
            let journal: RestoreJournal = durable::read_json(&path)?;
            if journal.request != *request || journal.command_digest != command_digest {
                return Err(invalid("conflicting recorded closure restore replay"));
            }
            if let Some(receipt) = &journal.receipt {
                self.verify_recorded_restore(
                    receipt,
                    &decoded,
                    journal
                        .owner
                        .as_ref()
                        .ok_or(invalid("recorded restore has no retained filesystem owner"))?,
                )?;
                return Ok(receipt.clone());
            }
            journal
        } else {
            let journal = RestoreJournal {
                request: request.clone(),
                command_digest: command_digest.clone(),
                receipt: None,
                owner: None,
            };
            durable::write_json(&path, &journal, false)?;
            journal
        };
        let attempt = operation_directory(
            self,
            "recorded-restores",
            &request.operation_id,
            &command_digest,
        )?;
        let native_path = attempt.join("native");
        let repository = instantiate(&decoded, &native_path)?;
        let conflict = materialize_and_conflicts(&repository, decoded.conflict.as_ref())?;
        if conflict
            .as_ref()
            .map(|value| value.hash().map_err(native))
            .transpose()?
            != decoded
                .conflict
                .as_ref()
                .map(|value| value.hash().map_err(native))
                .transpose()?
        {
            return Err(invalid(
                "recorded restore introduced or dropped a native conflict",
            ));
        }
        let (files, contents, directories) = collect_files(&repository)?;
        if files_digest(&files, &directories)?
            != files_digest(&decoded.header.files, &decoded.header.directories)?
        {
            return Err(HostError::Unsupported(
                "fresh native conflict presentation differs from exact captured materialization",
            ));
        }
        verify_materialized_output(&repository, &files, &directories)?;
        let restored_state = verify_semantics(&repository, &decoded)?;
        let output = attempt.join("files");
        copy_materialization(&repository, &output, &files, &contents, &directories)?;
        durable::sync_tree(&native_path.join(".atomic"))?;
        let mut receipt = RecordedClosureRestore {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            scope: request.expected_scope.clone(),
            capture_revision: request.closure.capture_revision,
            source_state: request.closure.source_state.clone(),
            restored_state,
            project_id: request.closure.project_id.clone(),
            project_identity_hash: request.closure.project_identity_hash.clone(),
            view_manifest_digest: request.closure.view_manifest_digest.clone(),
            materialization_manifest_digest: request
                .closure
                .materialization_manifest_digest
                .clone(),
            materialization_id: request.closure.materialization_id.clone(),
            native_conflict_hash: request
                .closure
                .conflict
                .as_ref()
                .map(|conflict| conflict.native_hash.clone()),
            object_count: request.closure.object_count,
            native_path,
            path: output,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = digest(&serde_json::to_vec(&receipt)?);
        durable::write_json(&attempt.join("receipt.json"), &receipt, false)?;
        journal.owner = Some(RestoreFileOwner {
            attempt: durable::identity(&attempt, true)?,
            native: durable::identity(&receipt.native_path, true)?,
            database: durable::identity(&repository.database_path(), false)?,
            dot_directory: durable::identity(repository.dot_dir(), true)?,
            files: durable::identity(&receipt.path, true)?,
        });
        journal.receipt = Some(receipt.clone());
        durable::write_json(&path, &journal, true)?;
        Ok(receipt)
    }

    fn verify_recorded_restore(
        &self,
        receipt: &RecordedClosureRestore,
        decoded: &Decoded,
        owner: &RestoreFileOwner,
    ) -> Result<()> {
        let mut expected = receipt.clone();
        expected.receipt_digest.clear();
        let parent = receipt
            .native_path
            .parent()
            .ok_or(invalid("recorded restore has no owner"))?;
        let expected_parent = self
            .config
            .spool_dir
            .join("recorded-restores")
            .join(digest(receipt.operation_id.as_bytes()));
        if digest(&serde_json::to_vec(&expected)?) != receipt.receipt_digest
            || receipt.native_path.file_name() != Some(std::ffi::OsStr::new("native"))
            || receipt.path != parent.join("files")
            || parent.parent() != Some(expected_parent.as_path())
            || !parent
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("attempt-"))
                .is_some_and(|name| {
                    uuid::Uuid::parse_str(name).is_ok_and(|value| value.to_string() == name)
                })
        {
            return Err(invalid("recorded restore receipt or private owner differs"));
        }
        let retained: RecordedClosureRestore = durable::read_json(&parent.join("receipt.json"))?;
        if retained != *receipt {
            return Err(invalid(
                "recorded restore is not the retained original receipt",
            ));
        }
        if owner.attempt != durable::identity(parent, true)?
            || owner.native != durable::identity(&receipt.native_path, true)?
            || owner.database
                != durable::identity(&receipt.native_path.join(".atomic/atomic.redb"), false)?
            || owner.dot_directory != durable::identity(&receipt.native_path.join(".atomic"), true)?
            || owner.files != durable::identity(&receipt.path, true)?
        {
            return Err(invalid("recorded restore filesystem owner was replaced"));
        }
        // Existing restores are observations only. Never re-materialize, repair
        // or reopen them writable: an unexpected parent/pointer must not turn
        // replay verification into an effect on another directory/common store.
        require_code_free(&receipt.native_path)?;
        let repository =
            Repository::open_readonly_without_migration(&receipt.native_path).map_err(native)?;
        verify_repository_location(&repository, &receipt.native_path)?;
        let actual = verify_semantics(&repository, decoded)?;
        if actual != receipt.restored_state {
            return Err(HostError::StaleBinding);
        }
        let conflict = repository
            .capture_view_conflict_set(&decoded.header.source_state.view)
            .map_err(native)?;
        verify_conflict_row_coverage(
            &repository,
            &decoded.header.source_state.view,
            conflict.as_ref(),
        )?;
        if conflict
            .as_ref()
            .map(|value| value.hash().map_err(native))
            .transpose()?
            != decoded
                .conflict
                .as_ref()
                .map(|value| value.hash().map_err(native))
                .transpose()?
        {
            return Err(invalid("recorded restore conflict state changed"));
        }
        let (files, _, directories) =
            collect_files_on(&repository, &decoded.header.source_state.view)?;
        if files_digest(&files, &directories)?
            != files_digest(&decoded.header.files, &decoded.header.directories)?
        {
            return Err(HostError::StaleBinding);
        }
        verify_files_directory(&receipt.path, &files, &directories)?;
        Ok(())
    }
}

fn receipt_for(
    request: &ExportRecordedClosureRequest,
    header: &Header,
    objects: &NativeObjects,
    conflicts: &[u8],
) -> Result<RecordedClosure> {
    let files_digest = files_digest(&header.files, &header.directories)?;
    let bytes = encode(header, objects, conflicts)?;
    let sha256 = digest(&bytes);
    Ok(RecordedClosure {
        format: RECORDED_CLOSURE_FORMAT,
        reader_version: RECORDED_CLOSURE_READER,
        profile: RecordedClosureProfile::RecordedViewExact,
        operation_id: request.operation_id.clone(),
        host: HostIdentity::default(),
        scope: request.scope.clone(),
        capture_revision: request.capture_revision,
        source_state: request.expected_state.clone(),
        project_id: header.project.project_id().map_err(native)?.to_base32(),
        project_identity_hash: header.project.hash.to_base32(),
        view_manifest_digest: digest(&serde_json::to_vec(&header.views)?),
        materialization_manifest_digest: files_digest.clone(),
        materialization_id: materialization_id(&files_digest)?,
        conflict: header.conflict.clone(),
        object_count: objects.len() as u64,
        payload: SpoolRef {
            name: format!("recorded-{sha256}.bin"),
            length: bytes.len() as u64,
            sha256,
        },
    })
}

#[cfg(test)]
mod tests;
