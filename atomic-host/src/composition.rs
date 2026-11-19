//! Real private native composition. This API never writes a live target and
//! cannot authorize adoption; services still need qualified target barriers.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use atomic_core::change::{Change, GraphOp, InodeAttr, InodeKind};
use atomic_core::{Base32, Hash};
use atomic_repository::{InsertOptions, Repository, ViewEntryKind};
use intent_atomic_proto::baselines::{BASELINE_POLICY_VERSION, MATERIALIZER_VERSION};
use intent_atomic_proto::composition::{
    CompositionInventory, CompositionStateManifest, ExactCompositionChange,
    PrivateCompositionInput, PrivateCompositionOutcome, PrivateCompositionReceipt,
};
use intent_atomic_proto::{HostIdentity, SpoolRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    baselines::{self, Manifest, SnapshotEntry, SnapshotKind},
    durable, Host, HostError, Result,
};

const MAX_OBJECTS: usize = 4096;
const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn parse_hash(value: &str) -> Result<Hash> {
    let hash = Hash::from_base32(value.as_bytes())
        .ok_or(HostError::Invalid("invalid composition change hash"))?;
    if hash == Hash::NONE || hash.to_base32() != value {
        return Err(HostError::Invalid("noncanonical composition change hash"));
    }
    Ok(hash)
}
fn hash_strings(hashes: impl IntoIterator<Item = Hash>) -> Vec<String> {
    hashes.into_iter().map(|hash| hash.to_base32()).collect()
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(HostError::Invalid(
            "composition object exceeds its read budget",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(native)? > limit {
        return Err(HostError::Invalid(
            "composition object exceeds its read budget",
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_spool(host: &Host, reference: &SpoolRef, limit: u64) -> Result<Vec<u8>> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    if reference.name.is_empty()
        || reference.name.len() > 128
        || reference.name.starts_with('.')
        || !reference
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || reference.length > limit
    {
        return Err(HostError::Invalid(
            "invalid private composition spool reference",
        ));
    }
    let bytes = read_file(&host.config.spool_dir.join(&reference.name), limit)?;
    if u64::try_from(bytes.len()).map_err(native)? != reference.length
        || digest(&bytes) != reference.sha256
    {
        return Err(HostError::Invalid(
            "private composition object digest changed",
        ));
    }
    Ok(bytes)
}

fn retain(host: &Host, bytes: &[u8]) -> Result<SpoolRef> {
    retain_bytes(host, bytes, MAX_METADATA_BYTES)
}

pub(crate) fn retain_bytes(host: &Host, bytes: &[u8], limit: u64) -> Result<SpoolRef> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    let sha256 = digest(bytes);
    let reference = SpoolRef {
        name: format!("composition-{sha256}.bin"),
        length: u64::try_from(bytes.len()).map_err(native)?,
        sha256,
    };
    if reference.length > limit {
        return Err(HostError::Invalid("composition metadata exceeds its bound"));
    }
    let path = host.config.spool_dir.join(&reference.name);
    if path.try_exists()? {
        read_spool(host, &reference, limit)?;
        return Ok(reference);
    }
    let temporary = host
        .config
        .spool_dir
        .join(format!(".pending-composition-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::hard_link(&temporary, &path)?;
    std::fs::remove_file(&temporary)?;
    File::open(&host.config.spool_dir)?.sync_all()?;
    Ok(reference)
}

struct Object {
    bytes: Vec<u8>,
    change: Change,
}
struct Expansion<'a> {
    host: &'a Host,
    repository: &'a Repository,
    pool: BTreeMap<Hash, &'a ExactCompositionChange>,
    objects: BTreeMap<Hash, Object>,
    visiting: BTreeSet<Hash>,
    seen: BTreeSet<Hash>,
    order: Vec<Hash>,
    bytes: u64,
}

impl Expansion<'_> {
    fn visit(&mut self, root: Hash) -> Result<()> {
        // History depth does not consume the host thread's call stack.
        let mut stack = vec![(root, false)];
        while let Some((hash, finish)) = stack.pop() {
            if hash == Hash::NONE || self.seen.contains(&hash) {
                continue;
            }
            if finish {
                self.visiting.remove(&hash);
                self.seen.insert(hash);
                self.order.push(hash);
                continue;
            }
            if !self.visiting.insert(hash) {
                return Err(HostError::Invalid("cyclic native composition dependency"));
            }
            if self.objects.len() >= MAX_OBJECTS {
                return Err(HostError::Invalid(
                    "composition closure exceeds object budget",
                ));
            }
            let bytes = if self.repository.has_change(&hash) {
                read_file(
                    &self.repository.change_store().change_path(&hash),
                    MAX_OBJECT_BYTES,
                )?
            } else {
                let source = self.pool.get(&hash).ok_or(HostError::Invalid(
                    "composition dependency bytes are unavailable",
                ))?;
                read_spool(self.host, &source.bytes, MAX_OBJECT_BYTES)?
            };
            self.bytes = self
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(native)?)
                .filter(|bytes| *bytes <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid(
                    "composition closure exceeds byte budget",
                ))?;
            let (change, actual) =
                Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
            if actual != hash || change.kind().is_snapshot() {
                return Err(HostError::Invalid(
                    "composition object is mismatched or a private snapshot",
                ));
            }
            if change.hunks().iter().any(|operation| {
                matches!(
                    operation,
                    GraphOp::SetAttr {
                        value: InodeAttr::Kind(InodeKind::Gitlink),
                        ..
                    }
                )
            }) {
                return Err(HostError::Unsupported(
                    "composition of gitlinks is not qualified",
                ));
            }
            let dependencies = change.dependencies().to_vec();
            if dependencies.len() > MAX_OBJECTS {
                return Err(HostError::Invalid(
                    "composition object exceeds dependency budget",
                ));
            }
            self.objects.insert(hash, Object { bytes, change });
            stack.push((hash, true));
            for dependency in dependencies.into_iter().rev() {
                if dependency != Hash::NONE && !self.seen.contains(&dependency) {
                    stack.push((dependency, false));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    operation_id: String,
    command_digest: String,
    input: SpoolRef,
    outcome: Option<PrivateCompositionOutcome>,
    materialization_directory: Option<durable::FileIdentity>,
    native_database: Option<durable::FileIdentity>,
}

fn import_order(
    repository: &Repository,
    objects: &BTreeMap<Hash, Object>,
    order: &[Hash],
    view: &str,
) -> Result<()> {
    let mut present: BTreeSet<_> = repository
        .view_manifest(view)
        .map_err(native)?
        .changes
        .into_iter()
        .collect();
    for hash in order {
        if present.contains(hash) {
            continue;
        }
        if !repository.has_change(hash) {
            repository
                .import_change_bytes(hash, &objects[hash].bytes)
                .map_err(native)?;
            crate::recording::sync_imported_object(repository, &hash.to_base32())?;
        }
        repository
            .insert_change(hash, InsertOptions::default().view(view))
            .map_err(native)?;
        present.insert(*hash);
    }
    Ok(())
}

fn collect_files(
    repository: &Repository,
    policy: &intent_atomic_proto::baselines::BaselinePolicy,
) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let mut files = BTreeMap::new();
    let mut entries = Vec::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    repository
        .materialize_view_entries(repository.current_view(), |entry| {
            if !baselines::source::safe_path(&entry.path)
                || baselines::source::excluded(&entry.path, policy)
                || (!policy.case_sensitive
                    && (!entry.path.is_ascii() || !folded.insert(entry.path.to_ascii_lowercase())))
            {
                return Err(HostError::Invalid(
                    "composed path violates its file or destination policy",
                ));
            }
            if entry.kind == ViewEntryKind::Directory {
                return Ok(());
            }
            let (kind, mode) = match entry.kind {
                ViewEntryKind::File if entry.mode == 0o644 => (SnapshotKind::Regular, 0o100_644),
                ViewEntryKind::File if entry.mode == 0o755 => (SnapshotKind::Executable, 0o100_755),
                ViewEntryKind::Symlink => (SnapshotKind::Symlink, 0o120_000),
                _ => {
                    return Err(HostError::Unsupported(
                        "composed native kind or mode is unqualified",
                    ));
                }
            };
            total = total
                .checked_add(u64::try_from(entry.content.len()).map_err(native)?)
                .filter(|bytes| *bytes <= 128 * 1024 * 1024)
                .ok_or(HostError::Invalid(
                    "composed materialization exceeds byte budget",
                ))?;
            if entry.content.len() > 32 * 1024 * 1024
                || entries.len() >= baselines::source::MAX_FILES
            {
                return Err(HostError::Invalid(
                    "composed materialization exceeds file budget",
                ));
            }
            entries.push(SnapshotEntry {
                path: entry.path.clone(),
                kind,
                mode,
                length: u64::try_from(entry.content.len()).map_err(native)?,
                sha256: digest(&entry.content),
            });
            if files.insert(entry.path, entry.content).is_some() {
                return Err(HostError::Invalid("composed native paths are ambiguous"));
            }
            Ok(())
        })
        .map_err(native)??;
    for path in files.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(ancestor) = parent {
            if files.contains_key(
                ancestor
                    .to_str()
                    .ok_or(HostError::Invalid("non UTF-8 candidate path"))?,
            ) {
                return Err(HostError::Invalid(
                    "file is an ancestor of another candidate path",
                ));
            }
            parent = ancestor.parent();
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((
        Manifest {
            policy_version: BASELINE_POLICY_VERSION,
            materializer_version: MATERIALIZER_VERSION,
            entries,
        },
        files,
    ))
}

fn native_materialize(repository: &Repository, manifest: &Manifest) -> Result<()> {
    let working_copy = repository.require_working_copy_id().map_err(native)?;
    let ordinary: HashSet<_> = manifest
        .entries
        .iter()
        .filter(|entry| {
            Path::new(&entry.path).file_name() != Some(std::ffi::OsStr::new(".gitattributes"))
        })
        .map(|entry| entry.path.clone())
        .collect();
    if !ordinary.is_empty() {
        repository
            .materialize_paths(working_copy, ordinary)
            .map_err(native)?;
    }
    let mut attributes: Vec<_> = manifest
        .entries
        .iter()
        .filter(|entry| {
            Path::new(&entry.path).file_name() == Some(std::ffi::OsStr::new(".gitattributes"))
        })
        .map(|entry| entry.path.clone())
        .collect();
    attributes.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for path in attributes {
        repository
            .materialize_paths(working_copy, HashSet::from([path]))
            .map_err(native)?;
    }
    if manifest.entries.is_empty() {
        repository.materialize(working_copy).map_err(native)?;
    }
    let expected: BTreeSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    if native_inventory(repository.root(), repository.root())? != expected {
        return Err(HostError::StaleBinding);
    }
    baselines::verify_materialized_entries(repository.root(), &manifest.entries)
}

pub(crate) fn native_inventory(root: &Path, current: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    for child in std::fs::read_dir(current)? {
        let child = child?;
        if current == root && child.file_name() == std::ffi::OsStr::new(".atomic") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(child.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            files.extend(native_inventory(root, &child.path())?);
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            let relative = child
                .path()
                .strip_prefix(root)
                .map_err(native)?
                .to_str()
                .ok_or(HostError::Invalid("non UTF-8 native output"))?
                .to_owned();
            if !baselines::source::safe_path(&relative) {
                return Err(HostError::Invalid("unsafe native output path"));
            }
            files.insert(relative);
        } else {
            return Err(HostError::Invalid("special file in native output"));
        }
        if files.len() > baselines::source::MAX_FILES {
            return Err(HostError::Invalid("native output exceeds file budget"));
        }
    }
    Ok(files)
}

fn copy_files(
    source: &Path,
    destination: &Path,
    manifest: &Manifest,
    contents: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    durable::private_dir(destination)?;
    for entry in &manifest.entries {
        let target = destination.join(&entry.path);
        let parent = target
            .parent()
            .ok_or(HostError::Invalid("candidate parent unavailable"))?;
        let mut path = destination.to_owned();
        for component in parent
            .strip_prefix(destination)
            .map_err(native)?
            .components()
        {
            path.push(component);
            durable::private_dir(&path)?;
        }
        if entry.kind == SnapshotKind::Symlink {
            use std::os::unix::ffi::OsStringExt;
            std::os::unix::fs::symlink(
                std::ffi::OsString::from_vec(contents[&entry.path].clone()),
                &target,
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
                .open(&target)?;
            file.write_all(&contents[&entry.path])?;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
        }
        File::open(parent)?.sync_all()?;
        // Keep the frozen native root code-free after actual materialization;
        // future graph reads cannot consult physical attribute files.
        std::fs::remove_file(source.join(&entry.path))?;
    }
    baselines::verify_materialization(destination, &manifest.entries)
}

fn conflict_summaries(
    conflict: Option<&atomic_repository::ConflictSetObject>,
) -> Result<Vec<intent_atomic_proto::composition::CompositionConflict>> {
    use intent_atomic_proto::composition::{
        CompositionConflict, CompositionConflictClaimant, CompositionConflictSide,
    };
    let side = |side: &atomic_repository::ConflictSideObject| CompositionConflictSide {
        change: side.change.to_base32(),
        start: side.start,
        end: side.end,
        content: side.content.to_base32(),
        mode: side.mode,
        kind: match side.kind.to_file_kind() {
            atomic_core::operation::FileKind::Regular => "regular",
            atomic_core::operation::FileKind::Symlink => "symlink",
            atomic_core::operation::FileKind::Gitlink => "gitlink",
            atomic_core::operation::FileKind::Directory => "directory",
        }
        .into(),
    };
    let mut summaries = Vec::new();
    if let Some(conflict) = conflict {
        for file in &conflict.files {
            for entry in &file.entries {
                summaries.push(CompositionConflict {
                    path: String::from_utf8(file.path.clone()).map_err(native)?,
                    kind: entry.kind.as_str().into(),
                    line: entry.line,
                    base: entry.base.as_ref().map(side),
                    sides: entry.sides.iter().map(side).collect(),
                    claimants: entry
                        .claimants
                        .iter()
                        .map(|claimant| CompositionConflictClaimant {
                            change: claimant.change.to_base32(),
                            inode: claimant.inode,
                            path: claimant.path.clone(),
                            directory: claimant.directory,
                        })
                        .collect(),
                });
            }
        }
    }
    Ok(summaries)
}

impl Host {
    /// Read a bounded immutable owner spool input for the private protocol.
    /// # Errors
    /// Refuses changed bytes and returns exact native preparation refusals.
    pub fn compose_private_spooled(&self, input: &SpoolRef) -> Result<PrivateCompositionOutcome> {
        let input: PrivateCompositionInput =
            serde_json::from_slice(&read_spool(self, input, MAX_METADATA_BYTES)?)?;
        self.compose_private(&input)
    }

    /// Compose in a new private store and inspect the actual native result.
    /// This is a qualification API and never an adoption or target write.
    /// # Errors
    /// Refuses stale bases, invalid closure bytes, unsafe outputs and uncertainty.
    pub fn compose_private(
        &self,
        input: &PrivateCompositionInput,
    ) -> Result<PrivateCompositionOutcome> {
        if input.operation_id.is_empty()
            || input.operation_id.len() > 256
            || input.operation_id.chars().any(char::is_control)
            || input.available_changes.len() > MAX_OBJECTS
            || input.selected_changes.len() > MAX_OBJECTS
            || input.target_changes.len() > MAX_OBJECTS
            || input.scope != input.target.scope
            || input.scope != input.inherited_baseline.scope
            || input.scope.repository_id != input.target.baseline.baseline.repository_id
            || input.scope.binding_epoch != input.target.baseline.baseline.binding_epoch
        {
            return Err(HostError::StaleBinding);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let command = serde_json::to_vec(input)?;
        let command_digest = digest(&command);
        let input_ref = retain(self, &command)?;
        let journals = self.config.config_dir.join("composition-operations");
        durable::private_dir(&journals)?;
        let journal_path = journals.join(format!("{}.json", digest(input.operation_id.as_bytes())));
        let mut journal = if journal_path.try_exists()? {
            let journal: Journal = durable::read_json(&journal_path)?;
            if journal.command_digest != command_digest || journal.input != input_ref {
                return Err(HostError::Invalid("conflicting private composition replay"));
            }
            if let Some(outcome) = journal.outcome {
                if let PrivateCompositionOutcome::Composed { receipt } = &outcome {
                    if journal.materialization_directory.as_ref()
                        != Some(&durable::identity(&receipt.candidate_path, true)?)
                        || journal.native_database.as_ref()
                            != Some(&durable::identity(
                                &receipt
                                    .candidate_path
                                    .parent()
                                    .ok_or(HostError::StaleBinding)?
                                    .join("native/.atomic/atomic.redb"),
                                false,
                            )?)
                    {
                        return Err(HostError::StaleBinding);
                    }
                    self.verify_composition_receipt(receipt)?;
                }
                return Ok(outcome);
            }
            return Err(HostError::Uncertain(input.operation_id.clone()));
        } else {
            let journal = Journal {
                operation_id: input.operation_id.clone(),
                command_digest: command_digest.clone(),
                input: input_ref,
                outcome: None,
                materialization_directory: None,
                native_database: None,
            };
            durable::write_json(&journal_path, &journal, false)?;
            journal
        };
        let compositions = self.config.spool_dir.join("compositions");
        durable::private_dir(&compositions)?;
        let directory = compositions.join(&command_digest);
        if directory.try_exists()? {
            return Err(HostError::Uncertain(input.operation_id.clone()));
        }
        durable::private_dir(&directory)?;
        let seed = self.portable_baseline_seed(&input.target)?;
        let policy = seed.receipt.policy.clone();
        let mut repository = if let Some(capture) = &input.captured_target {
            if capture.scope != input.scope
                || capture.state != input.expected_target
                || !input.target_changes.is_empty()
            {
                return Err(HostError::StaleBinding);
            }
            self.load_composition_capture(capture)?
                .instantiate(self, &directory.join("native"))?
        } else {
            if input.expected_target != seed.receipt.native_state
                || !input.target_changes.is_empty()
            {
                return Err(HostError::Unsupported(
                    "authored target requires an original host capture",
                ));
            }
            seed.instantiate(&directory.join("native"))?
        };
        drop(seed);
        let inherited_seed = self.portable_baseline_seed(&input.inherited_baseline)?;
        let inherited: BTreeSet<_> = inherited_seed.view.changes.iter().copied().collect();
        drop(inherited_seed);
        let mut pool = BTreeMap::new();
        for change in &input.available_changes {
            if pool.insert(parse_hash(&change.hash)?, change).is_some() {
                return Err(HostError::Invalid("duplicate available composition object"));
            }
        }
        let selected: BTreeSet<_> = input
            .selected_changes
            .iter()
            .map(|hash| parse_hash(hash))
            .collect::<Result<_>>()?;
        if selected.len() != input.selected_changes.len() {
            return Err(HostError::Invalid("duplicate composition selection"));
        }
        let target_view = input.expected_target.view.clone();
        if target_view.is_empty() || target_view.starts_with("wc/") || target_view.len() > 128 {
            return Err(HostError::Invalid("unsupported target view identity"));
        }
        let mut expansion = Expansion {
            host: self,
            repository: &repository,
            pool,
            objects: BTreeMap::new(),
            visiting: BTreeSet::new(),
            seen: BTreeSet::new(),
            order: Vec::new(),
            bytes: 0,
        };
        let (private_target_state, _, target_changes) =
            crate::native::snapshot_views(&repository, &target_view)?;
        let target_members: BTreeSet<_> = target_changes.into_iter().collect();
        if !inherited.is_subset(&target_members) {
            let missing = hash_strings(inherited.difference(&target_members).copied());
            let outcome = PrivateCompositionOutcome::InheritedBaselineRequired {
                operation_id: input.operation_id.clone(),
                host: HostIdentity::default(),
                scope: Box::new(input.scope.clone()),
                command_digest: command_digest.clone(),
                missing_count: u64::try_from(missing.len()).map_err(native)?,
                missing_changes: retain(self, &serde_json::to_vec(&missing)?)?,
            };
            journal.outcome = Some(outcome.clone());
            durable::write_json(&journal_path, &journal, true)?;
            return Ok(outcome);
        }
        for hash in &selected {
            expansion.visit(*hash)?;
        }
        let order = expansion.order.clone();
        let mut needed = BTreeSet::new();
        let mut stack: Vec<_> = selected.iter().copied().collect();
        while let Some(hash) = stack.pop() {
            if !needed.insert(hash) {
                continue;
            }
            for dependency in expansion.objects[&hash].change.dependencies() {
                if *dependency != Hash::NONE {
                    stack.push(*dependency);
                }
            }
        }
        let dependency_only: BTreeSet<_> = needed
            .difference(&selected)
            .filter(|hash| !inherited.contains(hash))
            .copied()
            .collect();
        let candidate_view = format!("candidate-{}", &command_digest[..16]);
        // Move exact objects out to end the repository borrow before changing
        // working-copy metadata. The native store, not caller metadata, supplies membership.
        let objects = expansion.objects;
        repository
            .create_view_from(&candidate_view, &target_view)
            .map_err(native)?;
        import_order(&repository, &objects, &order, &candidate_view)?;
        let working_copy = repository.require_working_copy_id().map_err(native)?;
        repository
            .set_current_view(working_copy, &candidate_view)
            .map_err(native)?;
        let (files, contents) = collect_files(&repository, &policy)?;
        native_materialize(&repository, &files)?;
        let conflict = repository
            .capture_view_conflict_set(&candidate_view)
            .map_err(native)?;
        let conflict_manifest = conflict
            .as_ref()
            .map(|conflict| retain(self, &conflict.canonical_bytes().map_err(native)?))
            .transpose()?;
        let native_conflict_hash = conflict
            .as_ref()
            .map(|conflict| conflict.hash().map(|hash| hash.to_base32()).map_err(native))
            .transpose()?;
        let conflicts = retain(
            self,
            &serde_json::to_vec(&conflict_summaries(conflict.as_ref())?)?,
        )?;
        let candidate_path = directory.join("files");
        copy_files(repository.root(), &candidate_path, &files, &contents)?;
        let (candidate_state, view_manifests, full_changes) =
            crate::native::snapshot_views(&repository, &candidate_view)?;
        let full: BTreeSet<_> = full_changes.iter().copied().collect();
        if full.len() > MAX_OBJECTS
            || !selected.is_subset(&full)
            || !needed.is_subset(&full)
            || !target_members.is_subset(&full)
        {
            return Err(HostError::Invalid(
                "native candidate membership is incomplete or exceeds budget",
            ));
        }
        let mut byte_budget = 0u64;
        let mut exact_objects = Vec::with_capacity(full.len());
        for hash in &full_changes {
            let metadata = std::fs::symlink_metadata(repository.change_store().change_path(hash))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HostError::Invalid(
                    "candidate object is not a regular native file",
                ));
            }
            byte_budget = byte_budget
                .checked_add(metadata.len())
                .filter(|total| *total <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid(
                    "candidate exact closure exceeds byte budget",
                ))?;
        }
        for hash in full_changes {
            let bytes = read_file(
                &repository.change_store().change_path(&hash),
                MAX_OBJECT_BYTES,
            )?;
            let (change, actual) =
                Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
            if actual != hash || change.kind().is_snapshot() {
                return Err(HostError::Invalid("candidate exact native object changed"));
            }
            exact_objects.push(ExactCompositionChange {
                hash: hash.to_base32(),
                bytes: retain_bytes(self, &bytes, MAX_OBJECT_BYTES)?,
            });
        }
        let inventory = CompositionInventory {
            selected_changes: hash_strings(selected.iter().copied()),
            dependency_only_changes: hash_strings(dependency_only),
            full_closed_changes: hash_strings(full),
            inherited_baseline_changes: hash_strings(inherited),
            target_context_changes: hash_strings(target_members),
        };
        let inventory_ref = retain(self, &serde_json::to_vec(&inventory)?)?;
        let materialization_manifest = retain(self, &serde_json::to_vec(&files)?)?;
        let materialization_id = digest(&serde_json::to_vec(&(
            MATERIALIZER_VERSION,
            &materialization_manifest.sha256,
        ))?);
        let state_manifest = retain(
            self,
            &serde_json::to_vec(&CompositionStateManifest {
                native_state: candidate_state.clone(),
                view_manifests: view_manifests
                    .iter()
                    .map(atomic_repository::ViewManifest::to_text)
                    .collect(),
                exact_objects,
                files: materialization_manifest.clone(),
                inventory: inventory_ref.clone(),
                full_closed_changes: inventory.full_closed_changes.clone(),
                materialization_id: materialization_id.clone(),
                conflicts: conflicts.clone(),
                conflict_manifest: conflict_manifest
                    .as_ref()
                    .map(|reference| reference.sha256.clone()),
            })?,
        )?;
        let selection_revision = digest(&serde_json::to_vec(&inventory.selected_changes)?);
        let composition_revision = digest(&serde_json::to_vec(&(
            &input.expected_target,
            &inventory,
            &materialization_id,
            &native_conflict_hash,
        ))?);
        durable::sync_tree(&repository.root().join(".atomic"))?;
        let mut receipt = PrivateCompositionReceipt {
            operation_id: input.operation_id.clone(),
            host: HostIdentity::default(),
            scope: input.scope.clone(),
            command_digest,
            target_state: input.expected_target.clone(),
            private_target_state,
            target_capture_digest: input
                .captured_target
                .as_ref()
                .map(|capture| capture.capture_digest.clone()),
            candidate_state,
            state_manifest,
            materialization_id,
            materialization_manifest,
            inventory: inventory_ref,
            conflict_manifest,
            conflicts,
            native_conflict_hash,
            candidate_path,
            selection_revision,
            composition_revision,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = digest(&serde_json::to_vec(&receipt)?);
        journal.materialization_directory = Some(durable::identity(&receipt.candidate_path, true)?);
        journal.native_database = Some(durable::identity(&repository.database_path(), false)?);
        journal.outcome = Some(PrivateCompositionOutcome::Composed {
            receipt: Box::new(receipt.clone()),
        });
        durable::write_json(&journal_path, &journal, true)?;
        Ok(PrivateCompositionOutcome::Composed {
            receipt: Box::new(receipt),
        })
    }

    /// Caller owns the host writer lane. A serialized receipt alone is not an
    /// owner capability: exact journal command, outcome and artifact identities
    /// must still agree before another private operation can consume it.
    pub(crate) fn original_private_composition(
        &self,
        receipt: &PrivateCompositionReceipt,
    ) -> Result<PrivateCompositionInput> {
        let path = self
            .config
            .config_dir
            .join("composition-operations")
            .join(format!("{}.json", digest(receipt.operation_id.as_bytes())));
        let journal: Journal = durable::read_json(&path)?;
        if journal.operation_id != receipt.operation_id
            || journal.command_digest != receipt.command_digest
            || !matches!(&journal.outcome,Some(PrivateCompositionOutcome::Composed{receipt:original}) if original.as_ref()==receipt)
            || journal.materialization_directory.as_ref()
                != Some(&durable::identity(&receipt.candidate_path, true)?)
            || journal.native_database.as_ref()
                != Some(&durable::identity(
                    &receipt
                        .candidate_path
                        .parent()
                        .ok_or(HostError::StaleBinding)?
                        .join("native/.atomic/atomic.redb"),
                    false,
                )?)
        {
            return Err(HostError::Invalid(
                "composition is not an original retained host receipt",
            ));
        }
        let bytes = read_spool(self, &journal.input, MAX_METADATA_BYTES)?;
        if digest(&bytes) != receipt.command_digest {
            return Err(HostError::Invalid("original composition command changed"));
        }
        let input: PrivateCompositionInput = serde_json::from_slice(&bytes)?;
        if input.operation_id != receipt.operation_id || input.scope != receipt.scope {
            return Err(HostError::StaleBinding);
        }
        self.verify_composition_receipt(receipt)?;
        Ok(input)
    }

    fn verify_composition_receipt(&self, receipt: &PrivateCompositionReceipt) -> Result<()> {
        let mut expected = receipt.clone();
        expected.receipt_digest.clear();
        if digest(&serde_json::to_vec(&expected)?) != receipt.receipt_digest {
            return Err(HostError::Invalid("composition receipt digest changed"));
        }
        let files: Manifest = serde_json::from_slice(&read_spool(
            self,
            &receipt.materialization_manifest,
            MAX_METADATA_BYTES,
        )?)?;
        baselines::verify_materialization(&receipt.candidate_path, &files.entries)?;
        let inventory: CompositionInventory =
            serde_json::from_slice(&read_spool(self, &receipt.inventory, MAX_METADATA_BYTES)?)?;
        let manifest: CompositionStateManifest = serde_json::from_slice(&read_spool(
            self,
            &receipt.state_manifest,
            MAX_METADATA_BYTES,
        )?)?;
        if manifest.native_state != receipt.candidate_state
            || manifest.files != receipt.materialization_manifest
            || manifest.inventory != receipt.inventory
            || manifest.full_closed_changes != inventory.full_closed_changes
            || manifest.conflicts != receipt.conflicts
            || manifest.materialization_id != receipt.materialization_id
            || manifest.conflict_manifest
                != receipt
                    .conflict_manifest
                    .as_ref()
                    .map(|reference| reference.sha256.clone())
        {
            return Err(HostError::Invalid(
                "candidate closure differs from retained receipt",
            ));
        }
        if let Some(conflicts) = &receipt.conflict_manifest {
            read_spool(self, conflicts, MAX_METADATA_BYTES)?;
        }
        let root = receipt
            .candidate_path
            .parent()
            .ok_or(HostError::Invalid("candidate owner namespace missing"))?
            .join("native");
        let repository = Repository::open_readonly_without_migration(root).map_err(native)?;
        let (state, views, changes) =
            crate::native::snapshot_views(&repository, &receipt.candidate_state.view)?;
        if state != receipt.candidate_state
            || views
                .iter()
                .map(atomic_repository::ViewManifest::to_text)
                .collect::<Vec<_>>()
                != manifest.view_manifests
            || hash_strings(changes.iter().copied().collect::<BTreeSet<_>>())
                != inventory.full_closed_changes
        {
            return Err(HostError::StaleBinding);
        }
        baselines::source::verify_native(&repository, &files.entries)?;
        let mut retained = BTreeSet::new();
        let mut total = 0u64;
        for object in &manifest.exact_objects {
            let hash = parse_hash(&object.hash)?;
            if !retained.insert(hash) {
                return Err(HostError::Invalid("duplicate retained candidate object"));
            }
            total = total
                .checked_add(object.bytes.length)
                .filter(|bytes| *bytes <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid(
                    "candidate closure exceeds retained byte budget",
                ))?;
            let bytes = read_spool(self, &object.bytes, MAX_OBJECT_BYTES)?;
            let (change, actual) =
                Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
            if actual != hash
                || change.kind().is_snapshot()
                || read_file(
                    &repository.change_store().change_path(&hash),
                    MAX_OBJECT_BYTES,
                )? != bytes
            {
                return Err(HostError::Invalid(
                    "retained candidate native object changed",
                ));
            }
        }
        if retained.len() > MAX_OBJECTS || retained != changes.into_iter().collect() {
            return Err(HostError::Invalid(
                "retained candidate closure is incomplete",
            ));
        }
        let actual_conflict = repository
            .capture_view_conflict_set(&receipt.candidate_state.view)
            .map_err(native)?;
        let neutral = read_spool(self, &receipt.conflicts, MAX_METADATA_BYTES)?;
        if neutral != serde_json::to_vec(&conflict_summaries(actual_conflict.as_ref())?)? {
            return Err(HostError::Invalid("retained typed conflict sides changed"));
        }
        let actual_bytes = actual_conflict
            .as_ref()
            .map(|conflict| conflict.canonical_bytes().map_err(native))
            .transpose()?;
        if actual_bytes.as_ref().map(|bytes| digest(bytes))
            != receipt
                .conflict_manifest
                .as_ref()
                .map(|reference| reference.sha256.clone())
            || actual_conflict
                .map(|conflict| conflict.hash().map(|hash| hash.to_base32()).map_err(native))
                .transpose()?
                != receipt.native_conflict_hash
        {
            return Err(HostError::Invalid(
                "retained native conflict evidence changed",
            ));
        }
        Ok(())
    }
}

pub(crate) mod capture;

#[cfg(test)]
mod tests;
