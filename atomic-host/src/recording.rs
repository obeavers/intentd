//! Exact-byte native record preparation and retained-effect admission. Private
//! transport uses the same journals; workspace activation has separate gates.
//! Prepared bytes are never reconstructed from a deserialized Change.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use atomic_core::change::{Author, Change, ChangeHeader};
use atomic_core::{Base32, Hash};
use atomic_repository::{InsertOptions, RecordError, RecordOptions, Repository, ViewEntryKind};
use intent_atomic_proto::recording::{
    NativeRecordReceipt, PrepareRecordRequest, PreparedNativeRecord, RecordPreparation,
    SelectedFileKind, RECORD_POLICY_VERSION,
};
use intent_atomic_proto::{HostIdentity, SpoolRef, StateToken};
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{durable, Host, HostError, Result};

const MAX_BYTES: u64 = 128 * 1024 * 1024;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.is_ascii()
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.eq_ignore_ascii_case(".git")
                && !part.eq_ignore_ascii_case(".atomic")
        })
}

fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(HostError::Invalid(
            "record payload is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(HostError::Invalid("record payload grew beyond its bound"));
    }
    Ok(bytes)
}

fn selected_bytes(
    root: &Path,
    file: &intent_atomic_proto::recording::SelectedFile,
) -> Result<Vec<u8>> {
    let mut full = root.to_path_buf();
    let parts: Vec<_> = file.path.split('/').collect();
    for (position, component) in parts.iter().enumerate() {
        // Any .gitattributes ancestor can run an external filter or alter raw
        // bytes. Until upstream accepts a raw filter policy, refuse explicitly.
        if full.join(".gitattributes").symlink_metadata().is_ok() {
            return Err(HostError::Unsupported(
                "raw record of attributed files awaits an explicit no-filter native primitive",
            ));
        }
        full.push(component);
        if position + 1 < parts.len() {
            match std::fs::symlink_metadata(&full) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Err(error)
                    if file.kind == SelectedFileKind::Deletion
                        && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Ok(Vec::new());
                }
                _ => {
                    return Err(HostError::Invalid(
                        "selected path has a missing or non-directory parent",
                    ));
                }
            }
        }
    }
    let metadata = match std::fs::symlink_metadata(&full) {
        Ok(metadata) => metadata,
        Err(error)
            if file.kind == SelectedFileKind::Deletion
                && error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error.into()),
    };
    match file.kind {
        SelectedFileKind::Deletion => Err(HostError::Invalid("selected deletion reappeared")),
        SelectedFileKind::Symlink if metadata.file_type().is_symlink() => {
            Ok(std::fs::read_link(full)?.as_os_str().as_bytes().to_vec())
        }
        SelectedFileKind::Regular | SelectedFileKind::Executable
            if metadata.is_file() && !metadata.file_type().is_symlink() =>
        {
            if (metadata.mode() & 0o111 != 0) != (file.kind == SelectedFileKind::Executable) {
                return Err(HostError::Invalid("selected executable mode changed"));
            }
            read_bytes(&full, MAX_BYTES)
        }
        _ => Err(HostError::Invalid("selected file kind changed")),
    }
}

fn verify_selection(request: &PrepareRecordRequest) -> Result<()> {
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for file in &request.files {
        if !safe_path(&file.path)
            || !names.insert(file.path.as_str())
            || file.length > MAX_BYTES
            || !canonical_hash(&file.sha256)
        {
            return Err(HostError::Invalid(
                "invalid or duplicate frozen selection path",
            ));
        }
        let bytes = selected_bytes(&request.sealed_source, file)?;
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if total > MAX_BYTES
            || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != file.length
            || digest(&bytes) != file.sha256
        {
            return Err(HostError::Invalid(
                "sealed selection bytes differ from their manifest",
            ));
        }
    }
    Ok(())
}

pub(crate) fn state(repository: &Repository, view: &str) -> Result<StateToken> {
    crate::native::snapshot_state(repository, view)
}

fn spool_path(root: &Path, reference: &SpoolRef) -> Result<PathBuf> {
    if reference.name.is_empty()
        || reference.name.len() > 128
        || reference
            .name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        || reference.name.starts_with('.')
        || reference.length > MAX_BYTES
        || !canonical_hash(&reference.sha256)
    {
        return Err(HostError::Invalid(
            "invalid prepared record spool reference",
        ));
    }
    durable::identity(root, true)?;
    Ok(root.join(&reference.name))
}

fn verified_spool(root: &Path, reference: &SpoolRef) -> Result<Vec<u8>> {
    let bytes = read_bytes(&spool_path(root, reference)?, reference.length)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.length
        || digest(&bytes) != reference.sha256
    {
        return Err(HostError::Invalid(
            "prepared encoding digest or length changed",
        ));
    }
    Ok(bytes)
}

fn retain(root: &Path, operation: &str, bytes: &[u8]) -> Result<SpoolRef> {
    let reference = SpoolRef {
        name: format!("record-{}.atom", digest(operation.as_bytes())),
        length: u64::try_from(bytes.len()).map_err(native)?,
        sha256: digest(bytes),
    };
    let path = spool_path(root, &reference)?;
    let temporary = root.join(format!(".pending-record-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        match std::fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if verified_spool(root, &reference)? != bytes {
                    return Err(HostError::Invalid(
                        "prepared operation already retains different bytes",
                    ));
                }
            }
            Err(error) => return Err(error.into()),
        }
        durable::sync_parent(&path)
    })();
    let _ = std::fs::remove_file(temporary);
    result?;
    Ok(reference)
}

struct AssembledRecord {
    change_hash: String,
    bytes: Vec<u8>,
    recorded_paths: Vec<String>,
    deleted_paths: Vec<String>,
    metadata_digest: String,
}

fn assemble(
    repository: &Repository,
    request: &PrepareRecordRequest,
) -> Result<Option<AssembledRecord>> {
    refuse_unsafe_ignore_controls(&request.sealed_source)?;
    verify_selection(request)?;
    if state(repository, &request.expected_state.view)? != request.expected_state {
        return Err(HostError::Invalid(
            "VIEW_STALE: sealed working copy differs from expected state",
        ));
    }
    let (expected_recorded, expected_deleted) = changed_selection(repository, request)?;
    let selection_digest = digest(&serde_json::to_vec(&request.files)?);
    let context: serde_json::Value = serde_json::from_str(&request.context_json)?;
    let metadata = serde_json::to_vec(&serde_json::json!({"policyVersion":RECORD_POLICY_VERSION,
        "operationId":request.operation_id,"repositoryId":request.binding.repository_id,
        "bindingEpoch":request.binding.binding_epoch,"selectionDigest":selection_digest,"context":context}))?;
    let mut header = ChangeHeader::builder()
        .message(&request.message)
        .author(Author::new(
            &request.author_name,
            request.author_email.clone(),
        ))
        .build();
    let offset = Duration::from_secs(request.unix_seconds.unsigned_abs());
    header.timestamp = if request.unix_seconds >= 0 {
        UNIX_EPOCH.checked_add(offset)
    } else {
        UNIX_EPOCH.checked_sub(offset)
    }
    .ok_or(HostError::Invalid(
        "native record timestamp is out of range",
    ))?
    .into();
    let working_copy = repository.require_working_copy_id().map_err(native)?;
    let outcome = match repository.record(
        working_copy,
        header,
        RecordOptions::new()
            .paths(request.files.iter().map(|file| file.path.clone()).collect())
            .include_untracked(true)
            .detect_raw_renames(false)
            .with_skip_binary(false)
            .with_max_file_size(MAX_BYTES)
            .apply_after_record(false)
            .save_to_store(false)
            .sync_vault(false)
            .enrich_kg(false)
            .update_file_index(false)
            .metadata_bytes(metadata.clone()),
    ) {
        Ok(outcome) => outcome,
        Err(RecordError::NothingToRecord) => {
            if !expected_recorded.is_empty() || !expected_deleted.is_empty() {
                return Err(HostError::Unsupported(
                    "native record omitted changed selected paths, possibly due to ignore policy",
                ));
            }
            if state(repository, &request.expected_state.view)? != request.expected_state {
                return Err(HostError::Invalid(
                    "native no-change preparation advanced authored state",
                ));
            }
            verify_selection(request)?;
            return Ok(None);
        }
        Err(error) => return Err(native(error)),
    };
    if outcome.was_saved()
        || outcome.was_applied()
        || !outcome.errors().is_empty()
        || !outcome.skipped_files().is_empty()
    {
        return Err(HostError::Invalid(
            "native preparation mutated membership or omitted selected input",
        ));
    }
    if state(repository, &request.expected_state.view)? != request.expected_state {
        return Err(HostError::Invalid(
            "native preparation advanced authored state",
        ));
    }
    verify_selection(request)?;
    // The pinned native outcome includes deleted FILE paths in both lists.
    // Directory deletions are outside this whole-file selection contract.
    let expected_all_recorded = expected_recorded
        .union(&expected_deleted)
        .cloned()
        .collect::<BTreeSet<_>>();
    if outcome
        .recorded_files()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_all_recorded
        || outcome
            .deleted_files()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_deleted
    {
        return Err(HostError::Unsupported(
            "native record did not encode every changed selected path exactly",
        ));
    }
    if outcome.recorded_files().is_empty() && outcome.deleted_files().is_empty() {
        return Ok(None);
    }
    let bytes = outcome
        .v3_bytes()
        .ok_or(HostError::Unsupported(
            "native record did not retain its original serialized encoding",
        ))?
        .to_vec();
    let (_, hash) = Change::deserialize(&mut bytes.as_slice()).map_err(native)?;
    if &hash != outcome.hash() {
        return Err(HostError::Invalid(
            "native serialized identity differs from record result",
        ));
    }
    Ok(Some(AssembledRecord {
        change_hash: hash.to_base32(),
        bytes,
        recorded_paths: outcome.recorded_files().to_vec(),
        deleted_paths: outcome.deleted_files().to_vec(),
        metadata_digest: digest(&metadata),
    }))
}

fn changed_selection(
    repository: &Repository,
    request: &PrepareRecordRequest,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let requested: BTreeSet<_> = request
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut original = BTreeMap::new();
    repository
        .materialize_view_entries(&request.expected_state.view, |entry| {
            if !requested.contains(entry.path.as_str()) {
                return Ok(());
            }
            let kind = match entry.kind {
                ViewEntryKind::File if entry.mode == 0o644 => SelectedFileKind::Regular,
                ViewEntryKind::File if entry.mode == 0o755 => SelectedFileKind::Executable,
                ViewEntryKind::Symlink => SelectedFileKind::Symlink,
                _ => {
                    return Err(HostError::Unsupported(
                        "selected original native path is not a qualified whole file",
                    ))
                }
            };
            if original
                .insert(
                    entry.path,
                    (kind, entry.content.len() as u64, digest(&entry.content)),
                )
                .is_some()
            {
                return Err(HostError::Invalid(
                    "selected original native path is ambiguous",
                ));
            }
            Ok(())
        })
        .map_err(native)??;
    let mut recorded = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    for file in &request.files {
        let before = original.get(&file.path);
        if file.kind == SelectedFileKind::Deletion {
            if before.is_some() {
                deleted.insert(file.path.clone());
            }
        } else if !before.is_some_and(|(kind, length, sha256)| {
            *kind == file.kind && *length == file.length && sha256 == &file.sha256
        }) {
            recorded.insert(file.path.clone());
        }
    }
    Ok((recorded, deleted))
}

fn refuse_unsafe_ignore_controls(root: &Path) -> Result<()> {
    fn visit(root: &Path, directory: &Path, count: &mut usize, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(HostError::Invalid(
                "sealed source ignore inventory depth exceeds bound",
            ));
        }
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            *count += 1;
            if *count > 100_000 {
                return Err(HostError::Invalid(
                    "sealed source ignore inventory exceeds bound",
                ));
            }
            if directory == root && entry.file_name() == ".atomic" {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if matches!(name.as_str(), ".gitignore" | ".ignore" | ".atomicignore")
                && (!metadata.is_file() || metadata.file_type().is_symlink())
            {
                return Err(HostError::Unsupported(
                    "sealed source ignore controls must be ordinary files",
                ));
            }
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                visit(root, &entry.path(), count, depth + 1)?;
            }
        }
        Ok(())
    }
    visit(root, root, &mut 0, 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RecordPhase {
    Prepared,
    Importing,
    ObjectDurable,
    MembershipKnown,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordJournal {
    prepared: PreparedNativeRecord,
    phase: RecordPhase,
    object_preexisting: bool,
    receipt: Option<NativeRecordReceipt>,
    #[serde(default)]
    last_error: Option<String>,
}

fn uncertain(
    path: &Path,
    journal: &mut RecordJournal,
    reason: impl std::fmt::Display,
) -> HostError {
    journal.last_error = Some(reason.to_string());
    let _ = durable::write_json(path, journal, true);
    #[cfg(test)]
    eprintln!(
        "exact record {:?}: {}",
        journal.phase,
        journal.last_error.as_deref().unwrap_or("unknown")
    );
    HostError::Uncertain(journal.prepared.operation_id.clone())
}

pub(crate) fn native_object_path(repository: &Repository, hash: &str) -> Result<PathBuf> {
    let parsed = Hash::from_base32(hash.as_bytes())
        .ok_or(HostError::Invalid("invalid native change hash"))?;
    if parsed.to_base32() != hash {
        return Err(HostError::Invalid("noncanonical native change hash"));
    }
    Ok(repository.change_store().change_path(&parsed))
}

fn exact_object(repository: &Repository, prepared: &PreparedNativeRecord) -> Result<bool> {
    let path = native_object_path(repository, &prepared.change_hash)?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(_) => {
            let bytes = read_bytes(&path, prepared.bytes.length)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != prepared.bytes.length
                || digest(&bytes) != prepared.bytes.sha256
            {
                return Err(HostError::Invalid(
                    "native hash already names a different or incomplete encoding",
                ));
            }
            Ok(true)
        }
    }
}

/// Close upstream's plain-write ingress gap before any graph membership update.
/// Each ancestor directory that can publish the new object is durably synced.
pub(crate) fn sync_imported_object(repository: &Repository, hash: &str) -> Result<()> {
    let path = native_object_path(repository, hash)?;
    let atomic = repository.root().join(".atomic");
    let mut current = path.clone();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(HostError::Invalid("native object is not regular"));
    }
    file.sync_all()?;
    while let Some(parent) = current.parent() {
        durable::identity(parent, true)?;
        File::open(parent)?.sync_all()?;
        if parent == atomic {
            return Ok(());
        }
        current = parent.into();
    }
    Err(HostError::Invalid("native object escaped its store"))
}

impl Host {
    fn records_directory(&self) -> Result<PathBuf> {
        let path = self.config.config_dir.join("exact-records");
        durable::private_dir(&path)?;
        Ok(path)
    }

    fn record_journal_path(&self, operation: &str) -> Result<PathBuf> {
        if operation.is_empty() || operation.len() > 256 {
            return Err(HostError::Invalid("invalid record operation identity"));
        }
        Ok(self
            .records_directory()?
            .join(format!("{}.json", digest(operation.as_bytes()))))
    }

    fn preparation_paths(&self, operation: &str) -> Result<(PathBuf, File)> {
        // A per-operation lease leaves distinct read-only preparations parallel
        // while fencing contradictory requests that reuse one identity.
        let root = self.config.config_dir.join("record-preparations");
        durable::private_dir(&root)?;
        let key = digest(operation.as_bytes());
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(root.join(format!("{key}.lock")))?;
        // Native connection workers are blocking threads. Wait only on this
        // operation's lease, then return its retained exact result; preparing a
        // different operation never waits on this descriptor.
        lease.lock()?;
        Ok((root.join(format!("{key}.no-change.json")), lease))
    }

    /// Prepare a native record from exact private inputs. This grants no source
    /// authority and does not enable existing user workspaces.
    /// # Errors
    /// Refuses mutable/foreign sources, stale state or nondurable prepared bytes.
    pub fn prepare_exact_record(
        &self,
        request: &PrepareRecordRequest,
    ) -> Result<RecordPreparation> {
        self.read_admitted()?;
        self.binding_path(&request.binding)?;
        self.cached_store(&request.binding)?;
        let command_bytes = serde_json::to_vec(request)?;
        if command_bytes.len() > 48_000
            || request.files.is_empty()
            || request.message.is_empty()
            || request.author_name.is_empty()
            || request.files.len() > 1024
        {
            return Err(HostError::Invalid(
                "record request exceeds its qualification bounds",
            ));
        }
        let journal_path = self.record_journal_path(&request.operation_id)?;
        let command_digest = digest(&command_bytes);
        let (no_change_path, _preparation_lease) = self.preparation_paths(&request.operation_id)?;
        if no_change_path.symlink_metadata().is_ok() {
            let outcome: RecordPreparation = durable::read_json(&no_change_path)?;
            let RecordPreparation::NoChanges {
                operation_id,
                command_digest: retained,
                expected_state,
                selection_digest,
            } = &outcome
            else {
                return Err(HostError::Invalid(
                    "no-change receipt contains an authored record",
                ));
            };
            if operation_id != &request.operation_id
                || retained != &command_digest
                || expected_state != &request.expected_state
                || selection_digest != &digest(&serde_json::to_vec(&request.files)?)
                || journal_path.symlink_metadata().is_ok()
            {
                return Err(HostError::Invalid(
                    "conflicting immutable no-change preparation replay",
                ));
            }
            return Ok(outcome);
        }
        if journal_path.symlink_metadata().is_ok() {
            let journal: RecordJournal = durable::read_json(&journal_path)?;
            if journal.prepared.command_digest != command_digest {
                return Err(HostError::Invalid("conflicting record preparation replay"));
            }
            verified_spool(&self.config.spool_dir, &journal.prepared.bytes)?;
            return Ok(RecordPreparation::Prepared {
                record: Box::new(journal.prepared),
            });
        }
        durable::identity(&request.sealed_source, true)?;
        let source = std::fs::canonicalize(&request.sealed_source)?;
        let spool = std::fs::canonicalize(&self.config.spool_dir)?;
        if source == spool
            || !source.starts_with(&spool)
            || source != request.sealed_source
            || source.join(".git").symlink_metadata().is_ok()
        {
            return Err(HostError::Invalid(
                "sealed working copy is outside its owner spool",
            ));
        }
        durable::identity(&source.join(".atomic"), true)?;
        durable::identity(&source.join(".atomic/atomic.redb"), false)?;
        // A real read-only native handle makes an unexpected preparation write
        // fail instead of silently advancing a shared store.
        let local_state = self.sealed_record_local_state(request)?;
        let repository = Repository::open_readonly_without_migration(&source).map_err(native)?;
        let selection_digest = digest(&serde_json::to_vec(&request.files)?);
        // Only a retained host source journal may translate private store-local
        // IDs. Original command/replay identity and canonical admission stay fixed.
        let mut local_request;
        let assembly_request = if let Some(local_state) = local_state {
            local_request = request.clone();
            local_request.expected_state = local_state;
            &local_request
        } else {
            request
        };
        let Some(assembled) = assemble(&repository, assembly_request)? else {
            let outcome = RecordPreparation::NoChanges {
                operation_id: request.operation_id.clone(),
                command_digest,
                expected_state: request.expected_state.clone(),
                selection_digest,
            };
            durable::write_json(&no_change_path, &outcome, false)?;
            return Ok(outcome);
        };
        let bytes = retain(
            &self.config.spool_dir,
            &request.operation_id,
            &assembled.bytes,
        )?;
        let prepared = PreparedNativeRecord {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            expected_state: request.expected_state.clone(),
            command_digest,
            selection_digest,
            metadata_digest: assembled.metadata_digest,
            change_hash: assembled.change_hash,
            bytes,
            recorded_paths: assembled.recorded_paths,
            deleted_paths: assembled.deleted_paths,
        };
        durable::write_json(
            &journal_path,
            &RecordJournal {
                prepared: prepared.clone(),
                phase: RecordPhase::Prepared,
                object_preexisting: false,
                receipt: None,
                last_error: None,
            },
            false,
        )?;
        Ok(RecordPreparation::Prepared {
            record: Box::new(prepared),
        })
    }

    /// Admit the retained original bytes under the sole native writer lane.
    /// # Errors
    /// Refuses stale expected state, changed envelopes or unproved native effects.
    pub fn admit_exact_record(
        &self,
        prepared: &PreparedNativeRecord,
    ) -> Result<NativeRecordReceipt> {
        self.admit_exact_record_observed(prepared, |_| Ok(()))
    }

    fn admit_exact_record_observed(
        &self,
        prepared: &PreparedNativeRecord,
        mut observed: impl FnMut(RecordPhase) -> Result<()>,
    ) -> Result<NativeRecordReceipt> {
        let ready = *self.recovered.lock().map_err(|_| HostError::Poisoned)?;
        if !ready {
            let recovery = self.reconcile()?;
            if !recovery.ready
                && recovery.unresolved_operation_ids != [prepared.operation_id.clone()]
            {
                return Err(HostError::RecoveryRequired);
            }
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)?
            && self.unresolved_records()? != [prepared.operation_id.clone()]
        {
            return Err(HostError::RecoveryRequired);
        }
        self.binding_path(&prepared.binding)?;
        if prepared.host != HostIdentity::default() {
            return Err(HostError::IncompatibleHost);
        }
        let path = self.record_journal_path(&prepared.operation_id)?;
        let mut journal: RecordJournal = durable::read_json(&path)?;
        if journal.prepared != *prepared {
            return Err(HostError::Invalid(
                "prepared record differs from its retained immutable command",
            ));
        }
        let store = self.cached_store(&prepared.binding)?;
        let repository = store.repository();
        let bytes = verified_spool(&self.config.spool_dir, &prepared.bytes)?;
        let (_, hash) = Change::deserialize(&mut bytes.as_slice()).map_err(native)?;
        if hash.to_base32() != prepared.change_hash {
            return Err(HostError::Invalid(
                "prepared native hash differs from its original bytes",
            ));
        }
        let contains = repository
            .views_containing_change(&hash)
            .map_err(native)?
            .contains(&prepared.expected_state.view);
        if contains {
            if !exact_object(repository, prepared)? {
                return Err(uncertain(
                    &path,
                    &mut journal,
                    "membership exists but original encoding is missing",
                ));
            }
            let mut receipt = journal.receipt.clone().unwrap_or(NativeRecordReceipt {
                operation_id: prepared.operation_id.clone(),
                change_hash: prepared.change_hash.clone(),
                encoding_sha256: prepared.bytes.sha256.clone(),
                encoding_length: prepared.bytes.length,
                before: prepared.expected_state.clone(),
                after: state(repository, &prepared.expected_state.view)?,
                replayed: true,
            });
            journal.receipt = Some(receipt.clone());
            journal.phase = RecordPhase::Terminal;
            durable::write_json(&path, &journal, true)?;
            *self.recovered.lock().map_err(|_| HostError::Poisoned)? = true;
            receipt.replayed = true;
            return Ok(receipt);
        }
        if journal.receipt.is_some()
            || matches!(
                journal.phase,
                RecordPhase::MembershipKnown | RecordPhase::Terminal
            )
        {
            return Err(uncertain(
                &path,
                &mut journal,
                "retained membership receipt no longer belongs to target view",
            ));
        }
        if state(repository, &prepared.expected_state.view)? != prepared.expected_state {
            return Err(HostError::Invalid(
                "VIEW_STALE: expected authored state changed before admission",
            ));
        }
        if repository
            .get_view_info(&prepared.expected_state.view)
            .map_err(native)?
            .scope
            != atomic_core::pristine::ViewScope::Draft
        {
            return Err(HostError::Unsupported(
                "exact record admission is qualified for owned draft views; shared publication requires its separate provenance gate",
            ));
        }
        let live = self.register_live_writer()?;
        if journal.phase == RecordPhase::Prepared {
            journal.object_preexisting = exact_object(repository, prepared)?;
            journal.phase = RecordPhase::Importing;
            durable::write_json(&path, &journal, true)?;
        }
        observed(RecordPhase::Importing)?;
        // A previous interrupted import of our formerly-absent object may have
        // left partial bytes. Reuse the sealed encoding; never record afresh.
        if !journal.object_preexisting || !exact_object(repository, prepared)? {
            repository
                .import_change_bytes(&hash, &bytes)
                .map_err(native)?;
        }
        if !exact_object(repository, prepared)? {
            return Err(uncertain(
                &path,
                &mut journal,
                "native importer returned without the exact original object",
            ));
        }
        sync_imported_object(repository, &prepared.change_hash)?;
        journal.phase = RecordPhase::ObjectDurable;
        durable::write_json(&path, &journal, true)?;
        observed(RecordPhase::ObjectDurable)?;
        if let Err(error) = repository.insert_change(
            &hash,
            InsertOptions::strict().view(&prepared.expected_state.view),
        ) {
            return Err(uncertain(&path, &mut journal, error));
        }
        let receipt = NativeRecordReceipt {
            operation_id: prepared.operation_id.clone(),
            change_hash: prepared.change_hash.clone(),
            encoding_sha256: prepared.bytes.sha256.clone(),
            encoding_length: prepared.bytes.length,
            before: prepared.expected_state.clone(),
            after: state(repository, &prepared.expected_state.view)
                .map_err(|error| uncertain(&path, &mut journal, error))?,
            replayed: false,
        };
        if !repository
            .views_containing_change(&hash)
            .map_err(native)?
            .contains(&prepared.expected_state.view)
        {
            return Err(uncertain(
                &path,
                &mut journal,
                "native insertion returned without exact target membership",
            ));
        }
        journal.phase = RecordPhase::MembershipKnown;
        journal.receipt = Some(receipt.clone());
        // Once membership is observed, a later persistence failure remains an
        // uncertain operation tied to this identity, never an invitation to retry a fresh record.
        if let Err(error) = durable::write_json(&path, &journal, true) {
            return Err(uncertain(&path, &mut journal, error));
        }
        observed(RecordPhase::MembershipKnown)?;
        journal.phase = RecordPhase::Terminal;
        if let Err(error) = durable::write_json(&path, &journal, true) {
            return Err(uncertain(&path, &mut journal, error));
        }
        observed(RecordPhase::Terminal)?;
        live.complete()
            .map_err(|_| HostError::Uncertain(prepared.operation_id.clone()))?;
        Ok(receipt)
    }

    /// Called only by `Host::reconcile` while it owns the writer lane. A valid
    /// local operation and exact original envelope authorize database repair.
    pub(crate) fn owned_record_recovery(
        &self,
        binding: &intent_atomic_proto::StoreBinding,
    ) -> Result<bool> {
        for entry in std::fs::read_dir(self.records_directory()?)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: RecordJournal = durable::read_json(&entry.path())?;
            if journal.prepared.binding != *binding || journal.phase == RecordPhase::Prepared {
                continue;
            }
            if journal.prepared.host != HostIdentity::default()
                || self.record_journal_path(&journal.prepared.operation_id)? != entry.path()
            {
                return Err(HostError::StaleBinding);
            }
            let bytes = verified_spool(&self.config.spool_dir, &journal.prepared.bytes)?;
            let (_, hash) = Change::deserialize(&mut bytes.as_slice()).map_err(native)?;
            if hash.to_base32() != journal.prepared.change_hash {
                return Err(HostError::Invalid(
                    "owned recovery journal envelope identity changed",
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Recovery enumeration hook. Call while holding `Host::writer`, before
    /// setting recovered=true. It never silently resumes a source mutation.
    pub(crate) fn unresolved_records(&self) -> Result<Vec<String>> {
        let mut unresolved = Vec::new();
        for entry in std::fs::read_dir(self.records_directory()?)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: RecordJournal = durable::read_json(&entry.path())?;
            if self.record_journal_path(&journal.prepared.operation_id)? != entry.path() {
                return Err(HostError::Invalid(
                    "record journal filename differs from its operation",
                ));
            }
            verified_spool(&self.config.spool_dir, &journal.prepared.bytes)?;
            if journal.phase == RecordPhase::Terminal {
                let prepared = &journal.prepared;
                let receipt = journal.receipt.as_ref().ok_or(HostError::Invalid(
                    "terminal native record has no retained effect receipt",
                ))?;
                if receipt.operation_id != prepared.operation_id
                    || receipt.change_hash != prepared.change_hash
                    || receipt.encoding_sha256 != prepared.bytes.sha256
                    || receipt.encoding_length != prepared.bytes.length
                    || receipt.before != prepared.expected_state
                    || receipt.after.view != prepared.expected_state.view
                {
                    return Err(HostError::Invalid(
                        "terminal effect receipt differs from its original native command",
                    ));
                }
                let store = self.cached_store(&prepared.binding)?;
                let repository = store.repository();
                let hash = Hash::from_base32(prepared.change_hash.as_bytes()).ok_or(
                    HostError::Invalid("terminal receipt has an invalid native hash"),
                )?;
                // Historical effect receipts stay immutable. Missing/corrupt
                // objects or unexpected removals close recovery instead of
                // rewriting a prior success or treating it as an empty view.
                let object_matches = exact_object(repository, prepared).unwrap_or(false);
                let membership_matches = repository
                    .views_containing_change(&hash)
                    .map_err(native)?
                    .contains(&prepared.expected_state.view);
                if !object_matches || !membership_matches {
                    unresolved.push(prepared.operation_id.clone());
                }
            }
            if !matches!(journal.phase, RecordPhase::Prepared | RecordPhase::Terminal) {
                unresolved.push(journal.prepared.operation_id);
            }
        }
        Ok(unresolved)
    }
}

#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod tests;
