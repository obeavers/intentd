//! Bounded selected-byte reconstruction over an exact captured original Draft.
//! This is source preparation, never provider-exit, callback-drain or SQL authority.
//! No live canonical database is copied, and no caller-selected source path is read.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use atomic_core::change::Change;
use atomic_core::pristine::ViewTxnT;
use atomic_core::{Base32, Hash};
use atomic_repository::{Repository, ViewEntryKind, ViewManifest};
use intent_atomic_proto::composition::{
    CaptureCompositionTargetRequest, CapturedCompositionTarget,
};
use intent_atomic_proto::recording::{SelectedFile, SelectedFileKind};
use intent_atomic_proto::sealed_record_source::{
    RecordSourcePayload, SealRecordSourceRequest, SealedRecordSource, MAX_RECORD_SOURCE_BYTES,
    MAX_RECORD_SOURCE_FILES, MAX_RECORD_SOURCE_FILE_BYTES, RECORD_SOURCE_PAYLOAD_VERSION,
};
use intent_atomic_proto::{HostIdentity, SpoolRef, StateToken};
use nix::libc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::working_copies::ChildCapture;
use crate::{durable, Host, HostError, Result};

const MAX_ENCODED_PAYLOAD: u64 = 2 * MAX_RECORD_SOURCE_BYTES + 32 * 1024 * 1024;
const MAX_NATIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 100_000;

fn invalid(reason: &'static str) -> HostError {
    HostError::Invalid(reason)
}
fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_operation(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn safe_path(path: &str) -> bool {
    crate::baselines::source::safe_path(path)
        && path.is_ascii()
        && !path.contains(':')
        && path.split('/').count() <= 64
        && !path
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".atomic") || part.eq_ignore_ascii_case(".git"))
}

fn ignore_control(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            ".gitignore" | ".ignore" | ".atomicignore"
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Prepared,
    Published,
    FailedKnown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    version: u32,
    command_digest: String,
    phase: Phase,
    directory: Option<durable::FileIdentity>,
    database: Option<durable::FileIdentity>,
    source_digest: Option<String>,
    receipt: Option<SealedRecordSource>,
    captured_target: Option<CapturedCompositionTarget>,
    files_digest: String,
}

struct SelectedBytes {
    file: SelectedFile,
    bytes: Vec<u8>,
}

fn selected_payload(root: &Path, request: &SealRecordSourceRequest) -> Result<Vec<SelectedBytes>> {
    let bytes = read_spool(root, &request.payload)?;
    let payload: RecordSourcePayload = serde_json::from_slice(&bytes)?;
    if payload.version != RECORD_SOURCE_PAYLOAD_VERSION
        || payload.files.len() != request.files.len()
    {
        return Err(invalid(
            "record-source payload version or descriptor count differs",
        ));
    }
    let mut output = Vec::with_capacity(payload.files.len());
    let mut total = 0u64;
    for (entry, expected) in payload.files.into_iter().zip(&request.files) {
        if entry.file != *expected
            || entry.content_hex.len() as u64 != expected.length.saturating_mul(2)
        {
            return Err(invalid(
                "record-source payload descriptor differs from frozen selection",
            ));
        }
        let mut decoded = Vec::with_capacity(usize::try_from(expected.length).map_err(native)?);
        for pair in entry.content_hex.as_bytes().as_chunks::<2>().0 {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let high = nibble(pair[0])
                .ok_or_else(|| invalid("record-source payload is not canonical hex"))?;
            let low = nibble(pair[1])
                .ok_or_else(|| invalid("record-source payload is not canonical hex"))?;
            decoded.push((high << 4) | low);
        }
        total = total
            .checked_add(decoded.len() as u64)
            .ok_or_else(|| invalid("record-source byte count overflow"))?;
        if total > MAX_RECORD_SOURCE_BYTES
            || hash(&decoded) != expected.sha256
            || expected.kind == SelectedFileKind::Deletion && !decoded.is_empty()
            || expected.kind == SelectedFileKind::Symlink
                && (decoded.is_empty() || decoded.len() > 4096 || decoded.contains(&0))
            || expected.kind == SelectedFileKind::Symlink && ignore_control(&expected.path)
        {
            return Err(invalid(
                "record-source payload bytes differ from frozen descriptors",
            ));
        }
        output.push(SelectedBytes {
            file: expected.clone(),
            bytes: decoded,
        });
    }
    Ok(output)
}

fn read_spool(root: &Path, reference: &SpoolRef) -> Result<Vec<u8>> {
    if reference.name.is_empty()
        || reference.name.len() > 256
        || reference.name.starts_with('.')
        || reference.name.contains(['/', '\\', ':'])
        || reference.name.chars().any(char::is_control)
        || reference.length > MAX_ENCODED_PAYLOAD
        || !canonical_hash(&reference.sha256)
    {
        return Err(invalid(
            "record-source payload reference exceeds its bounds",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(root.join(&reference.name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != reference.length || metadata.nlink() != 1 {
        return Err(invalid(
            "record-source payload is not the original bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(reference.length + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != reference.length || hash(&bytes) != reference.sha256 {
        return Err(invalid("record-source payload digest or length differs"));
    }
    Ok(bytes)
}

fn validate_descriptors(request: &SealRecordSourceRequest) -> Result<()> {
    if !valid_operation(&request.operation_id)
        || !canonical_hash(&request.selection_digest)
        || request.files.len() > MAX_RECORD_SOURCE_FILES
        || request.capture.repository_id != request.binding.repository_id
        || request.capture.binding_epoch != request.binding.binding_epoch
        || request.scope.repository_id != request.binding.repository_id
        || request.scope.binding_epoch != request.binding.binding_epoch
        || !valid_operation(&request.scope.workspace_id)
        || !valid_operation(&request.scope.root_id)
    {
        return Err(invalid(
            "record-source request identity or inventory exceeds its bounds",
        ));
    }
    check_casefold(request.files.iter().map(|file| file.path.as_str()))?;
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for file in &request.files {
        if !safe_path(&file.path)
            || !names.insert(file.path.as_str())
            || !canonical_hash(&file.sha256)
            || file.length > MAX_RECORD_SOURCE_FILE_BYTES
            || file.kind == SelectedFileKind::Deletion
                && (file.length != 0 || file.sha256 != hash(&[]))
        {
            return Err(invalid(
                "record-source selection has an invalid or duplicate descriptor",
            ));
        }
        total = total
            .checked_add(file.length)
            .ok_or_else(|| invalid("record-source selection byte count overflow"))?;
        if total > MAX_RECORD_SOURCE_BYTES {
            return Err(invalid("record-source selection exceeds byte bound"));
        }
    }
    // No selected entry can become another selected entry's path ancestor.
    for path in &names {
        for (index, _) in path.match_indices('/') {
            if names.contains(&path[..index]) {
                return Err(invalid("record-source selected paths overlap"));
            }
        }
    }
    Ok(())
}

fn check_casefold<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut prefixes = std::collections::BTreeMap::new();
    for path in paths {
        let mut prefix = String::new();
        for part in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let folded = prefix.to_ascii_lowercase();
            if prefixes.get(&folded).is_some_and(|prior| prior != &prefix) {
                return Err(HostError::Unsupported(
                    "record-source paths contain case aliases",
                ));
            }
            if !prefixes.contains_key(&folded) && prefixes.len() >= MAX_TREE_ENTRIES {
                return Err(invalid("record-source path-prefix inventory exceeds bound"));
            }
            prefixes.insert(folded, prefix.clone());
        }
    }
    Ok(())
}

fn capture(request: &SealRecordSourceRequest) -> ChildCapture {
    let capture = &request.capture;
    ChildCapture {
        operation_id: capture.operation_id.clone(),
        repository_id: capture.repository_id.clone(),
        binding_epoch: capture.binding_epoch,
        parent_working_copy_id: capture.parent_working_copy_id.clone(),
        parent_root: capture.parent_root.clone(),
        capture_generation: capture.capture_generation,
        selection_digest: capture.selection_digest.clone(),
        baseline: capture.baseline.clone(),
        baseline_manifest_digest: capture.baseline_manifest_digest.clone(),
        working_digest: capture.working_digest.clone(),
        path: capture.path.clone(),
        copied_entries: capture.copied_entries,
        copied_bytes: capture.copied_bytes,
        mechanism: capture.mechanism.clone(),
    }
}

impl Host {
    /// Journal ownership, exact files, graph capture and physical source identity
    /// are all required; a caller-provided token or locator cannot translate IDs.
    pub(crate) fn sealed_record_local_state(
        &self,
        request: &intent_atomic_proto::recording::PrepareRecordRequest,
    ) -> Result<Option<StateToken>> {
        let directory = self.config.spool_dir.join("record-sources");
        if !request.sealed_source.starts_with(&directory) {
            return Ok(None);
        }
        let operation = request
            .sealed_source
            .parent()
            .ok_or_else(|| invalid("sealed source operation owner missing"))?;
        let name = operation
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| canonical_hash(name))
            .ok_or_else(|| invalid("sealed source operation owner is invalid"))?;
        if operation.parent() != Some(directory.as_path())
            || request.sealed_source.file_name() != Some(std::ffi::OsStr::new("source"))
        {
            return Err(invalid(
                "sealed source locator is outside its retained operation",
            ));
        }
        let journal: Journal = durable::read_json(&directory.join(format!("{name}.json")))?;
        let receipt = journal
            .receipt
            .as_ref()
            .ok_or_else(|| invalid("sealed source has no published owner receipt"))?;
        let captured = journal
            .captured_target
            .as_ref()
            .ok_or_else(|| invalid("sealed source original native capture is missing"))?;
        if journal.version != 1
            || journal.phase != Phase::Published
            || receipt.host != HostIdentity::default()
            || receipt.command_digest != journal.command_digest
            || hash(receipt.operation_id.as_bytes()) != name
            || receipt.binding != request.binding
            || receipt.expected_state != request.expected_state
            || receipt.sealed_source != request.sealed_source
            || receipt.scope != captured.scope
            || captured.binding != request.binding
            || captured.state != request.expected_state
            || receipt.sealed_state.view != request.expected_state.view
            || receipt.sealed_state.own_merkle != request.expected_state.own_merkle
            || journal.files_digest != hash(&serde_json::to_vec(&request.files)?)
            || journal.directory != Some(durable::identity(&request.sealed_source, true)?)
            || journal.database
                != Some(durable::identity(
                    &request.sealed_source.join(".atomic/atomic.redb"),
                    false,
                )?)
            || journal.source_digest.as_ref() != Some(&tree_digest(&request.sealed_source)?)
        {
            return Err(HostError::StaleBinding);
        }
        self.load_composition_capture(captured)?;
        let repository =
            Repository::open_readonly_without_migration(&request.sealed_source).map_err(native)?;
        if crate::recording::state(&repository, &receipt.sealed_state.view)? != receipt.sealed_state
        {
            return Err(HostError::StaleBinding);
        }
        Ok(Some(receipt.sealed_state.clone()))
    }

    fn instantiate_record_source(
        &self,
        request: &SealRecordSourceRequest,
        captured: &CapturedCompositionTarget,
        root: &Path,
        policy: &intent_atomic_proto::baselines::BaselinePolicy,
    ) -> Result<StateToken> {
        let capture = self.load_composition_capture(captured)?;
        if capture.scope != request.scope
            || capture.binding != request.binding
            || capture.state != request.expected_state
        {
            return Err(HostError::StaleBinding);
        }
        let original = self.cached_store(&request.binding)?;
        if crate::recording::state(original.repository(), &request.expected_state.view)?
            != request.expected_state
        {
            return Err(HostError::StaleBinding);
        }
        refuse_conflicts(original.repository(), &request.expected_state.view)?;
        let expected =
            materialized_inventory(original.repository(), &request.expected_state.view, policy)?;
        check_casefold(
            expected
                .iter()
                .map(|entry| entry.path.as_str())
                .chain(request.files.iter().map(|file| file.path.as_str())),
        )?;
        let project = original
            .repository()
            .project_identity()
            .map_err(native)?
            .ok_or_else(|| invalid("record source has no original project identity"))?;
        atomic_repository::verify_project_identity(&project, None).map_err(native)?;
        let views = capture
            .views
            .iter()
            .map(|text| ViewManifest::parse(text).map_err(native))
            .collect::<Result<Vec<_>>>()?;
        let first = views
            .first()
            .ok_or_else(|| invalid("record source capture has no root view"))?;
        if first.parent.is_some()
            || views.last().is_none_or(|view| {
                view.name != request.expected_state.view
                    || view.scope != atomic_core::pristine::ViewScope::Draft
            })
        {
            return Err(HostError::Unsupported(
                "record source requires an original complete Draft view hierarchy",
            ));
        }
        // Persist the fresh source entry in its original operation directory;
        // file/tree fsync alone would not persist that parent linkage.
        durable::private_dir(root)?;
        let mut private = Repository::init_with_view(root, &first.name).map_err(native)?;
        private
            .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
            .map_err(native)?;
        private
            .adopt_remote_project_identity(&project)
            .map_err(native)?;
        private
            .set_view_scope(&first.name, first.scope)
            .map_err(native)?;
        let mut objects = BTreeSet::new();
        let mut total = 0u64;
        for object in &capture.objects {
            let hash = Hash::from_base32(object.hash.as_bytes())
                .ok_or_else(|| invalid("captured record object hash is invalid"))?;
            if hash == Hash::NONE || hash.to_base32() != object.hash || !objects.insert(hash) {
                return Err(invalid("captured record objects are ambiguous"));
            }
            total = total
                .checked_add(object.bytes.length)
                .filter(|total| *total <= MAX_NATIVE_BYTES)
                .ok_or_else(|| invalid("captured record source exceeds native object bound"))?;
            let bytes = crate::composition::read_spool(self, &object.bytes, MAX_NATIVE_BYTES)?;
            let (change, found) = Change::deserialize(&mut bytes.as_slice()).map_err(native)?;
            if found != hash || change.kind().is_snapshot() {
                return Err(invalid(
                    "captured record object changed or is an unsupported snapshot",
                ));
            }
            private.import_change_bytes(&hash, &bytes).map_err(native)?;
            crate::recording::sync_imported_object(&private, &object.hash)?;
        }
        if objects
            .iter()
            .map(Base32::to_base32)
            .collect::<BTreeSet<_>>()
            != capture
                .full_closed_changes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        {
            return Err(invalid(
                "captured record source object closure is incomplete",
            ));
        }
        for view in &views {
            private.apply_view_manifest(view).map_err(native)?;
        }
        let working_copy = private.require_working_copy_id().map_err(native)?;
        private
            .set_current_view(working_copy, &request.expected_state.view)
            .map_err(native)?;
        let (sealed_state, actual_views, actual_objects) =
            crate::native::snapshot_views(&private, &request.expected_state.view)?;
        if sealed_state.view != request.expected_state.view
            || sealed_state.own_merkle != request.expected_state.own_merkle
            || actual_views
                .iter()
                .map(ViewManifest::to_text)
                .collect::<Vec<_>>()
                != capture.views
            || actual_objects.into_iter().collect::<BTreeSet<_>>() != objects
            || private
                .project_identity()
                .map_err(native)?
                .is_none_or(|actual| actual.hash != project.hash)
        {
            return Err(invalid(
                "fresh record source differs from the original exact graph/project closure",
            ));
        }
        refuse_conflicts(&private, &sealed_state.view)?;
        if materialized_inventory(&private, &sealed_state.view, policy)? != expected {
            return Err(invalid(
                "fresh record source materialization differs from the original recorded view",
            ));
        }
        // This is a genuinely private native output. Validated paths cannot select
        // metadata or follow a symlink ancestor; attributes/conflicts were refused.
        let output = private.materialize(working_copy).map_err(native)?;
        if output.files_truncated != 0 || output.has_conflicts() {
            return Err(HostError::Unsupported(
                "private record source materialization is truncated or conflicted",
            ));
        }
        verify_materialized(root, &expected)?;
        if crate::recording::state(&private, &sealed_state.view)? != sealed_state
            || crate::recording::state(original.repository(), &request.expected_state.view)?
                != request.expected_state
        {
            return Err(HostError::StaleBinding);
        }
        Ok(sealed_state)
    }

    /// Reconstruct selected bytes in a fresh private native source. A successful
    /// receipt does not prove provider exit or make a live directory sealable.
    /// # Errors
    /// Refuses stale captures, changed operations, unsupported conflicts,
    /// aliases, payload mismatches and unknown partial private reconstructions.
    pub fn seal_record_source(
        &self,
        request: &SealRecordSourceRequest,
    ) -> Result<SealedRecordSource> {
        self.read_admitted()?;
        validate_descriptors(request)?;
        crate::embedding_policy::refuse_ambient_embedding()?;
        self.open_store(&request.binding)?;
        // This API retains exact original objects/manifests under the native writer
        // lane. It finishes before our reconstruction lane is acquired.
        let captured_target =
            self.capture_composition_target(&CaptureCompositionTargetRequest {
                operation_id: format!("record-source-{}", hash(request.operation_id.as_bytes())),
                scope: request.scope.clone(),
                binding: request.binding.clone(),
                view: request.expected_state.view.clone(),
                expected_state: request.expected_state.clone(),
            })?;
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        self.verify_marker(&request.binding)?;
        if durable::identity(&self.config.spool_dir, true)? != self.spool_root_identity {
            return Err(HostError::StaleBinding);
        }
        let encoded = serde_json::to_vec(request)?;
        if encoded.len() > 16 * 1024 * 1024 {
            return Err(invalid("record-source command exceeds metadata bound"));
        }
        let command_digest = hash(&encoded);
        let directory = self.config.spool_dir.join("record-sources");
        durable::private_dir(&directory)?;
        let operation = directory.join(hash(request.operation_id.as_bytes()));
        let journal_path =
            directory.join(format!("{}.json", hash(request.operation_id.as_bytes())));
        let source = operation.join("source");
        let selected = selected_payload(&self.config.spool_dir, request)?;
        if journal_path.symlink_metadata().is_ok() {
            let journal: Journal = durable::read_json(&journal_path)?;
            if journal.version != 1 || journal.command_digest != command_digest {
                return Err(invalid(
                    "record-source operation replay changed its immutable command",
                ));
            }
            if journal.phase != Phase::Published {
                return Err(HostError::Uncertain(request.operation_id.clone()));
            }
            let receipt = journal
                .receipt
                .ok_or_else(|| invalid("published record-source receipt is missing"))?;
            if !receipt.matches_request(request)
                || receipt.command_digest != command_digest
                || receipt.sealed_source != source
                || journal.directory != Some(durable::identity(&source, true)?)
                || journal.database
                    != Some(durable::identity(
                        &source.join(".atomic/atomic.redb"),
                        false,
                    )?)
                || journal.source_digest.as_ref() != Some(&tree_digest(&source)?)
                || journal.files_digest != hash(&serde_json::to_vec(&request.files)?)
                || journal.captured_target.as_ref() != Some(&captured_target)
            {
                return Err(HostError::StaleBinding);
            }
            self.load_composition_capture(&captured_target)?;
            verify_source(&source, &receipt.sealed_state, &selected)?;
            return Ok(receipt);
        }
        let mut journal = Journal {
            version: 1,
            command_digest: command_digest.clone(),
            phase: Phase::Prepared,
            directory: None,
            database: None,
            source_digest: None,
            receipt: None,
            captured_target: Some(captured_target.clone()),
            files_digest: hash(&serde_json::to_vec(&request.files)?),
        };
        durable::write_json(&journal_path, &journal, false)?;
        let result = (|| {
            self.validate_child_capture(&capture(request))?;
            let baseline = self.baseline_store(&request.capture.baseline)?;
            if baseline.receipt.manifest_digest != request.capture.baseline_manifest_digest {
                return Err(HostError::StaleBinding);
            }
            for file in &request.files {
                if crate::baselines::source::excluded(&file.path, &baseline.receipt.policy) {
                    return Err(HostError::Unsupported(
                        "record-source selection includes an excluded credential or control path",
                    ));
                }
            }
            if operation.symlink_metadata().is_ok() {
                return Err(HostError::Uncertain(request.operation_id.clone()));
            }
            durable::private_dir(&operation)?;
            let sealed_state = self.instantiate_record_source(
                request,
                &captured_target,
                &source,
                &baseline.receipt.policy,
            )?;
            for entry in &selected {
                let target = source.join(&entry.file.path);
                private_parents(
                    &source,
                    target
                        .parent()
                        .ok_or_else(|| invalid("selected source parent missing"))?,
                )?;
                match std::fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                        std::fs::remove_file(&target)?;
                    }
                    Ok(_) => {
                        return Err(HostError::Unsupported(
                            "record-source selection cannot replace a directory",
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if entry.file.kind != SelectedFileKind::Deletion {
                    write_entry(&target, entry.file.kind, &entry.bytes)?;
                }
            }
            verify_source(&source, &sealed_state, &selected)?;
            // Revalidate the immutable original before publication, not a live store.
            self.baseline_store(&request.capture.baseline)?;
            self.validate_child_capture(&capture(request))?;
            if crate::recording::state(
                self.cached_store(&request.binding)?.repository(),
                &request.expected_state.view,
            )? != request.expected_state
            {
                return Err(HostError::StaleBinding);
            }
            sync_source(&source)?;
            let receipt = SealedRecordSource {
                host: HostIdentity::default(),
                operation_id: request.operation_id.clone(),
                binding: request.binding.clone(),
                scope: request.scope.clone(),
                expected_state: request.expected_state.clone(),
                sealed_state,
                capture_operation_id: request.capture.operation_id.clone(),
                baseline_manifest_digest: request.capture.baseline_manifest_digest.clone(),
                selection_digest: request.selection_digest.clone(),
                payload: request.payload.clone(),
                sealed_source: source.clone(),
                file_count: request.files.len() as u64,
                total_bytes: request.files.iter().map(|file| file.length).sum(),
                command_digest,
            };
            journal.directory = Some(durable::identity(&source, true)?);
            journal.database = Some(durable::identity(
                &source.join(".atomic/atomic.redb"),
                false,
            )?);
            journal.source_digest = Some(tree_digest(&source)?);
            journal.receipt = Some(receipt.clone());
            journal.phase = Phase::Published;
            durable::write_json(&journal_path, &journal, true)?;
            Ok(receipt)
        })();
        if result.is_err() {
            journal.phase = Phase::FailedKnown;
            durable::write_json(&journal_path, &journal, true)?;
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MaterializedEntry {
    path: String,
    kind: u8,
    mode: u32,
    bytes: Vec<u8>,
}

fn refuse_conflicts(repository: &Repository, view: &str) -> Result<()> {
    if repository
        .capture_view_conflict_set(view)
        .map_err(native)?
        .is_some()
    {
        return Err(HostError::Unsupported(
            "record-source sealing of native conflicts requires a separate conflict owner",
        ));
    }
    let transaction = repository.pristine().read_txn().map_err(native)?;
    let view = transaction
        .get_view(view)
        .map_err(native)?
        .ok_or_else(|| invalid("record source view disappeared"))?;
    for (_, rows) in transaction.iter_conflicts(view.id).map_err(native)? {
        if !rows.is_empty() {
            return Err(HostError::Unsupported(
                "record-source sealing has unrepresented native conflict rows",
            ));
        }
    }
    Ok(())
}

fn materialized_inventory(
    repository: &Repository,
    view: &str,
    policy: &intent_atomic_proto::baselines::BaselinePolicy,
) -> Result<Vec<MaterializedEntry>> {
    let mut entries = std::collections::BTreeMap::new();
    let mut total = 0u64;
    repository
        .materialize_view_entries(view, |entry| {
            if !safe_path(&entry.path)
                || crate::baselines::source::excluded(&entry.path, policy)
                || entry
                    .path
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case(".gitattributes"))
            {
                return Err(HostError::Unsupported(
                    "recorded source path violates private output or raw-filter policy",
                ));
            }
            let kind = match entry.kind {
                ViewEntryKind::Directory if entry.mode == 0o755 && entry.content.is_empty() => 0,
                ViewEntryKind::File if entry.mode == 0o644 => 1,
                ViewEntryKind::File if entry.mode == 0o755 => 2,
                ViewEntryKind::Symlink
                    if !entry.content.is_empty()
                        && entry.content.len() <= 4096
                        && !entry.content.contains(&0) =>
                {
                    3
                }
                _ => {
                    return Err(HostError::Unsupported(
                        "recorded source kind or mode is unqualified",
                    ))
                }
            };
            if kind == 3 && ignore_control(&entry.path) {
                return Err(HostError::Unsupported(
                    "record-source ignore controls cannot be symlinks",
                ));
            }
            total = total
                .checked_add(entry.content.len() as u64)
                .filter(|total| *total <= MAX_RECORD_SOURCE_BYTES)
                .ok_or_else(|| invalid("recorded source output exceeds byte bound"))?;
            if entries.len() >= MAX_RECORD_SOURCE_FILES
                || entry.content.len() as u64 > MAX_RECORD_SOURCE_FILE_BYTES
            {
                return Err(invalid("recorded source output exceeds file bound"));
            }
            let path = entry.path;
            if entries
                .insert(
                    path.clone(),
                    MaterializedEntry {
                        path,
                        kind,
                        mode: u32::from(entry.mode),
                        bytes: entry.content,
                    },
                )
                .is_some()
            {
                return Err(invalid("recorded source has duplicate paths"));
            }
            Ok(())
        })
        .map_err(native)??;
    let paths = entries.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        for (index, _) in path.match_indices('/') {
            let parent = &path[..index];
            if entries.get(parent).is_some_and(|entry| entry.kind != 0) {
                return Err(invalid(
                    "recorded source file or symlink is another path's ancestor",
                ));
            }
            if !entries.contains_key(parent) {
                if entries.len() >= MAX_TREE_ENTRIES {
                    return Err(invalid("recorded source directory inventory exceeds bound"));
                }
                entries.insert(
                    parent.into(),
                    MaterializedEntry {
                        path: parent.into(),
                        kind: 0,
                        mode: 0o755,
                        bytes: Vec::new(),
                    },
                );
            }
        }
    }
    if entries.len() > MAX_TREE_ENTRIES {
        return Err(invalid("recorded source directory inventory exceeds bound"));
    }
    check_casefold(entries.keys().map(String::as_str))?;
    Ok(entries.into_values().collect())
}

fn verify_materialized(root: &Path, entries: &[MaterializedEntry]) -> Result<()> {
    for entry in entries {
        let path = root.join(&entry.path);
        checked_parents(root, &path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let bytes = match entry.kind {
            0 if metadata.is_dir() && !metadata.file_type().is_symlink() => Vec::new(),
            1 | 2 if metadata.is_file() && (metadata.mode() & 0o777) == entry.mode => {
                read_regular(&path, MAX_RECORD_SOURCE_FILE_BYTES)?
            }
            3 if metadata.file_type().is_symlink() => {
                std::fs::read_link(path)?.as_os_str().as_bytes().to_vec()
            }
            _ => {
                return Err(invalid(
                    "native private output differs from recorded kind/mode",
                ))
            }
        };
        if bytes != entry.bytes {
            return Err(invalid(
                "native private output differs from exact recorded bytes",
            ));
        }
    }
    Ok(())
}

fn checked_parents(root: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| invalid("source path needs a parent"))?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| invalid("source path escaped private root"))?;
    durable::identity(root, true)?;
    let mut current = root.to_owned();
    for part in relative.components() {
        current.push(part);
        durable::identity(&current, true)?;
    }
    Ok(())
}

fn private_parents(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| invalid("source parent escaped private root"))?;
    let mut current = root.to_owned();
    for part in relative.components() {
        current.push(part);
        durable::private_dir(&current)?;
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum {
        return Err(invalid("source file exceeds its kind or byte bound"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("source file grew beyond its byte bound"));
    }
    Ok(bytes)
}

fn write_entry(path: &Path, kind: SelectedFileKind, bytes: &[u8]) -> Result<()> {
    if kind == SelectedFileKind::Symlink {
        std::os::unix::fs::symlink(std::ffi::OsString::from_vec(bytes.to_vec()), path)?;
    } else {
        let mode = if kind == SelectedFileKind::Executable {
            0o755
        } else {
            0o644
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
    }
    Ok(())
}

fn verify_source(
    source: &Path,
    expected_state: &StateToken,
    selected: &[SelectedBytes],
) -> Result<()> {
    let repository = Repository::open_readonly_without_migration(source).map_err(native)?;
    if crate::recording::state(&repository, &expected_state.view)? != *expected_state {
        return Err(HostError::StaleBinding);
    }
    drop(repository);
    for entry in selected {
        let target = source.join(&entry.file.path);
        checked_parents(source, &target)?;
        if entry.file.kind == SelectedFileKind::Deletion {
            match target.symlink_metadata() {
                Ok(_) => return Err(invalid("selected deletion reappeared")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            continue;
        }
        let metadata = std::fs::symlink_metadata(&target)?;
        let bytes = if entry.file.kind == SelectedFileKind::Symlink
            && metadata.file_type().is_symlink()
        {
            std::fs::read_link(&target)?.as_os_str().as_bytes().to_vec()
        } else if matches!(
            entry.file.kind,
            SelectedFileKind::Regular | SelectedFileKind::Executable
        ) && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && (metadata.mode() & 0o111 != 0) == (entry.file.kind == SelectedFileKind::Executable)
        {
            read_regular(&target, MAX_RECORD_SOURCE_FILE_BYTES)?
        } else {
            return Err(invalid("selected sealed source kind differs"));
        };
        if bytes != entry.bytes {
            return Err(invalid("selected sealed source bytes differ"));
        }
    }
    Ok(())
}

fn sync_source(root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_source(&entry.path())?;
        } else if kind.is_file() {
            File::open(entry.path())?.sync_all()?;
        } else if !kind.is_symlink() {
            return Err(invalid("special file in sealed source"));
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

fn tree_digest(root: &Path) -> Result<String> {
    fn visit(
        root: &Path,
        path: &Path,
        rows: &mut Vec<(String, u32, u64, String)>,
        total: &mut u64,
    ) -> Result<()> {
        if rows.len() >= MAX_TREE_ENTRIES {
            return Err(invalid("sealed source inventory exceeds bound"));
        }
        let metadata = std::fs::symlink_metadata(path)?;
        let name = path
            .strip_prefix(root)
            .map_err(|_| invalid("sealed source inventory escaped root"))?
            .to_str()
            .ok_or_else(|| invalid("sealed source inventory is not UTF8"))?
            .to_owned();
        if metadata.is_dir() {
            rows.push((name, 0o040_000, 0, String::new()));
            for entry in std::fs::read_dir(path)? {
                visit(root, &entry?.path(), rows, total)?;
            }
        } else {
            let bytes = if metadata.file_type().is_symlink() {
                std::fs::read_link(path)?.as_os_str().as_bytes().to_vec()
            } else if metadata.is_file() && metadata.nlink() == 1 {
                read_regular(path, MAX_NATIVE_BYTES)?
            } else {
                return Err(invalid(
                    "sealed source inventory contains an alias or special file",
                ));
            };
            *total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("sealed source inventory byte count overflow"))?;
            if *total > MAX_NATIVE_BYTES + 2 * MAX_RECORD_SOURCE_BYTES {
                return Err(invalid("sealed source inventory exceeds byte bound"));
            }
            rows.push((
                name,
                metadata.mode() & 0o170_777,
                bytes.len() as u64,
                hash(&bytes),
            ));
        }
        Ok(())
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows, &mut 0)?;
    rows.sort();
    Ok(hash(&serde_json::to_vec(&rows)?))
}

#[cfg(test)]
#[path = "sealed_record_source_tests.rs"]
mod tests;
