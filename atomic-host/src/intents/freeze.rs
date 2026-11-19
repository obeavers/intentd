//! `HostFacadeFreezeV1` is a reviewed port of the pinned private native effect:
//! validate the exact declared UID while holding turn-end.lock, then fsync the
//! native intent-N.frozen marker. It additionally freezes the selected original
//! source projection in an immutable host journal. It never calls or claims the
//! private upstream method, and never grants permission to execute code.

use super::{
    digest, entry_pins, exact_bytes, native, operation_valid, projection_command_bytes,
    source_entry, spool_bytes, validate_source, Journal, Phase, ARTIFACT_LIMIT, SOURCE_LIMIT,
};
use crate::{durable, Host, HostError, Result};
use atomic_agent::turn::SessionStore;
use intent_atomic_proto::intents::{
    FreezeNativeTurnRequest, IntentProjectionReceipt, IntentProjectionRef,
    NativeIntentFreezeMethod, NativeTurnFreezeReceipt,
};
use intent_atomic_proto::recording::{PrepareRecordRequest, RecordPreparation};
use intent_atomic_proto::{HostIdentity, SpoolRef, StoreBinding};
use nix::fcntl::{Flock, FlockArg, OFlag};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreezeJournal {
    request: FreezeNativeTurnRequest,
    command_digest: String,
    session_directory: durable::FileIdentity,
    marker: Option<durable::FileIdentity>,
    receipt: Option<NativeTurnFreezeReceipt>,
}
fn session_valid(value: &str) -> bool {
    operation_valid(value) && !value.contains(['/', '\\']) && !value.contains("..") && value != "."
}
fn command(request: &FreezeNativeTurnRequest) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(
        "HostFacadeFreezeV1",
        request,
    ))?))
}
fn marker_path(sessions: &Path, request: &FreezeNativeTurnRequest) -> PathBuf {
    sessions
        .join(&request.session_id)
        .join(format!("intent-{}.frozen", request.expected_turn))
}
fn exact_native_binding(store: &SessionStore, request: &FreezeNativeTurnRequest) -> Result<()> {
    let binding = store
        .turn_intent_binding(&request.session_id, request.expected_turn)
        .map_err(native)?
        .ok_or(HostError::Invalid(
            "exact native turn has no declared intent",
        ))?;
    if binding.intent_uid != request.native_intent_id {
        return Err(HostError::Invalid(
            "native turn declares a different governing intent",
        ));
    }
    Ok(())
}
fn active_native_turn(store: &SessionStore, request: &FreezeNativeTurnRequest) -> Result<()> {
    let session = store
        .load(&request.session_id)
        .map_err(native)?
        .ok_or(HostError::Invalid("native freeze session is unavailable"))?;
    if session.session_id != request.session_id
        || !session.is_turn_active()
        || session.is_ended()
        || session.incomplete().is_some()
        || session.turn_count.checked_add(1) != Some(request.expected_turn)
    {
        return Err(HostError::Invalid(
            "native freeze requires the exact active complete session turn",
        ));
    }
    Ok(())
}

impl Host {
    fn freeze_journal_path(&self, operation: &str) -> Result<PathBuf> {
        self.intent_journals()?;
        if !operation_valid(operation) {
            return Err(HostError::Invalid(
                "invalid native freeze operation identity",
            ));
        }
        let root = self.config.config_dir.join("intent-freezes");
        durable::private_dir(&root)?;
        Ok(root.join(format!("{}.json", digest(operation.as_bytes()))))
    }

    fn frozen_projection(
        &self,
        request: &FreezeNativeTurnRequest,
    ) -> Result<IntentProjectionReceipt> {
        self.original_projection(
            &request.binding,
            &request.projection,
            &request.native_intent_id,
        )
    }

    pub(super) fn original_projection(
        &self,
        binding: &StoreBinding,
        projection: &IntentProjectionRef,
        native_intent_id: &str,
    ) -> Result<IntentProjectionReceipt> {
        let journal: Journal =
            durable::read_json(&self.intent_journal_path(&projection.operation_id)?)?;
        let receipt = journal.receipt.ok_or(HostError::Invalid(
            "native freeze source projection receipt is unavailable",
        ))?;
        if journal.phase != Phase::Terminal
            || receipt.binding != *binding
            || receipt.projection != *projection
            || receipt.identity.native_intent_id != native_intent_id
            || digest(&projection_command_bytes(&journal.request)?) != receipt.request_digest
        {
            return Err(HostError::Invalid(
                "native freeze source projection differs from original task pins",
            ));
        }
        let source_bytes = spool_bytes(&self.config.spool_dir, &receipt.task_source, SOURCE_LIMIT)?;
        let source = validate_source(&journal.request, &source_bytes)?;
        let entry = source_entry(&journal.request, &source)?;
        let artifact = spool_bytes(&self.config.spool_dir, &receipt.artifact, ARTIFACT_LIMIT)?;
        if receipt.task_source.sha256 != journal.request.source.sha256
            || receipt.task_source.length != journal.request.source.length
            || entry_pins(&entry, &artifact)? != receipt.projection.pins
        {
            return Err(HostError::Invalid(
                "original native source/canonical/substance pins no longer verify",
            ));
        }
        // This deliberately uses the retained original version. A later task
        // projection never silently replaces an earlier turn's governing source.
        Ok(receipt)
    }

    /// Freeze an exact actual native UID binding plus selected original source.
    /// This versioned local effect ports the pinned native marker semantics; it
    /// is not a call to the upstream crate-private function or a source grant.
    /// # Errors
    /// Refuses stale/missing native session, conflicting replay, unowned marker,
    /// changed projection evidence, lock contention or nondurable marker writes.
    pub fn freeze_native_turn_for_record(
        &self,
        request: &FreezeNativeTurnRequest,
    ) -> Result<NativeTurnFreezeReceipt> {
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.binding_path(&request.binding)?;
        self.cached_store(&request.binding)?;
        if !session_valid(&request.session_id)
            || !operation_valid(&request.work_binding_id)
            || request.expected_turn == 0
        {
            return Err(HostError::Invalid(
                "native freeze requires exact task binding/session/turn identities",
            ));
        }
        let projection = self.frozen_projection(request)?;
        let store = self.cached_store(&request.binding)?;
        let sessions = store.repository().dot_dir().join("sessions");
        durable::identity(&sessions, true)?;
        let session_store = SessionStore::new(&sessions).map_err(native)?;
        exact_native_binding(&session_store, request)?;
        let path = self.freeze_journal_path(&request.operation_id)?;
        let expected = command(request)?;
        if path.symlink_metadata().is_ok() {
            let journal: FreezeJournal = durable::read_json(&path)?;
            if journal.request != *request || journal.command_digest != expected {
                return Err(HostError::Invalid(
                    "conflicting frozen native turn operation replay",
                ));
            }
            if let Some(receipt) = journal.receipt {
                self.validate_native_turn_freeze(&receipt)?;
                return Ok(receipt);
            }
        } else {
            active_native_turn(&session_store, request)?;
            let directory = sessions.join(&request.session_id);
            let directory_id = durable::identity(&directory, true)?;
            if marker_path(&sessions, request).symlink_metadata().is_ok() {
                return Err(HostError::Unsupported(
                    "native marker predates the host's original task-source proof; it cannot be adopted as a frozen binding",
                ));
            }
            durable::write_json(
                &path,
                &FreezeJournal {
                    request: request.clone(),
                    command_digest: expected,
                    session_directory: directory_id,
                    marker: None,
                    receipt: None,
                },
                false,
            )?;
        }
        let live = self.begin_live_write()?;
        let receipt = self.freeze_turn_observed(&path, || Ok(()))?;
        live.complete()?;
        // Pin the envelope before returning it; source and artifact bytes have
        // independent immutable references and hashing namespaces.
        let bytes = serde_json::to_vec(&receipt)?;
        exact_bytes(
            &self.config.spool_dir.join(format!(
                "native-freeze-{}.json",
                digest(request.operation_id.as_bytes())
            )),
            &bytes,
        )?;
        let _ = projection;
        Ok(receipt)
    }

    fn freeze_turn_observed(
        &self,
        path: &Path,
        after_marker: impl FnOnce() -> Result<()>,
    ) -> Result<NativeTurnFreezeReceipt> {
        let mut journal: FreezeJournal = durable::read_json(path)?;
        let request = &journal.request;
        if self.freeze_journal_path(&request.operation_id)? != path
            || journal.command_digest != command(request)?
        {
            return Err(HostError::Invalid("native freeze journal command changed"));
        }
        let projection = self.frozen_projection(request)?;
        let store = self.intent_store(&request.binding)?;
        let sessions = store.repository().dot_dir().join("sessions");
        durable::identity(&sessions, true)?;
        let directory = sessions.join(&request.session_id);
        if durable::identity(&directory, true)? != journal.session_directory {
            return Err(HostError::StaleBinding);
        }
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(directory.join("turn-end.lock"))?;
        if !lock.metadata()?.is_file() || lock.metadata()?.nlink() != 1 {
            return Err(HostError::Invalid(
                "native turn lock is not an owned regular file",
            ));
        }
        let _lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| native(error))?;
        let session_store = SessionStore::new(&sessions).map_err(native)?;
        exact_native_binding(&session_store, request)?;
        let marker = marker_path(&sessions, request);
        if marker.symlink_metadata().is_err() {
            active_native_turn(&session_store, request)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
                .open(&marker)?;
            file.sync_all()?;
            File::open(&directory)?.sync_all()?;
        }
        let marker_id = durable::identity(&marker, false)?;
        let metadata = std::fs::symlink_metadata(&marker)?;
        if metadata.len() != 0
            || metadata.nlink() != 1
            || journal
                .marker
                .as_ref()
                .is_some_and(|prior| prior != &marker_id)
        {
            return Err(HostError::Invalid(
                "native frozen marker differs from the exact host proof",
            ));
        }
        after_marker()?;
        let receipt = NativeTurnFreezeReceipt {
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            operation_id: request.operation_id.clone(),
            work_binding_id: request.work_binding_id.clone(),
            projection: request.projection.clone(),
            session_id: request.session_id.clone(),
            turn: request.expected_turn,
            native_intent_id: request.native_intent_id.clone(),
            method: NativeIntentFreezeMethod::HostFacadeFreezeV1,
            task_source: projection.task_source.clone(),
            artifact: projection.artifact.clone(),
            projection_receipt_digest: digest(&serde_json::to_vec(&projection)?),
        };
        if journal
            .receipt
            .as_ref()
            .is_some_and(|prior| prior != &receipt)
        {
            return Err(HostError::Invalid(
                "native freeze receipt changed after its effect",
            ));
        }
        journal.marker = Some(marker_id);
        journal.receipt = Some(receipt.clone());
        durable::write_json(path, &journal, true)?;
        exact_bytes(
            &self.config.spool_dir.join(format!(
                "native-freeze-{}.json",
                digest(request.operation_id.as_bytes())
            )),
            &serde_json::to_vec(&receipt)?,
        )?;
        Ok(receipt)
    }

    /// Verify the actual retained source/marker proof; a deserialized DTO alone
    /// can never satisfy native grant creation or record metadata binding.
    /// # Errors
    /// Refuses foreign/stale roots, missing/changed markers or receipt forgery.
    pub fn validate_native_turn_freeze(&self, receipt: &NativeTurnFreezeReceipt) -> Result<()> {
        self.binding_path(&receipt.binding)?;
        let store = self.cached_store(&receipt.binding)?;
        let path = self.freeze_journal_path(&receipt.operation_id)?;
        let journal: FreezeJournal = durable::read_json(&path)?;
        if journal.command_digest != command(&journal.request)?
            || journal.receipt.as_ref() != Some(receipt)
            || receipt.method != NativeIntentFreezeMethod::HostFacadeFreezeV1
        {
            return Err(HostError::Invalid(
                "frozen native receipt differs from actual retained proof",
            ));
        }
        let projection = self.frozen_projection(&journal.request)?;
        if digest(&serde_json::to_vec(&projection)?) != receipt.projection_receipt_digest {
            return Err(HostError::Invalid(
                "frozen native task source receipt changed",
            ));
        }
        let sessions = store.repository().dot_dir().join("sessions");
        let directory = sessions.join(&receipt.session_id);
        if durable::identity(&directory, true)? != journal.session_directory
            || journal.marker.as_ref()
                != Some(&durable::identity(
                    &marker_path(&sessions, &journal.request),
                    false,
                )?)
        {
            return Err(HostError::StaleBinding);
        }
        let metadata = std::fs::symlink_metadata(marker_path(&sessions, &journal.request))?;
        if metadata.len() != 0 || metadata.nlink() != 1 {
            return Err(HostError::Invalid("native frozen marker contents changed"));
        }
        exact_native_binding(
            &SessionStore::new(sessions).map_err(native)?,
            &journal.request,
        )?;
        let envelope = SpoolRef {
            name: format!(
                "native-freeze-{}.json",
                digest(receipt.operation_id.as_bytes())
            ),
            length: u64::try_from(serde_json::to_vec(receipt)?.len()).map_err(native)?,
            sha256: digest(&serde_json::to_vec(receipt)?),
        };
        spool_bytes(&self.config.spool_dir, &envelope, 65_536)?;
        Ok(())
    }

    pub(crate) fn reconcile_intent_freezes(&self) -> Result<Vec<String>> {
        let root = self.config.config_dir.join("intent-freezes");
        if root.symlink_metadata().is_err() {
            return Ok(vec![]);
        }
        durable::identity(&root, true)?;
        let mut unresolved = vec![];
        for file in std::fs::read_dir(root)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: FreezeJournal = durable::read_json(&file.path())?;
            if self.freeze_turn_observed(&file.path(), || Ok(())).is_err() {
                unresolved.push(journal.request.operation_id);
            }
        }
        Ok(unresolved)
    }

    pub(super) fn owned_pending_freeze_recovery(&self, binding: &StoreBinding) -> Result<bool> {
        let root = self.config.config_dir.join("intent-freezes");
        if root.symlink_metadata().is_err() {
            return Ok(false);
        }
        durable::identity(&root, true)?;
        for file in std::fs::read_dir(root)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: FreezeJournal = durable::read_json(&file.path())?;
            if journal.request.binding != *binding || journal.receipt.is_some() {
                continue;
            }
            if self.freeze_journal_path(&journal.request.operation_id)? != file.path()
                || command(&journal.request)? != journal.command_digest
            {
                return Err(HostError::Invalid(
                    "pending native freeze journal identity changed",
                ));
            }
            self.frozen_projection(&journal.request)?;
            let sessions = binding.store_path.join(".atomic/sessions");
            durable::identity(&sessions, true)?;
            let directory = sessions.join(&journal.request.session_id);
            if durable::identity(&directory, true)? != journal.session_directory {
                return Err(HostError::StaleBinding);
            }
            let actual = SessionStore::new(&sessions).map_err(native)?;
            exact_native_binding(&actual, &journal.request)?;
            let marker = marker_path(&sessions, &journal.request);
            if marker.symlink_metadata().is_ok() {
                let identity = durable::identity(&marker, false)?;
                let metadata = marker.symlink_metadata()?;
                if metadata.len() != 0
                    || metadata.nlink() != 1
                    || journal
                        .marker
                        .as_ref()
                        .is_some_and(|expected| *expected != identity)
                {
                    return Err(HostError::Invalid("pending native freeze marker changed"));
                }
            } else {
                active_native_turn(&actual, &journal.request)?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// The bound route constructs a reserved, hashed server-owned namespace
    /// from the actual frozen journal. Caller context remains a separate claim.
    /// # Errors
    /// Refuses a different operation/root, forged freeze or native preparation failure.
    pub fn prepare_exact_record_for_bound_turn(
        &self,
        request: &PrepareRecordRequest,
        freeze: &NativeTurnFreezeReceipt,
    ) -> Result<RecordPreparation> {
        if request.operation_id != freeze.operation_id || request.binding != freeze.binding {
            return Err(HostError::Invalid(
                "record operation differs from its frozen native turn",
            ));
        }
        self.validate_native_turn_freeze(freeze)?;
        let claims: Value = serde_json::from_str(&request.context_json)?;
        let mut bound = request.clone();
        bound.context_json = serde_json::to_string(
            &json!({"callerClaims":claims,"intentHostBinding":{"method":"hostFacadeFreezeV1","receiptDigest":digest(&serde_json::to_vec(freeze)?),"workBindingId":freeze.work_binding_id,"taskRevision":freeze.projection.task_revision,"nativeIntentId":freeze.native_intent_id,"sessionId":freeze.session_id,"turn":freeze.turn,"pins":freeze.projection.pins,"projectionReceiptDigest":freeze.projection_receipt_digest}}),
        )?;
        self.prepare_exact_record(&bound)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        declared_turn_fixture, frozen_turn_fixture, retain_source, task_source,
    };
    use super::*;
    use atomic_core::pristine::ViewScope;
    use atomic_repository::Repository;

    #[test]
    fn host_freeze_changes_actual_public_same_uid_binding_behavior_and_refuses_forgery() {
        let (_directory, host, request, _projection, freeze) = declared_turn_fixture();
        let store = host.cached_store(&request.binding).unwrap();
        let sessions = SessionStore::new(store.repository().dot_dir().join("sessions")).unwrap();
        sessions
            .bind_turn_intent(&freeze.session_id, Some(1), &freeze.native_intent_id)
            .unwrap();
        let receipt = host.freeze_native_turn_for_record(&freeze).unwrap();
        assert_eq!(receipt.method, NativeIntentFreezeMethod::HostFacadeFreezeV1);
        let failure = sessions
            .bind_turn_intent(&freeze.session_id, Some(1), &freeze.native_intent_id)
            .unwrap_err()
            .to_string();
        assert!(
            failure.contains("governing intent is frozen"),
            "same UID was idempotent before freeze: {failure}"
        );
        host.validate_native_turn_freeze(&receipt).unwrap();
        assert_eq!(
            host.freeze_native_turn_for_record(&freeze).unwrap(),
            receipt
        );
        let mut forged = receipt.clone();
        forged.work_binding_id = "different-binding".into();
        assert!(host.validate_native_turn_freeze(&forged).is_err());
        let mut conflicting = freeze.clone();
        conflicting.projection.pins.substance_hash = "blake3:changed".into();
        assert!(host.freeze_native_turn_for_record(&conflicting).is_err());
        let marker = marker_path(&store.repository().dot_dir().join("sessions"), &freeze);
        std::fs::write(&marker, b"changed same inode").unwrap();
        assert!(host.validate_native_turn_freeze(&receipt).is_err());
    }

    #[test]
    fn freeze_keeps_original_source_after_later_projection_and_failed_or_no_change_record() {
        use intent_atomic_proto::recording::{SelectedFile, SelectedFileKind};
        let (_directory, host, request, original, receipt) = frozen_turn_fixture();
        let mut later = request.clone();
        later.operation_id = "project-later-task".into();
        later.projection_revision = 2;
        later.previous = Some(original.projection.clone());
        let source = task_source(
            1,
            "A later different task must not replace the record-start source",
        );
        later.task_revision = source.reference.clone();
        later.source = retain_source(&host, "later-task.json", &source);
        let changed = host.project_task_intent(&later).unwrap();
        assert_ne!(
            changed.projection.pins.substance_hash,
            receipt.projection.pins.substance_hash
        );
        host.validate_native_turn_freeze(&receipt).unwrap();
        assert_eq!(receipt.projection, original.projection);
        let store = host.cached_store(&request.binding).unwrap();
        store
            .repository()
            .set_view_scope(store.repository().current_view(), ViewScope::Draft)
            .unwrap();
        let sealed = host.config.spool_dir.join("sealed-frozen-turn");
        durable::private_dir(&sealed).unwrap();
        let repo = Repository::init(&sealed).unwrap();
        repo.set_view_scope(repo.current_view(), ViewScope::Draft)
            .unwrap();
        repo.ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
            .unwrap();
        let expected = store.state().unwrap();
        drop(repo);
        let mut record = PrepareRecordRequest {
            operation_id: receipt.operation_id.clone(),
            binding: request.binding.clone(),
            sealed_source: sealed,
            expected_state: expected,
            files: vec![SelectedFile {
                path: "absent.txt".into(),
                kind: SelectedFileKind::Deletion,
                length: 0,
                sha256: digest(b""),
            }],
            message: "Exact original governance".into(),
            author_name: "Intent fixture".into(),
            author_email: None,
            unix_seconds: 1_800_000_000,
            context_json:
                "{\"intentHostBinding\":\"caller cannot replace the reserved namespace\"}".into(),
        };
        let original_path = record.sealed_source.clone();
        record.sealed_source = host.config.spool_dir.join("missing-private-copy");
        assert!(host
            .prepare_exact_record_for_bound_turn(&record, &receipt)
            .is_err());
        record.sealed_source = original_path;
        assert!(matches!(
            host.prepare_exact_record_for_bound_turn(&record, &receipt)
                .unwrap(),
            RecordPreparation::NoChanges { .. }
        ));
        host.validate_native_turn_freeze(&receipt).unwrap();
        let sessions = SessionStore::new(store.repository().dot_dir().join("sessions")).unwrap();
        assert!(sessions
            .bind_turn_intent(
                &receipt.session_id,
                Some(receipt.turn),
                &receipt.native_intent_id
            )
            .unwrap_err()
            .to_string()
            .contains("governing intent is frozen"));
    }

    #[test]
    fn marker_effect_recovers_after_interruption_without_adopting_an_unknown_marker() {
        let (_directory, host, request, _projection, freeze) = declared_turn_fixture();
        let sessions = host
            .cached_store(&request.binding)
            .unwrap()
            .repository()
            .dot_dir()
            .join("sessions");
        let path = host.freeze_journal_path(&freeze.operation_id).unwrap();
        durable::write_json(
            &path,
            &FreezeJournal {
                request: freeze.clone(),
                command_digest: command(&freeze).unwrap(),
                session_directory: durable::identity(&sessions.join(&freeze.session_id), true)
                    .unwrap(),
                marker: None,
                receipt: None,
            },
            false,
        )
        .unwrap();
        assert!(host
            .freeze_turn_observed(&path, || Err(HostError::Invalid(
                "injected post-marker interruption"
            )))
            .is_err());
        assert!(marker_path(&sessions, &freeze).exists());
        let config = host.config.clone();
        drop(host);
        let reopened = Host::new(config).unwrap();
        assert!(reopened.reconcile().unwrap().ready);
        let receipt = reopened.freeze_native_turn_for_record(&freeze).unwrap();
        reopened.validate_native_turn_freeze(&receipt).unwrap();
        let (_directory, host, request, _projection, freeze) = declared_turn_fixture();
        let sessions = host
            .cached_store(&request.binding)
            .unwrap()
            .repository()
            .dot_dir()
            .join("sessions");
        File::create(marker_path(&sessions, &freeze))
            .unwrap()
            .sync_all()
            .unwrap();
        assert!(matches!(
            host.freeze_native_turn_for_record(&freeze),
            Err(HostError::Unsupported(_))
        ));
        assert!(!host
            .freeze_journal_path(&freeze.operation_id)
            .unwrap()
            .exists());
    }

    #[test]
    fn actual_native_turn_lock_prevents_freeze_and_retry_repairs_only_its_exact_journal() {
        let (_directory, host, request, _projection, freeze) = declared_turn_fixture();
        let sessions = host
            .cached_store(&request.binding)
            .unwrap()
            .repository()
            .dot_dir()
            .join("sessions");
        let file = OpenOptions::new()
            .write(true)
            .open(sessions.join(&freeze.session_id).join("turn-end.lock"))
            .unwrap();
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
        assert!(host.freeze_native_turn_for_record(&freeze).is_err());
        assert!(!marker_path(&sessions, &freeze).exists());
        drop(lock);
        assert!(host.reconcile().unwrap().ready);
        let receipt = host.freeze_native_turn_for_record(&freeze).unwrap();
        host.validate_native_turn_freeze(&receipt).unwrap();
    }

    #[test]
    #[ignore = "subprocess fixture invoked by the recovery qualification test"]
    fn freeze_crash_worker() {
        let config = crate::HostConfig {
            stores_dir: PathBuf::from(std::env::var_os("INTENT_FREEZE_CRASH_STORES").unwrap()),
            config_dir: PathBuf::from(std::env::var_os("INTENT_FREEZE_CRASH_CONFIG").unwrap()),
            spool_dir: PathBuf::from(std::env::var_os("INTENT_FREEZE_CRASH_SPOOL").unwrap()),
        };
        let path = PathBuf::from(std::env::var_os("INTENT_FREEZE_CRASH_JOURNAL").unwrap());
        let host = Host::new(config).unwrap();
        let _ = host.freeze_turn_observed(&path, || std::process::exit(77));
        panic!("fixture must exit after the durable native marker");
    }

    #[test]
    fn process_exit_after_native_marker_recovers_original_source_and_freeze_witness() {
        let (_directory, host, request, original, freeze) = declared_turn_fixture();
        let sessions = host
            .cached_store(&request.binding)
            .unwrap()
            .repository()
            .dot_dir()
            .join("sessions");
        let journal = host.freeze_journal_path(&freeze.operation_id).unwrap();
        durable::write_json(
            &journal,
            &FreezeJournal {
                request: freeze.clone(),
                command_digest: command(&freeze).unwrap(),
                session_directory: durable::identity(&sessions.join(&freeze.session_id), true)
                    .unwrap(),
                marker: None,
                receipt: None,
            },
            false,
        )
        .unwrap();
        let config = host.config.clone();
        drop(host);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "intents::freeze::tests::freeze_crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("INTENT_FREEZE_CRASH_STORES", &config.stores_dir)
            .env("INTENT_FREEZE_CRASH_CONFIG", &config.config_dir)
            .env("INTENT_FREEZE_CRASH_SPOOL", &config.spool_dir)
            .env("INTENT_FREEZE_CRASH_JOURNAL", &journal)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let interrupted: FreezeJournal = durable::read_json(&journal).unwrap();
        assert!(interrupted.receipt.is_none());
        assert!(marker_path(&sessions, &freeze).exists());
        let host = Host::new(config).unwrap();
        assert!(host.reconcile().unwrap().ready);
        let receipt = host.freeze_native_turn_for_record(&freeze).unwrap();
        assert_eq!(receipt.projection, original.projection);
        host.validate_native_turn_freeze(&receipt).unwrap();
        let actual = SessionStore::new(&sessions).unwrap();
        assert!(actual
            .bind_turn_intent(&freeze.session_id, Some(1), &freeze.native_intent_id)
            .unwrap_err()
            .to_string()
            .contains("governing intent is frozen"));
    }
}
