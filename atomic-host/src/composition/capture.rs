//! Captures a canonical recorded target without interpreting a private replay's
//! numeric view identity as the original source fence.

use super::{
    digest, hash_strings, native, parse_hash, read_file, read_spool, retain, retain_bytes,
    MAX_METADATA_BYTES, MAX_OBJECTS, MAX_OBJECT_BYTES,
};
use crate::{durable, Host, HostError, Result};
use atomic_core::{change::Change, Base32};
use atomic_repository::{Repository, ViewManifest};
use intent_atomic_proto::composition::{
    CaptureCompositionTargetRequest, CapturedCompositionTarget, ExactCompositionChange,
};
use intent_atomic_proto::{HostIdentity, StateToken, StoreBinding};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureData {
    pub(crate) scope: intent_atomic_proto::closures::ClosureScope,
    pub(crate) binding: StoreBinding,
    pub(crate) state: StateToken,
    pub(crate) views: Vec<String>,
    pub(crate) full_closed_changes: Vec<String>,
    pub(crate) objects: Vec<ExactCompositionChange>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureJournal {
    request: CaptureCompositionTargetRequest,
    command_digest: String,
    receipt: Option<CapturedCompositionTarget>,
}

fn path(host: &Host, operation: &str) -> Result<std::path::PathBuf> {
    let directory = host.config.config_dir.join("composition-captures");
    durable::private_dir(&directory)?;
    Ok(directory.join(format!("{}.json", digest(operation.as_bytes()))))
}

impl CaptureData {
    pub(crate) fn instantiate(&self, host: &Host, root: &Path) -> Result<Repository> {
        let views = self
            .views
            .iter()
            .map(|text| ViewManifest::parse(text).map_err(native))
            .collect::<Result<Vec<_>>>()?;
        let first = views
            .first()
            .ok_or(HostError::Invalid("captured target has no root view"))?;
        if first.parent.is_some() {
            return Err(HostError::Invalid(
                "captured target chain has no independent root",
            ));
        }
        durable::private_dir(root)?;
        let mut repository = Repository::init_with_view(root, &first.name).map_err(native)?;
        repository
            .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
            .map_err(native)?;
        repository
            .set_view_scope(&first.name, first.scope)
            .map_err(native)?;
        let mut actual = BTreeSet::new();
        let mut total = 0u64;
        for object in &self.objects {
            let hash = parse_hash(&object.hash)?;
            if !actual.insert(hash) {
                return Err(HostError::Invalid("duplicate captured target object"));
            }
            total = total
                .checked_add(object.bytes.length)
                .filter(|total| *total <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid("captured target exceeds byte budget"))?;
            let bytes = read_spool(host, &object.bytes, MAX_OBJECT_BYTES)?;
            let (change, found) =
                Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
            if found != hash || change.kind().is_snapshot() {
                return Err(HostError::Invalid("captured target native object changed"));
            }
            repository
                .import_change_bytes(&hash, &bytes)
                .map_err(native)?;
            crate::recording::sync_imported_object(&repository, &object.hash)?;
        }
        if actual
            != self
                .full_closed_changes
                .iter()
                .map(|hash| parse_hash(hash))
                .collect::<Result<_>>()?
        {
            return Err(HostError::Invalid("captured target closure is incomplete"));
        }
        for manifest in &views {
            repository.apply_view_manifest(manifest).map_err(native)?;
        }
        let (private, actual_views, actual_changes) =
            crate::native::snapshot_views(&repository, &self.state.view)?;
        if private.own_merkle != self.state.own_merkle
            || actual_views
                .iter()
                .map(ViewManifest::to_text)
                .collect::<Vec<_>>()
                != self.views
            || actual_changes.iter().copied().collect::<BTreeSet<_>>() != actual
        {
            return Err(HostError::Invalid(
                "private target differs from captured semantic native state",
            ));
        }
        let working_copy = repository.require_working_copy_id().map_err(native)?;
        repository
            .set_current_view(working_copy, &self.state.view)
            .map_err(native)?;
        Ok(repository)
    }
}

impl Host {
    /// Retain actual recorded source state under its original persisted binding.
    /// Working files and adoption authority are outside this read-only capture.
    /// # Errors
    /// Refuses stale source state, raced exports and unqualified object budgets.
    pub fn capture_composition_target(
        &self,
        request: &CaptureCompositionTargetRequest,
    ) -> Result<CapturedCompositionTarget> {
        self.capture_composition_target_observed(request, || {})
    }

    pub(super) fn capture_composition_target_observed(
        &self,
        request: &CaptureCompositionTargetRequest,
        after_export: impl FnOnce(),
    ) -> Result<CapturedCompositionTarget> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || request.operation_id.chars().any(char::is_control)
            || request.scope.workspace_id.is_empty()
            || request.scope.workspace_id.len() > 256
            || request.scope.root_id.is_empty()
            || request.scope.root_id.len() > 256
            || request.view.len() > 128
            || request.scope.repository_id != request.binding.repository_id
            || request.scope.binding_epoch != request.binding.binding_epoch
            || request.view != request.expected_state.view
            || request.view.starts_with("wc/")
        {
            return Err(HostError::StaleBinding);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let journal_path = path(self, &request.operation_id)?;
        let command_digest = digest(&serde_json::to_vec(request)?);
        let mut journal = if journal_path.try_exists()? {
            let journal: CaptureJournal = durable::read_json(&journal_path)?;
            if journal.request != *request || journal.command_digest != command_digest {
                return Err(HostError::Invalid("conflicting target capture replay"));
            }
            if let Some(receipt) = journal.receipt {
                self.load_composition_capture(&receipt)?;
                return Ok(receipt);
            }
            journal
        } else {
            let journal = CaptureJournal {
                request: request.clone(),
                command_digest,
                receipt: None,
            };
            durable::write_json(&journal_path, &journal, false)?;
            journal
        };
        let store = self.cached_store(&request.binding)?;
        let repository = store.repository();
        let (state, views, changes) = crate::native::snapshot_views(repository, &request.view)?;
        if state != request.expected_state {
            return Err(HostError::StaleBinding);
        }
        if changes.len() > MAX_OBJECTS {
            return Err(HostError::Invalid("captured target exceeds object budget"));
        }
        let mut total = 0u64;
        for hash in &changes {
            let metadata = std::fs::symlink_metadata(repository.change_store().change_path(hash))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HostError::Invalid(
                    "captured target object is not a regular file",
                ));
            }
            total = total
                .checked_add(metadata.len())
                .filter(|total| *total <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid("captured target exceeds byte budget"))?;
        }
        let mut objects = Vec::with_capacity(changes.len());
        for hash in &changes {
            let bytes = read_file(
                &repository.change_store().change_path(hash),
                MAX_OBJECT_BYTES,
            )?;
            let (change, actual) =
                Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
            if actual != *hash || change.kind().is_snapshot() {
                return Err(HostError::Invalid(
                    "captured target native object is invalid",
                ));
            }
            objects.push(ExactCompositionChange {
                hash: hash.to_base32(),
                bytes: retain_bytes(self, &bytes, MAX_OBJECT_BYTES)?,
            });
        }
        // Objects are immutable, while membership is mutable. Recheck the full
        // single-transaction descriptor after exporting to refuse a raced cut.
        after_export();
        let second = crate::native::snapshot_views(repository, &request.view)?;
        if second.0 != state || second.1 != views || second.2 != changes {
            return Err(HostError::StaleBinding);
        }
        self.cached_store(&request.binding)?;
        let manifest = retain(
            self,
            &serde_json::to_vec(&CaptureData {
                scope: request.scope.clone(),
                binding: request.binding.clone(),
                state: state.clone(),
                views: views.iter().map(ViewManifest::to_text).collect(),
                full_closed_changes: hash_strings(changes),
                objects,
            })?,
        )?;
        let mut receipt = CapturedCompositionTarget {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            scope: request.scope.clone(),
            binding: request.binding.clone(),
            state,
            manifest,
            capture_digest: String::new(),
        };
        receipt.capture_digest = digest(&serde_json::to_vec(&receipt)?);
        journal.receipt = Some(receipt.clone());
        durable::write_json(&journal_path, &journal, true)?;
        Ok(receipt)
    }

    pub(crate) fn load_composition_capture(
        &self,
        receipt: &CapturedCompositionTarget,
    ) -> Result<CaptureData> {
        let journal: CaptureJournal = durable::read_json(&path(self, &receipt.operation_id)?)?;
        let mut expected = receipt.clone();
        expected.capture_digest.clear();
        if journal.receipt.as_ref() != Some(receipt)
            || receipt.host != HostIdentity::default()
            || digest(&serde_json::to_vec(&expected)?) != receipt.capture_digest
            || journal.request.scope != receipt.scope
            || journal.request.binding != receipt.binding
            || journal.request.expected_state != receipt.state
        {
            return Err(HostError::Invalid(
                "target capture is not an original host receipt",
            ));
        }
        let captured: CaptureData =
            serde_json::from_slice(&read_spool(self, &receipt.manifest, MAX_METADATA_BYTES)?)?;
        if captured.scope != receipt.scope
            || captured.binding != receipt.binding
            || captured.state != receipt.state
            || captured.objects.len() > MAX_OBJECTS
        {
            return Err(HostError::Invalid(
                "captured target manifest differs from its source fence",
            ));
        }
        Ok(captured)
    }
}
