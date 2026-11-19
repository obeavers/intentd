//! Read-only current source export for private native triage. Historical task
//! projection receipts remain historical; the full current manifest and entry
//! inventory are exposed separately, never silently reduced to the selected UID.

use super::{
    entry_pins, native, read_bytes, same_entry, source_entry, spool_bytes, validate_source,
    ControlOwner, Journal, ARTIFACT_LIMIT, SOURCE_LIMIT,
};
use crate::{durable, Host, HostError, Result};
use atomic_core::kg::project_id::ProjectIdentityRecord;
use atomic_core::pristine::{VaultEntry, VaultEntryMeta, VaultManifest};
use atomic_core::Base32;
use intent_atomic_proto::intents::{IntentProjectionReceipt, IntentProjectionRef};
use intent_atomic_proto::StoreBinding;
use serde_json::Value;

/// Private native objects, never a wire credential or a deserialized grant.
pub(crate) struct CurrentIntentControlExport {
    receipt: IntentProjectionReceipt,
    entry: VaultEntry,
    project_identity: ProjectIdentityRecord,
    manifest: VaultManifest,
    manifest_merkle: String,
    entry_inventory: Vec<VaultEntryMeta>,
    source_bytes: Vec<u8>,
}
impl CurrentIntentControlExport {
    pub(crate) fn receipt(&self) -> &IntentProjectionReceipt {
        &self.receipt
    }
    pub(crate) fn entry(&self) -> &VaultEntry {
        &self.entry
    }
    pub(crate) fn vault_path(&self) -> &str {
        &self.receipt.vault_path
    }
    pub(crate) fn project_identity(&self) -> &ProjectIdentityRecord {
        &self.project_identity
    }
    pub(crate) fn manifest(&self) -> &VaultManifest {
        &self.manifest
    }
    pub(crate) fn manifest_merkle(&self) -> &str {
        &self.manifest_merkle
    }
    pub(crate) fn entry_inventory(&self) -> &[VaultEntryMeta] {
        &self.entry_inventory
    }
    pub(crate) fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }
}

impl Host {
    /// Caller holds `Host.writer` across this bounded metadata export and its
    /// private projection. This helper neither locks nor reopens/mutates a
    /// canonical repository, working copy or view. It exports exact selected
    /// current source only, with the full observed manifest/inventory so its
    /// caller can refuse unpinned additional control rows.
    pub(crate) fn export_current_intent_control(
        &self,
        binding: &StoreBinding,
        projection: &IntentProjectionRef,
        native_intent_id: &str,
    ) -> Result<CurrentIntentControlExport> {
        self.read_admitted()?;
        let receipt = self.original_projection(binding, projection, native_intent_id)?;
        let store = self.cached_store(binding)?;
        let project_identity = store
            .repository()
            .project_identity()
            .map_err(native)?
            .ok_or(HostError::Invalid(
                "current native project identity is unavailable",
            ))?;
        if project_identity.project_id().map_err(native)?.to_base32() != receipt.identity.project_id
            || project_identity.hash.to_base32() != receipt.identity.project_identity_hash
        {
            return Err(HostError::StaleBinding);
        }
        let journal: Journal =
            durable::read_json(&self.intent_journal_path(&projection.operation_id)?)?;
        let original = spool_bytes(&self.config.spool_dir, &receipt.task_source, SOURCE_LIMIT)?;
        let task = validate_source(&journal.request, &original)?;
        let expected = source_entry(&journal.request, &task)?;
        let entry = store
            .repository()
            .vault_retrieve(&receipt.vault_path)
            .map_err(native)?
            .ok_or(HostError::Invalid(
                "selected current native intent source is missing",
            ))?;
        let parent = self.binding_path(binding)?;
        let control = parent.join("intent-control");
        let owner: ControlOwner = durable::read_json(&parent.join("intent-control.json"))?;
        if owner.binding != *binding
            || owner.directory != durable::identity(&control, true)?
            || owner.working_copy.as_deref() != Some(receipt.control_working_copy_id.as_str())
            || !owner.view_started
        {
            return Err(HostError::StaleBinding);
        }
        let artifact = control.join(".vault").join(&receipt.vault_path);
        for directory in [
            control.join(".vault"),
            control.join(".vault/intents"),
            artifact
                .parent()
                .ok_or(HostError::Invalid("native intent artifact has no parent"))?
                .to_path_buf(),
        ] {
            durable::identity(&directory, true)?;
        }
        let source_bytes = read_bytes(&artifact, ARTIFACT_LIMIT)?;
        if !same_entry(&entry, &expected) {
            // Recognize only a real newer source revision through the explicit
            // operation retained in that native entry. Unknown edits or corrupt
            // materialization are not relabeled as a clean stale reference.
            let fm: Value = serde_json::from_str(&entry.frontmatter_json)?;
            let operation = fm["intentProjectionOperation"]
                .as_str()
                .ok_or(HostError::Invalid(
                    "changed current native source has no retained projection identity",
                ))?;
            let current: Journal = durable::read_json(&self.intent_journal_path(operation)?)?;
            let current_receipt = current.receipt.as_ref().ok_or(HostError::Invalid(
                "changed current native projection has no terminal source receipt",
            ))?;
            let verified =
                self.original_projection(binding, &current_receipt.projection, native_intent_id)?;
            let current_source =
                spool_bytes(&self.config.spool_dir, &verified.task_source, SOURCE_LIMIT)?;
            let current_task = validate_source(&current.request, &current_source)?;
            let current_entry = source_entry(&current.request, &current_task)?;
            if verified.projection.projection_revision > receipt.projection.projection_revision
                && same_entry(&entry, &current_entry)
                && entry_pins(&entry, &source_bytes)? == verified.projection.pins
            {
                return Err(HostError::StaleBinding);
            }
            return Err(HostError::Invalid(
                "changed current native source does not verify as a newer owned projection",
            ));
        }
        if entry_pins(&entry, &source_bytes)? != receipt.projection.pins {
            return Err(HostError::Invalid(
                "current native source/canonical/substance pins changed",
            ));
        }
        let manifest = store.repository().vault_manifest().map_err(native)?;
        let summary =
            manifest
                .intents
                .get(&receipt.identity.display_key)
                .ok_or(HostError::Invalid(
                    "current native intent summary is missing",
                ))?;
        let fm: Value = serde_json::from_str(&entry.frontmatter_json)?;
        if summary.uid != native_intent_id
            || summary.vault_path != receipt.vault_path
            || summary.human_key != receipt.identity.display_key
            || summary.title != task.title
            || fm["status"].as_str() != Some(summary.status.as_str())
        {
            return Err(HostError::Invalid(
                "current native intent summary differs from selected source",
            ));
        }
        let manifest_merkle = store
            .repository()
            .vault_manifest_merkle()
            .map_err(native)?
            .to_base32();
        let mut entry_inventory = store.repository().vault_list("", None).map_err(native)?;
        if entry_inventory.len() > 10_000 {
            return Err(HostError::Unsupported(
                "current native control inventory exceeds qualified triage budget",
            ));
        }
        entry_inventory.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(CurrentIntentControlExport {
            receipt,
            entry,
            project_identity,
            manifest,
            manifest_merkle,
            entry_inventory,
            source_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, retain_source, task_source};
    use super::*;

    #[test]
    fn current_control_export_retains_exact_source_and_full_inventory_without_code_mutation() {
        let (_directory, host, request) = fixture();
        let receipt = host.project_task_intent(&request).unwrap();
        let before = host
            .cached_store(&request.binding)
            .unwrap()
            .state()
            .unwrap();
        let _writer = host.writer.lock().unwrap();
        let exported = host
            .export_current_intent_control(
                &request.binding,
                &receipt.projection,
                &request.identity.native_intent_id,
            )
            .unwrap();
        assert_eq!(exported.receipt(), &receipt);
        assert_eq!(exported.vault_path(), receipt.vault_path);
        assert_eq!(
            exported.project_identity().hash.to_base32(),
            receipt.identity.project_identity_hash
        );
        assert_eq!(
            entry_pins(exported.entry(), exported.source_bytes()).unwrap(),
            receipt.projection.pins
        );
        assert!(exported
            .entry_inventory()
            .iter()
            .any(|entry| entry.path == receipt.vault_path));
        assert_eq!(exported.manifest().intents.len(), 1);
        assert_eq!(exported.manifest_merkle(), receipt.vault_manifest_merkle);
        assert_eq!(
            host.cached_store(&request.binding)
                .unwrap()
                .state()
                .unwrap(),
            before
        );
    }

    #[test]
    fn historical_projection_or_changed_materialization_cannot_be_exported_as_current() {
        let (_directory, host, request) = fixture();
        let original = host.project_task_intent(&request).unwrap();
        let mut next = request.clone();
        next.operation_id = "next-export-source".into();
        next.projection_revision = 2;
        next.previous = Some(original.projection.clone());
        let task = task_source(1, "Changed current task source");
        next.task_revision = task.reference.clone();
        next.source = retain_source(&host, "next-export-source.payload", &task);
        let current = host.project_task_intent(&next).unwrap();
        let _writer = host.writer.lock().unwrap();
        assert!(matches!(
            host.export_current_intent_control(
                &request.binding,
                &original.projection,
                &request.identity.native_intent_id
            ),
            Err(HostError::StaleBinding)
        ));
        assert!(host
            .export_current_intent_control(
                &request.binding,
                &current.projection,
                &request.identity.native_intent_id
            )
            .is_ok());
        let control = host
            .binding_path(&request.binding)
            .unwrap()
            .join("intent-control/.vault");
        std::fs::write(
            control.join(&current.vault_path),
            b"changed materialized source",
        )
        .unwrap();
        assert!(matches!(
            host.export_current_intent_control(
                &request.binding,
                &current.projection,
                &request.identity.native_intent_id
            ),
            Err(HostError::Invalid(_))
        ));
    }

    #[test]
    fn export_retains_unpinned_inventory_and_does_not_classify_malformed_source_as_stale() {
        use atomic_core::pristine::{VaultEntryType, VaultMutTxnT};
        use atomic_core::MutTxnT;
        let (_directory, host, request) = fixture();
        let receipt = host.project_task_intent(&request).unwrap();
        let store = host.cached_store(&request.binding).unwrap();
        let scratch = VaultEntry::new(
            VaultEntryType::Scratch,
            b"Unpinned native control row".to_vec(),
            "{}".into(),
            "2026-11-13T12:00:00Z".into(),
        );
        {
            // Inject native row corruption directly. The convenience vault
            // writer has automatic provider side effects, unrelated to this
            // read-only export refusal fixture.
            let mut transaction = store.repository().pristine().write_txn().unwrap();
            transaction
                .put_vault_entry("scratch/unpinned.md", &scratch)
                .unwrap();
            transaction.commit().unwrap();
        }
        let _writer = host.writer.lock().unwrap();
        let exported = host
            .export_current_intent_control(
                &request.binding,
                &receipt.projection,
                &request.identity.native_intent_id,
            )
            .unwrap();
        assert!(
            exported
                .entry_inventory()
                .iter()
                .any(|row| row.path == "scratch/unpinned.md"),
            "the triage owner must see and refuse unsupported extra control rows"
        );
        let mut malformed = exported.entry().clone();
        malformed.frontmatter_json = "{".into();
        {
            let mut transaction = store.repository().pristine().write_txn().unwrap();
            transaction
                .put_vault_entry(&receipt.vault_path, &malformed)
                .unwrap();
            transaction.commit().unwrap();
        }
        assert!(matches!(
            host.export_current_intent_control(
                &request.binding,
                &receipt.projection,
                &request.identity.native_intent_id
            ),
            Err(HostError::Json(_))
        ));
    }
}
