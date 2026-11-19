//! Native triage on a separate exact-object/control replica. The original
//! candidate's namespace, project identity, code and proof remain untouched.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::Path,
};

use atomic_core::{
    change::Change,
    pristine::{KgMutTxnT, VaultManifest, VaultMutTxnT, ViewScope},
    Base32, Hash, MutTxnT,
};
use atomic_repository::{Repository, ViewManifest};
use intent_atomic_proto::{
    composition::CompositionStateManifest,
    triage::{
        NativeControlReadPin, NativeEvidenceAuthority, NativeTriagePreparation,
        NativeTriageReadRevision, NativeTriageReceipt, NativeTriageVerdict,
        PrepareNativeTriageRequest, ReviewerExecutionAvailability,
    },
    HostIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{baselines, composition, durable, signing, Host, HostError, Result};

const MAX_REPORT: u64 = 8 * 1024 * 1024;
const MAX_FILES: usize = 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRIAGE_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(atomic_canonical::jcs::canonicalize(&serde_json::to_value(value)?).into_bytes())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    command_digest: String,
    outcome: NativeTriagePreparation,
}

fn replica(
    host: &Host,
    root: &Path,
    manifest: &CompositionStateManifest,
    project: &atomic_core::kg::project_id::ProjectIdentityRecord,
) -> Result<Repository> {
    let views = manifest
        .view_manifests
        .iter()
        .map(|text| ViewManifest::parse(text).map_err(native))
        .collect::<Result<Vec<_>>>()?;
    let first = views
        .first()
        .ok_or(HostError::Invalid("triage replica has no root view"))?;
    if first.parent.is_some() {
        return Err(HostError::Invalid(
            "triage replica has a non-root first view",
        ));
    }
    // Public pure verification rejects a signed project without an explicit key.
    // It never falls back to the user's default Atomic identity configuration.
    atomic_repository::verify_project_identity(project, None).map_err(native)?;
    durable::private_dir(root)?;
    let mut repository = Repository::init_with_view(root, &first.name).map_err(native)?;
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .map_err(native)?;
    repository
        .adopt_remote_project_identity(project)
        .map_err(native)?;
    if repository
        .project_identity()
        .map_err(native)?
        .as_ref()
        .map(|identity| identity.hash)
        != Some(project.hash)
    {
        return Err(HostError::Invalid(
            "triage replica project identity differs from captured source",
        ));
    }
    repository
        .set_view_scope(&first.name, first.scope)
        .map_err(native)?;
    let mut total = 0u64;
    let mut found = BTreeSet::new();
    for object in &manifest.exact_objects {
        total = total
            .checked_add(object.bytes.length)
            .filter(|total| *total <= 512 * 1024 * 1024)
            .ok_or(HostError::Invalid("triage closure exceeds byte budget"))?;
        let hash = Hash::from_base32(object.hash.as_bytes()).ok_or(HostError::Invalid(
            "triage native object identity is malformed",
        ))?;
        if !found.insert(hash) || hash.to_base32() != object.hash {
            return Err(HostError::Invalid(
                "triage native object identity is duplicated/noncanonical",
            ));
        }
        let bytes = composition::read_spool(host, &object.bytes, 512 * 1024 * 1024)?;
        let (change, actual) =
            Change::deserialize(&mut std::io::Cursor::new(&bytes)).map_err(native)?;
        if actual != hash || change.kind().is_snapshot() {
            return Err(HostError::Invalid("triage exact native object changed"));
        }
        repository
            .import_change_bytes(&hash, &bytes)
            .map_err(native)?;
        crate::recording::sync_imported_object(&repository, &object.hash)?;
    }
    for view in &views {
        repository.apply_view_manifest(view).map_err(native)?;
    }
    let (_, actual_views, closed) =
        crate::native::snapshot_views(&repository, &manifest.native_state.view)?;
    if actual_views != views
        || closed
            .iter()
            .map(Base32::to_base32)
            .collect::<BTreeSet<_>>()
            != manifest.full_closed_changes.iter().cloned().collect()
    {
        return Err(HostError::Invalid(
            "triage replica semantic code state differs",
        ));
    }
    Ok(repository)
}

fn unavailable(reason: impl Into<String>) -> NativeTriagePreparation {
    NativeTriagePreparation::Unavailable {
        reason: reason.into(),
    }
}

impl Host {
    /// Native projection only. It never creates a review intent, acknowledges an
    /// independent reviewer execution, changes a task, or authorizes adoption.
    /// # Errors
    /// Returns storage/owner failures. Known source drift is Stale; malformed and
    /// unavailable native outputs never become an empty clean report.
    pub fn prepare_native_triage(
        &self,
        request: &PrepareNativeTriageRequest,
    ) -> Result<NativeTriagePreparation> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || request.operation_id.chars().any(char::is_control)
            || request.projections.is_empty()
            || request.projections.len() > 64
        {
            return Ok(unavailable(
                "triage requires a bounded exact control projection inventory",
            ));
        }
        if request.binding.repository_id != request.composition.scope.repository_id
            || request.binding.binding_epoch != request.composition.scope.binding_epoch
        {
            return Err(HostError::StaleBinding);
        }
        self.original_private_composition(&request.composition)?;
        let command_digest = digest(&canonical(request)?);
        let journals = self.config.config_dir.join("triage-operations");
        durable::private_dir(&journals)?;
        let journal_path =
            journals.join(format!("{}.json", digest(request.operation_id.as_bytes())));
        let prior = if journal_path.try_exists()? {
            let journal: Journal = durable::read_json(&journal_path)?;
            if journal.command_digest != command_digest {
                return Err(HostError::Invalid("conflicting native triage replay"));
            }
            Some(journal.outcome)
        } else {
            None
        };
        let mut exports = Vec::new();
        let mut seen = BTreeSet::new();
        for selected in &request.projections {
            if !seen.insert(selected.native_intent_id.clone()) {
                return Err(HostError::Invalid(
                    "duplicate native triage control projection",
                ));
            }
            match self.export_current_intent_control(
                &request.binding,
                &selected.projection,
                &selected.native_intent_id,
            ) {
                Ok(export) => exports.push(export),
                Err(HostError::StaleBinding) => {
                    return Ok(NativeTriagePreparation::Stale {
                        reason: "selected native control projection changed".into(),
                    });
                }
                Err(error) => {
                    return Ok(unavailable(format!(
                        "exact current control export unavailable: {error}"
                    )));
                }
            }
        }
        let first = &exports[0];
        let snapshot = match self.original_native_control(&request.control_snapshot) {
            Ok(snapshot) => snapshot,
            Err(HostError::StaleBinding) => {
                return Ok(NativeTriagePreparation::Stale {
                    reason: "selected control snapshot task projection changed".into(),
                });
            }
            Err(error) => {
                return Ok(unavailable(format!(
                    "full pinned control snapshot unavailable: {error}"
                )));
            }
        };
        if snapshot.request.binding != request.binding
            || snapshot.request.projections != request.projections
        {
            return Err(HostError::Invalid(
                "triage control snapshot differs from selected original projections",
            ));
        }
        let project: Value = serde_json::from_slice(&first.project_identity().object)?;
        if project.get("proof").is_some() {
            return Ok(unavailable(
                "signed native project identity requires explicit daemon-owned signer resolution",
            ));
        }
        let manifest_bytes = canonical(first.manifest())?;
        if snapshot.manifest_merkle != first.manifest_merkle()
            || canonical(&snapshot.manifest)? != manifest_bytes
        {
            return Ok(NativeTriagePreparation::Stale {
                reason: "exact control manifest differs from pinned full snapshot".into(),
            });
        }
        if let Some(outcome) = prior {
            if let NativeTriagePreparation::Produced { receipt } = &outcome {
                let bytes = composition::read_spool(self, &receipt.report, MAX_REPORT)?;
                let report: atomic_repository::triage::TriageReport =
                    serde_json::from_slice(&bytes)?;
                let pinned: NativeTriageReadRevision = serde_json::from_slice(
                    &composition::read_spool(self, &receipt.read_revision, MAX_REPORT)?,
                )?;
                if pinned.control_manifest_merkle != first.manifest_merkle()
                    || pinned.control_manifest_sha256 != digest(&manifest_bytes)
                    || pinned.control_snapshot != request.control_snapshot
                    || pinned
                        .controls
                        .iter()
                        .map(|pin| (&pin.native_intent_id, &pin.projection))
                        .collect::<BTreeMap<_, _>>()
                        != exports
                            .iter()
                            .map(|export| {
                                (
                                    &export.receipt().identity.native_intent_id,
                                    &export.receipt().projection,
                                )
                            })
                            .collect::<BTreeMap<_, _>>()
                {
                    return Ok(NativeTriagePreparation::Stale {
                        reason: "native triage read revisions changed".into(),
                    });
                }
                let signed = signing::verify(self, &receipt.evidence)?;
                if signed["reportSha256"] != receipt.report.sha256
                    || signed["readRevisionSha256"] != receipt.read_revision.sha256
                    || signed["operationId"] != request.operation_id
                    || signed["scope"] != serde_json::to_value(&request.composition.scope)?
                    || report.reference != receipt.native_reference
                    || pinned.composition_receipt_digest != request.composition.receipt_digest
                    || pinned.candidate_state != request.composition.candidate_state
                    || pinned.original_target_state != request.composition.target_state
                    || pinned.materialization_id != request.composition.materialization_id
                {
                    return Err(HostError::Invalid(
                        "retained native triage evidence pins changed",
                    ));
                }
            }
            return Ok(outcome);
        }
        let state: CompositionStateManifest = serde_json::from_slice(&composition::read_spool(
            self,
            &request.composition.state_manifest,
            16 * 1024 * 1024,
        )?)?;
        if state
            .exact_objects
            .iter()
            .try_fold(0u64, |sum, object| sum.checked_add(object.bytes.length))
            .is_none_or(|total| total > MAX_TRIAGE_OBJECT_BYTES)
        {
            return Ok(unavailable(
                "native triage exact-object metadata exceeds qualified budget",
            ));
        }
        let files: baselines::Manifest = serde_json::from_slice(&composition::read_spool(
            self,
            &request.composition.materialization_manifest,
            16 * 1024 * 1024,
        )?)?;
        if files.entries.len() > MAX_FILES
            || files.entries.iter().map(|entry| entry.length).sum::<u64>() > MAX_SOURCE_BYTES
        {
            return Ok(unavailable(
                "native full syntax triage exceeds qualified file/source budget",
            ));
        }
        let directory = self.config.spool_dir.join("triage");
        durable::private_dir(&directory)?;
        let directory = directory.join(&command_digest);
        if directory.try_exists()? {
            return Err(HostError::Uncertain(request.operation_id.clone()));
        }
        durable::private_dir(&directory)?;
        let mut repository = replica(
            self,
            &directory.join("native"),
            &state,
            first.project_identity(),
        )?;
        let feature = &request.composition.candidate_state.view;
        let target = &request.composition.private_target_state.view;
        let before = crate::native::snapshot_views(&repository, feature)?;
        baselines::source::verify_native_on_view(&repository, feature, &files.entries)?;
        let control = "intent-triage-control";
        repository
            .create_view_with_identity(control, ViewScope::Draft, None)
            .map_err(native)?;
        let working_copy = repository.require_working_copy_id().map_err(native)?;
        repository
            .set_current_view(working_copy, control)
            .map_err(native)?;
        durable::private_dir(&repository.vault_dir())?;
        for name in ["goals", "memory", "skills", "intents", "scratch", "prompts"] {
            durable::private_dir(&repository.vault_dir().join(name))?;
        }
        // The public convenience vault writers auto-resolve embedding providers.
        // Copy the exact observed canonical tables through native transactions,
        // then rebuild the derived KG explicitly without an embedding side effect.
        let native_manifest: VaultManifest = serde_json::from_value(snapshot.manifest.clone())?;
        {
            let mut transaction = repository.pristine().write_txn().map_err(native)?;
            transaction.init_vault().map_err(native)?;
            transaction.init_kg().map_err(native)?;
            for export in &exports {
                transaction
                    .put_vault_entry(export.vault_path(), export.entry())
                    .map_err(native)?;
            }
            for auxiliary in &snapshot.auxiliaries {
                transaction
                    .put_vault_entry(&auxiliary.pin.path, &auxiliary.entry)
                    .map_err(native)?;
            }
            transaction
                .put_vault_manifest(&native_manifest)
                .map_err(native)?;
            transaction.commit().map_err(native)?;
        }
        let mut controls = Vec::new();
        for export in &exports {
            repository
                .vault_materialize(export.vault_path())
                .map_err(native)?;
            let bytes = std::fs::read(repository.vault_dir().join(export.vault_path()))?;
            if bytes != export.source_bytes() {
                return Err(HostError::Invalid(
                    "triage control replica differs from exact source artifact",
                ));
            }
            let inputs = atomic_repository::intent_bridge::inputs_from_entry(export.entry())
                .map_err(native)?;
            let node = atomic_repository::intent_bridge::lift(&inputs).map_err(native)?;
            let proof_sha256 = node
                .to_value()
                .get("proof")
                .map(canonical)
                .transpose()?
                .map(|bytes| digest(&bytes));
            controls.push(NativeControlReadPin {
                native_intent_id: export.receipt().identity.native_intent_id.clone(),
                projection: export.receipt().projection.clone(),
                vault_path: export.vault_path().into(),
                source_sha256: digest(export.source_bytes()),
                native_entry_sha256: digest(&canonical(export.entry())?),
                canonical_hash: node.compute_content_hash(),
                substance_hash: atomic_canonical::intent_substance_hash(&node),
                proof_sha256,
            });
        }
        for auxiliary in &snapshot.auxiliaries {
            repository
                .vault_materialize(&auxiliary.pin.path)
                .map_err(native)?;
            let rendered = std::fs::read(repository.vault_dir().join(&auxiliary.pin.path))?;
            let actual = composition::read_spool(self, &auxiliary.source, 1024 * 1024)?;
            if rendered != actual {
                return Ok(unavailable(
                    "private native auxiliary materialization differs from exact pinned source",
                ));
            }
        }
        repository.rebuild_kg(true).map_err(native)?;
        let set = match repository.triage_candidate_set(feature, target) {
            Ok(set) => set,
            Err(error) => {
                return Ok(unavailable(format!(
                    "native candidate set unavailable: {error}"
                )));
            }
        };
        let report = match atomic_repository::triage::build_report(&repository, feature, target) {
            Ok(report) => report,
            Err(error) => {
                return Ok(unavailable(format!(
                    "native triage report unavailable: {error}"
                )));
            }
        };
        if report.inputs.feature != *feature
            || report.inputs.target != *target
            || report.inputs.view_merkle != before.0.own_merkle
            || report
                .inputs
                .candidate_changes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                != set.only_in_feature.iter().cloned().collect()
            || report
                .inputs
                .closure_additions
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                != set.closure_additions.iter().cloned().collect()
        {
            return Ok(NativeTriagePreparation::Malformed {
                reason: "native triage report pins differ from actual candidate/target".into(),
            });
        }
        let native_pins = atomic_canonical::TriagePins {
            feature: report.inputs.feature.clone(),
            target: report.inputs.target.clone(),
            view_merkle: report.inputs.view_merkle.clone(),
            candidate_changes: report.inputs.candidate_changes.clone(),
            intent_substance_hashes: report.inputs.intent_substance_hashes.clone(),
        };
        if !atomic_canonical::verify_triage_reference(&native_pins, &report.reference) {
            return Ok(NativeTriagePreparation::Malformed {
                reason: "native triage reference does not match its declared pins".into(),
            });
        }
        for (selected, original) in request.projections.iter().zip(&exports) {
            let current = match self.export_current_intent_control(
                &request.binding,
                &selected.projection,
                &selected.native_intent_id,
            ) {
                Ok(value) => value,
                Err(HostError::StaleBinding) => {
                    return Ok(NativeTriagePreparation::Stale {
                        reason: "native control changed during triage".into(),
                    });
                }
                Err(error) => {
                    return Ok(unavailable(format!(
                        "native control recheck unavailable: {error}"
                    )));
                }
            };
            if current.manifest_merkle() != original.manifest_merkle()
                || canonical(current.manifest())? != manifest_bytes
                || current.source_bytes() != original.source_bytes()
            {
                return Ok(NativeTriagePreparation::Stale {
                    reason: "native control snapshot changed during triage".into(),
                });
            }
        }
        match self.original_native_control(&request.control_snapshot) {
            Ok(current) if canonical(&current)? == canonical(&snapshot)? => {}
            Ok(_) => {
                return Ok(unavailable(
                    "full control snapshot changed during native triage",
                ));
            }
            Err(HostError::StaleBinding) => {
                return Ok(NativeTriagePreparation::Stale {
                    reason: "control task projection changed during triage".into(),
                });
            }
            Err(error) => {
                return Ok(unavailable(format!(
                    "full control recheck unavailable: {error}"
                )));
            }
        }
        if crate::native::snapshot_views(&repository, feature)? != before {
            return Err(HostError::Invalid(
                "triage metadata mutated candidate code identity",
            ));
        }
        baselines::source::verify_native_on_view(&repository, feature, &files.entries)?;
        self.original_private_composition(&request.composition)?;
        controls.sort_by(|left, right| left.native_intent_id.cmp(&right.native_intent_id));
        let revision = NativeTriageReadRevision {
            composition_receipt_digest: request.composition.receipt_digest.clone(),
            candidate_state: request.composition.candidate_state.clone(),
            original_target_state: request.composition.target_state.clone(),
            materialization_id: request.composition.materialization_id.clone(),
            control_manifest_merkle: first.manifest_merkle().into(),
            control_manifest_sha256: digest(&manifest_bytes),
            project_identity_hash: first.project_identity().hash.to_base32(),
            controls,
            control_snapshot: request.control_snapshot.clone(),
            auxiliaries: snapshot
                .auxiliaries
                .iter()
                .map(|auxiliary| auxiliary.pin.clone())
                .collect(),
        };
        let report_bytes = serde_json::to_vec(&report)?;
        let report_ref = composition::retain_bytes(self, &report_bytes, MAX_REPORT)?;
        let read_revision = composition::retain_bytes(self, &canonical(&revision)?, MAX_REPORT)?;
        let evidence = signing::attest(
            self,
            json!({"@type":"IntentNativeTriageEvidence","schema":"intent.native-triage-evidence.v1","authority":"evidenceOnly","operationId":request.operation_id,"scope":request.composition.scope,"reportSchema":"atomic.triage.report.v1","reportSha256":report_ref.sha256,"reportLength":report_ref.length,"nativeReference":report.reference,"readRevision":revision,"readRevisionSha256":read_revision.sha256,"reviewerExecution":"unavailable"}),
        )?;
        let verdict = match report.verdict {
            atomic_repository::triage::Verdict::Ready => NativeTriageVerdict::Ready,
            atomic_repository::triage::Verdict::Blocked => NativeTriageVerdict::Blocked,
            atomic_repository::triage::Verdict::Stale => NativeTriageVerdict::Stale,
        };
        let receipt = NativeTriageReceipt {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            scope: request.composition.scope.clone(),
            authority: NativeEvidenceAuthority::EvidenceOnly,
            reviewer_execution: ReviewerExecutionAvailability::Unavailable,
            report_schema: "atomic.triage.report.v1".into(),
            report: report_ref,
            native_reference: report.reference,
            native_verdict: verdict,
            read_revision,
            evidence,
        };
        durable::sync_tree(&repository.root().join(".atomic"))?;
        durable::sync_tree(&repository.vault_dir())?;
        File::open(&directory)?.sync_all()?;
        let outcome = NativeTriagePreparation::Produced {
            receipt: Box::new(receipt),
        };
        durable::write_json(
            &journal_path,
            &Journal {
                command_digest,
                outcome: outcome.clone(),
            },
            false,
        )?;
        Ok(outcome)
    }
}

mod control_snapshot;

#[cfg(test)]
pub(crate) mod tests;
