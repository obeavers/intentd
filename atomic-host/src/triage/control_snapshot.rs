//! Exact observed control cut. Unknown rows are never dropped from the read set.

use atomic_core::{
    pristine::{VaultEntry, VaultEntryType, VaultTxnT},
    Base32, Hash,
};
use intent_atomic_proto::{
    triage::{
        AuxiliaryControlReadPin, CaptureNativeControlRequest, NativeCanonicalObservation,
        NativeControlSnapshotRef, NativeProofObservation, NativeSubstanceObservation,
    },
    HostIdentity, SpoolRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path,
};

use super::{canonical, digest, native};
use crate::{composition, durable, Host, HostError, Result};

const MAX_SNAPSHOT: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACT: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Auxiliary {
    pub(super) entry: VaultEntry,
    pub(super) source: SpoolRef,
    pub(super) pin: AuxiliaryControlReadPin,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Snapshot {
    pub(super) request: CaptureNativeControlRequest,
    pub(super) manifest: Value,
    pub(super) manifest_merkle: String,
    pub(super) auxiliaries: Vec<Auxiliary>,
    pub(super) task_entries: Vec<(String, String)>,
    pub(super) project_identity_hash: String,
    pub(super) project_id: String,
    pub(super) policy_version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    request_digest: String,
    reference: NativeControlSnapshotRef,
}

fn journal(host: &Host, operation: &str) -> Result<std::path::PathBuf> {
    let root = host.config.config_dir.join("native-control-snapshots");
    durable::private_dir(&root)?;
    Ok(root.join(format!("{}.json", digest(operation.as_bytes()))))
}
fn artifact(root: &Path, path: &str) -> Result<Vec<u8>> {
    if !crate::baselines::source::safe_path(path) {
        return Err(HostError::Invalid("unsafe control snapshot path"));
    }
    let mut parent = root.to_owned();
    if let Some(relative) = Path::new(path).parent() {
        for part in relative.components() {
            parent.push(part);
            durable::identity(&parent, true)?;
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(root.join(path))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT {
        return Err(HostError::Invalid(
            "control snapshot artifact is missing or exceeds budget",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ARTIFACT + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(native)? > MAX_ARTIFACT {
        return Err(HostError::Invalid(
            "control snapshot artifact exceeds budget",
        ));
    }
    Ok(bytes)
}
fn observation(entry: &VaultEntry) -> Result<NativeCanonicalObservation> {
    let frontmatter: Value = serde_json::from_str(&entry.frontmatter_json)?;
    let object = frontmatter.as_object().ok_or(HostError::Invalid(
        "control source frontmatter is not an object",
    ))?;
    let raw_proof_sha256 = object
        .get("proof")
        .map(canonical)
        .transpose()?
        .map(|bytes| digest(&bytes));
    if raw_proof_sha256.is_some() {
        return Err(HostError::Unsupported(
            "auxiliary canonical proof verification is not yet qualified",
        ));
    }
    std::str::from_utf8(&entry.content_bytes).map_err(native)?;
    if entry.entry_type == VaultEntryType::Memory
        && object
            .keys()
            .any(|key| matches!(key.as_str(), "uid" | "id" | "memoryKind"))
    {
        return Err(HostError::Unsupported(
            "canonical Memory spine is outside the bounded legacy default source profile",
        ));
    }
    Ok(NativeCanonicalObservation::NotApplicable {
        reason: if entry.entry_type == VaultEntryType::Skill {
            "the pinned native library has no canonical Skill node"
        } else {
            "legacy native Memory source has no canonical memory identity"
        }
        .into(),
        raw_proof_sha256,
    })
}

impl Host {
    // Caller holds writer. The source is observed only; physical/native equality
    // is additionally verified by real private native rendering before triage.
    pub(super) fn collect_native_control(
        &self,
        request: &CaptureNativeControlRequest,
    ) -> Result<Snapshot> {
        if request.projections.is_empty() || request.projections.len() > 64 {
            return Err(HostError::Unsupported(
                "exact bounded task projections are required for control capture",
            ));
        }
        let mut expected = BTreeSet::new();
        let mut first = None;
        for selected in &request.projections {
            let export = self.export_current_intent_control(
                &request.binding,
                &selected.projection,
                &selected.native_intent_id,
            )?;
            if !expected.insert(export.vault_path().to_owned()) {
                return Err(HostError::Invalid("duplicate control source projection"));
            }
            if let Some(original) = &first {
                let original: &crate::intents::control_export::CurrentIntentControlExport =
                    original;
                if canonical(export.manifest())? != canonical(original.manifest())?
                    || export.manifest_merkle() != original.manifest_merkle()
                {
                    return Err(HostError::StaleBinding);
                }
            } else {
                first = Some(export);
            }
        }
        let first = first.ok_or(HostError::Invalid(
            "control capture has no source projection",
        ))?;
        if first.manifest().intents.len() != expected.len() || !first.manifest().goals.is_empty() {
            return Err(HostError::Unsupported(
                "unselected native intent/goal summaries remain unpinned",
            ));
        }
        let store = self.cached_store(&request.binding)?;
        let root = self
            .binding_path(&request.binding)?
            .join("intent-control/.vault");
        durable::identity(&root, true)?;
        if first.entry_inventory().len() > 256 {
            return Err(HostError::Unsupported(
                "full native control snapshot exceeds qualified entry budget",
            ));
        }
        let transaction = store.repository().pristine().read_txn().map_err(native)?;
        let actual_manifest = transaction.get_vault_manifest().map_err(native)?;
        let actual_identity =
            transaction
                .project_identity()
                .map_err(native)?
                .ok_or(HostError::Invalid(
                    "native control project identity is missing",
                ))?;
        if canonical(&actual_manifest)? != canonical(first.manifest())?
            || actual_identity.hash != first.project_identity().hash
        {
            return Err(HostError::StaleBinding);
        }
        let mut inventory = transaction.list_vault_entries("", None).map_err(native)?;
        inventory.sort_by(|left, right| left.path.cmp(&right.path));
        if inventory.len() > 256 {
            return Err(HostError::Unsupported(
                "full native control snapshot exceeds qualified entry budget",
            ));
        }
        let mut auxiliaries = Vec::new();
        let mut task_entries = Vec::new();
        let mut total = 0u64;
        for meta in &inventory {
            let entry = transaction
                .get_vault_entry(&meta.path)
                .map_err(native)?
                .ok_or(HostError::Invalid(
                    "native control snapshot entry disappeared",
                ))?;
            if entry.introduced_by != 0 {
                return Err(HostError::Unsupported(
                    "native control origin mapping is not yet qualified for this internal node id",
                ));
            }
            if entry.entry_type == VaultEntryType::Intent {
                task_entries.push((meta.path.clone(), digest(&canonical(&entry)?)));
                if !expected.remove(&meta.path) {
                    return Err(HostError::Unsupported(
                        "unselected current native intent remains unpinned",
                    ));
                }
                continue;
            }
            let qualified = matches!(
                (meta.path.as_str(), entry.entry_type),
                (
                    "prompts/system_prompt.md"
                        | "skills/atomic-vault.md"
                        | "skills/code-intelligence.md",
                    VaultEntryType::Skill
                ) | ("memory/MEMORY.md", VaultEntryType::Memory)
            );
            if !qualified {
                return Err(HostError::Unsupported(
                    "native auxiliary path/type is outside the bounded four-default source profile",
                ));
            }
            if entry.content_hash != meta.content_hash
                || entry.content_bytes.len() != meta.content_size
                || entry.entry_type != meta.entry_type
                || entry.updated_at != meta.updated_at
                || Hash::of(&entry.content_bytes).as_bytes() != &entry.content_hash
            {
                return Err(HostError::Invalid(
                    "native control entry differs from its indexed body metadata",
                ));
            }
            serde_json::from_str::<Value>(&entry.frontmatter_json)?
                .as_object()
                .ok_or(HostError::Invalid(
                    "auxiliary control frontmatter is not an object",
                ))?;
            std::str::from_utf8(&entry.content_bytes).map_err(native)?;
            let bytes = artifact(&root, &meta.path)?;
            std::str::from_utf8(&bytes).map_err(native)?;
            total = total
                .checked_add(u64::try_from(bytes.len()).map_err(native)?)
                .filter(|bytes| *bytes <= MAX_SNAPSHOT)
                .ok_or(HostError::Unsupported(
                    "native control artifacts exceed qualified snapshot budget",
                ))?;
            let source = composition::retain_bytes(self, &bytes, MAX_ARTIFACT)?;
            let pin = AuxiliaryControlReadPin {
                path: meta.path.clone(),
                kind: entry.entry_type.as_str().into(),
                native_entry_sha256: digest(&canonical(&entry)?),
                native_body_hash: Hash::from_bytes(entry.content_hash).to_base32(),
                source_sha256: source.sha256.clone(),
                canonical: observation(&entry)?,
                substance:NativeSubstanceObservation::NotApplicable{reason:"native intent substance semantics do not apply to auxiliary Skill/Memory data".into()},
                proof:NativeProofObservation::Absent,
            };
            auxiliaries.push(Auxiliary { entry, source, pin });
        }
        if !expected.is_empty() {
            return Err(HostError::Invalid(
                "selected native intent source is absent from full control inventory",
            ));
        }
        auxiliaries.sort_by(|left, right| left.pin.path.cmp(&right.pin.path));
        drop(transaction);
        if canonical(&store.repository().vault_manifest().map_err(native)?)?
            != canonical(&actual_manifest)?
        {
            return Err(HostError::StaleBinding);
        }
        Ok(Snapshot {
            request: request.clone(),
            manifest: serde_json::to_value(actual_manifest)?,
            manifest_merkle: first.manifest_merkle().into(),
            auxiliaries,
            task_entries,
            project_identity_hash: actual_identity.hash.to_base32(),
            project_id: actual_identity.project_id().map_err(native)?.to_base32(),
            policy_version: 1,
        })
    }

    /// Observe exact current auxiliary data alongside original task projections.
    /// This descriptor is historical evidence only, never task/reviewer authority.
    /// # Errors
    /// Refuses unknown source kinds, unselected intents, missing artifacts and drift.
    pub fn capture_native_triage_control(
        &self,
        request: &CaptureNativeControlRequest,
    ) -> Result<NativeControlSnapshotRef> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || request.operation_id.chars().any(char::is_control)
        {
            return Err(HostError::Invalid("invalid control snapshot operation"));
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        let current = self.collect_native_control(request)?;
        let bytes = canonical(&current)?;
        let descriptor = composition::retain_bytes(self, &bytes, MAX_SNAPSHOT)?;
        let request_digest = digest(&canonical(request)?);
        let path = journal(self, &request.operation_id)?;
        if path.try_exists()? {
            let existing: Journal = durable::read_json(&path)?;
            if existing.request_digest != request_digest {
                return Err(HostError::Invalid(
                    "conflicting native control snapshot replay",
                ));
            }
            if existing.reference.descriptor != descriptor {
                return Err(HostError::StaleBinding);
            }
            return Ok(existing.reference);
        }
        let reference = NativeControlSnapshotRef {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            manifest_merkle: current.manifest_merkle,
            snapshot_digest: descriptor.sha256.clone(),
            descriptor,
        };
        durable::write_json(
            &path,
            &Journal {
                request_digest,
                reference: reference.clone(),
            },
            false,
        )?;
        Ok(reference)
    }

    pub(super) fn original_native_control(
        &self,
        reference: &NativeControlSnapshotRef,
    ) -> Result<Snapshot> {
        let journal: Journal = durable::read_json(&journal(self, &reference.operation_id)?)?;
        if journal.reference != *reference
            || reference.host != HostIdentity::default()
            || reference.snapshot_digest != reference.descriptor.sha256
        {
            return Err(HostError::Invalid(
                "native control descriptor is not an original host observation",
            ));
        }
        let bytes = composition::read_spool(self, &reference.descriptor, MAX_SNAPSHOT)?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
        if digest(&canonical(&snapshot.request)?) != journal.request_digest
            || snapshot.request.binding != reference.binding
            || snapshot.manifest_merkle != reference.manifest_merkle
        {
            return Err(HostError::Invalid(
                "native control descriptor source pins changed",
            ));
        }
        let current = self.collect_native_control(&snapshot.request)?;
        if digest(&canonical(&current)?) != reference.snapshot_digest {
            return Err(HostError::Invalid(
                "current native auxiliary control snapshot drifted",
            ));
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::observation;
    use atomic_core::pristine::{VaultEntry, VaultEntryType};
    #[test]
    fn legacy_default_pin_never_claims_a_canonical_memory_from_a_spine() {
        let source = VaultEntry::new(
            VaultEntryType::Memory,
            b"observed source".to_vec(),
            r#"{"uid":"not-in-this-profile","memoryKind":"decision"}"#.into(),
            "2026-11-13T00:00:00Z".into(),
        );
        assert!(observation(&source).is_err());
    }
}
