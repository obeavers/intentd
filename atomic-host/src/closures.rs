//! Portable frozen-baseline closures. Objects and exact view membership travel
//! together; restoring never reopens a source Git repository or copies a redb DB.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use atomic_core::change::Change;
use atomic_core::{Base32, Hash};
use atomic_repository::{Repository, ViewManifest};
use intent_atomic_proto::baselines::{
    BaselineReceipt, BASELINE_POLICY_VERSION, MATERIALIZER_VERSION,
};
use intent_atomic_proto::closures::{
    BaselineClosure, ClosureProfile, ClosureScope, ExportBaselineClosureRequest,
    RestoreBaselineClosureRequest, CLOSURE_FORMAT,
};
use intent_atomic_proto::{HostIdentity, SpoolRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    baselines::{self, Manifest},
    durable, Host, HostError, Result,
};

const MAGIC: &[u8] = b"INTENT-ATOMIC-CLOSURE-2\n";
const MAX_PAYLOAD: u64 = 512 * 1024 * 1024;
const MAX_HEADER: usize = 24 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = MAX_PAYLOAD - 24 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_operation(operation: &str) -> bool {
    !operation.is_empty() && operation.len() <= 256 && !operation.chars().any(char::is_control)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Object {
    hash: String,
    length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    format: u32,
    profile: ClosureProfile,
    host: HostIdentity,
    scope: ClosureScope,
    capture_revision: u64,
    baseline: BaselineReceipt,
    files: Manifest,
    view_manifest: String,
    objects: Vec<Object>,
    /// Frozen Git imports are conflict-free native roots. Graph conflict objects
    /// and live overlays require a separate qualified checkpoint profile.
    conflict_state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportJournal {
    request: ExportBaselineClosureRequest,
    command_digest: String,
    receipt: Option<BaselineClosure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreJournal {
    request: RestoreBaselineClosureRequest,
    command_digest: String,
    receipt: Option<BaselineReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreOwner {
    operation_id: String,
    command_digest: String,
    directory: durable::FileIdentity,
}

pub(crate) struct PortableBaselineSeed {
    pub(crate) receipt: BaselineReceipt,
    pub(crate) files: Manifest,
    pub(crate) view: ViewManifest,
    objects: Vec<(Hash, Vec<u8>)>,
}

impl PortableBaselineSeed {
    pub(crate) fn instantiate(&self, root: &std::path::Path) -> Result<Repository> {
        durable::private_dir(root)?;
        let mut repository = Repository::init_with_view(root, &self.view.name).map_err(native)?;
        repository
            .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
            .map_err(native)?;
        for (hash, bytes) in &self.objects {
            repository
                .import_change_bytes(hash, bytes)
                .map_err(native)?;
            crate::recording::sync_imported_object(&repository, &hash.to_base32())?;
        }
        repository.apply_view_manifest(&self.view).map_err(native)?;
        baselines::source::verify_native(&repository, &self.files.entries)?;
        if baselines::source::native_state(&repository)? != self.receipt.native_state {
            return Err(HostError::Invalid(
                "private seed differs from captured native state",
            ));
        }
        Ok(repository)
    }
}

fn validate_scope(
    scope: &ClosureScope,
    baseline: &intent_atomic_proto::baselines::BaselineRef,
) -> Result<()> {
    if scope.workspace_id.is_empty()
        || scope.workspace_id.len() > 256
        || scope.root_id.is_empty()
        || scope.root_id.len() > 256
        || scope.repository_id != baseline.repository_id
        || scope.binding_epoch != baseline.binding_epoch
    {
        return Err(HostError::StaleBinding);
    }
    Ok(())
}

fn read_payload(host: &Host, reference: &SpoolRef) -> Result<Vec<u8>> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    if reference.length > MAX_PAYLOAD
        || reference.name.len() > 128
        || !reference.name.starts_with("closure-")
        || std::path::Path::new(&reference.name).extension() != Some(std::ffi::OsStr::new("bin"))
        || !reference
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(HostError::Invalid(
            "invalid portable closure spool reference",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(host.config.spool_dir.join(&reference.name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != reference.length {
        return Err(HostError::Invalid(
            "portable closure length differs from retained reference",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_PAYLOAD + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(native)? != reference.length
        || digest(&bytes) != reference.sha256
    {
        return Err(HostError::Invalid(
            "portable closure bytes differ from retained digest",
        ));
    }
    Ok(bytes)
}

fn retain_payload(host: &Host, bytes: &[u8]) -> Result<SpoolRef> {
    if durable::identity(&host.config.spool_dir, true)? != host.spool_root_identity {
        return Err(HostError::StaleBinding);
    }
    let sha256 = digest(bytes);
    let reference = SpoolRef {
        name: format!("closure-{sha256}.bin"),
        length: u64::try_from(bytes.len()).map_err(native)?,
        sha256,
    };
    if reference.length > MAX_PAYLOAD {
        return Err(HostError::Invalid("portable closure exceeds byte budget"));
    }
    let path = host.config.spool_dir.join(&reference.name);
    if path.try_exists()? {
        read_payload(host, &reference)?;
        return Ok(reference);
    }
    let temporary = host
        .config
        .spool_dir
        .join(format!(".pending-closure-{}", uuid::Uuid::new_v4()));
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

fn encode(header: &Header, objects: &[(Hash, Vec<u8>)]) -> Result<Vec<u8>> {
    let metadata = serde_json::to_vec(header)?;
    let total = objects
        .iter()
        .try_fold(MAGIC.len() + 8 + metadata.len(), |total, (_, bytes)| {
            total.checked_add(bytes.len())
        })
        .ok_or(HostError::Invalid("closure length overflow"))?;
    if metadata.len() > MAX_HEADER || u64::try_from(total).map_err(native)? > MAX_PAYLOAD {
        return Err(HostError::Invalid("portable closure exceeds budget"));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&u64::try_from(metadata.len()).map_err(native)?.to_be_bytes());
    bytes.extend_from_slice(&metadata);
    for (_, object) in objects {
        bytes.extend_from_slice(object);
    }
    Ok(bytes)
}

type DecodedClosure = (Header, ViewManifest, Vec<(Hash, Vec<u8>)>);

fn decode(bytes: &[u8], expected: &BaselineClosure) -> Result<DecodedClosure> {
    if bytes.len() < MAGIC.len() + 8 || !bytes.starts_with(MAGIC) {
        return Err(HostError::Invalid("unsupported portable closure format"));
    }
    let length = usize::try_from(u64::from_be_bytes(
        bytes[MAGIC.len()..MAGIC.len() + 8]
            .try_into()
            .map_err(native)?,
    ))
    .map_err(native)?;
    let mut cursor = MAGIC.len() + 8;
    if length > MAX_HEADER
        || cursor
            .checked_add(length)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(HostError::Invalid("portable closure header exceeds budget"));
    }
    let header: Header = serde_json::from_slice(&bytes[cursor..cursor + length])?;
    cursor += length;
    if header.format != CLOSURE_FORMAT
        || header.profile != ClosureProfile::FrozenBaseline
        || header.host != HostIdentity::default()
        || header.scope != expected.scope
        || header.capture_revision != expected.capture_revision
        || header.baseline != expected.baseline
        || header.objects.len() > MAX_OBJECTS
        || u64::try_from(header.objects.len()).map_err(native)? != expected.object_count
        || header.conflict_state != "none"
        || header.files.policy_version != BASELINE_POLICY_VERSION
        || header.files.materializer_version != MATERIALIZER_VERSION
        || digest(&serde_json::to_vec(&header.files)?) != header.baseline.manifest_digest
    {
        return Err(HostError::Invalid(
            "portable closure manifest differs from its retained owner",
        ));
    }
    let manifest = ViewManifest::parse(&header.view_manifest).map_err(native)?;
    manifest.verify().map_err(native)?;
    if manifest.name != header.baseline.native_state.view
        || manifest.name.starts_with("wc/")
        || manifest.parent.is_some()
        || manifest.state.to_base32() != header.baseline.native_state.own_merkle
        || manifest.changes.len() != header.objects.len()
    {
        return Err(HostError::Invalid(
            "portable baseline view identity differs from captured membership",
        ));
    }
    let mut objects = Vec::with_capacity(header.objects.len());
    let mut seen = BTreeSet::new();
    for (entry, member) in header.objects.iter().zip(&manifest.changes) {
        let hash = Hash::from_base32(entry.hash.as_bytes())
            .ok_or(HostError::Invalid("invalid native closure hash"))?;
        let size = usize::try_from(entry.length).map_err(native)?;
        let end = cursor
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(HostError::Invalid("truncated native closure object"))?;
        let object = &bytes[cursor..end];
        cursor = end;
        let (change, actual) =
            Change::deserialize(&mut std::io::Cursor::new(object)).map_err(native)?;
        if hash != *member
            || actual != hash
            || digest(object) != entry.sha256
            || change.kind().is_snapshot()
            || change
                .dependencies()
                .iter()
                .any(|dependency| *dependency != Hash::NONE && !seen.contains(dependency))
            || !seen.insert(hash)
        {
            return Err(HostError::Invalid(
                "native object is foreign, duplicated, private or missing a dependency",
            ));
        }
        objects.push((hash, object.to_vec()));
    }
    if cursor != bytes.len() {
        return Err(HostError::Invalid("unexpected bytes after native closure"));
    }
    Ok((header, manifest, objects))
}

impl Host {
    pub(crate) fn portable_baseline_seed(
        &self,
        closure: &BaselineClosure,
    ) -> Result<PortableBaselineSeed> {
        if closure.format != CLOSURE_FORMAT
            || closure.profile != ClosureProfile::FrozenBaseline
            || closure.host != HostIdentity::default()
        {
            return Err(HostError::Invalid("unqualified portable baseline seed"));
        }
        validate_scope(&closure.scope, &closure.baseline.baseline)?;
        let bytes = read_payload(self, &closure.payload)?;
        let (header, view, objects) = decode(&bytes, closure)?;
        Ok(PortableBaselineSeed {
            receipt: header.baseline,
            files: header.files,
            view,
            objects,
        })
    }
    /// Export only exact, recorded, conflict-free frozen baseline membership.
    /// # Errors
    /// Refuses stale scope, private snapshots, missing dependencies and budgets.
    pub fn export_baseline_closure(
        &self,
        request: &ExportBaselineClosureRequest,
    ) -> Result<BaselineClosure> {
        validate_scope(&request.scope, &request.baseline)?;
        if !valid_operation(&request.operation_id) || request.capture_revision == 0 {
            return Err(HostError::Invalid(
                "bounded operation and allocated capture revision required",
            ));
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let journals = self.config.config_dir.join("closure-operations");
        durable::private_dir(&journals)?;
        let path = journals.join(format!(
            "export-{}.json",
            digest(request.operation_id.as_bytes())
        ));
        let command_digest = digest(&serde_json::to_vec(request)?);
        let mut journal = if path.try_exists()? {
            let journal: ExportJournal = durable::read_json(&path)?;
            if journal.command_digest != command_digest || journal.request != *request {
                return Err(HostError::Invalid("conflicting closure export replay"));
            }
            if let Some(receipt) = &journal.receipt {
                let bytes = read_payload(self, &receipt.payload)?;
                decode(&bytes, receipt)?;
                return Ok(receipt.clone());
            }
            journal
        } else {
            let journal = ExportJournal {
                request: request.clone(),
                command_digest,
                receipt: None,
            };
            durable::write_json(&path, &journal, false)?;
            journal
        };
        let store = self.baseline_store(&request.baseline)?;
        let view = &store.receipt.native_state.view;
        if store
            .repository
            .capture_view_conflict_set(view)
            .map_err(native)?
            .is_some()
        {
            return Err(HostError::Unsupported(
                "portable conflict-bearing baselines are not qualified",
            ));
        }
        let manifest = store.repository.view_manifest(view).map_err(native)?;
        if manifest.parent.is_some()
            || manifest.name.starts_with("wc/")
            || manifest.changes.len() > MAX_OBJECTS
        {
            return Err(HostError::Unsupported(
                "portable baseline requires a bounded independent recorded root",
            ));
        }
        let mut object_bytes = 0u64;
        for hash in &manifest.changes {
            let metadata =
                std::fs::symlink_metadata(store.repository.change_store().change_path(hash))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HostError::Invalid(
                    "portable object must be a regular native file",
                ));
            }
            object_bytes = object_bytes
                .checked_add(metadata.len())
                .filter(|length| *length <= MAX_OBJECT_BYTES)
                .ok_or(HostError::Invalid(
                    "native closure exceeds pre-read byte budget",
                ))?;
        }
        // This native API refuses any object outside the captured view closure.
        let objects = store
            .repository
            .export_sandbox_changes(view, &manifest.changes)
            .map_err(native)?
            .map_err(native)?;
        let header = Header {
            format: CLOSURE_FORMAT,
            profile: ClosureProfile::FrozenBaseline,
            host: HostIdentity::default(),
            scope: request.scope.clone(),
            capture_revision: request.capture_revision,
            baseline: store.receipt.clone(),
            files: store.manifest.clone(),
            view_manifest: manifest.to_text(),
            objects: objects
                .iter()
                .map(|(hash, bytes)| {
                    Ok(Object {
                        hash: hash.to_base32(),
                        length: u64::try_from(bytes.len()).map_err(native)?,
                        sha256: digest(bytes),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            conflict_state: "none".into(),
        };
        let bytes = encode(&header, &objects)?;
        let receipt = BaselineClosure {
            format: CLOSURE_FORMAT,
            profile: ClosureProfile::FrozenBaseline,
            host: HostIdentity::default(),
            scope: request.scope.clone(),
            capture_revision: request.capture_revision,
            baseline: store.receipt.clone(),
            payload: retain_payload(self, &bytes)?,
            object_count: u64::try_from(objects.len()).map_err(native)?,
        };
        decode(&bytes, &receipt)?;
        journal.receipt = Some(receipt.clone());
        durable::write_json(&path, &journal, true)?;
        Ok(receipt)
    }

    /// Restore into an owner-private namespace from complete retained closure
    /// bytes alone. No source locator or old native database is consulted.
    /// # Errors
    /// Refuses stale epochs, corrupt closures, foreign members and changed output.
    pub fn restore_baseline_closure(
        &self,
        request: &RestoreBaselineClosureRequest,
    ) -> Result<BaselineReceipt> {
        if !valid_operation(&request.operation_id)
            || request.expected_scope != request.closure.scope
            || request.closure.format != CLOSURE_FORMAT
            || request.closure.host != HostIdentity::default()
        {
            return Err(HostError::StaleBinding);
        }
        validate_scope(&request.expected_scope, &request.closure.baseline.baseline)?;
        let bytes = read_payload(self, &request.closure.payload)?;
        let (header, manifest, objects) = decode(&bytes, &request.closure)?;
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let journals = self.config.config_dir.join("closure-operations");
        durable::private_dir(&journals)?;
        let path = journals.join(format!(
            "restore-{}.json",
            digest(request.operation_id.as_bytes())
        ));
        let command_digest = digest(&serde_json::to_vec(request)?);
        let mut journal = if path.try_exists()? {
            let journal: RestoreJournal = durable::read_json(&path)?;
            if journal.command_digest != command_digest || journal.request != *request {
                return Err(HostError::Invalid("conflicting closure restore replay"));
            }
            journal
        } else {
            let journal = RestoreJournal {
                request: request.clone(),
                command_digest: command_digest.clone(),
                receipt: None,
            };
            durable::write_json(&path, &journal, false)?;
            journal
        };
        let repository_id = &header.baseline.baseline.repository_id;
        if uuid::Uuid::parse_str(repository_id)
            .map_err(native)?
            .to_string()
            != *repository_id
        {
            return Err(HostError::Invalid(
                "portable repository identity must be a canonical UUID",
            ));
        }
        // A fresh host needs no old canonical/cache database. This creates only
        // its private restore namespace; it grants no workspace execution right.
        durable::private_dir(&self.config.stores_dir.join(repository_id))?;
        let root = self.baseline_root(&header.baseline.baseline)?;
        if root.join("published.json").try_exists()? {
            let current = self
                .baseline_store(&header.baseline.baseline)?
                .receipt
                .clone();
            if current != header.baseline {
                return Err(HostError::StaleBinding);
            }
            journal.receipt = Some(current.clone());
            durable::write_json(&path, &journal, true)?;
            return Ok(current);
        }
        if root.try_exists()? {
            let owner: RestoreOwner = durable::read_json(&root.join("restore-owner.json"))?;
            if owner.operation_id != request.operation_id
                || owner.command_digest != command_digest
                || owner.directory != durable::identity(&root, true)?
            {
                return Err(HostError::Uncertain(request.operation_id.clone()));
            }
            // Retain an interrupted private attempt. It was never published as
            // a usable baseline, so rebuilding a fresh owner namespace is safe.
            std::fs::rename(
                &root,
                root.with_extension(format!("retained-{}", uuid::Uuid::new_v4())),
            )?;
        }
        self.baselines
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .remove(&header.baseline.baseline.baseline_id);
        durable::private_dir(
            root.parent()
                .ok_or(HostError::Invalid("restore parent unavailable"))?,
        )?;
        durable::private_dir(&root)?;
        durable::write_json(
            &root.join("restore-owner.json"),
            &RestoreOwner {
                operation_id: request.operation_id.clone(),
                command_digest,
                directory: durable::identity(&root, true)?,
            },
            false,
        )?;
        let native_root = root.join("native");
        durable::private_dir(&native_root)?;
        let mut repository =
            Repository::init_with_view(&native_root, &manifest.name).map_err(native)?;
        repository
            .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
            .map_err(native)?;
        for (hash, object) in objects {
            repository
                .import_change_bytes(&hash, &object)
                .map_err(native)?;
            crate::recording::sync_imported_object(&repository, &hash.to_base32())?;
        }
        repository.apply_view_manifest(&manifest).map_err(native)?;
        // Exact application, never set-union reconciliation. The frozen profile
        // has no conflicts or live overlay whose filesystem effects could escape.
        if repository
            .view_manifest(&manifest.name)
            .map_err(native)?
            .to_text()
            != header.view_manifest
        {
            return Err(HostError::Invalid(
                "restored view membership differs from checkpoint",
            ));
        }
        baselines::source::verify_native(&repository, &header.files.entries)?;
        let receipt =
            self.publish_restored_baseline(&root, &header.baseline, &header.files, repository)?;
        journal.receipt = Some(receipt.clone());
        durable::write_json(&path, &journal, true)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
