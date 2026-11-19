//! Frozen baseline ownership using independent full native imports. The pin has
//! live-parent drafts, so no view label is treated as an immutability guarantee.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atomic_repository::Repository;
use intent_atomic_proto::baselines::{
    BaselineMaterialization, BaselineReceipt, BaselineRef, BaselineStorage, ImportBaselineRequest,
    MaterializeBaselineRequest, BASELINE_POLICY_VERSION, MATERIALIZER_VERSION,
};
use intent_atomic_proto::HostIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{durable, Host, HostError, Result};

pub(crate) mod source;
pub(crate) use source::{SnapshotEntry, SnapshotKind};

const MANIFEST_MAX_BYTES: u64 = 16 * 1024 * 1024;

type Contents = std::collections::BTreeMap<String, Vec<u8>>;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn operation_valid(operation: &str) -> bool {
    !operation.is_empty() && operation.len() <= 256 && !operation.chars().any(char::is_control)
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) policy_version: u32,
    pub(crate) materializer_version: u32,
    pub(crate) entries: Vec<SnapshotEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Owner {
    baseline: BaselineRef,
    directory: durable::FileIdentity,
    database: durable::FileIdentity,
    manifest_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterializationOwner {
    receipt: BaselineMaterialization,
    directory: durable::FileIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    command_digest: String,
    request: ImportBaselineRequest,
    phase: Phase,
    receipt: Option<BaselineReceipt>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Prepared,
    Published,
    FailedKnown,
}

pub(crate) struct BaselineStore {
    pub(crate) receipt: BaselineReceipt,
    pub(crate) manifest: Manifest,
    owner: Owner,
    pub(crate) repository: Repository,
}

fn large_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MANIFEST_MAX_BYTES {
        return Err(HostError::Invalid("baseline manifest exceeds budget"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MANIFEST_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(native)? > MANIFEST_MAX_BYTES {
        return Err(HostError::Invalid("baseline manifest exceeds budget"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    if u64::try_from(bytes.len()).map_err(native)? > MANIFEST_MAX_BYTES {
        return Err(HostError::Invalid("baseline manifest exceeds budget"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    durable::sync_parent(path)
}

impl Host {
    pub(crate) fn baseline_root(&self, reference: &BaselineRef) -> Result<PathBuf> {
        if durable::identity(&self.config.stores_dir, true)? != self.stores_root_identity {
            return Err(HostError::StaleBinding);
        }
        if uuid::Uuid::parse_str(&reference.repository_id)
            .map_err(native)?
            .to_string()
            != reference.repository_id
            || reference.binding_epoch == 0
            || !hash_valid(&reference.baseline_id)
        {
            return Err(HostError::Invalid("invalid frozen baseline identity"));
        }
        let repository = self.config.stores_dir.join(&reference.repository_id);
        durable::identity(&repository, true)?;
        let baselines = repository.join("baselines");
        if baselines.try_exists()? {
            durable::private_dir(&baselines)?;
        }
        Ok(baselines.join(&reference.baseline_id))
    }

    pub(crate) fn baseline_store(&self, reference: &BaselineRef) -> Result<Arc<BaselineStore>> {
        self.baseline_store_with_contents(reference)
            .map(|(store, _)| store)
    }

    fn baseline_store_with_contents(
        &self,
        reference: &BaselineRef,
    ) -> Result<(Arc<BaselineStore>, Contents)> {
        let root = self.baseline_root(reference)?;
        let mut stores = self.baselines.lock().map_err(|_| HostError::Poisoned)?;
        if let Some(store) = stores.get(&reference.baseline_id) {
            let contents = store.validate(&root, reference)?;
            return Ok((store.clone(), contents));
        }
        // Cold loading already performs the full exact native validation. Keep
        // those rendered bytes rather than rendering the same 50k-file root twice.
        let (store, contents) = load(&root, reference)?;
        let store = Arc::new(store);
        stores.insert(reference.baseline_id.clone(), store.clone());
        Ok((store, contents))
    }

    /// Publish only a fully verified, privately reconstructed portable root.
    /// The caller owns the host writer lane and retained restore command.
    pub(crate) fn publish_restored_baseline(
        &self,
        root: &Path,
        receipt: &BaselineReceipt,
        manifest: &Manifest,
        repository: Repository,
    ) -> Result<BaselineReceipt> {
        if source::native_state(&repository)? != receipt.native_state
            || digest(&serde_json::to_vec(manifest)?) != receipt.manifest_digest
        {
            return Err(HostError::Invalid(
                "restored native state or manifest differs from checkpoint",
            ));
        }
        source::verify_native(&repository, &manifest.entries)?;
        durable::sync_tree(&root.join("native/.atomic"))?;
        write_manifest(&root.join("manifest.json"), manifest)?;
        durable::write_json(&root.join("receipt.json"), receipt, false)?;
        let owner = Owner {
            baseline: receipt.baseline.clone(),
            directory: durable::identity(&root.join("native"), true)?,
            database: durable::identity(&repository.database_path(), false)?,
            manifest_digest: receipt.manifest_digest.clone(),
        };
        durable::write_json(&root.join("owner.json"), &owner, false)?;
        drop(repository);
        durable::write_json(
            &root.join("published.json"),
            &digest(&serde_json::to_vec(receipt)?),
            false,
        )?;
        self.baseline_store(&receipt.baseline)?;
        Ok(receipt.clone())
    }

    /// Import an immutable Git tree into an independent native root. This is
    /// the documented full-reimport fallback; previous is provenance, never a
    /// mutable parent membership edge. No source worktree is read or changed.
    /// # Errors
    /// Refuses unsafe policy, missing retained source, stale binding or fidelity
    /// loss. Incomplete disposable imports are retained, never accepted as roots.
    pub fn import_baseline(&self, request: &ImportBaselineRequest) -> Result<BaselineReceipt> {
        if !operation_valid(&request.operation_id)
            || !request.source_path.is_absolute()
            || request.commit.len() != 40
            || !request
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || request.policy.version != BASELINE_POLICY_VERSION
            || request.policy.excluded_paths.len() > 64
            || request
                .policy
                .excluded_paths
                .iter()
                .any(|path| !source::safe_path(path))
            || serde_json::to_vec(request)?.len() > 16_384
        {
            return Err(HostError::Invalid(
                "invalid immutable baseline request or file policy",
            ));
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        self.verify_marker(&request.binding)?;
        if let Some(previous) = &request.previous {
            if previous.repository_id != request.binding.repository_id
                || previous.binding_epoch != request.binding.binding_epoch
            {
                return Err(HostError::StaleBinding);
            }
            self.baseline_store(previous)?;
        }
        let command_digest = digest(&serde_json::to_vec(request)?);
        let reference = BaselineRef {
            repository_id: request.binding.repository_id.clone(),
            binding_epoch: request.binding.binding_epoch,
            baseline_id: command_digest.clone(),
        };
        let root = self.baseline_root(&reference)?;
        let journals = self.config.config_dir.join("baseline-operations");
        durable::private_dir(&journals)?;
        let journal_path =
            journals.join(format!("{}.json", digest(request.operation_id.as_bytes())));
        if journal_path.try_exists()? {
            let journal: Journal = durable::read_json(&journal_path)?;
            if journal.command_digest != command_digest || journal.request != *request {
                return Err(HostError::Invalid("conflicting baseline operation replay"));
            }
            if journal.phase == Phase::Published {
                return Ok(self.baseline_store(&reference)?.receipt.clone());
            }
            return Err(HostError::Uncertain(request.operation_id.clone()));
        }
        // Preflight the entire immutable tree before creating any native data.
        let snapshot = source::read_git(&request.source_path, &request.commit, &request.policy)?;
        let mut journal = Journal {
            command_digest,
            request: request.clone(),
            phase: Phase::Prepared,
            receipt: None,
        };
        durable::write_json(&journal_path, &journal, false)?;
        let result = (|| {
            durable::private_dir(
                root.parent()
                    .ok_or(HostError::Invalid("baseline parent unavailable"))?,
            )?;
            if root.try_exists()? {
                return Err(HostError::Uncertain(request.operation_id.clone()));
            }
            durable::private_dir(&root)?;
            let native_root = root.join("native");
            durable::private_dir(&native_root)?;
            let repository = source::import_native(&native_root, &snapshot, &request.commit)?;
            let manifest = Manifest {
                policy_version: BASELINE_POLICY_VERSION,
                materializer_version: MATERIALIZER_VERSION,
                entries: snapshot.entries,
            };
            let manifest_digest = digest(&serde_json::to_vec(&manifest)?);
            let receipt = BaselineReceipt {
                baseline: reference.clone(),
                host: HostIdentity::default(),
                source_commit: request.commit.clone(),
                source_tree: snapshot.tree,
                previous: request.previous.clone(),
                storage: BaselineStorage::FullReimport,
                native_state: source::native_state(&repository)?,
                materialization_id: digest(&serde_json::to_vec(&(
                    MATERIALIZER_VERSION,
                    &manifest_digest,
                ))?),
                manifest_digest: manifest_digest.clone(),
                file_count: u64::try_from(manifest.entries.len()).map_err(native)?,
                total_bytes: manifest.entries.iter().map(|entry| entry.length).sum(),
                policy: request.policy.clone(),
            };
            write_manifest(&root.join("manifest.json"), &manifest)?;
            durable::write_json(&root.join("receipt.json"), &receipt, false)?;
            let owner = Owner {
                baseline: reference.clone(),
                directory: durable::identity(&native_root, true)?,
                database: durable::identity(&native_root.join(".atomic/atomic.redb"), false)?,
                manifest_digest,
            };
            durable::write_json(&root.join("owner.json"), &owner, false)?;
            drop(repository);
            durable::sync_tree(&native_root.join(".atomic"))?;
            durable::write_json(
                &root.join("published.json"),
                &digest(&serde_json::to_vec(&receipt)?),
                false,
            )?;
            journal.phase = Phase::Published;
            journal.receipt = Some(receipt.clone());
            durable::write_json(&journal_path, &journal, true)?;
            self.baseline_store(&reference)?;
            Ok(receipt)
        })();
        if result.is_err() {
            journal.phase = Phase::FailedKnown;
            durable::write_json(&journal_path, &journal, true)?;
        }
        result
    }

    /// Verify the frozen native root and manifest before returning its receipt.
    /// # Errors
    /// Refuses missing, replaced, mutated or unproved frozen stores.
    pub fn read_baseline(&self, reference: &BaselineRef) -> Result<BaselineReceipt> {
        self.read_admitted()?;
        Ok(self.baseline_store(reference)?.receipt.clone())
    }

    /// Materialize only in a fresh host-private spool directory. Exact native
    /// bytes are verified before writes; caller destinations are never accepted.
    /// # Errors
    /// Refuses changed native state, conflicting operation replay and filesystem
    /// substitutions. Existing user directories are never overwritten.
    pub fn materialize_baseline(
        &self,
        request: &MaterializeBaselineRequest,
    ) -> Result<BaselineMaterialization> {
        if !operation_valid(&request.operation_id) {
            return Err(HostError::Invalid(
                "invalid materialization operation identity",
            ));
        }
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if durable::identity(&self.config.spool_dir, true)? != self.spool_root_identity {
            return Err(HostError::StaleBinding);
        }
        let (store, contents) = self.baseline_store_with_contents(&request.baseline)?;
        let materializations = self.config.spool_dir.join("baseline-materializations");
        durable::private_dir(&materializations)?;
        let path = materializations.join(digest(&serde_json::to_vec(request)?));
        let receipt = BaselineMaterialization {
            baseline: request.baseline.clone(),
            materialization_id: store.receipt.materialization_id.clone(),
            path: path.join("files"),
            manifest_digest: store.receipt.manifest_digest.clone(),
            file_count: store.receipt.file_count,
            total_bytes: store.receipt.total_bytes,
        };
        if path.try_exists()? {
            let retained: MaterializationOwner = durable::read_json(&path.join("receipt.json"))?;
            if retained.receipt != receipt
                || retained.directory != durable::identity(&receipt.path, true)?
            {
                return Err(HostError::Invalid(
                    "conflicting or replaced materialization replay",
                ));
            }
            verify_materialization(&receipt.path, &store.manifest.entries)?;
            return Ok(retained.receipt);
        }
        durable::private_dir(&path)?;
        durable::private_dir(&receipt.path)?;
        let mut changed_directories = std::collections::BTreeSet::new();
        for entry in &store.manifest.entries {
            let target = receipt.path.join(&entry.path);
            let parent = target
                .parent()
                .ok_or(HostError::Invalid("materialized path parent unavailable"))?;
            private_parents(&receipt.path, parent)?;
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
            changed_directories.insert(parent.to_owned());
        }
        // Every regular file is durable above. Flush each directory once after
        // its final entry write, before publishing the immutable receipt.
        for directory in changed_directories {
            File::open(directory)?.sync_all()?;
        }
        verify_materialization(&receipt.path, &store.manifest.entries)?;
        durable::write_json(
            &path.join("receipt.json"),
            &MaterializationOwner {
                receipt: receipt.clone(),
                directory: durable::identity(&receipt.path, true)?,
            },
            false,
        )?;
        // These private directories are qualification materializations, not an
        // admitted working copy or an advertised source-mutation capability.
        Ok(receipt)
    }

    pub(crate) fn reconcile_baselines(&self) -> Result<()> {
        let journals = self.config.config_dir.join("baseline-operations");
        if !journals.try_exists()? {
            return Ok(());
        }
        durable::private_dir(&journals)?;
        for file in std::fs::read_dir(journals)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let mut journal: Journal = durable::read_json(&file.path())?;
            if journal.command_digest != digest(&serde_json::to_vec(&journal.request)?)
                || file.file_name().to_string_lossy()
                    != format!("{}.json", digest(journal.request.operation_id.as_bytes()))
            {
                return Err(HostError::Invalid(
                    "baseline journal immutable command mismatch",
                ));
            }
            let reference = BaselineRef {
                repository_id: journal.request.binding.repository_id.clone(),
                binding_epoch: journal.request.binding.binding_epoch,
                baseline_id: journal.command_digest.clone(),
            };
            let root = self.baseline_root(&reference)?;
            if root.join("published.json").try_exists()? {
                journal.receipt = Some(self.baseline_store(&reference)?.receipt.clone());
                journal.phase = Phase::Published;
            } else {
                journal.phase = Phase::FailedKnown;
            }
            durable::write_json(&file.path(), &journal, true)?;
        }
        Ok(())
    }
}

impl BaselineStore {
    fn validate(&self, root: &Path, reference: &BaselineRef) -> Result<Contents> {
        if self.receipt.baseline != *reference
            || self.owner.baseline != *reference
            || self.receipt.host != HostIdentity::default()
            || self.owner.directory != durable::identity(&root.join("native"), true)?
            || self.owner.database
                != durable::identity(&root.join("native/.atomic/atomic.redb"), false)?
            || self.owner.manifest_digest != self.receipt.manifest_digest
            || digest(&serde_json::to_vec(&self.manifest)?) != self.receipt.manifest_digest
            || source::native_state(&self.repository)? != self.receipt.native_state
        {
            return Err(HostError::StaleBinding);
        }
        source::verify_native(&self.repository, &self.manifest.entries)
    }
}

fn load(root: &Path, reference: &BaselineRef) -> Result<(BaselineStore, Contents)> {
    durable::identity(root, true)?;
    let receipt: BaselineReceipt = durable::read_json(&root.join("receipt.json"))?;
    let published: String = durable::read_json(&root.join("published.json"))?;
    if digest(&serde_json::to_vec(&receipt)?) != published {
        return Err(HostError::Invalid("baseline publication proof mismatch"));
    }
    let owner: Owner = durable::read_json(&root.join("owner.json"))?;
    let manifest = large_json(&root.join("manifest.json"))?;
    let repository =
        Repository::open_readonly_without_migration(root.join("native")).map_err(native)?;
    let store = BaselineStore {
        receipt,
        manifest,
        owner,
        repository,
    };
    let contents = store.validate(root, reference)?;
    Ok((store, contents))
}

fn private_parents(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent.strip_prefix(root).map_err(native)?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        durable::private_dir(&current)?;
    }
    Ok(())
}

pub(crate) fn verify_materialization(root: &Path, entries: &[SnapshotEntry]) -> Result<()> {
    durable::identity(root, true)?;
    let expected: std::collections::BTreeSet<_> =
        entries.iter().map(|entry| entry.path.clone()).collect();
    if materialized_inventory(root, root)? != expected {
        return Err(HostError::StaleBinding);
    }
    verify_materialized_entries(root, entries)
}

pub(crate) fn verify_materialized_entries(root: &Path, entries: &[SnapshotEntry]) -> Result<()> {
    for entry in entries {
        verify_parents(
            root,
            Path::new(&entry.path)
                .parent()
                .unwrap_or_else(|| Path::new("")),
        )?;
        let path = root.join(&entry.path);
        let metadata = std::fs::symlink_metadata(&path)?;
        let bytes = if entry.kind == SnapshotKind::Symlink {
            use std::os::unix::ffi::OsStrExt;
            if !metadata.file_type().is_symlink() {
                return Err(HostError::StaleBinding);
            }
            std::fs::read_link(&path)?.as_os_str().as_bytes().to_vec()
        } else {
            let mode = if entry.kind == SnapshotKind::Executable {
                0o755
            } else {
                0o644
            };
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o777 != mode
            {
                return Err(HostError::StaleBinding);
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    (nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits(),
                )
                .open(&path)?;
            if file.metadata()?.len() != entry.length {
                return Err(HostError::StaleBinding);
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(entry.length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            bytes
        };
        if u64::try_from(bytes.len()).map_err(native)? != entry.length
            || digest(&bytes) != entry.sha256
        {
            return Err(HostError::StaleBinding);
        }
    }
    Ok(())
}

fn verify_parents(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        durable::identity(&current, true)?;
    }
    Ok(())
}

fn materialized_inventory(
    root: &Path,
    current: &Path,
) -> Result<std::collections::BTreeSet<String>> {
    let mut files = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            files.extend(materialized_inventory(root, &entry.path())?);
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(native)?
                .to_str()
                .ok_or(HostError::Invalid("materialized path is not UTF-8"))?
                .to_owned();
            if !source::safe_path(&relative) {
                return Err(HostError::Invalid("unsafe materialized path"));
            }
            files.insert(relative);
        } else {
            return Err(HostError::Invalid("special file in materialization"));
        }
        if files.len() > source::MAX_FILES {
            return Err(HostError::Invalid(
                "materialization inventory exceeds budget",
            ));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests;
