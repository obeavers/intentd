//! Actual private native composition bridge. Only an authenticated host reply,
//! verified retained artifacts and an exact materialization produce the opaque
//! contribution receipt. No live target/adoption capability is granted here.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
    sync::Arc,
};

use intent_atomic_proto::{
    baselines::{BASELINE_POLICY_VERSION, MATERIALIZER_VERSION},
    composition::{
        CaptureCompositionTargetRequest, CapturedCompositionTarget, CompositionConflict,
        CompositionInventory, CompositionStateManifest, PrivateCompositionInput,
        PrivateCompositionOutcome, PrivateCompositionReceipt,
    },
    Command, HostIdentity, Reply, SpoolRef, StateToken,
};
use intent_core::{
    vcs::{
        self, AtomicChangeHash, AtomicStateHash, ContentDigest, MaterializationId, NativeChangeRef,
        NativeStateRef, OperationId, RootBinding, VcsKind,
    },
    work_evidence::composition::{NativeCompositionReceipt, VerifiedCompositionReceipt},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{spool::Spool, HostError, HostSupervisor, Result};

const MAX_METADATA: u64 = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;

pub struct AtomicCompositionClient {
    host: Arc<HostSupervisor>,
}

/// This result is Rust-only. Serialized metadata cannot mint verified inventory.
#[derive(Debug)]
pub enum AtomicCompositionPreparation {
    InheritedBaselineRequired {
        missing_changes: Vec<NativeChangeRef>,
    },
    Prepared {
        composition: Box<vcs::PreparedComposition>,
        native: Box<PrivateCompositionReceipt>,
    },
}

impl AtomicCompositionClient {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self { host }
    }

    /// Capture original numeric state and exact native closure at the host.
    /// This records no working overlay and grants no live source mutation.
    /// # Errors
    /// Refuses a foreign root/epoch, source race or mismatched host response.
    pub async fn capture_target(
        &self,
        root: &RootBinding,
        request: CaptureCompositionTargetRequest,
    ) -> Result<CapturedCompositionTarget> {
        scope(root, &request.scope)?;
        if request.binding.repository_id != root.repository_id.as_str()
            || request.binding.binding_epoch != root.epoch
        {
            return Err(invalid(
                "native capture binding differs from persisted root",
            ));
        }
        let expected = request.clone();
        let Reply::StoreOpened { binding } = self
            .host
            .request(Command::OpenStore {
                binding: request.binding.clone(),
            })
            .await?
        else {
            return Err(invalid("expected admitted canonical native store"));
        };
        if binding != request.binding {
            return Err(invalid("canonical native store binding differs"));
        }
        let Reply::CompositionTargetCaptured { capture } = self
            .host
            .request(Command::CaptureCompositionTarget { request })
            .await?
        else {
            return Err(invalid("expected native target capture"));
        };
        let mut empty = capture.clone();
        empty.capture_digest.clear();
        if capture.host != HostIdentity::default()
            || capture.operation_id != expected.operation_id
            || capture.scope != expected.scope
            || capture.binding != expected.binding
            || capture.state != expected.expected_state
            || digest(&serde_json::to_vec(&empty)?) != capture.capture_digest
        {
            return Err(invalid(
                "native capture receipt differs from original source fence",
            ));
        }
        let spool_root = self.host.spool_path();
        let manifest = capture.manifest.clone();
        tokio::task::spawn_blocking(move || {
            Spool::open(&spool_root)?
                .open_verified(&manifest, MAX_METADATA)
                .map(|_| ())
        })
        .await
        .map_err(|_| invalid("native capture verification worker failed"))??;
        Ok(capture)
    }

    /// Compose immutable source objects in an independent host-private store.
    /// The only opaque receipt constructor is reached after actual host effects
    /// and retained file, state, inventory and conflict evidence are verified.
    /// # Errors
    /// Refuses mismatched replies, changed retained artifacts and source scope.
    pub async fn compose(
        &self,
        root: &RootBinding,
        input: PrivateCompositionInput,
    ) -> Result<AtomicCompositionPreparation> {
        scope(root, &input.scope)?;
        if input.selected_changes.len() > MAX_OBJECTS || input.available_changes.len() > MAX_OBJECTS
        {
            return Err(invalid("native composition input exceeds object budget"));
        }
        // Startup establishes the one owner-private spool. A dropped waiter never
        // removes an input needed to reconcile a running native operation.
        if !matches!(self.host.request(Command::Ping).await?, Reply::Pong) {
            return Err(invalid("expected admitted native host"));
        }
        let bytes = serde_json::to_vec(&input)?;
        if u64::try_from(bytes.len()).map_err(|_| invalid("native input length overflow"))?
            > MAX_METADATA
        {
            return Err(invalid("native composition input exceeds metadata budget"));
        }
        let command_digest = digest(&bytes);
        let spool_root = self.host.spool_path();
        let input_ref =
            tokio::task::spawn_blocking(move || Spool::open(&spool_root)?.retain(&bytes))
                .await
                .map_err(|_| invalid("native composition input worker failed"))??;
        let Reply::PrivateComposed { outcome } = self
            .host
            .request(Command::ComposePrivate { input: input_ref })
            .await?
        else {
            return Err(invalid("expected actual native composition result"));
        };
        let spool_root = self.host.spool_path();
        let root = root.clone();
        tokio::task::spawn_blocking(move || {
            verify(&spool_root, &root, &input, &command_digest, *outcome)
        })
        .await
        .map_err(|_| invalid("native composition verification worker failed"))?
    }
}

fn invalid(message: &'static str) -> HostError {
    HostError::Protocol(message)
}
fn digest(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn native_hash(value: &str) -> bool {
    value.len() == 52
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        && matches!(value.as_bytes().last(), Some(b'A' | b'Q'))
}
fn scope(root: &RootBinding, scope: &intent_atomic_proto::closures::ClosureScope) -> Result<()> {
    if root.kind != VcsKind::Atomic
        || root.workspace_id.as_str() != scope.workspace_id
        || root.root_id != scope.root_id
        || root.repository_id.as_str() != scope.repository_id
        || root.epoch != scope.binding_epoch
    {
        return Err(invalid(
            "native composition differs from persisted root scope",
        ));
    }
    Ok(())
}
fn read(spool: &Spool, reference: &SpoolRef, limit: u64) -> Result<Vec<u8>> {
    let mut file = spool.open_verified(reference, limit)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| invalid("native spool length overflow"))?
        != reference.length
        || digest(&bytes) != reference.sha256
    {
        return Err(invalid("native spool changed while being read"));
    }
    Ok(bytes)
}
fn keys(values: &[String]) -> Result<BTreeSet<String>> {
    if values.len() > MAX_OBJECTS
        || values
            .iter()
            .any(|value| !native_hash(value) || value.bytes().all(|byte| byte == b'A'))
    {
        return Err(invalid(
            "native composition contains invalid change identities",
        ));
    }
    let set: BTreeSet<_> = values.iter().cloned().collect();
    if set.len() != values.len() {
        return Err(invalid("native composition contains duplicate changes"));
    }
    Ok(set)
}
fn changes(root: &RootBinding, values: &[String]) -> Vec<NativeChangeRef> {
    values
        .iter()
        .map(|value| NativeChangeRef::Atomic {
            repository_id: root.repository_id.clone(),
            change: AtomicChangeHash::from_string(value),
        })
        .collect()
}
fn state(root: &RootBinding, token: &StateToken, manifest: &str) -> Result<NativeStateRef> {
    if !native_hash(&token.effective_state)
        || !native_hash(&token.own_merkle)
        || token.view.is_empty()
        || token.view.starts_with("wc/")
        || !sha(manifest)
    {
        return Err(invalid("native composition state lacks retained identity"));
    }
    Ok(NativeStateRef::Atomic {
        repository_id: root.repository_id.clone(),
        view: token.view.clone(),
        effective_state: AtomicStateHash::from_string(&token.effective_state),
        own_merkle: AtomicStateHash::from_string(&token.own_merkle),
        manifest: ContentDigest::from_string(manifest),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileManifest {
    policy_version: u32,
    materializer_version: u32,
    entries: Vec<FileEntry>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum FileKind {
    Regular,
    Executable,
    Symlink,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileEntry {
    path: String,
    kind: FileKind,
    mode: u32,
    length: u64,
    sha256: String,
}

fn safe(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn inventory(root: &Path, current: &Path) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            values.extend(inventory(root, &entry.path())?);
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            let name = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| invalid("native candidate escaped its private root"))?
                .to_str()
                .ok_or(invalid("native candidate path is not UTF-8"))?
                .to_owned();
            if !safe(&name) {
                return Err(invalid("unsafe native candidate path"));
            }
            values.insert(name);
        } else {
            return Err(invalid("special file in native candidate"));
        }
        if values.len() > 50_000 {
            return Err(invalid("native candidate exceeds file budget"));
        }
    }
    Ok(values)
}
fn verify_files(path: &Path, manifest: &FileManifest) -> Result<()> {
    if manifest.policy_version != BASELINE_POLICY_VERSION
        || manifest.materializer_version != MATERIALIZER_VERSION
        || manifest.entries.len() > 50_000
        || std::fs::symlink_metadata(path)?.file_type().is_symlink()
    {
        return Err(invalid("native materialization policy changed"));
    }
    let expected: BTreeSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    if expected.len() != manifest.entries.len() || inventory(path, path)? != expected {
        return Err(invalid("native materialization inventory changed"));
    }
    let mut total = 0u64;
    for entry in &manifest.entries {
        if !safe(&entry.path) || !sha(&entry.sha256) || entry.length > 32 * 1024 * 1024 {
            return Err(invalid("native materialization entry violates its budget"));
        }
        total = total
            .checked_add(entry.length)
            .filter(|bytes| *bytes <= 128 * 1024 * 1024)
            .ok_or(invalid("native materialization exceeds byte budget"))?;
        let target = path.join(&entry.path);
        let metadata = std::fs::symlink_metadata(&target)?;
        let bytes = if matches!(entry.kind, FileKind::Symlink) {
            if entry.mode != 0o120_000 || !metadata.file_type().is_symlink() {
                return Err(invalid("native candidate symlink kind changed"));
            }
            std::fs::read_link(target)?.as_os_str().as_bytes().to_vec()
        } else {
            let mode = if matches!(entry.kind, FileKind::Executable) {
                0o755
            } else {
                0o644
            };
            if entry.mode != (0o100_000 | mode)
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.mode() & 0o777 != mode
                || metadata.len() != entry.length
            {
                return Err(invalid("native candidate kind/mode/length changed"));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(target)?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(entry.length + 1)
                .read_to_end(&mut bytes)?;
            bytes
        };
        if u64::try_from(bytes.len()).map_err(|_| invalid("native candidate length overflow"))?
            != entry.length
            || digest(&bytes) != entry.sha256
        {
            return Err(invalid("native candidate exact bytes changed"));
        }
    }
    Ok(())
}

fn verify(
    spool_root: &Path,
    root: &RootBinding,
    input: &PrivateCompositionInput,
    command_digest: &str,
    outcome: PrivateCompositionOutcome,
) -> Result<AtomicCompositionPreparation> {
    scope(root, &input.scope)?;
    let spool = Spool::open(spool_root)?;
    let receipt = match outcome {
        PrivateCompositionOutcome::InheritedBaselineRequired {
            operation_id,
            host,
            scope: actual_scope,
            command_digest: actual_command,
            missing_changes,
            missing_count,
        } => {
            if operation_id != input.operation_id
                || host != HostIdentity::default()
                || *actual_scope != input.scope
                || actual_command != command_digest
                || missing_count == 0
                || missing_count > 4096
            {
                return Err(invalid(
                    "native inherited baseline refusal differs from its command",
                ));
            }
            let missing: Vec<String> =
                serde_json::from_slice(&read(&spool, &missing_changes, MAX_METADATA)?)?;
            keys(&missing)?;
            if u64::try_from(missing.len()).map_err(|_| invalid("missing native count overflow"))?
                != missing_count
                || missing.is_empty()
            {
                return Err(invalid(
                    "inherited baseline refusal lacks exact missing inventory",
                ));
            }
            return Ok(AtomicCompositionPreparation::InheritedBaselineRequired {
                missing_changes: changes(root, &missing),
            });
        }
        PrivateCompositionOutcome::Composed { receipt } => *receipt,
    };
    let mut cleared = receipt.clone();
    cleared.receipt_digest.clear();
    if receipt.host != HostIdentity::default()
        || receipt.operation_id != input.operation_id
        || receipt.scope != input.scope
        || receipt.command_digest != command_digest
        || digest(&serde_json::to_vec(&cleared)?) != receipt.receipt_digest
        || receipt.target_state != input.expected_target
        || receipt.target_capture_digest
            != input
                .captured_target
                .as_ref()
                .map(|capture| capture.capture_digest.clone())
        || receipt.private_target_state.view != input.expected_target.view
        || receipt.private_target_state.own_merkle != input.expected_target.own_merkle
        || receipt
            .native_conflict_hash
            .as_ref()
            .is_some_and(|hash| !native_hash(hash))
        || receipt.candidate_path
            != spool_root
                .join("compositions")
                .join(command_digest)
                .join("files")
    {
        return Err(invalid(
            "native receipt differs from actual requested composition",
        ));
    }
    for directory in [
        spool_root.join("compositions"),
        spool_root.join("compositions").join(command_digest),
        receipt.candidate_path.clone(),
    ] {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
            return Err(invalid("native candidate namespace is not owner-private"));
        }
    }
    let membership: CompositionInventory =
        serde_json::from_slice(&read(&spool, &receipt.inventory, MAX_METADATA)?)?;
    let selected = keys(&membership.selected_changes)?;
    let dependencies = keys(&membership.dependency_only_changes)?;
    let full = keys(&membership.full_closed_changes)?;
    let inherited = keys(&membership.inherited_baseline_changes)?;
    let context = keys(&membership.target_context_changes)?;
    if selected != keys(&input.selected_changes)?
        || !selected.is_subset(&full)
        || !dependencies.is_subset(&full)
        || !inherited.is_subset(&full)
        || !context.is_subset(&full)
        || !selected.is_disjoint(&dependencies)
        || receipt.selection_revision != digest(&serde_json::to_vec(&membership.selected_changes)?)
        || receipt.composition_revision
            != digest(&serde_json::to_vec(&(
                &input.expected_target,
                &membership,
                &receipt.materialization_id,
                &receipt.native_conflict_hash,
            ))?)
    {
        return Err(invalid(
            "native inventory differs from actual selection or closure",
        ));
    }
    let manifest: CompositionStateManifest =
        serde_json::from_slice(&read(&spool, &receipt.state_manifest, MAX_METADATA)?)?;
    if manifest.native_state != receipt.candidate_state
        || manifest.files != receipt.materialization_manifest
        || manifest.inventory != receipt.inventory
        || manifest.conflicts != receipt.conflicts
        || manifest.full_closed_changes != membership.full_closed_changes
        || manifest.materialization_id != receipt.materialization_id
        || manifest.conflict_manifest
            != receipt
                .conflict_manifest
                .as_ref()
                .map(|reference| reference.sha256.clone())
    {
        return Err(invalid("native retained closure differs from host receipt"));
    }
    let mut exact = BTreeSet::new();
    let mut total = 0u64;
    for object in &manifest.exact_objects {
        if !native_hash(&object.hash) || !exact.insert(object.hash.clone()) {
            return Err(invalid(
                "native exact closure has duplicate/invalid objects",
            ));
        }
        total = total
            .checked_add(object.bytes.length)
            .filter(|bytes| *bytes <= MAX_OBJECT_BYTES)
            .ok_or(invalid("native exact closure exceeds byte budget"))?;
        spool.open_verified(&object.bytes, MAX_OBJECT_BYTES)?;
    }
    if exact != full {
        return Err(invalid("native exact closure is incomplete"));
    }
    let files: FileManifest = serde_json::from_slice(&read(
        &spool,
        &receipt.materialization_manifest,
        MAX_METADATA,
    )?)?;
    if receipt.materialization_id
        != digest(&serde_json::to_vec(&(
            MATERIALIZER_VERSION,
            &receipt.materialization_manifest.sha256,
        ))?)
    {
        return Err(invalid("native materialization identity changed"));
    }
    verify_files(&receipt.candidate_path, &files)?;
    let conflicts: Vec<CompositionConflict> =
        serde_json::from_slice(&read(&spool, &receipt.conflicts, MAX_METADATA)?)?;
    if conflicts.is_empty() != receipt.conflict_manifest.is_none()
        || receipt.conflict_manifest.is_some() != receipt.native_conflict_hash.is_some()
    {
        return Err(invalid("native conflict evidence is incomplete"));
    }
    if let Some(binary) = &receipt.conflict_manifest {
        spool.open_verified(binary, MAX_METADATA)?;
    }
    let mut neutral = Vec::new();
    for conflict in conflicts {
        if !safe(&conflict.path)
            || !matches!(
                conflict.kind.as_str(),
                "order" | "cyclic" | "zombie" | "zombie-file" | "name"
            )
        {
            return Err(invalid(
                "native conflict summary contains an invalid path/kind",
            ));
        }
        let mut ids = BTreeSet::new();
        for side in conflict.base.iter().chain(&conflict.sides) {
            if !full.contains(&side.change)
                || !native_hash(&side.content)
                || side.start > side.end
                || !matches!(
                    side.kind.as_str(),
                    "regular" | "symlink" | "gitlink" | "directory"
                )
            {
                return Err(invalid("native conflict side is outside candidate closure"));
            }
            ids.insert(side.change.clone());
        }
        for claimant in &conflict.claimants {
            if !full.contains(&claimant.change) {
                return Err(invalid(
                    "native conflict claimant is outside candidate closure",
                ));
            }
            ids.insert(claimant.change.clone());
        }
        if ids.is_empty() {
            return Err(invalid("native conflict has no actual side"));
        }
        neutral.push(vcs::ConflictInfo {
            details: None,
            path: conflict.path,
            changes: changes(root, &ids.into_iter().collect::<Vec<_>>()),
            reason: conflict.kind,
        });
    }
    let base_state = state(
        root,
        &input.inherited_baseline.baseline.native_state,
        &input.inherited_baseline.payload.sha256,
    )?;
    let target_manifest = input
        .captured_target
        .as_ref()
        .map_or(&input.target.payload.sha256, |capture| {
            &capture.manifest.sha256
        });
    let target_state = state(root, &receipt.target_state, target_manifest)?;
    let candidate_state = state(
        root,
        &receipt.candidate_state,
        &receipt.state_manifest.sha256,
    )?;
    let materialization_id = MaterializationId::from_string(&receipt.materialization_id);
    let native_receipt = NativeCompositionReceipt {
        operation_id: OperationId::from_string(&receipt.operation_id),
        root: root.clone(),
        base_state,
        target_state,
        candidate_state: candidate_state.clone(),
        materialization_id: materialization_id.clone(),
        selected_changes: changes(root, &membership.selected_changes),
        dependency_only_changes: changes(root, &membership.dependency_only_changes),
        full_closed_changes: changes(root, &membership.full_closed_changes),
        inherited_baseline_changes: changes(root, &membership.inherited_baseline_changes),
        target_context_changes: changes(root, &membership.target_context_changes),
        composition_only_changes: Vec::new(),
        selection_revision: ContentDigest::from_string(&receipt.selection_revision),
        composition_revision: ContentDigest::from_string(&receipt.composition_revision),
        conflict_manifest: receipt
            .conflict_manifest
            .as_ref()
            .map(|reference| ContentDigest::from_string(&reference.sha256)),
        receipt_digest: ContentDigest::from_string(&receipt.receipt_digest),
    };
    let verified = VerifiedCompositionReceipt::from_verified_backend(native_receipt)
        .map_err(|_| invalid("native owner receipt failed structural verification"))?;
    let selection = spool.retain(&serde_json::to_vec(&membership.selected_changes)?)?;
    let retained_receipt = spool.retain(&serde_json::to_vec(&receipt)?)?;
    Ok(AtomicCompositionPreparation::Prepared {
        composition: Box::new(vcs::PreparedComposition {
            candidate: vcs::CompositionCandidate {
                state: candidate_state.clone(),
                selected_changes: changes(root, &membership.selected_changes),
                required_dependencies: changes(root, &membership.dependency_only_changes),
                materialization_id: materialization_id.clone(),
                conflicts: neutral,
            },
            materialization: vcs::MaterializationReceipt {
                state: candidate_state.clone(),
                materialization_id,
                destination: receipt.candidate_path.clone(),
            },
            closure: vcs::NativeClosureManifest {
                state: candidate_state,
                changes: changes(root, &membership.full_closed_changes),
                manifest_digest: ContentDigest::from_string(&receipt.state_manifest.sha256),
                spool_path: spool_root.join(&receipt.state_manifest.name),
            },
            selection_path: spool_root.join(selection.name),
            manifest_path: spool_root.join(retained_receipt.name),
            receipt: verified,
        }),
        native: Box::new(receipt),
    })
}

#[cfg(test)]
mod tests;
