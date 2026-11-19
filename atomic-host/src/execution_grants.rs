//! Adapted bindings over the actual shared native handle. Native grant-core
//! authentication is reused; no upstream per-request repository open is used.
//! This facade serves pinned recorded bytes and exposes no submit/record/view
//! mutation. Source workflow activation remains a separate composition gate.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use atomic_core::{pristine::ViewTxnT, Base32};
use atomic_repository::{MaterializedEntry, ViewEntryKind};
use intent_atomic_proto::execution::{
    CloseExecutionGrantRequest, ExecutionCapability, ExecutionGrantClosed, GrantedFileKind,
    GrantedFileReceipt, GrantedReadBasis, IssueExecutionGrantRequest, NativeExecutionGrantIssued,
    NativeExecutionGrantReceipt, ReadGrantedFileRequest, EXECUTION_FACADE_VERSION,
    MAX_GRANTED_READ_BYTES,
};
use intent_atomic_proto::{HostIdentity, StateToken};
use libatomic::daemon::sandbox_grants::{
    grant_capabilities, GrantRequest, InMemorySandboxGrants, SandboxGrants,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::baselines::{SnapshotEntry, SnapshotKind};
use crate::{durable, Host, HostError, Result};

#[cfg(test)]
mod tests;

pub(crate) struct NativeGrants {
    registry: InMemorySandboxGrants,
    generation: String,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}
impl Default for NativeGrants {
    fn default() -> Self {
        Self {
            registry: InMemorySandboxGrants::new(),
            generation: uuid::Uuid::new_v4().to_string(),
            entries: Mutex::new(HashMap::new()),
        }
    }
}
struct Admission {
    closed: bool,
    readers: usize,
    store: Option<Arc<crate::native::NativeStore>>,
    token: Option<String>,
}
struct Entry {
    request_digest: String,
    receipt: NativeExecutionGrantReceipt,
    receipt_digest: String,
    manifest: BTreeMap<String, SnapshotEntry>,
    capture_identity: durable::FileIdentity,
    state: Mutex<Admission>,
    changed: Condvar,
}
struct ReadGuard {
    entry: Arc<Entry>,
    store: Arc<crate::native::NativeStore>,
}
impl Drop for ReadGuard {
    fn drop(&mut self) {
        let mut state = self
            .entry
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.readers = state.readers.saturating_sub(1);
        self.entry.changed.notify_all();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    version: u32,
    request_digest: String,
    receipt: NativeExecutionGrantReceipt,
    closed: bool,
}

fn invalid(reason: &'static str) -> HostError {
    HostError::Invalid(reason)
}
fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bounded(text: &str) -> bool {
    !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(native)?
            .as_millis(),
    )
    .map_err(native)
}
fn safe_path(path: &str) -> bool {
    crate::baselines::source::safe_path(path) && path.is_ascii() && !path.contains(':')
}
fn allowed(prefixes: &[String], path: &str) -> bool {
    safe_path(path)
        && prefixes.iter().any(|prefix| {
            prefix == "."
                || path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing into a string");
    }
    result
}

fn view_state(store: &crate::native::NativeStore, name: &str) -> Result<(u64, StateToken)> {
    let txn = store.repository().pristine().read_txn().map_err(native)?;
    let view = txn
        .get_view(name)
        .map_err(native)?
        .ok_or_else(|| invalid("granted native view is unavailable"))?;
    if view.parent.is_some() {
        return Err(HostError::Unsupported(
            "granted native read ancestry is not qualified; an independently frozen parentless view is required",
        ));
    }
    // Parentless effective encoding is the exact pinned sandbox domain. All
    // authoritative fields here come from this one native read transaction.
    let mut encoded = b"atomic.sandbox.effective-view.v1".to_vec();
    encoded.extend_from_slice(&view.id.to_le_bytes());
    encoded.push(view.kind as u8);
    encoded.extend_from_slice(view.state.as_bytes());
    encoded.extend_from_slice(&view.change_count.to_le_bytes());
    Ok((
        view.id,
        StateToken {
            view: name.into(),
            effective_state: atomic_core::Hash::of(&encoded).to_base32(),
            own_merkle: view.state.to_base32(),
        },
    ))
}

impl Host {
    pub(crate) fn reconcile_execution_grants(&self) -> Result<()> {
        let root = self.config.config_dir.join("execution-grants");
        match root.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self
                    .native_grants
                    .entries
                    .lock()
                    .map_err(|_| HostError::Poisoned)?
                    .is_empty()
                {
                    return Ok(());
                }
                return Err(HostError::StaleBinding);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => durable::identity(&root, true)?,
        };
        let entries = self
            .native_grants
            .entries
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        for file in std::fs::read_dir(&root)? {
            let path = file?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".pending-"))
            {
                continue;
            }
            let mut journal: Journal = durable::read_json(&path)?;
            if journal.version != EXECUTION_FACADE_VERSION
                || path
                    != root.join(format!(
                        "{}.json",
                        hash(journal.receipt.operation_id.as_bytes())
                    ))
            {
                return Err(invalid(
                    "native grant journal identity or version is unavailable",
                ));
            }
            if journal.closed {
                continue;
            }
            let live = entries
                .get(&journal.receipt.claim.grant_id)
                .filter(|entry| {
                    entry.receipt == journal.receipt
                        && entry.request_digest == journal.request_digest
                });
            if journal.receipt.host_generation != self.native_grants.generation || live.is_none() {
                // No physical native capability is reconstructed from JSON.
                // The host read dispatcher cannot admit an absent generation.
                // Do not close by view name: that could revoke a replacement.
                journal.closed = true;
                durable::write_json(&path, &journal, true)?;
            }
        }
        Ok(())
    }

    fn grant_journal(&self, id: &str) -> Result<std::path::PathBuf> {
        if !bounded(id) {
            return Err(invalid("native grant operation identity is invalid"));
        }
        if durable::identity(&self.journal_dir, true)? == self.journal_root_identity {
            let root = self.config.config_dir.join("execution-grants");
            durable::private_dir(&root)?;
            return Ok(root.join(format!("{}.json", hash(id.as_bytes()))));
        }
        Err(HostError::StaleBinding)
    }

    /// Issue only a read-capable mechanical lease after actual retained native
    /// freeze and capture proofs match the original server-owned claim. Task
    /// permission is additionally admitted in Services/Store before exposure.
    /// # Errors
    /// Refuses mismatched proof/epoch/state, expired scope, active view reuse,
    /// native grant failure or uncertain operation replay after restart.
    pub fn issue_native_execution_grant(
        &self,
        request: &IssueExecutionGrantRequest,
    ) -> Result<NativeExecutionGrantIssued> {
        let claim = &request.claim;
        if !bounded(&request.operation_id)
            || !bounded(&claim.grant_id)
            || claim.revision == 0
            || !bounded(&claim.agent_id)
            || !bounded(&claim.attempt_id)
            || claim.work_binding_id != request.freeze.work_binding_id
            || claim.task_revision != request.freeze.projection.task_revision
            || claim.workspace_id != claim.task_revision.workspace_id
            || claim.root_locator != request.capture.parent_root
            || request.binding != request.freeze.binding
            || request.binding.repository_id != request.capture.repository_id
            || request.binding.binding_epoch != request.capture.binding_epoch
            || request.view != request.expected_state.view
            || claim.path_prefixes.is_empty()
            || claim.path_prefixes.len() > 256
            || claim
                .path_prefixes
                .iter()
                .any(|path| path != "." && !safe_path(path))
            || claim
                .path_prefixes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !claim
                .capabilities
                .contains(&ExecutionCapability::ReadSource)
            || claim.capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "native grant claim differs from original frozen source/capture",
            ));
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        self.validate_native_turn_freeze(&request.freeze)?;
        let capture: crate::working_copies::ChildCapture =
            serde_json::from_value(serde_json::to_value(&request.capture)?)?;
        let capture_identity = durable::identity(&capture.path, true)?;
        self.validate_child_capture(&capture)?;
        let proof = self.verify_marker(&request.binding)?;
        let store = self.cached_store(&request.binding)?;
        store.validate(&request.binding, &proof)?;
        let (view_id, state) = view_state(&store, &request.view)?;
        if state != request.expected_state {
            return Err(HostError::StaleBinding);
        }
        let baseline = self.baseline_store(&request.capture.baseline)?;
        let mut manifest = Vec::new();
        let rendered = store
            .repository()
            .materialize_view_entries(&request.view, |entry| {
                if entry.kind == ViewEntryKind::Directory {
                    return Ok::<_, HostError>(());
                }
                let (kind, mode) = match entry.kind {
                    ViewEntryKind::File if entry.mode == 0o644 => {
                        (SnapshotKind::Regular, 0o100_644)
                    }
                    ViewEntryKind::File if entry.mode == 0o755 => {
                        (SnapshotKind::Executable, 0o100_755)
                    }
                    ViewEntryKind::Symlink => (SnapshotKind::Symlink, 0o120_000),
                    _ => {
                        return Err(HostError::Unsupported(
                            "native grant manifest attributes are unqualified",
                        ));
                    }
                };
                manifest.push(SnapshotEntry {
                    path: entry.path,
                    kind,
                    mode,
                    length: u64::try_from(entry.content.len()).map_err(native)?,
                    sha256: hash(&entry.content),
                });
                Ok(())
            })
            .map_err(native)??;
        manifest.sort_by(|left, right| left.path.cmp(&right.path));
        if manifest != baseline.manifest.entries
            || rendered.state != state.own_merkle
            || view_state(&store, &request.view)? != (view_id, state.clone())
        {
            return Err(HostError::StaleBinding);
        }
        self.validate_child_capture(&capture)?;
        if durable::identity(&capture.path, true)? != capture_identity {
            return Err(HostError::StaleBinding);
        }
        let request_digest = hash(&serde_json::to_vec(request)?);
        let journal_path = self.grant_journal(&request.operation_id)?;
        let mut entries = self
            .native_grants
            .entries
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        if let Some(entry) = entries.get(&claim.grant_id) {
            let admission = entry.state.lock().map_err(|_| HostError::Poisoned)?;
            if entry.request_digest != request_digest || admission.closed {
                return Err(invalid(
                    "native grant operation replay conflicts or is closed",
                ));
            }
            let retained: Journal = durable::read_json(&journal_path)?;
            if retained.version != EXECUTION_FACADE_VERSION
                || retained.closed
                || retained.request_digest != entry.request_digest
                || retained.receipt != entry.receipt
            {
                return Err(HostError::Uncertain(
                    "native grant replay has no matching durable live receipt".into(),
                ));
            }
            let token = admission
                .token
                .as_ref()
                .ok_or_else(|| invalid("native grant token is no longer retained"))?;
            self.native_grants
                .registry
                .resolve(token.as_bytes())
                .map_err(native)?;
            return Ok(NativeExecutionGrantIssued {
                receipt: entry.receipt.clone(),
                token: token.clone(),
            });
        }
        if journal_path.symlink_metadata().is_ok() {
            return Err(HostError::Uncertain("native grant belongs to a retired host generation; no authority is reconstructed from its journal".into()));
        }
        for entry in entries.values() {
            if entry.receipt.binding.repository_id == request.binding.repository_id
                && entry.receipt.native_state.view == request.view
                && !entry.state.lock().map_err(|_| HostError::Poisoned)?.closed
            {
                return Err(invalid("native view already has an original live grant"));
            }
        }
        let remaining = claim
            .expires_at_unix_ms
            .checked_sub(now_ms()?)
            .filter(|remaining| *remaining >= 2_000)
            .ok_or_else(|| invalid("native grant expiry is too near or expired"))?;
        let ttl_secs = (remaining / 1000).saturating_sub(1).min(365 * 24 * 60 * 60);
        let native_repository =
            libatomic::daemon::state::RepoHandle::new(request.binding.store_path.clone())
                .repository_id();
        let capabilities = grant_capabilities(&["sandbox.read".into()]).map_err(native)?;
        let (token, grant) = self
            .native_grants
            .registry
            .open(GrantRequest {
                repository_id: native_repository.clone(),
                view: request.view.clone(),
                view_id: Some(view_id),
                acting_as: None,
                capabilities,
                ttl_secs,
            })
            .map_err(native)?;
        let token = String::from_utf8(token).map_err(native)?;
        let receipt = NativeExecutionGrantReceipt {
            host: HostIdentity::default(),
            facade_version: EXECUTION_FACADE_VERSION,
            binding: request.binding.clone(),
            operation_id: request.operation_id.clone(),
            claim: claim.clone(),
            native_grant_id: uuid::Uuid::new_v4().to_string(),
            native_repository_id: hex(&native_repository),
            native_view_id: view_id,
            native_state: state,
            native_capabilities: grant.capabilities.iter().cloned().collect(),
            native_expires_at_unix_ms: u64::try_from(grant.expires.timestamp_millis())
                .map_err(native)?,
            freeze_digest: hash(&serde_json::to_vec(&request.freeze)?),
            capture: request.capture.clone(),
            token_sha256: hash(token.as_bytes()),
            host_generation: self.native_grants.generation.clone(),
        };
        let journal = Journal {
            version: EXECUTION_FACADE_VERSION,
            request_digest: request_digest.clone(),
            receipt: receipt.clone(),
            closed: false,
        };
        if let Err(error) = durable::write_json(&journal_path, &journal, false) {
            let _ = self
                .native_grants
                .registry
                .close(&native_repository, &request.view);
            return Err(error);
        }
        let entry = Arc::new(Entry {
            request_digest,
            receipt_digest: hash(&serde_json::to_vec(&receipt)?),
            manifest: manifest
                .into_iter()
                .map(|entry| (entry.path.clone(), entry))
                .collect(),
            capture_identity,
            receipt: receipt.clone(),
            state: Mutex::new(Admission {
                closed: false,
                readers: 0,
                store: Some(store),
                token: Some(token.clone()),
            }),
            changed: Condvar::new(),
        });
        entries.insert(claim.grant_id.clone(), entry);
        Ok(NativeExecutionGrantIssued { receipt, token })
    }

    /// Read one already-authorized recorded path on the existing shared handle.
    /// Exact bytes must match the pinned manifest; this never reports a fresh
    /// atomic current-view observation or a clean working directory.
    /// # Errors
    /// Refuses missing/revoked/expired scopes, path escape, replaced roots/view
    /// IDs, changed native state, oversized files or manifest mismatches.
    pub fn read_native_granted_file(
        &self,
        request: &ReadGrantedFileRequest,
    ) -> Result<GrantedFileReceipt> {
        self.read_native_granted_file_observed(request, || {})
    }

    fn read_native_granted_file_observed(
        &self,
        request: &ReadGrantedFileRequest,
        admitted: impl FnOnce(),
    ) -> Result<GrantedFileReceipt> {
        self.read_admitted()?;
        if !bounded(&request.request_id) {
            return Err(invalid("native read request identity is invalid"));
        }
        let entry = self
            .native_grants
            .entries
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .get(&request.grant_id)
            .cloned()
            .ok_or_else(|| {
                invalid("native grant belongs to an unavailable or retired host generation")
            })?;
        let journal: Journal = durable::read_json(
            &self
                .config
                .config_dir
                .join("execution-grants")
                .join(format!(
                    "{}.json",
                    hash(entry.receipt.operation_id.as_bytes())
                )),
        )?;
        if journal.version != EXECUTION_FACADE_VERSION
            || journal.closed
            || journal.receipt != entry.receipt
            || journal.request_digest != entry.request_digest
        {
            return Err(HostError::StaleBinding);
        }
        if request.grant_receipt_digest != entry.receipt_digest
            || hash(request.token.as_bytes()) != entry.receipt.token_sha256
            || !allowed(&entry.receipt.claim.path_prefixes, &request.path)
        {
            return Err(invalid(
                "native read target or credential differs from original grant",
            ));
        }
        // Authenticate with the actual native grant registry before acquiring
        // private source bytes. The entry gate then makes close/admit atomic.
        let grant = self
            .native_grants
            .registry
            .resolve(request.token.as_bytes())
            .map_err(native)?;
        if grant.view != entry.receipt.native_state.view
            || grant.view_id != Some(entry.receipt.native_view_id)
            || !grant.allows("sandbox.read")
            || hex(&grant.repository_id) != entry.receipt.native_repository_id
        {
            return Err(invalid("resolved native grant scope changed"));
        }
        let expected = entry
            .manifest
            .get(&request.path)
            .ok_or_else(|| invalid("path is absent from the granted recorded manifest"))?;
        if expected.length > u64::try_from(MAX_GRANTED_READ_BYTES).map_err(native)? {
            return Err(HostError::Unsupported(
                "granted recorded file exceeds the bounded inline read budget",
            ));
        }
        let guard = {
            let mut admission = entry.state.lock().map_err(|_| HostError::Poisoned)?;
            if admission.closed
                || now_ms()?
                    >= entry
                        .receipt
                        .claim
                        .expires_at_unix_ms
                        .min(entry.receipt.native_expires_at_unix_ms)
            {
                return Err(invalid("original native grant admission ended"));
            }
            self.native_grants
                .registry
                .resolve(request.token.as_bytes())
                .map_err(native)?;
            let store = admission
                .store
                .clone()
                .ok_or_else(|| invalid("original native grant handle retired"))?;
            admission.readers = admission
                .readers
                .checked_add(1)
                .ok_or_else(|| invalid("native read ownership overflow"))?;
            ReadGuard {
                entry: Arc::clone(&entry),
                store,
            }
        };
        admitted();
        if durable::identity(&entry.receipt.capture.path, true)? != entry.capture_identity {
            return Err(HostError::StaleBinding);
        }
        let proof = self.verify_marker(&entry.receipt.binding)?;
        guard.store.validate(&entry.receipt.binding, &proof)?;
        let expected_state = (
            entry.receipt.native_view_id,
            entry.receipt.native_state.clone(),
        );
        if view_state(&guard.store, &entry.receipt.native_state.view)? != expected_state {
            return Err(HostError::StaleBinding);
        }
        let materialized = guard
            .store
            .repository()
            .get_materialized_entry_on_view(&request.path, &entry.receipt.native_state.view)
            .map_err(native)?;
        let bytes = match materialized {
            MaterializedEntry::Present { bytes, .. } => bytes,
            MaterializedEntry::Absent { .. } => {
                return Err(invalid("granted recorded path no longer exists"));
            }
        };
        if bytes.len() > MAX_GRANTED_READ_BYTES
            || u64::try_from(bytes.len()).map_err(native)? != expected.length
            || hash(&bytes) != expected.sha256
            || view_state(&guard.store, &entry.receipt.native_state.view)? != expected_state
        {
            return Err(HostError::StaleBinding);
        }
        let kind = match expected.kind {
            SnapshotKind::Regular => GrantedFileKind::Regular,
            SnapshotKind::Executable => GrantedFileKind::Executable,
            SnapshotKind::Symlink => GrantedFileKind::Symlink,
        };
        // guard remains alive until the actual native primitive and its exact
        // content-bound receipt have completed. Caller cancellation cannot drop
        // this synchronous handler's ownership out from under its worker.
        Ok(GrantedFileReceipt {
            request_id: request.request_id.clone(),
            grant_id: request.grant_id.clone(),
            grant_receipt_digest: entry.receipt_digest.clone(),
            path: request.path.clone(),
            grant_state: entry.receipt.native_state.clone(),
            basis: GrantedReadBasis::PinnedGrantManifest,
            kind,
            content_sha256: expected.sha256.clone(),
            content_hex: hex(&bytes),
        })
    }

    /// Close native admission first, revoke the actual registry token, then
    /// retain the shared handle until every admitted read has a real receipt.
    /// # Errors
    /// Refuses mismatched credentials and reports persistence/drain failure.
    pub fn close_native_execution_grant(
        &self,
        request: &CloseExecutionGrantRequest,
    ) -> Result<ExecutionGrantClosed> {
        self.close_native_execution_grant_observed(request, || {})
    }

    fn close_native_execution_grant_observed(
        &self,
        request: &CloseExecutionGrantRequest,
        revoked: impl FnOnce(),
    ) -> Result<ExecutionGrantClosed> {
        let entry = self
            .native_grants
            .entries
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .get(&request.grant_id)
            .cloned()
            .ok_or_else(|| invalid("original native grant is unavailable"))?;
        if entry.receipt_digest != request.grant_receipt_digest
            || hash(request.token.as_bytes()) != entry.receipt.token_sha256
        {
            return Err(invalid(
                "native close credential differs from original grant",
            ));
        }
        let mut admission = entry.state.lock().map_err(|_| HostError::Poisoned)?;
        if !admission.closed {
            admission.closed = true;
            let native_repository =
                libatomic::daemon::state::RepoHandle::new(entry.receipt.binding.store_path.clone())
                    .repository_id();
            self.native_grants
                .registry
                .close(&native_repository, &entry.receipt.native_state.view)
                .map_err(native)?;
        }
        revoked();
        while admission.readers > 0 {
            admission = entry
                .changed
                .wait(admission)
                .map_err(|_| HostError::Poisoned)?;
        }
        admission.store.take();
        admission.token.take();
        drop(admission);
        let path = self.grant_journal(&entry.receipt.operation_id)?;
        let mut journal: Journal = durable::read_json(&path)?;
        if journal.receipt != entry.receipt || journal.request_digest != entry.request_digest {
            return Err(HostError::StaleBinding);
        }
        if !journal.closed {
            journal.closed = true;
            durable::write_json(&path, &journal, true)?;
        }
        Ok(ExecutionGrantClosed {
            grant_id: request.grant_id.clone(),
            grant_receipt_digest: entry.receipt_digest.clone(),
            admitted_reads_drained: true,
        })
    }
}
