//! Local capture ownership and byte-verified warm copies. This does not issue a
//! native assignment, register a source working copy, or mark a child ready to
//! launch: native freeze/grant ingress remains unavailable at the pinned API.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use intent_atomic_proto::baselines::{BaselineReceipt, BaselineRef};
use intent_atomic_proto::StoreBinding;
use serde::{Deserialize, Serialize};

use crate::{durable, Host, HostError, Result};

mod clone_tree;
mod manifest;

struct State {
    closed: bool,
    poisoned: bool,
    generation: u64,
    turns: BTreeSet<(String, String)>,
    writers: usize,
    selection_digest: Option<String>,
    selection_known: bool,
}
pub(crate) struct Inner {
    binding: StoreBinding,
    working_copy_id: String,
    root: PathBuf,
    root_identity: durable::FileIdentity,
    baseline: BaselineReceipt,
    state: Mutex<State>,
    changed: Condvar,
}

/// One server-owned physical directory allocation. A clone of this handle still
/// points to the original root/epoch; no lookup by current agent is performed.
#[derive(Clone)]
pub struct WorkingCopyOwner(Arc<Inner>);

/// The actual turn future must retain this owner until it has stopped writing.
/// A detached primitive additionally owns its writer token through its receipt.
pub struct WorkingTurn {
    original: Arc<Inner>,
    key: (String, String),
    generation: u64,
}
pub struct WorkingWriter(Arc<Inner>);

/// Admission is closed before waiting for original turns and admitted writers.
/// Move this token into the actual blocking capture worker, never its waiter.
pub struct CaptureClosure {
    original: Arc<Inner>,
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildCapture {
    pub operation_id: String,
    pub repository_id: String,
    pub binding_epoch: u64,
    pub parent_working_copy_id: String,
    pub parent_root: PathBuf,
    pub capture_generation: u64,
    pub selection_digest: Option<String>,
    pub baseline: BaselineRef,
    pub baseline_manifest_digest: String,
    pub working_digest: String,
    pub path: PathBuf,
    pub copied_entries: u64,
    pub copied_bytes: u64,
    pub mechanism: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureJournal {
    schema_version: u32,
    command_digest: String,
    working_digest: String,
    phase: CapturePhase,
    receipt: Option<ChildCapture>,
    directory: Option<durable::FileIdentity>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum CapturePhase {
    Prepared,
    Cloning,
    Verified,
    FailedKnown,
    Uncertain,
}
fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Hardened filesystem half of the pinned in-tree pointer fallback. The caller
/// must already own the private directory and separately verify the actual
/// native token; these bytes alone never constitute an execution grant.
/// The pinned CLI has no environment-supplied pointer discovery path.
/// # Errors
/// Refuses nonprivate/replaced roots, existing pointer paths and I/O failure.
pub fn write_private_sandbox_pointer(
    root: &Path,
    pointer: &atomic_repository::RemoteSandboxPointer,
) -> Result<PathBuf> {
    let identity = durable::identity(root, true)?;
    durable::private_dir(root)?;
    if std::fs::canonicalize(root)? != root || durable::identity(root, true)? != identity {
        return Err(HostError::StaleBinding);
    }
    if pointer.token.is_empty() || pointer.token.len() > 4096 || !bounded(&pointer.view) {
        return Err(invalid("sandbox pointer identity is invalid"));
    }
    let path = root.join(atomic_repository::SANDBOX_POINTER);
    durable::write_json(&path, pointer, false)?;
    Ok(path)
}

fn invalid(reason: &'static str) -> HostError {
    HostError::Invalid(reason)
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

impl WorkingCopyOwner {
    /// Admit only the original exact assignment, before provider work queues.
    /// # Errors
    /// Refuses capture closure, stale allocation, duplicate turn or invalid IDs.
    pub fn try_begin_turn(&self, agent: &str, attempt: &str) -> Result<WorkingTurn> {
        if !bounded(agent) || !bounded(attempt) {
            return Err(invalid("working turn identities are invalid"));
        }
        if durable::identity(&self.0.root, true)? != self.0.root_identity {
            return Err(HostError::StaleBinding);
        }
        let mut state = self.0.state.lock().map_err(|_| HostError::Poisoned)?;
        if state.closed || state.poisoned {
            return Err(invalid("working-copy turn admission is closed"));
        }
        if !state.turns.is_empty() {
            return Err(invalid("working copy already has its original source turn"));
        }
        let key = (agent.to_owned(), attempt.to_owned());
        if !state.turns.insert(key.clone()) {
            return Err(invalid("working-copy turn is already admitted"));
        }
        Ok(WorkingTurn {
            original: Arc::clone(&self.0),
            key,
            generation: state.generation,
        })
    }

    /// Close turn and writer admission synchronously. A capture worker then
    /// drains the actual retained owners before taking the host store lane.
    /// # Errors
    /// Refuses an existing closure or a directory requiring reconciliation.
    pub fn close_for_capture(&self) -> Result<CaptureClosure> {
        let mut state = self.0.state.lock().map_err(|_| HostError::Poisoned)?;
        if state.closed || state.poisoned {
            return Err(invalid(
                "working-copy capture is already closed or uncertain",
            ));
        }
        state.closed = true;
        Ok(CaptureClosure {
            original: Arc::clone(&self.0),
            generation: state.generation,
        })
    }
}
impl WorkingTurn {
    /// A writer token is held by the real primitive, not its timed-out waiter.
    /// # Errors
    /// Refuses a late write after capture closure or original-turn retirement.
    pub fn admit_writer(&self) -> Result<WorkingWriter> {
        let mut state = self
            .original
            .state
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        if state.closed
            || state.poisoned
            || state.generation != self.generation
            || !state.turns.contains(&self.key)
        {
            return Err(invalid("original working-copy write admission is closed"));
        }
        state.writers = state
            .writers
            .checked_add(1)
            .ok_or_else(|| invalid("working-copy writer count overflow"))?;
        Ok(WorkingWriter(Arc::clone(&self.original)))
    }
}
impl WorkingWriter {
    /// Selection is local state governed by the same admitted writer. A child
    /// cannot silently inherit a selection in place of its frozen baseline.
    /// # Errors
    /// Refuses a poisoned owner or malformed digest.
    pub fn set_selection(&self, digest: Option<&str>) -> Result<()> {
        if digest.is_some_and(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) {
            return Err(invalid("working-copy selection digest is invalid"));
        }
        let mut state = self.0.state.lock().map_err(|_| HostError::Poisoned)?;
        state.selection_digest = digest.map(str::to_owned);
        state.selection_known = true;
        Ok(())
    }
}
impl Drop for WorkingTurn {
    fn drop(&mut self) {
        let mut state = self
            .original
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.turns.remove(&self.key);
        self.original.changed.notify_all();
    }
}
impl Drop for WorkingWriter {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.writers = state.writers.saturating_sub(1);
        self.0.changed.notify_all();
    }
}
impl CaptureClosure {
    fn drain(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("capture drain deadline is invalid"))?;
        let mut state = self
            .original
            .state
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        while !state.turns.is_empty() || state.writers > 0 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| invalid("working-copy turns or writers did not quiesce"))?;
            let (next, timed) = self
                .original
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| HostError::Poisoned)?;
            state = next;
            if timed.timed_out() && (!state.turns.is_empty() || state.writers > 0) {
                return Err(invalid("working-copy turns or writers did not quiesce"));
            }
        }
        if !state.selection_known {
            return Err(HostError::Unsupported(
                "working-copy selection observation is unavailable",
            ));
        }
        if state.poisoned || state.generation != self.generation || state.selection_digest.is_some()
        {
            return Err(invalid(
                "inherited-baseline-required: selection or original allocation changed",
            ));
        }
        Ok(())
    }
    fn poison(&self) {
        if let Ok(mut state) = self.original.state.lock() {
            state.poisoned = true;
        }
    }
}
impl Drop for CaptureClosure {
    fn drop(&mut self) {
        let mut state = self
            .original
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation == self.generation && !state.poisoned {
            state.closed = false;
        }
        self.original.changed.notify_all();
    }
}

impl Host {
    /// Validate the actual published capture journal, native baseline and full
    /// immutable copy. A deserialized capture DTO alone grants no authority.
    /// # Errors
    /// Refuses forged, stale, replaced, dirty or unpublished capture receipts.
    pub fn validate_child_capture(&self, capture: &ChildCapture) -> Result<()> {
        self.read_admitted()?;
        if !bounded(&capture.operation_id)
            || durable::identity(&self.config.spool_dir, true)? != self.spool_root_identity
        {
            return Err(HostError::StaleBinding);
        }
        let captures = self.config.spool_dir.join("working-copy-captures");
        durable::identity(&captures, true)?;
        let journal: CaptureJournal = durable::read_json(
            &captures.join(format!("{}.json", hash(capture.operation_id.as_bytes()))),
        )?;
        if journal.schema_version != 1
            || journal.phase != CapturePhase::Verified
            || journal.receipt.as_ref() != Some(capture)
            || capture.path != captures.join(&journal.command_digest)
            || journal.directory != Some(durable::identity(&capture.path, true)?)
            || capture.working_digest != journal.working_digest
            || capture.selection_digest.is_some()
            || capture.capture_generation == 0
        {
            return Err(HostError::StaleBinding);
        }
        let baseline = self.baseline_store(&capture.baseline)?;
        if baseline.receipt.manifest_digest != capture.baseline_manifest_digest
            || capture.repository_id != capture.baseline.repository_id
            || capture.binding_epoch != capture.baseline.binding_epoch
        {
            return Err(HostError::StaleBinding);
        }
        let actual = manifest::scan(&capture.path)?;
        if manifest::digest(&actual)? != capture.working_digest
            || u64::try_from(actual.len())
                .map_err(|_| invalid("capture inventory count overflow"))?
                != capture.copied_entries
            || actual.iter().map(|entry| entry.length).sum::<u64>() != capture.copied_bytes
        {
            return Err(HostError::StaleBinding);
        }
        manifest::verify_parent(&capture.path, &actual, &baseline.manifest.entries)
    }

    /// Enroll only local capture ownership against an actual verified native
    /// frozen baseline. This does not register an upstream source working copy
    /// or grant any agent access. The composition owner must reuse this handle
    /// for every turn/writer for that physical directory.
    /// # Errors
    /// Refuses stale native/root epochs, replaced roots or dirty source content.
    pub fn register_working_copy_capture(
        &self,
        binding: &StoreBinding,
        baseline: &BaselineRef,
        working_root: &Path,
        working_copy_id: &str,
    ) -> Result<WorkingCopyOwner> {
        self.read_admitted()?;
        self.verify_marker(binding)?;
        if !bounded(working_copy_id)
            || baseline.repository_id != binding.repository_id
            || baseline.binding_epoch != binding.binding_epoch
        {
            return Err(HostError::StaleBinding);
        }
        let root = std::fs::canonicalize(working_root)?;
        if root != working_root
            || root.starts_with(&self.config.stores_dir)
            || self.config.stores_dir.starts_with(&root)
        {
            return Err(invalid(
                "working copy must be a distinct canonical directory outside native stores",
            ));
        }
        let root_identity = durable::identity(&root, true)?;
        let mut owners = self
            .working_copies
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        if let Some(original) = owners.get(&root).and_then(std::sync::Weak::upgrade) {
            if original.binding != *binding
                || original.baseline.baseline != *baseline
                || original.working_copy_id != working_copy_id
                || original.root_identity != root_identity
            {
                return Err(HostError::StaleBinding);
            }
            return Ok(WorkingCopyOwner(original));
        }
        let frozen = self.baseline_store(baseline)?;
        let before = manifest::scan(&root)?;
        manifest::verify_parent(&root, &before, &frozen.manifest.entries)?;
        let original = Arc::new(Inner {
            binding: binding.clone(),
            working_copy_id: working_copy_id.into(),
            root: root.clone(),
            root_identity,
            baseline: frozen.receipt.clone(),
            state: Mutex::new(State {
                closed: false,
                poisoned: false,
                generation: 1,
                turns: BTreeSet::new(),
                writers: 0,
                selection_digest: None,
                selection_known: false,
            }),
            changed: Condvar::new(),
        });
        owners.insert(root, Arc::downgrade(&original));
        Ok(WorkingCopyOwner(original))
    }

    /// Capture a verified clean parent, including ignored warm output, into a
    /// fresh host-private directory using actual filesystem `CoW` primitives.
    /// The barrier is released after this immutable local verification. This
    /// receipt is bytes only: native draft/grant/checkpoint readiness is absent.
    /// # Errors
    /// Refuses running owners, dirty/untracked/selected parents, source races,
    /// unsupported `CoW`, stale native epochs or a changed full postcopy manifest.
    pub fn capture_warm_child(
        &self,
        closure: CaptureClosure,
        operation: &str,
        timeout: Duration,
    ) -> Result<ChildCapture> {
        self.capture_warm_child_with(closure, operation, timeout, |_| {})
    }

    fn capture_warm_child_with(
        &self,
        closure: CaptureClosure,
        operation: &str,
        timeout: Duration,
        observe_clone: impl FnOnce(&Path),
    ) -> Result<ChildCapture> {
        if !bounded(operation) {
            return Err(invalid("invalid child capture operation"));
        }
        closure.drain(timeout)?;
        // Fixed lock order: closed admission → drained writers → barrier → store.
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.read_admitted()?;
        self.verify_marker(&closure.original.binding)?;
        let frozen = self.baseline_store(&closure.original.baseline.baseline)?;
        if frozen.receipt != closure.original.baseline
            || durable::identity(&closure.original.root, true)? != closure.original.root_identity
        {
            return Err(HostError::StaleBinding);
        }
        if durable::identity(&self.config.spool_dir, true)? != self.spool_root_identity {
            return Err(HostError::StaleBinding);
        }
        let captures_root = self.config.spool_dir.join("working-copy-captures");
        durable::private_dir(&captures_root)?;
        let command_digest = hash(&serde_json::to_vec(&(
            operation,
            &closure.original.binding,
            &closure.original.working_copy_id,
            &closure.original.root,
            &closure.original.root_identity,
            &closure.original.baseline,
        ))?);
        let journal_path = captures_root.join(format!("{}.json", hash(operation.as_bytes())));
        let path = captures_root.join(&command_digest);
        if journal_path.symlink_metadata().is_ok() {
            let journal: CaptureJournal = durable::read_json(&journal_path)?;
            if journal.schema_version != 1 || journal.command_digest != command_digest {
                return Err(invalid(
                    "conflicting immutable child capture operation replay",
                ));
            }
            if journal.phase == CapturePhase::FailedKnown {
                return Err(invalid(
                    "child capture operation already failed; retained partial bytes are not a ready child",
                ));
            }
            if journal.phase != CapturePhase::Verified {
                return Err(HostError::Uncertain(
                    "interrupted child copy is retained; it is not an empty or ready child".into(),
                ));
            }
            let receipt = journal
                .receipt
                .ok_or_else(|| invalid("verified child copy has no receipt"))?;
            if receipt.path != path
                || receipt.working_digest != journal.working_digest
                || journal.directory != Some(durable::identity(&path, true)?)
                || manifest::digest(&manifest::scan(&path)?)? != receipt.working_digest
            {
                return Err(HostError::StaleBinding);
            }
            return Ok(receipt);
        }
        let before = manifest::scan(&closure.original.root)?;
        manifest::verify_parent(&closure.original.root, &before, &frozen.manifest.entries)?;
        let mut journal = CaptureJournal {
            schema_version: 1,
            command_digest,
            working_digest: manifest::digest(&before)?,
            phase: CapturePhase::Prepared,
            receipt: None,
            directory: None,
        };
        durable::write_json(&journal_path, &journal, false)?;
        journal.phase = CapturePhase::Cloning;
        durable::write_json(&journal_path, &journal, true)?;
        let mechanism = match clone_tree::clone_warm(&closure.original.root, &path, &before) {
            Ok(mechanism) => mechanism,
            Err(error) => {
                journal.phase = CapturePhase::FailedKnown;
                durable::write_json(&journal_path, &journal, true)?;
                return Err(error);
            }
        };
        observe_clone(&path);
        let result = manifest::scan(&closure.original.root)
            .and_then(|after| manifest::scan(&path).map(|copied| (after, copied)));
        let (after, copied) = match result {
            Ok(scans) => scans,
            Err(error) => {
                closure.poison();
                journal.phase = CapturePhase::Uncertain;
                durable::write_json(&journal_path, &journal, true)?;
                return Err(error);
            }
        };
        if before != after
            || copied != before
            || durable::identity(&closure.original.root, true)? != closure.original.root_identity
        {
            closure.poison();
            journal.phase = CapturePhase::Uncertain;
            durable::write_json(&journal_path, &journal, true)?;
            return Err(HostError::Uncertain("working directory changed during capture; private copy retained for reconciliation".into()));
        }
        manifest::verify_parent(&path, &copied, &frozen.manifest.entries)?;
        manifest::sync_tree(&path, &copied)?;
        durable::sync_parent(&path)?;
        let receipt = ChildCapture {
            operation_id: operation.into(),
            repository_id: closure.original.binding.repository_id.clone(),
            binding_epoch: closure.original.binding.binding_epoch,
            parent_working_copy_id: closure.original.working_copy_id.clone(),
            parent_root: closure.original.root.clone(),
            capture_generation: closure.generation,
            selection_digest: None,
            baseline: closure.original.baseline.baseline.clone(),
            baseline_manifest_digest: closure.original.baseline.manifest_digest.clone(),
            working_digest: manifest::digest(&before)?,
            path: path.clone(),
            copied_entries: u64::try_from(before.len())
                .map_err(|_| invalid("capture entry count overflow"))?,
            copied_bytes: before.iter().map(|entry| entry.length).sum(),
            mechanism: mechanism.into(),
        };
        journal.phase = CapturePhase::Verified;
        journal.directory = Some(durable::identity(&path, true)?);
        journal.receipt = Some(receipt.clone());
        durable::write_json(&journal_path, &journal, true)?;
        drop(closure);
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
