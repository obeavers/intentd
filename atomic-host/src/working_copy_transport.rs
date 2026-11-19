//! Host-retained capture ownership across private transport calls. A connection
//! or waiter disappearing never drops the actual turn or writer guards. There
//! are deliberately no serialized begin/end-turn or release-writer commands.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use intent_atomic_proto::execution::WarmWorkingCopyCapture;
use intent_atomic_proto::working_copies::{
    CaptureRegisteredWorkingCopyRequest, RegisterWorkingCopyCaptureRequest,
    WorkingCopyCaptureRegistration, MAX_CAPTURE_DRAIN_MILLIS, WORKING_COPY_CAPTURE_FACADE_VERSION,
};
use intent_atomic_proto::HostIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::working_copies::{ChildCapture, WorkingCopyOwner, WorkingTurn};
use crate::{durable, Host, HostError, Result};

const MAX_REGISTRATIONS: usize = 1024;

pub(crate) struct Registry {
    generation: String,
    state: Mutex<RegistryState>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            generation: uuid::Uuid::new_v4().to_string(),
            state: Mutex::new(RegistryState::default()),
        }
    }
}

#[derive(Default)]
struct RegistryState {
    directory_identity: Option<durable::FileIdentity>,
    entries: HashMap<String, Arc<Entry>>,
}

struct Entry {
    owner: WorkingCopyOwner,
    journal: RegistrationJournal,
    paths: [PathBuf; 3],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationJournal {
    version: u32,
    request: RegisterWorkingCopyCaptureRequest,
    root_identity: durable::FileIdentity,
    registration: WorkingCopyCaptureRegistration,
}

fn invalid(reason: &'static str) -> HostError {
    HostError::Invalid(reason)
}

fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn journal_paths(
    directory: &Path,
    request: &RegisterWorkingCopyCaptureRequest,
    root_identity: &durable::FileIdentity,
) -> Result<[PathBuf; 3]> {
    Ok([
        directory.join(format!(
            "root-{}.json",
            hash(&serde_json::to_vec(&request.working_root)?)
        )),
        directory.join(format!(
            "physical-{}.json",
            hash(&serde_json::to_vec(root_identity)?)
        )),
        directory.join(format!(
            "operation-{}.json",
            hash(request.operation_id.as_bytes())
        )),
    ])
}

fn verify_journals(entry: &Entry) -> Result<()> {
    for path in &entry.paths {
        let actual: RegistrationJournal = durable::read_json(path)?;
        if actual != entry.journal {
            return Err(HostError::StaleBinding);
        }
    }
    Ok(())
}

impl RegistryState {
    fn verify_directory(&mut self, path: &Path) -> Result<()> {
        durable::private_dir(path)?;
        let actual = durable::identity(path, true)?;
        if self
            .directory_identity
            .as_ref()
            .is_some_and(|expected| *expected != actual)
        {
            return Err(HostError::StaleBinding);
        }
        self.directory_identity = Some(actual);
        Ok(())
    }
}

impl Host {
    /// Retain one real capture owner under a process-scoped opaque reference.
    /// This does not observe selection, admit a provider, or mark a child ready.
    /// # Errors
    /// Refuses aliases, changed operations/epochs, dirty registration sources,
    /// replaced roots and ownership left by a previous process incarnation.
    pub fn register_transport_working_copy_capture(
        &self,
        request: &RegisterWorkingCopyCaptureRequest,
    ) -> Result<WorkingCopyCaptureRegistration> {
        self.read_admitted()?;
        if !bounded(&request.operation_id) || !bounded(&request.working_copy_id) {
            return Err(invalid("working-copy registration identities are invalid"));
        }
        let root_identity = durable::identity(&request.working_root, true)?;
        let mut state = self
            .working_copy_transport
            .state
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        let directory = self.config.config_dir.join("working-copy-registry");
        state.verify_directory(&directory)?;
        let paths = journal_paths(&directory, request, &root_identity)?;
        if let Some(entry) = state.entries.values().find(|entry| {
            entry.journal.request.operation_id == request.operation_id
                || entry.journal.request.working_root == request.working_root
                || entry.journal.root_identity == root_identity
        }) {
            // Losing every on-disk index does not make an already published
            // operation new. Preserve the original reference or refuse.
            verify_journals(entry)?;
            if entry.journal.request != *request
                || entry.journal.root_identity != root_identity
                || entry.paths != paths
            {
                return Err(HostError::StaleBinding);
            }
            self.register_working_copy_capture(
                &request.binding,
                &request.baseline,
                &request.working_root,
                &request.working_copy_id,
            )?;
            return Ok(entry.journal.registration.clone());
        }
        if let Some(existing) = paths.iter().find(|path| path.symlink_metadata().is_ok()) {
            let journal: RegistrationJournal = durable::read_json(existing)?;
            // A dead transport or new host incarnation is not physical source
            // custody proof. Never recreate an empty admission owner here.
            if journal.registration.host_generation != self.working_copy_transport.generation {
                return Err(HostError::Uncertain(
                    "working-copy registration survived its runtime owner; teardown remains unproved"
                        .into(),
                ));
            }
            if journal.version != WORKING_COPY_CAPTURE_FACADE_VERSION
                || journal.request != *request
                || journal.root_identity != root_identity
                || journal.registration.request_digest != hash(&serde_json::to_vec(request)?)
            {
                return Err(HostError::StaleBinding);
            }
            let entry = state
                .entries
                .get(&journal.registration.registration_id)
                .ok_or_else(|| {
                    HostError::Uncertain(
                        "retained registration has no original runtime owner".into(),
                    )
                })?;
            verify_journals(entry)?;
            if entry.paths != paths || entry.journal != journal {
                return Err(HostError::StaleBinding);
            }
            // Revalidate store/root/epoch against the original retained owner.
            self.register_working_copy_capture(
                &request.binding,
                &request.baseline,
                &request.working_root,
                &request.working_copy_id,
            )?;
            return Ok(journal.registration);
        }
        if state.entries.len() >= MAX_REGISTRATIONS {
            return Err(invalid("working-copy capture owner budget exceeded"));
        }
        let owner = self.register_working_copy_capture(
            &request.binding,
            &request.baseline,
            &request.working_root,
            &request.working_copy_id,
        )?;
        if durable::identity(&request.working_root, true)? != root_identity {
            return Err(HostError::StaleBinding);
        }
        let registration = WorkingCopyCaptureRegistration {
            host: HostIdentity::default(),
            facade_version: WORKING_COPY_CAPTURE_FACADE_VERSION,
            registration_id: uuid::Uuid::new_v4().to_string(),
            host_generation: self.working_copy_transport.generation.clone(),
            operation_id: request.operation_id.clone(),
            binding: request.binding.clone(),
            baseline: request.baseline.clone(),
            working_root: request.working_root.clone(),
            working_copy_id: request.working_copy_id.clone(),
            request_digest: hash(&serde_json::to_vec(request)?),
        };
        let journal = RegistrationJournal {
            version: WORKING_COPY_CAPTURE_FACADE_VERSION,
            request: request.clone(),
            root_identity,
            registration: registration.clone(),
        };
        // All indexes refer to the same immutable inode. Partial publication
        // remains uncertain and cannot admit another owner on replay/restart.
        durable::write_json(&paths[0], &journal, false)?;
        for path in &paths[1..] {
            std::fs::hard_link(&paths[0], path)?;
        }
        durable::sync_parent(&paths[0])?;
        state.entries.insert(
            registration.registration_id.clone(),
            Arc::new(Entry {
                owner,
                journal,
                paths,
            }),
        );
        Ok(registration)
    }

    fn registered_capture_entry(
        &self,
        registration: &WorkingCopyCaptureRegistration,
    ) -> Result<Arc<Entry>> {
        self.read_admitted()?;
        self.verify_marker(&registration.binding)?;
        let mut state = self
            .working_copy_transport
            .state
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        state.verify_directory(&self.config.config_dir.join("working-copy-registry"))?;
        if registration.host != HostIdentity::default()
            || registration.facade_version != WORKING_COPY_CAPTURE_FACADE_VERSION
            || registration.host_generation != self.working_copy_transport.generation
        {
            return Err(HostError::StaleBinding);
        }
        let entry = state
            .entries
            .get(&registration.registration_id)
            .ok_or(HostError::StaleBinding)?;
        if entry.journal.registration != *registration
            || durable::identity(&registration.working_root, true)? != entry.journal.root_identity
        {
            return Err(HostError::StaleBinding);
        }
        verify_journals(entry)?;
        Ok(Arc::clone(entry))
    }

    /// Actual host-local ingress retains the returned turn through the physical
    /// primitive. No wire request can release it or assert that its writer left.
    /// # Errors
    /// Refuses a forged/stale registration, closed barrier or another live turn.
    pub fn admit_registered_working_copy_turn(
        &self,
        registration: &WorkingCopyCaptureRegistration,
        agent: &str,
        attempt: &str,
    ) -> Result<WorkingTurn> {
        self.registered_capture_entry(registration)?
            .owner
            .try_begin_turn(agent, attempt)
    }

    /// Close and drain actual host-owned admission, then create the verified
    /// warm copy. Request/connection lifetime never substitutes for those guards.
    /// # Errors
    /// Refuses forged/stale references, unknown selection, active owners, source
    /// changes or unavailable copy-on-write; no fallback or child readiness.
    pub fn capture_registered_working_copy(
        &self,
        request: &CaptureRegisteredWorkingCopyRequest,
    ) -> Result<WarmWorkingCopyCapture> {
        if !bounded(&request.operation_id) || request.drain_timeout_ms > MAX_CAPTURE_DRAIN_MILLIS {
            return Err(invalid(
                "working-copy capture exceeds its operation or drain bound",
            ));
        }
        let entry = self.registered_capture_entry(&request.registration)?;
        let closure = entry.owner.close_for_capture()?;
        let capture = self.capture_warm_child(
            closure,
            &request.operation_id,
            Duration::from_millis(u64::from(request.drain_timeout_ms)),
        )?;
        self.validate_child_capture(&capture)?;
        Ok(wire_capture(capture))
    }
}

fn wire_capture(capture: ChildCapture) -> WarmWorkingCopyCapture {
    WarmWorkingCopyCapture {
        operation_id: capture.operation_id,
        repository_id: capture.repository_id,
        binding_epoch: capture.binding_epoch,
        parent_working_copy_id: capture.parent_working_copy_id,
        parent_root: capture.parent_root,
        capture_generation: capture.capture_generation,
        selection_digest: capture.selection_digest,
        baseline: capture.baseline,
        baseline_manifest_digest: capture.baseline_manifest_digest,
        working_digest: capture.working_digest,
        path: capture.path,
        copied_entries: capture.copied_entries,
        copied_bytes: capture.copied_bytes,
        mechanism: capture.mechanism,
    }
}

#[cfg(test)]
mod tests;
