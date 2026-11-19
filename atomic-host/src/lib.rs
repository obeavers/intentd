//! Isolated, owner-controlled Atomic host foundation.
//!
//! Native stores are opened once and shared across readers. Local lifecycle
//! primitives are exposed only over exact private daemon requests; these do not
//! enable a source workspace or confer task/source authorization. Incomplete effects without retained proof remain
//! uncertain and close admission instead of being interpreted as empty stores.

#![cfg(unix)]

mod baselines;
#[cfg(test)]
mod cli_sandbox_qualification;
mod closures;
mod composition;
mod durable;
mod embedding_policy;
pub mod execution_grants;
pub mod intents;
mod knowledge;
mod native;
mod provenance;
pub mod recorded_closures;
pub mod recording;
pub mod sealed_record_source;
pub mod sessions;
mod signing;
pub mod transport;
mod triage;
pub mod working_copies;
pub mod working_copy_transport;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use intent_atomic_proto::{
    Command, FailureCode, HostFailure, HostIdentity, RecoveryReport, Reply, StoreBinding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, HostError>;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("host I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("host metadata: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Unsupported(&'static str),
    #[error("native Atomic repository: {0}")]
    Native(String),
    #[error("persisted repository binding differs from the request")]
    StaleBinding,
    #[error("host identity handshake is incompatible")]
    IncompatibleHost,
    #[error("host recovery has unresolved operations")]
    RecoveryRequired,
    #[error("initialization outcome remains uncertain: {0}")]
    Uncertain(String),
    #[error("host lock poisoned")]
    Poisoned,
}

impl HostError {
    fn failure(&self) -> HostFailure {
        let (code, operation_id) = match self {
            Self::StaleBinding => (FailureCode::StaleBinding, None),
            Self::IncompatibleHost => (FailureCode::IncompatibleHost, None),
            Self::RecoveryRequired => (FailureCode::RecoveryRequired, None),
            Self::Uncertain(operation) => (FailureCode::Uncertain, Some(operation.clone())),
            Self::Invalid(_) => (FailureCode::InvalidRequest, None),
            Self::Unsupported(_) => (FailureCode::Unsupported, None),
            _ => (FailureCode::Unavailable, None),
        };
        HostFailure {
            code,
            message: self.to_string(),
            operation_id,
        }
    }
}

/// All locators are provided by intentd. No user Atomic installation is discovered.
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub stores_dir: PathBuf,
    pub config_dir: PathBuf,
    pub spool_dir: PathBuf,
}

/// Connection-local handshake and recovery admission; another peer cannot borrow it.
#[derive(Default)]
pub struct Session {
    handshaken: bool,
    reconciled: bool,
    recovered: bool,
    unresolved_operations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalEntry {
    operation_id: String,
    command_digest: String,
    binding: StoreBinding,
    phase: InitPhase,
    proof: Option<native::StoreProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum InitPhase {
    Prepared,
    Running,
    EffectKnown,
    Terminal,
}

/// One process-level owner. The writer lane never guards an existing store read.
pub struct Host {
    config: HostConfig,
    journal_dir: PathBuf,
    stores_root_identity: durable::FileIdentity,
    spool_root_identity: durable::FileIdentity,
    journal_root_identity: durable::FileIdentity,
    stores: Mutex<HashMap<String, Arc<native::NativeStore>>>,
    knowledge: Mutex<HashMap<String, Arc<knowledge::DerivedStore>>>,
    baselines: Mutex<HashMap<String, Arc<baselines::BaselineStore>>>,
    working_copies: Mutex<HashMap<PathBuf, std::sync::Weak<working_copies::Inner>>>,
    working_copy_transport: working_copy_transport::Registry,
    native_grants: execution_grants::NativeGrants,
    writer: Mutex<()>,
    recovered: Mutex<bool>,
    live_writer: Mutex<bool>,
}

/// Process-local ownership of one verified native transition. Dropping a failed
/// operation leaves recovery closed; this token can never survive a crash.
pub(crate) struct LiveWrite<'a> {
    host: &'a Host,
    completed: bool,
}

impl LiveWrite<'_> {
    pub(crate) fn complete(mut self) -> Result<()> {
        let mut live = self
            .host
            .live_writer
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        let mut recovered = self
            .host
            .recovered
            .lock()
            .map_err(|_| HostError::Poisoned)?;
        *recovered = true;
        *live = false;
        self.completed = true;
        Ok(())
    }
}

impl Drop for LiveWrite<'_> {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(mut live) = self.host.live_writer.lock() {
                if let Ok(mut recovered) = self.host.recovered.lock() {
                    *recovered = false;
                    *live = false;
                }
            }
        }
    }
}

impl Host {
    /// Open inert host ownership metadata; this does not initialize any repository.
    /// # Errors
    /// Refuses nonabsolute, symlink or nonprivate owner directories.
    pub fn new(config: HostConfig) -> Result<Self> {
        for path in [&config.stores_dir, &config.config_dir, &config.spool_dir] {
            if !path.is_absolute() {
                return Err(HostError::Invalid("absolute host directories are required"));
            }
            durable::private_dir(path)?;
        }
        let journal_dir = config.config_dir.join("operations");
        durable::private_dir(&journal_dir)?;
        Ok(Self {
            stores_root_identity: durable::identity(&config.stores_dir, true)?,
            spool_root_identity: durable::identity(&config.spool_dir, true)?,
            journal_root_identity: durable::identity(&journal_dir, true)?,
            config,
            journal_dir,
            stores: Mutex::new(HashMap::new()),
            knowledge: Mutex::new(HashMap::new()),
            baselines: Mutex::new(HashMap::new()),
            working_copies: Mutex::new(HashMap::new()),
            working_copy_transport: working_copy_transport::Registry::default(),
            native_grants: execution_grants::NativeGrants::default(),
            writer: Mutex::new(()),
            recovered: Mutex::new(false),
            live_writer: Mutex::new(false),
        })
    }

    pub(crate) fn read_admitted(&self) -> Result<()> {
        let live = self.live_writer.lock().map_err(|_| HostError::Poisoned)?;
        let recovered = self.recovered.lock().map_err(|_| HostError::Poisoned)?;
        if *recovered || *live {
            Ok(())
        } else {
            Err(HostError::RecoveryRequired)
        }
    }

    /// The caller owns the writer lane and has checked its immutable inputs.
    pub(crate) fn begin_live_write(&self) -> Result<LiveWrite<'_>> {
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        self.register_live_writer()
    }

    // Exact record recovery may register only after proving the unique retained
    // operation, original bytes and unchanged before-state under the writer.
    fn register_live_writer(&self) -> Result<LiveWrite<'_>> {
        let mut live = self.live_writer.lock().map_err(|_| HostError::Poisoned)?;
        let mut recovered = self.recovered.lock().map_err(|_| HostError::Poisoned)?;
        if *live {
            return Err(HostError::Invalid("native writer already has a live owner"));
        }
        *live = true;
        *recovered = false;
        Ok(LiveWrite {
            host: self,
            completed: false,
        })
    }

    fn binding_path(&self, binding: &StoreBinding) -> Result<PathBuf> {
        if durable::identity(&self.config.stores_dir, true)? != self.stores_root_identity {
            return Err(HostError::StaleBinding);
        }
        let uuid = uuid::Uuid::parse_str(&binding.repository_id)
            .map_err(|_| HostError::Invalid("repository identity must be a UUID"))?;
        if uuid.to_string() != binding.repository_id || binding.binding_epoch == 0 {
            return Err(HostError::Invalid(
                "canonical repository UUID and positive binding epoch are required",
            ));
        }
        let parent = self.config.stores_dir.join(&binding.repository_id);
        if binding.store_path != parent.join("native") {
            return Err(HostError::Invalid(
                "store locator is outside its configured repository namespace",
            ));
        }
        if std::fs::symlink_metadata(&parent).is_ok() {
            durable::identity(&parent, true)?;
        }
        Ok(parent)
    }

    fn operation_path(&self, operation: &str) -> Result<PathBuf> {
        if durable::identity(&self.journal_dir, true)? != self.journal_root_identity {
            return Err(HostError::StaleBinding);
        }
        if operation.is_empty() || operation.len() > 256 {
            return Err(HostError::Invalid(
                "operation identity is empty or too long",
            ));
        }
        Ok(self
            .journal_dir
            .join(format!("{:x}.json", Sha256::digest(operation.as_bytes()))))
    }

    /// Initialize a disposable or newly admitted canonical store under an immutable
    /// operation ID. This is deliberately absent from the network command surface.
    /// # Errors
    /// Refuses conflicting replay, existing unowned native data, stale binding,
    /// or unproved interrupted effects. Failed admission never reports success.
    pub fn initialize_store(&self, binding: &StoreBinding, operation: &str) -> Result<()> {
        self.initialize_observed(binding, operation, |_| Ok(()))
    }

    fn initialize_observed(
        &self,
        binding: &StoreBinding,
        operation: &str,
        mut observed: impl FnMut(InitPhase) -> Result<()>,
    ) -> Result<()> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let parent = self.binding_path(binding)?;
        let operation_path = self.operation_path(operation)?;
        let command_digest = format!("{:x}", Sha256::digest(serde_json::to_vec(binding)?));
        if std::fs::symlink_metadata(&operation_path).is_ok() {
            let entry: JournalEntry = durable::read_json(&operation_path)?;
            if entry.operation_id != operation
                || entry.command_digest != command_digest
                || entry.binding != *binding
            {
                return Err(HostError::Invalid("conflicting operation replay"));
            }
            if entry.phase != InitPhase::Terminal {
                return Err(HostError::Uncertain(operation.into()));
            }
            let proof = self.verify_marker(binding)?;
            if entry.proof.as_ref() != Some(&proof) {
                return Err(HostError::StaleBinding);
            }
            self.verify_effect(binding, &proof)?;
            return Ok(());
        }
        if std::fs::symlink_metadata(&binding.store_path).is_ok()
            || std::fs::symlink_metadata(parent.join("identity.json")).is_ok()
        {
            return Err(HostError::Invalid(
                "native store already exists; initialization never adopts it",
            ));
        }
        let live = self.begin_live_write()?;
        let mut entry = JournalEntry {
            operation_id: operation.into(),
            command_digest,
            binding: binding.clone(),
            phase: InitPhase::Prepared,
            proof: None,
        };
        durable::write_json(&operation_path, &entry, false)?;
        observed(InitPhase::Prepared)?;
        durable::private_dir(&parent)?;
        entry.phase = InitPhase::Running;
        durable::write_json(&operation_path, &entry, true)?;
        observed(InitPhase::Running)?;
        let proof = native::initialize(binding)?;
        entry.proof = Some(proof.clone());
        entry.phase = InitPhase::EffectKnown;
        durable::write_json(&operation_path, &entry, true)?;
        observed(InitPhase::EffectKnown)?;
        durable::write_json(&parent.join("identity.json"), &proof, false)?;
        entry.phase = InitPhase::Terminal;
        durable::write_json(&operation_path, &entry, true)?;
        observed(InitPhase::Terminal)?;
        live.complete()?;
        Ok(())
    }

    fn verify_marker(&self, binding: &StoreBinding) -> Result<native::StoreProof> {
        let parent = self.binding_path(binding)?;
        let proof: native::StoreProof = durable::read_json(&parent.join("identity.json"))?;
        proof.validate(binding)?;
        Ok(proof)
    }

    /// Inspect the host's own complete journal. Only retained effect identities
    /// can resolve uncertain initialization; no missing store becomes empty success.
    /// # Errors
    /// Corrupt or replaced journal metadata refuses recovery, closing admission.
    pub fn reconcile(&self) -> Result<RecoveryReport> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        *self.recovered.lock().map_err(|_| HostError::Poisoned)? = false;
        let mut unresolved = Vec::new();
        for file in std::fs::read_dir(&self.journal_dir)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let mut entry: JournalEntry = durable::read_json(&file.path())?;
            if self.operation_path(&entry.operation_id)? != file.path() {
                return Err(HostError::Invalid(
                    "journal filename does not match its operation",
                ));
            }
            let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&entry.binding)?));
            if digest != entry.command_digest {
                return Err(HostError::Invalid(
                    "journal immutable command digest changed",
                ));
            }
            self.binding_path(&entry.binding)?;
            match entry.phase {
                InitPhase::Prepared | InitPhase::Running => unresolved.push(entry.operation_id),
                InitPhase::EffectKnown | InitPhase::Terminal => {
                    let proof = entry
                        .proof
                        .as_ref()
                        .ok_or(HostError::Invalid("journal effect has no identity receipt"))?;
                    proof.validate(&entry.binding)?;
                    // Validate actual native data through its own schema and stable
                    // project identity before reconstructing an interrupted marker.
                    self.verify_effect(&entry.binding, proof)?;
                    let marker = entry
                        .binding
                        .store_path
                        .parent()
                        .ok_or(HostError::Invalid("store locator has no parent"))?
                        .join("identity.json");
                    if std::fs::symlink_metadata(&marker).is_ok() {
                        let actual: native::StoreProof = durable::read_json(&marker)?;
                        if &actual != proof {
                            return Err(HostError::StaleBinding);
                        }
                    } else {
                        durable::write_json(&marker, proof, false)?;
                    }
                    if entry.phase != InitPhase::Terminal {
                        entry.phase = InitPhase::Terminal;
                        durable::write_json(&file.path(), &entry, true)?;
                    }
                }
            }
        }
        self.reconcile_derived()?;
        self.reconcile_baselines()?;
        self.reconcile_native_sessions()?;
        unresolved.extend(self.unresolved_records()?);
        unresolved.extend(self.reconcile_intents()?);
        self.reconcile_execution_grants()?;
        unresolved.sort();
        let ready = unresolved.is_empty();
        *self.recovered.lock().map_err(|_| HostError::Poisoned)? = ready;
        Ok(RecoveryReport {
            ready,
            unresolved_operation_ids: unresolved,
        })
    }

    fn verify_effect(&self, binding: &StoreBinding, proof: &native::StoreProof) -> Result<()> {
        let cached = self
            .stores
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .get(&binding.repository_id)
            .cloned();
        if let Some(store) = cached {
            store.validate(binding, proof)
        } else if self.owned_record_recovery(binding)? || self.owned_intent_recovery(binding)? {
            let store = Arc::new(native::NativeStore::open_owned_recovery(binding, proof)?);
            self.stores
                .lock()
                .map_err(|_| HostError::Poisoned)?
                .insert(binding.repository_id.clone(), store);
            Ok(())
        } else {
            native::NativeStore::open(binding, proof).map(|_| ())
        }
    }

    /// Handle one already-framed request with per-connection admission.
    /// # Errors
    /// Returns typed failures for incompatible peers, incomplete recovery,
    /// unavailable operations, stale bindings, and native or filesystem errors.
    pub fn handle(
        &self,
        session: &mut Session,
        command: Command,
    ) -> std::result::Result<Reply, HostFailure> {
        self.handle_inner(session, command)
            .map_err(|error| error.failure())
    }

    fn handle_inner(&self, session: &mut Session, command: Command) -> Result<Reply> {
        if let Command::Handshake { identity } = command {
            session.handshaken = false;
            session.reconciled = false;
            session.recovered = false;
            session.unresolved_operations.clear();
            if identity != HostIdentity::default() {
                return Err(HostError::IncompatibleHost);
            }
            session.handshaken = true;
            return Ok(Reply::Handshake {
                identity: HostIdentity::default(),
            });
        }
        if !session.handshaken {
            return Err(HostError::IncompatibleHost);
        }
        match command {
            Command::Reconcile => {
                let recovery = self.reconcile()?;
                session.reconciled = true;
                session.recovered = recovery.ready;
                session
                    .unresolved_operations
                    .clone_from(&recovery.unresolved_operation_ids);
                Ok(Reply::Reconciled { recovery })
            }
            Command::Ping => Ok(Reply::Pong),
            Command::Shutdown => Ok(Reply::Shutdown),
            Command::CloseExecutionGrant { request } => self
                .close_native_execution_grant(&request)
                .map(|receipt| Reply::ExecutionGrantClosed { receipt }),
            // Recovery is a narrow retained-effect lane. It cannot prepare a
            // new record, change its immutable command or borrow another
            // peer's reconciliation. The native owner proves its unique
            // unresolved operation and retained bytes before any effect.
            Command::AdmitExactRecord { prepared } => {
                if !session.reconciled
                    || (!session.recovered
                        && session.unresolved_operations != [prepared.operation_id.clone()])
                {
                    return Err(HostError::RecoveryRequired);
                }
                self.admit_exact_record(&prepared)
                    .map(|receipt| Reply::ExactRecordAdmitted { receipt })
            }
            command => {
                if !session.recovered {
                    return Err(HostError::RecoveryRequired);
                }
                if command.is_read_only() {
                    self.read_admitted()?;
                } else if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
                    return Err(HostError::RecoveryRequired);
                }
                match command {
                    Command::SealRecordSource { request } => {
                        self.seal_record_source(&request)
                            .map(|source| Reply::RecordSourceSealed {
                                source: Box::new(source),
                            })
                    }
                    Command::ExportRecordedClosure { request } => self
                        .export_recorded_closure(&request)
                        .map(|receipt| Reply::RecordedClosureExported {
                            receipt: Box::new(receipt),
                        }),
                    Command::RestoreRecordedClosure { request } => self
                        .restore_recorded_closure(&request)
                        .map(|receipt| Reply::RecordedClosureRestored {
                            receipt: Box::new(receipt),
                        }),
                    Command::InitializeStore {
                        binding,
                        operation_id,
                    } => {
                        self.initialize_store(&binding, &operation_id)?;
                        Ok(Reply::StoreInitialized {
                            binding,
                            operation_id,
                        })
                    }
                    Command::BeginNativeSession { request } => self
                        .begin_native_session(&request)
                        .map(|receipt| Reply::NativeSessionBegan { receipt }),
                    Command::CloseNativeSession { request } => self
                        .close_native_session(&request)
                        .map(|receipt| Reply::NativeSessionClosed { receipt }),
                    Command::RegisterWorkingCopyCapture { request } => self
                        .register_transport_working_copy_capture(&request)
                        .map(|registration| Reply::WorkingCopyCaptureRegistered {
                            registration: Box::new(registration),
                        }),
                    Command::CaptureRegisteredWorkingCopy { request } => self
                        .capture_registered_working_copy(&request)
                        .map(|capture| Reply::WorkingCopyCaptured {
                            capture: Box::new(capture),
                        }),
                    Command::ReadNativeProject { binding } => self
                        .native_project_identity(&binding)
                        .map(|identity| Reply::NativeProject { identity }),
                    Command::ProjectTaskIntent { request } => self
                        .project_task_intent(&request)
                        .map(|receipt| Reply::TaskIntentProjected {
                            receipt: Box::new(receipt),
                        }),
                    Command::DeclareNativeTurn { request } => self
                        .declare_native_turn_intent(&request)
                        .map(|receipt| Reply::NativeTurnDeclared { receipt }),
                    Command::FreezeNativeTurn { request } => self
                        .freeze_native_turn_for_record(&request)
                        .map(|receipt| Reply::NativeTurnFrozen {
                            receipt: Box::new(receipt),
                        }),
                    Command::PrepareExactRecord { request } => self
                        .prepare_exact_record(&request)
                        .map(|outcome| Reply::ExactRecordPrepared {
                            outcome: Box::new(outcome),
                        }),
                    Command::PrepareBoundExactRecord { request, freeze } => self
                        .prepare_exact_record_for_bound_turn(&request, &freeze)
                        .map(|outcome| Reply::ExactRecordPrepared {
                            outcome: Box::new(outcome),
                        }),
                    Command::CaptureNativeControl { request } => self
                        .capture_native_triage_control(&request)
                        .map(|snapshot| Reply::NativeControlCaptured { snapshot }),
                    Command::PrepareNativeTriage { request } => self
                        .prepare_native_triage(&request)
                        .map(|outcome| Reply::NativeTriagePrepared {
                            outcome: Box::new(outcome),
                        }),
                    Command::IssueExecutionGrant { request } => self
                        .issue_native_execution_grant(&request)
                        .map(|issued| Reply::ExecutionGrantIssued {
                            issued: Box::new(issued),
                        }),
                    Command::ReadGrantedFile { request } => self
                        .read_native_granted_file(&request)
                        .map(|receipt| Reply::GrantedFile { receipt }),
                    Command::CaptureCompositionTarget { request } => self
                        .capture_composition_target(&request)
                        .map(|capture| Reply::CompositionTargetCaptured { capture }),
                    Command::ComposePrivate { input } => {
                        self.compose_private_spooled(&input)
                            .map(|outcome| Reply::PrivateComposed {
                                outcome: Box::new(outcome),
                            })
                    }
                    Command::ExportBaselineClosure { request } => self
                        .export_baseline_closure(&request)
                        .map(|receipt| Reply::BaselineClosureExported { receipt }),
                    Command::RestoreBaselineClosure { request } => self
                        .restore_baseline_closure(&request)
                        .map(|receipt| Reply::BaselineClosureRestored { receipt }),
                    Command::ImportBaseline { request } => self
                        .import_baseline(&request)
                        .map(|receipt| Reply::BaselineImported { receipt }),
                    Command::ReadBaseline { baseline } => self
                        .read_baseline(&baseline)
                        .map(|receipt| Reply::Baseline { receipt }),
                    Command::MaterializeBaseline { request } => self
                        .materialize_baseline(&request)
                        .map(|receipt| Reply::BaselineMaterialized { receipt }),
                    Command::ClassifyTool { request } => provenance::classify(&request)
                        .map(|receipt| Reply::ToolClassified { receipt }),
                    Command::ImportDerived { request } => self
                        .import_derived(&request)
                        .map(|receipt| Reply::DerivedImported { receipt }),
                    Command::QueryCode { request } => self
                        .query_code(&request)
                        .map(|result| Reply::CodeQuery { result }),
                    Command::OpenStore { binding } => {
                        self.open_store(&binding)?;
                        Ok(Reply::StoreOpened { binding })
                    }
                    Command::ReadState { binding } => {
                        let store = self.cached_store(&binding)?;
                        let state = store.state()?;
                        Ok(Reply::State { binding, state })
                    }
                    Command::CloseStore { binding } => {
                        self.verify_marker(&binding)?;
                        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
                        let mut stores = self.stores.lock().map_err(|_| HostError::Poisoned)?;
                        if stores
                            .get(&binding.repository_id)
                            .is_some_and(|store| Arc::strong_count(store) > 1)
                        {
                            return Err(HostError::Invalid("store still has an admitted reader"));
                        }
                        stores.remove(&binding.repository_id);
                        Ok(Reply::StoreClosed { binding })
                    }
                    _ => Err(HostError::Unsupported(
                        "host command is not available in this build",
                    )),
                }
            }
        }
    }

    fn open_store(&self, binding: &StoreBinding) -> Result<()> {
        let proof = self.verify_marker(binding)?;
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if let Some(store) = self
            .stores
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .get(&binding.repository_id)
        {
            store.validate(binding, &proof)?;
            return Ok(());
        }
        let store = Arc::new(native::NativeStore::open(binding, &proof)?);
        self.stores
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .insert(binding.repository_id.clone(), store);
        Ok(())
    }

    fn cached_store(&self, binding: &StoreBinding) -> Result<Arc<native::NativeStore>> {
        let proof = self.verify_marker(binding)?;
        let store = self
            .stores
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .get(&binding.repository_id)
            .cloned()
            .ok_or(HostError::Invalid("store must be opened before a read"))?;
        store.validate(binding, &proof)?;
        Ok(store)
    }
}

#[cfg(test)]
mod aggregate_checkpoint_tests;
#[cfg(test)]
mod aggregate_recorded_checkpoint_tests;
#[cfg(test)]
mod native_dispatch_tests;
#[cfg(test)]
mod tests;
