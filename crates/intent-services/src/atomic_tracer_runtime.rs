//! Production Services adapter for the explicit developer T1 command.
//!
//! Every database, config, log, host journal and fixture belongs to the supplied
//! run directory. Authentication stays with the ordinary configured provider.
//! No installed daemon, application database or native-writing route is used.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use intent_atomic::{knowledge::AtomicCodeClient, HostLaunchConfig, HostSupervisor};
use intent_atomic_proto::{
    knowledge::{CodeQuery, DerivedReceipt, QueryBudget},
    Command,
};
use intent_core::{
    vcs::{GitCommitId, GitTreeId, NativeChangeRef, NativeStateRef, OperationId, RootBinding},
    work_evidence::planning::{
        TaskConfigureWorkDefinitionInput, TaskCriterionRequirement, TaskFileReference,
        TaskFileRole, TaskWorkDefinition, TaskWorkPurpose,
    },
    work_explanation::{WorkContributionProvenance, WorkContributionReceipt},
    AgentCreateExtra, AgentId, AgentStatus, BoxFuture, Caller, FileSecretStore, HostRole,
    MessageOrigin, NoteCreate, Result, TaskMetadata, WorkspaceApi, WorkspaceCreate, WorkspaceId,
};
use intent_store::{EvidenceBlobStore, Store};

use crate::{
    atomic_tracer::{
        ConfirmedTaskSource, ExecutionCounts, Fixture, GitSourceIdentity, ProviderExecution,
        QueryObservation, RecordedRun, RetainedAssociation, TaskQueryAssociation, TaskSpec,
        TracerDriver,
    },
    AgentManager, BusEventSink, Error, EventBus, Services, SettingsRegistry,
};

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidParams(format!("Atomic tracer setup: {}", message.into()))
}

fn host_error(error: impl std::fmt::Display) -> Error {
    Error::Unsupported(format!("Actual Atomic host is unavailable: {error}"))
}

fn original_turn_settled(binding_active: bool, session_active: bool, status: AgentStatus) -> bool {
    !binding_active
        && !session_active
        && matches!(status, AgentStatus::RuntimeIdle | AgentStatus::Idle)
}

/// Explicit developer-only execution profile. Construction performs no I/O.
#[derive(Clone, Debug)]
pub struct ServicesTracerConfig {
    pub directory: PathBuf,
    pub host_binary: PathBuf,
    pub provider: String,
    pub model: Option<String>,
    pub timeout: Duration,
}

struct Runtime {
    services: Services,
    store: Store,
    manager: Arc<AgentManager>,
    bus: EventBus,
    host: Arc<HostSupervisor>,
    auto_commit: tokio::task::JoinHandle<()>,
    caller: Caller,
}

/// A driver owns the scenario's original identity across Services/host restart.
pub struct ServicesTracerDriver {
    config: ServicesTracerConfig,
    composer: Option<fn(Services) -> Services>,
    runtime: Option<Runtime>,
    workspace_id: Option<WorkspaceId>,
    agent_id: Option<AgentId>,
    binding_id: Option<OperationId>,
    output: Option<Arc<crate::atomic_tracer::DirectoryGuard>>,
    daemon: Option<Arc<crate::atomic_tracer::DirectoryGuard>>,
    database: Option<crate::atomic_tracer::FileGuard>,
}

impl ServicesTracerDriver {
    /// Build inert ownership state for a new isolated run.
    /// # Errors
    /// Refuses unsupported runtime platforms, incomplete paths or unknown providers.
    pub fn new(config: ServicesTracerConfig) -> Result<Self> {
        if !cfg!(any(
            all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ),
            all(
                target_os = "linux",
                target_arch = "x86_64",
                any(target_env = "gnu", target_env = "musl")
            ),
        )) {
            return Err(Error::Unsupported("T1 runtime supports macOS ARM64/x64 and Linux x64 GNU/musl; Linux aarch64 is not runtime-qualified".into()));
        }
        if !config.directory.is_absolute()
            || !config.host_binary.is_absolute()
            || config.timeout.is_zero()
        {
            return Err(invalid(
                "absolute isolated directory/host paths and a nonzero timeout are required",
            ));
        }
        if !intent_providers::ACP_PROVIDERS
            .iter()
            .any(|provider| provider.id == config.provider)
        {
            return Err(invalid(
                "--provider must name an existing configured Intent ACP adapter",
            ));
        }
        Ok(Self {
            config,
            composer: None,
            runtime: None,
            workspace_id: None,
            agent_id: None,
            binding_id: None,
            output: None,
            daemon: None,
            database: None,
        })
    }

    /// Supply the application's production feature registration without a
    /// dependency from Services back to its composition crate. The developer
    /// binary passes `intent_app::compose`; missing composition refuses startup.
    #[must_use]
    pub fn with_composer(mut self, composer: fn(Services) -> Services) -> Self {
        self.composer = Some(composer);
        self
    }

    fn runtime(&self) -> Result<&Runtime> {
        self.runtime
            .as_ref()
            .ok_or_else(|| invalid("scenario Services have not been started"))
    }

    fn workspace(&self) -> Result<&WorkspaceId> {
        self.workspace_id
            .as_ref()
            .ok_or_else(|| invalid("scenario workspace is not retained"))
    }

    fn agent(&self) -> Result<&AgentId> {
        self.agent_id
            .as_ref()
            .ok_or_else(|| invalid("scenario agent is not retained"))
    }

    async fn open_runtime(&mut self, reopen: bool) -> Result<()> {
        if self.runtime.is_some() {
            return Err(invalid("Services already own this run"));
        }
        let compose = self
            .composer
            .ok_or_else(|| invalid("the production application composer is required"))?;
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| invalid("original output directory owner is absent"))?;
        output.validate()?;
        if !reopen {
            if self.daemon.is_some() {
                return Err(invalid("daemon directory already has an original owner"));
            }
            self.daemon = Some(Arc::new(output.create_child("daemon")?));
        }
        self.validate_owned_paths(reopen)?;
        let data = self.config.directory.join("daemon");
        let database = data.join("intentd.db");
        if !reopen && std::fs::symlink_metadata(&database).is_ok() {
            return Err(invalid(
                "the dedicated database already exists; choose a new run directory",
            ));
        }
        if !self.config.host_binary.is_file() {
            return Err(invalid("--host does not name the pinned built native host"));
        }
        let host = Arc::new(
            HostSupervisor::new(HostLaunchConfig::new(
                self.config.host_binary.clone(),
                data.clone(),
                data.join("atomic-stores"),
            ))
            .map_err(host_error)?,
        );
        // Real handshake/IPC happens before a provider is admitted. A restricted
        // execution profile therefore produces a setup failure, not a model bill.
        let mut opened_store = None;
        let setup = async {
            self.validate_owned_paths(reopen)?;
            host.request(Command::Ping).await.map_err(host_error)?;
            self.validate_owned_paths(reopen)?;
            let store = Store::open_for_daemon(&database).await?;
            opened_store = Some(store.clone());
            if !reopen {
                self.database = Some(crate::atomic_tracer::FileGuard::open(&database)?);
            }
            self.validate_owned_paths(true)?;
            let primary = store.get_primary_principal().await?;
            let caller = Caller::Wire {
                principal_id: primary.id,
                host_role: HostRole::Owner,
            };
            let registry = Arc::new(SettingsRegistry::load(data.join("config.toml"))?);
            registry.pin(
                "model.defaultProvider",
                serde_json::json!(self.config.provider),
                "atomic-tracer --provider",
            )?;
            registry.pin(
                "mcp.enableUserServers",
                serde_json::json!(false),
                "atomic-tracer isolated scenario",
            )?;
            self.validate_owned_paths(true)?;
            let bus = EventBus::new(store.clone());
            let services = Services::new_with_repository_sources(
                store.clone(),
                FileSecretStore::with_path(data.join("repository-secrets.json")),
                None,
            )
            .with_settings_registry(registry)
            .with_event_bus(bus.clone())
            .with_workspaces_root(data.join("workspaces"))
            .with_chief_cwd_root(data.join("chief"))
            .with_assets_root(data.join("assets"))
            .with_models_cache_dir(&data)
            .with_provider_profiles_dir(&data)
            .with_script_output_dir(&data)
            .with_atomic_code_client(Arc::new(AtomicCodeClient::new(Arc::clone(&host))));
            let services = compose(services);
            let manager = Arc::new(
                AgentManager::new(
                    services.clone(),
                    Arc::new(BusEventSink::new(bus.clone())),
                    1,
                )
                .with_agent_log_root(data.join("agent-logs"))
                .with_agent_config_root(data.join("agent-configs"))
                .with_agent_tmp_root(data.join("agent-tmp")),
            );
            services.attach_agent_manager(&manager);
            let auto_commit = services.spawn_auto_commit_loop();
            Ok::<_, Error>(Runtime {
                services,
                store,
                manager,
                bus,
                host: Arc::clone(&host),
                auto_commit,
                caller,
            })
        }
        .await;
        let runtime = match setup {
            Ok(runtime) => runtime,
            Err(error) => {
                if let Some(store) = opened_store {
                    store.close().await;
                }
                return match host.shutdown().await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(Error::Internal(format!(
                        "{error}; failed to stop setup host: {cleanup}"
                    ))),
                };
            }
        };
        self.runtime = Some(runtime);
        tokio::task::yield_now().await;
        Ok(())
    }

    fn validate_owned_paths(&self, database: bool) -> Result<()> {
        self.output
            .as_ref()
            .ok_or_else(|| invalid("original output owner missing"))?
            .validate()?;
        self.daemon
            .as_ref()
            .ok_or_else(|| invalid("original daemon directory owner missing"))?
            .validate()?;
        if database {
            self.database
                .as_ref()
                .ok_or_else(|| invalid("original database owner missing"))?
                .validate()?;
        }
        Ok(())
    }

    async fn close_runtime(&mut self) -> Result<()> {
        let Some(runtime) = self.runtime.take() else {
            return Ok(());
        };
        runtime.auto_commit.abort();
        let _ = runtime.auto_commit.await;
        // Keep the original handles until every shutdown stage has been tried.
        let manager = runtime.manager.shutdown_with_native_outcome().await;
        runtime.services.shutdown_settings().await;
        runtime.services.shutdown_store_writers().await;
        let bus = runtime.bus.shutdown().await;
        let host = runtime.host.shutdown().await.map_err(host_error);
        runtime.store.close().await;
        manager?;
        bus?;
        host
    }

    async fn read_run(&self) -> Result<Option<RecordedRun>> {
        let runtime = self.runtime()?;
        let workspace = self.workspace()?;
        let agent = self.agent()?;
        let Some(binding) = runtime
            .store
            .first_work_binding_for_agent(workspace, agent)
            .await?
        else {
            return Ok(None);
        };
        let session = runtime.store.get_agent_session_summary(agent).await?;
        // Contribution retention may precede the manager's final retirement.
        // Observe the actual original binding inactive before admitting it.
        if !original_turn_settled(binding.active, session.is_active, session.status) {
            return Ok(None);
        }
        let contributions = runtime
            .store
            .work_contributions_for_binding(workspace, &binding.admission.binding_id, 2)
            .await?;
        if contributions.is_empty() {
            return Ok(None);
        }
        if contributions.len() != 1 {
            return Err(invalid(
                "multiple contributions were retained for the original run",
            ));
        }
        let contribution = &contributions[0];
        let task = runtime
            .store
            .task_revision(&binding.task_revision)
            .await?
            .ok_or_else(|| invalid("original retained task source is missing"))?;
        let task_metadata: TaskMetadata =
            serde_json::from_str(&task.task_json).map_err(|error| {
                Error::Internal(format!("read original task requirements: {error}"))
            })?;
        let allowed_paths = task_metadata
            .work_definition
            .as_ref()
            .ok_or_else(|| invalid("original confirmed task has no source definition"))?
            .files
            .iter()
            .filter(|file| file.role == TaskFileRole::InScope)
            .map(|file| file.path.clone())
            .collect();
        let root = binding
            .admission
            .root
            .clone()
            .ok_or_else(|| invalid("original admission has no Git root"))?;
        let source = observed_contribution(&runtime.services, &root, contribution).await?;
        if session.acp_session_id.is_none()
            || session.provider.as_deref() != Some(self.config.provider.as_str())
        {
            return Err(invalid(
                "no actual configured provider session was retained for this run",
            ));
        }
        Ok(Some(RecordedRun {
            task: ConfirmedTaskSource {
                reference: task.reference,
                title: task.title,
                content: task.content,
                criteria: task
                    .criteria
                    .into_iter()
                    .map(|criterion| criterion.text)
                    .collect(),
                allowed_paths,
            },
            binding,
            contribution_operation_id: contribution.operation_id.clone(),
            contribution_receipt: contribution.receipt_digest.clone(),
            source,
            changed_paths: contribution.recording.files.clone(),
            provider: ProviderExecution {
                adapter_id: session.provider.clone().unwrap_or_default(),
                model_id: session.model.clone(),
                real_configured_provider: true,
            },
        }))
    }
}

async fn observed_contribution(
    services: &Services,
    root: &RootBinding,
    contribution: &WorkContributionReceipt,
) -> Result<GitSourceIdentity> {
    if contribution.provenance
        != WorkContributionProvenance::RecordingGovernanceOnlySharedWorkingCopy
        || contribution.root.repository_id != root.repository_id
        || contribution.root.root_id != root.root_id
        || contribution.root.root_epoch != root.epoch
    {
        return Err(invalid(
            "contribution lacks its original exact recording governance",
        ));
    }
    let NativeChangeRef::Git {
        repository_id,
        commit,
    } = &contribution.recording.change
    else {
        return Err(invalid("T1 requires an actual Git contribution"));
    };
    if repository_id != &root.repository_id {
        return Err(invalid(
            "contribution repository differs from original root",
        ));
    }
    let engine = services.git_workspace_engine();
    let binding = root.clone();
    let change = contribution.recording.change.clone();
    let (state, mut paths) = tokio::task::spawn_blocking(move || {
        let state = engine
            .recorded_state(&binding)
            .map_err(crate::vcs_ops::engine_error)?;
        let paths: Vec<_> = engine
            .diff_change(&binding, &change)
            .map_err(crate::vcs_ops::engine_error)?
            .into_iter()
            .map(|diff| diff.file.path)
            .collect();
        Ok::<_, Error>((state, paths))
    })
    .await
    .map_err(|error| Error::Internal(format!("observe recorded Git contribution: {error}")))??;
    let NativeStateRef::Git {
        repository_id,
        commit: Some(current),
        tree,
    } = state
    else {
        return Err(invalid("recorded Git source is unavailable"));
    };
    if current != *commit || repository_id != root.repository_id {
        return Err(invalid(
            "fixture HEAD drifted from the original retained contribution",
        ));
    }
    paths.sort();
    paths.dedup();
    let mut recorded_paths = contribution.recording.files.clone();
    recorded_paths.sort();
    recorded_paths.dedup();
    if paths != recorded_paths {
        return Err(invalid(
            "actual commit paths differ from the contribution receipt",
        ));
    }
    Ok(GitSourceIdentity {
        root: root.clone(),
        commit: current,
        tree,
    })
}

impl TracerDriver for ServicesTracerDriver {
    fn prepare_fixture<'a>(
        &'a mut self,
        fixture: &'a Fixture,
    ) -> BoxFuture<'a, Result<GitSourceIdentity>> {
        Box::pin(async move {
            if fixture.directory.parent() != Some(self.config.directory.as_path()) {
                return Err(invalid(
                    "fixture does not belong to the configured output directory",
                ));
            }
            fixture.output.validate()?;
            self.output = Some(Arc::clone(&fixture.output));
            let path = fixture.directory.clone();
            let (commit, tree) = tokio::task::spawn_blocking(move || {
                intent_git::fixture::initialize_disposable_repository(
                    &path,
                    "Intent Atomic tracer",
                    "atomic-tracer@localhost",
                    "test: initialize fee rounding fixture",
                )
            })
            .await
            .map_err(|error| {
                Error::Internal(format!("initialize tracer Git fixture: {error}"))
            })??;
            self.open_runtime(false).await?;
            let runtime = self.runtime()?;
            let path = fixture.directory.to_string_lossy().into_owned();
            let created = intent_core::with_caller(
                runtime.caller.clone(),
                runtime.services.create_workspace(
                    WorkspaceCreate {
                        title: Some("Atomic T1 tracer".into()),
                        repository_path: Some(path.clone()),
                        path: Some(path.clone()),
                        worktree_path: Some(path),
                        skip_isolation: Some(true),
                        skip_base_refresh: Some(true),
                        ..WorkspaceCreate::default()
                    },
                    Some(format!("atomic-tracer-workspace:{}", uuid::Uuid::now_v7())),
                ),
            )
            .await?;
            let root = runtime
                .services
                .git_engine_binding(&created.workspace, None, &fixture.directory)
                .await?;
            self.workspace_id = Some(created.workspace.id);
            Ok(GitSourceIdentity {
                root,
                commit: GitCommitId::from_string(commit),
                tree: GitTreeId::from_string(tree),
            })
        })
    }

    fn confirm_and_run<'a>(
        &'a mut self,
        _fixture: &'a Fixture,
        task: &'a TaskSpec,
    ) -> BoxFuture<'a, Result<RecordedRun>> {
        Box::pin(async move {
            if self.agent_id.is_some() {
                return Err(invalid("the tracer never retries or starts a second agent"));
            }
            let runtime = self.runtime()?;
            let workspace = self.workspace()?.clone();
            let root = runtime
                .store
                .vcs_root_binding(&workspace, "primary")
                .await?
                .ok_or_else(|| invalid("fixture root binding missing"))?;
            let caller = runtime.caller.clone();
            let created = intent_core::with_caller(
                caller.clone(),
                runtime.services.create_note(
                    workspace.clone(),
                    NoteCreate {
                        title: task.title.clone(),
                        content: Some(task.content.clone()),
                        ..NoteCreate::default()
                    },
                    Some(format!("atomic-tracer-task:{}", uuid::Uuid::now_v7())),
                    None,
                ),
            )
            .await?;
            let note = created.note.id;
            intent_core::with_caller(
                caller.clone(),
                runtime.services.mark_as_task(
                    workspace.clone(),
                    note.clone(),
                    "todo".into(),
                    task.criteria.clone(),
                    None,
                    None,
                    None,
                    None,
                ),
            )
            .await?;
            let current = runtime.store.get_note(&workspace, &note).await?;
            let criteria = task
                .criteria
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    Ok(TaskCriterionRequirement {
                        index: u32::try_from(index)
                            .map_err(|_| invalid("too many task criteria"))?,
                        text_digest: crate::atomic_tracer::digest(text.as_bytes()),
                        required_kinds: vec!["test-observation".into()],
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let configured = intent_core::with_caller(
                caller.clone(),
                runtime.services.task_configure_work_definition(
                    workspace.clone(),
                    note.clone(),
                    TaskConfigureWorkDefinitionInput {
                        expected_note_version: current.rev,
                        acceptance_criteria: task.criteria.clone(),
                        work_definition: Some(TaskWorkDefinition {
                            purpose: TaskWorkPurpose::Source,
                            criteria,
                            files: task
                                .allowed_paths
                                .iter()
                                .map(|path| TaskFileReference {
                                    root_id: root.root_id.clone(),
                                    path: path.clone(),
                                    role: TaskFileRole::InScope,
                                })
                                .collect(),
                        }),
                    },
                ),
            )
            .await?;
            intent_core::with_caller(
                caller.clone(),
                runtime
                    .services
                    .set_workspace_auto_commit(workspace.clone(), true),
            )
            .await?;
            let created = intent_core::with_caller(
                caller.clone(),
                runtime.services.agent_create(
                    workspace.clone(),
                    Some("Atomic tracer agent".into()),
                    self.config.model.clone(),
                    None,
                    None,
                    Some(format!("atomic-tracer-agent:{}", uuid::Uuid::now_v7())),
                    AgentCreateExtra {
                        provider: Some(self.config.provider.clone()),
                        expected_task_revision: Some(configured.task_revision),
                        metadata: Some(serde_json::json!({"taskNoteId":note.as_str()})),
                        ..AgentCreateExtra::default()
                    },
                ),
            )
            .await?;
            let agent = created
                .get("agent")
                .and_then(|agent| agent.get("id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("normal agent.create returned no agent identity"))?;
            self.agent_id = Some(AgentId::from_string(agent));
            let runtime = self.runtime()?;
            let agent = self.agent()?.clone();
            intent_core::with_caller(
                caller,
                runtime.services.agent_send_message(
                    workspace,
                    agent.clone(),
                    task.content.clone(),
                    Some(format!("atomic-tracer-message:{}", uuid::Uuid::now_v7())),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    MessageOrigin::User,
                ),
            )
            .await?;
            let deadline = tokio::time::Instant::now() + self.config.timeout;
            loop {
                if let Some(run) = self.read_run().await? {
                    self.binding_id = Some(run.binding.admission.binding_id.clone());
                    return Ok(run);
                }
                let session = self
                    .runtime()?
                    .store
                    .get_agent_session_summary(&agent)
                    .await?;
                if matches!(session.status, AgentStatus::Error | AgentStatus::Deleted) {
                    return Err(invalid(
                        "the real provider failed; inspect this run's dedicated agent logs",
                    ));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(invalid("timed out waiting for the real provider's original retained Git contribution"));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    }

    fn materialize<'a>(
        &'a mut self,
        run: &'a RecordedRun,
        destination: &'a Path,
    ) -> BoxFuture<'a, Result<GitSourceIdentity>> {
        Box::pin(async move {
            let engine = self.runtime()?.services.git_workspace_engine();
            let source = run.source.clone();
            let root = source.root.clone();
            let state = source.state();
            let path = destination.to_path_buf();
            let materialized = tokio::task::spawn_blocking(move || {
                engine
                    .materialize(&root, &state, &path)
                    .map_err(crate::vcs_ops::engine_error)
            })
            .await
            .map_err(|error| {
                Error::Internal(format!("materialize original contribution: {error}"))
            })??;
            if materialized.state != source.state() || materialized.destination != destination {
                return Err(invalid(
                    "materialization receipt changed source or destination",
                ));
            }
            Ok(source)
        })
    }

    fn prepare_recorded_code<'a>(
        &'a mut self,
        run: &'a RecordedRun,
    ) -> BoxFuture<'a, Result<DerivedReceipt>> {
        Box::pin(async move {
            let runtime = self.runtime()?;
            intent_core::with_caller(
                runtime.caller.clone(),
                runtime
                    .services
                    .prepare_recorded_code(run.source.root.workspace_id.clone(), None),
            )
            .await
        })
    }

    fn query_recorded_code<'a>(
        &'a mut self,
        run: &'a RecordedRun,
        pattern: &'a str,
    ) -> BoxFuture<'a, Result<QueryObservation>> {
        Box::pin(async move {
            let runtime = self.runtime()?;
            let result = intent_core::with_caller(
                runtime.caller.clone(),
                runtime.services.query_recorded_code(
                    run.source.root.workspace_id.clone(),
                    None,
                    CodeQuery::Search {
                        pattern: pattern.into(),
                        literal: true,
                    },
                    vec![crate::atomic_tracer::SOURCE_PATH.into()],
                    QueryBudget::default(),
                ),
            )
            .await?;
            serde_json::from_value(result)
                .map_err(|error| Error::Internal(format!("decode actual recorded query: {error}")))
        })
    }

    fn retain_association<'a>(
        &'a mut self,
        association: &'a TaskQueryAssociation,
    ) -> BoxFuture<'a, Result<RetainedAssociation>> {
        Box::pin(async move {
            let bytes = association.retained_bytes()?;
            let path = self.config.directory.join("daemon/evidence-blobs");
            let blob =
                tokio::task::spawn_blocking(move || EvidenceBlobStore::open(&path)?.put(&bytes))
                    .await
                    .map_err(|error| {
                        Error::Internal(format!("retain tracer evidence bytes: {error}"))
                    })??;
            self.runtime()?
                .store
                .retain_evidence_blob(
                    &blob,
                    "atomic-tracer",
                    association.run.binding.admission.binding_id.as_str(),
                    "task-query-association",
                )
                .await?;
            Ok(RetainedAssociation {
                digest: blob.digest,
                length: blob.length,
            })
        })
    }

    fn restart(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.close_runtime().await?;
            self.open_runtime(true).await
        })
    }

    fn retained_run<'a>(
        &'a mut self,
        _original: &'a RecordedRun,
    ) -> BoxFuture<'a, Result<RecordedRun>> {
        Box::pin(async move {
            self.read_run()
                .await?
                .ok_or_else(|| invalid("original run evidence was unavailable after restart"))
        })
    }

    fn read_association<'a>(
        &'a mut self,
        retained: &'a RetainedAssociation,
    ) -> BoxFuture<'a, Result<TaskQueryAssociation>> {
        Box::pin(async move {
            let owner = self
                .binding_id
                .as_ref()
                .ok_or_else(|| invalid("original association owner missing"))?;
            let blob = self
                .runtime()?
                .store
                .retained_evidence_blob("atomic-tracer", owner.as_str(), "task-query-association")
                .await?
                .ok_or_else(|| invalid("retained association owner slot disappeared"))?;
            if blob.digest != retained.digest || blob.length != retained.length {
                return Err(invalid("retained association identity changed"));
            }
            let path = self.config.directory.join("daemon/evidence-blobs");
            let bytes =
                tokio::task::spawn_blocking(move || EvidenceBlobStore::open(&path)?.read(&blob))
                    .await
                    .map_err(|error| {
                        Error::Internal(format!("reopen tracer evidence bytes: {error}"))
                    })??;
            serde_json::from_slice(&bytes).map_err(|error| {
                Error::Internal(format!("decode retained tracer association: {error}"))
            })
        })
    }

    fn execution_counts(&mut self) -> BoxFuture<'_, Result<ExecutionCounts>> {
        Box::pin(async move {
            let runtime = self.runtime()?;
            let workspace = self.workspace()?;
            let agent = self.agent()?;
            let admissions = runtime
                .store
                .work_admission_count_up_to(workspace, agent, 2)
                .await?;
            let contributions = if let Some(binding) = runtime
                .store
                .first_work_binding_for_agent(workspace, agent)
                .await?
            {
                runtime
                    .store
                    .work_contributions_for_binding(workspace, &binding.admission.binding_id, 2)
                    .await?
                    .len() as u64
            } else {
                0
            };
            Ok(ExecutionCounts {
                agent_runs: admissions,
                contributions,
            })
        })
    }

    fn shutdown(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.close_runtime().await })
    }
}

#[cfg(test)]
mod tests;
