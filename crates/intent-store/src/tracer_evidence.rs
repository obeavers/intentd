//! Minimum retained Git/task evidence for T1. Native writing and acceptance are
//! intentionally absent. Both backends run the same validation inside their
//! normal write transaction; Postgres supplies tenant-scoped SQL and writer lock.

use std::path::Path;

use intent_core::vcs::{
    ContentDigest, NativeChangeRef, NativeStateRef, OperationId, RecordedChange, RepositoryId,
    RootBinding, VcsKind,
};
use intent_core::work_evidence::{
    CriterionOrigin, EvidenceOutboxEvent, NativeBindingState, NewEvidenceOutboxEvent,
    RevisionCriterion, TaskRevision, TaskRevisionRef, WorkBinding, WorkBindingAdmission,
    TASK_PROJECTION_SCHEMA_VERSION,
};
use intent_core::work_explanation::{
    ExplanationRoot, WorkContributionProvenance, WorkContributionReceipt,
};
use intent_core::{
    now_iso, AgentId, AgentSession, AgentStatus, Error, Note, NoteId, Result, TaskMetadata,
    TaskStatus, WorkspaceId, WorkspaceStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EvidenceBlob, NoteWriteLock, Store};

mod sqlite;
#[cfg(test)]
mod tests;

/// Original admission observation. This is not a serializable permission token.
#[derive(Clone, Debug)]
pub struct WorkTurnFence {
    workspace_id: WorkspaceId,
    agent_id: AgentId,
    revision: i64,
    source_work: bool,
}

impl WorkTurnFence {
    #[must_use]
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
    #[must_use]
    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }
    /// Whether this observed task declares source work requiring an actual root.
    #[must_use]
    pub fn requires_work_binding(&self) -> bool {
        self.source_work
    }
}

pub(crate) fn database(error: impl std::fmt::Display) -> Error {
    Error::Internal(format!("T1 evidence persistence: {error}"))
}
pub(crate) fn invalid(reason: &str) -> Error {
    Error::InvalidParams(reason.into())
}
fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(database)
}
fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(database)
}
fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest(format!("{:x}", Sha256::digest(bytes)))
}
fn key(value: &impl Serialize) -> Result<String> {
    Ok(digest(encode(value)?.as_bytes()).0)
}

#[derive(Clone, Debug)]
pub(crate) struct SourceNote {
    pub rev: i64,
    pub title: String,
    pub content: String,
    pub content_type: String,
    pub task_json: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct AgentState {
    pub task_note_id: Option<String>,
    pub status: String,
    pub retired_at: Option<String>,
    pub workspace_status: String,
    pub revision: i64,
    pub assignment_revision: i64,
}

#[derive(Serialize, Deserialize)]
struct RevisionSource {
    source: TaskRevision,
    content_type: String,
    governing_digest: ContentDigest,
}
#[derive(Serialize, Deserialize)]
struct Confirmation {
    reference: TaskRevisionRef,
    assignment_revision: i64,
}
#[derive(Serialize, Deserialize)]
struct Admission {
    workspace: WorkspaceId,
    agent: AgentId,
    command_digest: ContentDigest,
    binding: Option<OperationId>,
}
#[derive(Serialize, Deserialize)]
struct Repository {
    id: RepositoryId,
    kind: VcsKind,
    format: u32,
    alias: Option<String>,
}

// Concrete backend adapters own cancellation-safe transactions. SQL never
// leaves the Store layer, and caller-supplied JSON cannot invoke this trait.
pub(crate) trait EvidenceTx: Send {
    fn object(
        &mut self,
        kind: &str,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<(i64, String)>>> + Send;
    fn insert(
        &mut self,
        kind: &str,
        key: &str,
        raw: &str,
    ) -> impl std::future::Future<Output = Result<i64>> + Send;
    fn active(
        &mut self,
        agent: &AgentId,
        binding: Option<&OperationId>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn note(
        &mut self,
        workspace: &WorkspaceId,
        note: &NoteId,
    ) -> impl std::future::Future<Output = Result<Option<SourceNote>>> + Send;
    fn locator(
        &mut self,
        workspace: &WorkspaceId,
        root: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>>> + Send;
    fn root_epoch(
        &mut self,
        workspace: &WorkspaceId,
        root: &str,
    ) -> impl std::future::Future<Output = Result<Option<u64>>> + Send;
    fn agent(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
    ) -> impl std::future::Future<Output = Result<Option<AgentState>>> + Send;
    fn activate(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        timestamp: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn write_note(
        &mut self,
        lock: &NoteWriteLock,
        note: &Note,
        expected: i64,
    ) -> impl std::future::Future<Output = Result<i64>> + Send;
    fn insert_agent(
        &mut self,
        session: &AgentSession,
        graph: bool,
        remember: bool,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn contributions(
        &mut self,
        workspace: &WorkspaceId,
        owner: &OperationId,
        limit: u32,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
    fn admission_count(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        limit: u32,
    ) -> impl std::future::Future<Output = Result<i64>> + Send;
}

async fn retained<T: serde::de::DeserializeOwned>(
    tx: &mut impl EvidenceTx,
    kind: &str,
    id: &str,
) -> Result<Option<T>> {
    tx.object(kind, id)
        .await?
        .map(|(_, raw)| decode(&raw))
        .transpose()
}

async fn immutable<T: Serialize>(
    tx: &mut impl EvidenceTx,
    kind: &str,
    id: &str,
    value: &T,
) -> Result<i64> {
    let raw = encode(value)?;
    if let Some((sequence, prior)) = tx.object(kind, id).await? {
        if prior != raw {
            return Err(invalid("conflicting immutable evidence replay"));
        }
        return Ok(sequence);
    }
    tx.insert(kind, id, &raw).await
}

fn governing_digest(source: &SourceNote, task: &TaskMetadata) -> Result<ContentDigest> {
    crate::task_work_definition::validate(task)?;
    Ok(digest(
        encode(&(
            1u32,
            &source.title,
            &source.content,
            &source.content_type,
            &task.acceptance_criteria,
            &task.work_definition,
            &task.estimated_effort,
            &task.depends_on,
            &task.conflicts_with,
        ))?
        .as_bytes(),
    ))
}

async fn capture_revision(
    tx: &mut impl EvidenceTx,
    workspace: &WorkspaceId,
    note: &NoteId,
    expected: Option<i64>,
) -> Result<TaskRevision> {
    let source = tx
        .note(workspace, note)
        .await?
        .ok_or_else(|| invalid("governing task is missing"))?;
    if expected.is_some_and(|rev| rev != source.rev) {
        return Err(invalid("governing task revision changed"));
    }
    let task_json = source
        .task_json
        .as_ref()
        .ok_or_else(|| invalid("governing note is not a task"))?;
    let task: TaskMetadata = decode(task_json)?;
    crate::task_work_definition::validate(&task)?;
    let source_digest = digest(
        encode(&(
            TASK_PROJECTION_SCHEMA_VERSION,
            workspace,
            note,
            source.rev,
            &source.title,
            &source.content,
            task_json,
        ))?
        .as_bytes(),
    );
    let id = key(&(workspace, note, source.rev))?;
    if let Some(prior) = retained::<RevisionSource>(tx, "task-revision", &id).await? {
        if prior.source.reference.digest != source_digest
            || prior.content_type != source.content_type
        {
            return Err(invalid(
                "task source changed without advancing its revision",
            ));
        }
        return Ok(prior.source);
    }
    let criteria = task
        .acceptance_criteria
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let index = u32::try_from(index).map_err(|_| invalid("too many criteria"))?;
            let text_digest = digest(text.as_bytes());
            Ok(RevisionCriterion {
                criterion_id: digest(encode(&(&source_digest, index, &text_digest))?.as_bytes()),
                index,
                text: text.clone(),
                text_digest,
                origin: CriterionOrigin::ExplicitTaskContent,
                required_kinds: task
                    .work_definition
                    .as_ref()
                    .and_then(|d| d.criteria.iter().find(|c| c.index == index))
                    .map(|c| c.required_kinds.clone())
                    .unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let revision = TaskRevision {
        reference: TaskRevisionRef {
            workspace_id: workspace.clone(),
            note_id: note.clone(),
            rev: source.rev,
            digest: source_digest,
            projection_schema_version: TASK_PROJECTION_SCHEMA_VERSION,
        },
        title: source.title.clone(),
        content: source.content.clone(),
        task_json: task_json.clone(),
        criteria,
        created_at: now_iso(),
    };
    let governing_digest = governing_digest(&source, &task)?;
    immutable(
        tx,
        "task-revision",
        &id,
        &RevisionSource {
            source: revision.clone(),
            content_type: source.content_type,
            governing_digest,
        },
    )
    .await?;
    Ok(revision)
}

async fn original(
    tx: &mut impl EvidenceTx,
    reference: &TaskRevisionRef,
) -> Result<Option<RevisionSource>> {
    let value = retained::<RevisionSource>(
        tx,
        "task-revision",
        &key(&(&reference.workspace_id, &reference.note_id, reference.rev))?,
    )
    .await?;
    if value
        .as_ref()
        .is_some_and(|value| value.source.reference != *reference)
    {
        return Ok(None);
    }
    if let Some(value) = &value {
        let source = &value.source;
        let expected = digest(
            encode(&(
                TASK_PROJECTION_SCHEMA_VERSION,
                &reference.workspace_id,
                &reference.note_id,
                reference.rev,
                &source.title,
                &source.content,
                &source.task_json,
            ))?
            .as_bytes(),
        );
        let task: TaskMetadata = decode(&source.task_json)?;
        let note = SourceNote {
            rev: reference.rev,
            title: source.title.clone(),
            content: source.content.clone(),
            content_type: value.content_type.clone(),
            task_json: Some(source.task_json.clone()),
        };
        if expected != reference.digest
            || reference.projection_schema_version != TASK_PROJECTION_SCHEMA_VERSION
            || governing_digest(&note, &task)? != value.governing_digest
        {
            return Err(invalid("retained task source digest is inconsistent"));
        }
    }
    Ok(value)
}

async fn current_original(
    tx: &mut impl EvidenceTx,
    reference: &TaskRevisionRef,
) -> Result<TaskRevision> {
    let retained = original(tx, reference)
        .await?
        .ok_or_else(|| invalid("original task source is unavailable"))?;
    let current = tx
        .note(&reference.workspace_id, &reference.note_id)
        .await?
        .ok_or_else(|| invalid("governing task is missing"))?;
    let task: TaskMetadata = decode(
        current
            .task_json
            .as_deref()
            .ok_or_else(|| invalid("governing note is no longer a task"))?,
    )?;
    if matches!(task.status, TaskStatus::Complete | TaskStatus::Cancelled)
        || governing_digest(&current, &task)? != retained.governing_digest
    {
        return Err(invalid(
            "original governing task changed or became terminal",
        ));
    }
    Ok(retained.source)
}

fn validate_agent(state: &AgentState) -> Result<()> {
    if crate::enum_from_db::<AgentStatus>(&state.status)? == AgentStatus::Deleted
        || state.retired_at.is_some()
        || matches!(
            crate::enum_from_db::<WorkspaceStatus>(&state.workspace_status)?,
            WorkspaceStatus::Deleted | WorkspaceStatus::Retired
        )
    {
        return Err(invalid("agent or workspace is deleted or retired"));
    }
    Ok(())
}

async fn require_confirmation(
    tx: &mut impl EvidenceTx,
    agent: &AgentId,
    confirmation: &Confirmation,
) -> Result<TaskRevision> {
    let state = tx
        .agent(&confirmation.reference.workspace_id, agent)
        .await?
        .ok_or_else(|| invalid("confirmed agent is unavailable"))?;
    validate_agent(&state)?;
    if state.task_note_id.as_deref() != Some(confirmation.reference.note_id.as_str())
        || state.assignment_revision != confirmation.assignment_revision
    {
        return Err(invalid("confirmed original assignment changed"));
    }
    current_original(tx, &confirmation.reference).await
}

async fn pin_confirmation(
    tx: &mut impl EvidenceTx,
    agent: &AgentId,
    expected: &TaskRevisionRef,
) -> Result<()> {
    let state = tx
        .agent(&expected.workspace_id, agent)
        .await?
        .ok_or_else(|| invalid("confirmed agent is unavailable"))?;
    validate_agent(&state)?;
    if state.task_note_id.as_deref() != Some(expected.note_id.as_str()) {
        return Err(invalid(
            "confirmed source differs from new agent assignment",
        ));
    }
    current_original(tx, expected).await?;
    immutable(
        tx,
        "confirmed-plan",
        agent.as_str(),
        &Confirmation {
            reference: expected.clone(),
            assignment_revision: state.assignment_revision,
        },
    )
    .await?;
    Ok(())
}

async fn binding(tx: &mut impl EvidenceTx, id: &OperationId) -> Result<Option<WorkBinding>> {
    let Some(mut binding) = retained::<WorkBinding>(tx, "binding", id.as_str()).await? else {
        return Ok(None);
    };
    let active: Option<OperationId> =
        retained::<Option<OperationId>>(tx, "active-binding", binding.admission.agent_id.as_str())
            .await?
            .flatten();
    binding.active = active.as_ref() == Some(id);
    Ok(Some(binding))
}

async fn root_binding(
    tx: &mut impl EvidenceTx,
    workspace: &WorkspaceId,
    root: &str,
) -> Result<Option<RootBinding>> {
    let retained: Option<RootBinding> =
        retained(tx, "root-binding", &key(&(workspace, root))?).await?;
    if let Some(binding) = &retained {
        if tx.root_epoch(workspace, root).await? != Some(binding.epoch) {
            return Err(invalid(
                "root incarnation changed; explicit rebind required",
            ));
        }
    }
    Ok(retained)
}

async fn ensure_root(
    tx: &mut impl EvidenceTx,
    workspace: &WorkspaceId,
    root: &str,
    alias: Option<&str>,
    locator: &Path,
    kind: VcsKind,
    format: u32,
) -> Result<RootBinding> {
    if root.is_empty()
        || root.len() > 256
        || !locator.is_absolute()
        || alias.is_some_and(|a| a.is_empty() || a.len() > 1024)
        || format == 0
    {
        return Err(invalid(
            "bounded root identity, absolute locator and engine format required",
        ));
    }
    if kind != VcsKind::Git {
        return Err(Error::Unsupported(
            "T1 root persistence admits Git only".into(),
        ));
    }
    let locator = locator
        .to_str()
        .ok_or_else(|| invalid("root locator must be UTF-8"))?;
    if tx.locator(workspace, root).await?.as_deref() != Some(locator) {
        return Err(invalid(
            "root locator differs from the owned workspace root",
        ));
    }
    if let Some(prior) = root_binding(tx, workspace, root).await? {
        if prior.kind != kind || prior.locator != Path::new(locator) {
            return Err(invalid("root binding changed; explicit rebind required"));
        }
        let repository: Repository = retained(tx, "repository", prior.repository_id.as_str())
            .await?
            .ok_or_else(|| invalid("root repository metadata missing"))?;
        let expected_alias: Option<Repository> = if let Some(alias) = alias {
            retained(tx, "repository-alias", alias).await?
        } else {
            None
        };
        if repository.format != format
            || repository.alias.as_deref() != alias
            || expected_alias
                .as_ref()
                .is_some_and(|r| r.id != prior.repository_id)
        {
            return Err(invalid("root engine format or repository alias changed"));
        }
        return Ok(prior);
    }
    let existing: Option<Repository> = if let Some(alias) = alias {
        retained(tx, "repository-alias", alias).await?
    } else {
        None
    };
    let repository = existing.unwrap_or_else(|| Repository {
        id: RepositoryId::from_string(uuid::Uuid::new_v4().to_string()),
        kind,
        format,
        alias: alias.map(str::to_owned),
    });
    if repository.kind != kind || repository.format != format {
        return Err(invalid("repository engine or format differs"));
    }
    immutable(tx, "repository", repository.id.as_str(), &repository).await?;
    if let Some(alias) = alias {
        immutable(tx, "repository-alias", alias, &repository).await?;
    }
    let epoch = tx
        .root_epoch(workspace, root)
        .await?
        .ok_or_else(|| invalid("owned root incarnation missing"))?;
    let result = RootBinding {
        workspace_id: workspace.clone(),
        root_id: root.into(),
        repository_id: repository.id,
        kind,
        locator: locator.into(),
        epoch,
    };
    immutable(tx, "root-binding", &key(&(workspace, root))?, &result).await?;
    Ok(result)
}

async fn admit(
    tx: &mut impl EvidenceTx,
    fence: &WorkTurnFence,
    attempt: &str,
    root: Option<&RootBinding>,
    baseline: Option<&NativeStateRef>,
    timestamp: &str,
) -> Result<Option<WorkBinding>> {
    if attempt.is_empty() || attempt.len() > 256 || timestamp.is_empty() {
        return Err(invalid("bounded turn attempt and timestamp required"));
    }
    if root.is_some_and(|r| r.kind != VcsKind::Git)
        || baseline.is_some_and(|s| s.kind() != VcsKind::Git)
    {
        return Err(Error::Unsupported(
            "T1 admission supports ordinary Git execution only".into(),
        ));
    }
    if fence.source_work && (root.is_none() || baseline.is_none()) {
        return Err(invalid(
            "declared source work requires an observed Git root and baseline",
        ));
    }
    if baseline.is_some() && root.is_none() {
        return Err(invalid(
            "an observed baseline requires its exact root identity",
        ));
    }
    if let (Some(root), Some(baseline)) = (root, baseline) {
        if root.repository_id != *baseline.repository_id() {
            return Err(invalid("baseline repository differs from root"));
        }
    }
    let command_digest = digest(
        encode(&(
            &fence.workspace_id,
            &fence.agent_id,
            attempt,
            root,
            baseline,
        ))?
        .as_bytes(),
    );
    if tx.object("cancelled-turn", attempt).await?.is_some() {
        return Err(invalid("turn attempt was cancelled"));
    }
    if let Some(prior) = retained::<Admission>(tx, "admission", attempt).await? {
        if prior.command_digest != command_digest
            || prior.workspace != fence.workspace_id
            || prior.agent != fence.agent_id
        {
            return Err(invalid("conflicting turn admission replay"));
        }
        return match prior.binding {
            Some(id) => binding(tx, &id).await,
            None => Ok(None),
        };
    }
    let state = tx
        .agent(&fence.workspace_id, &fence.agent_id)
        .await?
        .ok_or_else(|| invalid("turn agent unavailable"))?;
    validate_agent(&state)?;
    if state.revision != fence.revision {
        return Err(invalid("status or assignment changed after observed fence"));
    }
    if let Some(root) = root {
        if root.workspace_id != fence.workspace_id
            || root_binding(tx, &fence.workspace_id, &root.root_id)
                .await?
                .as_ref()
                != Some(root)
            || tx
                .locator(&fence.workspace_id, &root.root_id)
                .await?
                .as_deref()
                .map(Path::new)
                != Some(root.locator.as_path())
        {
            return Err(invalid("original source root changed"));
        }
    }
    let confirmed: Option<Confirmation> =
        retained(tx, "confirmed-plan", fence.agent_id.as_str()).await?;
    let claimed = tx
        .object("confirmed-claim", fence.agent_id.as_str())
        .await?
        .is_some();
    let result = if let Some(note_id) = state.task_note_id {
        let note_id = NoteId::from(note_id);
        let revision = if let Some(confirmed) = confirmed.filter(|_| !claimed) {
            if confirmed.reference.note_id != note_id {
                return Err(invalid("confirmed first admission cannot retarget source"));
            }
            require_confirmation(tx, &fence.agent_id, &confirmed).await?
        } else {
            capture_revision(tx, &fence.workspace_id, &note_id, None).await?
        };
        let task: TaskMetadata = decode(&revision.task_json)?;
        if task.work_definition.as_ref().is_some_and(|d| {
            d.purpose == intent_core::work_evidence::planning::TaskWorkPurpose::Source
        }) && (root.is_none() || baseline.is_none())
        {
            return Err(invalid(
                "current source task requires actual Git root and baseline",
            ));
        }
        let admission = WorkBindingAdmission {
            binding_id: OperationId::from_string(attempt),
            workspace_id: fence.workspace_id.clone(),
            note_id,
            expected_task_rev: revision.reference.rev,
            root: root.cloned(),
            baseline: baseline.cloned(),
            agent_id: fence.agent_id.clone(),
            session_id: fence.agent_id.as_str().into(),
            turn_attempt: attempt.into(),
            native_intent: None,
            delegation_parent: None,
            delegation_group: None,
        };
        let result = WorkBinding {
            command_digest: digest(encode(&admission)?.as_bytes()),
            admission,
            task_revision: revision.reference,
            native_state: NativeBindingState::NotRequired,
            declaration_receipt: None,
            active: true,
            created_at: timestamp.into(),
        };
        immutable(tx, "binding", attempt, &result).await?;
        if !claimed
            && tx
                .object("confirmed-plan", fence.agent_id.as_str())
                .await?
                .is_some()
        {
            immutable(
                tx,
                "confirmed-claim",
                fence.agent_id.as_str(),
                &result.admission.binding_id,
            )
            .await?;
        }
        Some(result)
    } else {
        if confirmed.is_some() && !claimed {
            return Err(invalid("confirmed first admission lost its assigned task"));
        }
        None
    };
    immutable(
        tx,
        "admission",
        attempt,
        &Admission {
            workspace: fence.workspace_id.clone(),
            agent: fence.agent_id.clone(),
            command_digest,
            binding: result.as_ref().map(|b| b.admission.binding_id.clone()),
        },
    )
    .await?;
    tx.active(
        &fence.agent_id,
        result.as_ref().map(|b| &b.admission.binding_id),
    )
    .await?;
    tx.activate(&fence.workspace_id, &fence.agent_id, timestamp)
        .await?;
    Ok(result)
}

macro_rules! with_tx {
    ($store:expr, $write:expr, $tx:ident => $body:expr) => {{
        match &$store.backend {
            crate::Backend::Sqlite(backend) => {
                let mut $tx = sqlite::SqliteEvidenceTx::begin(backend, $write).await?;
                let result = async { $body }.await;
                $tx.finish(result).await
            }
            #[cfg(feature = "postgres")]
            crate::Backend::Postgres(backend) => {
                let mut $tx =
                    crate::postgres::tracer_evidence::PgEvidenceTx::begin(backend, $write).await?;
                let result = async { $body }.await;
                $tx.finish(result).await
            }
        }
    }};
}

impl Store {
    /// Resolve a stable owned Git root. This is persistence, not authority.
    /// # Errors
    /// Refuses a changed locator, incompatible engine, missing root or storage failure.
    pub async fn ensure_vcs_root_binding(
        &self,
        workspace: &WorkspaceId,
        root: &str,
        alias: Option<&str>,
        locator: &Path,
        kind: VcsKind,
        format: u32,
    ) -> Result<RootBinding> {
        // Warm observations avoid a writer reservation.
        let present = self.vcs_root_binding(workspace, root).await?.is_some();
        with_tx!(self, !present, tx => ensure_root(&mut tx, workspace, root, alias, locator, kind, format).await)
    }
    /// Read retained identity without filesystem discovery.
    /// # Errors
    /// Returns storage or retained-data failures.
    pub async fn vcs_root_binding(
        &self,
        workspace: &WorkspaceId,
        root: &str,
    ) -> Result<Option<RootBinding>> {
        with_tx!(self, false, tx => root_binding(&mut tx, workspace, root).await)
    }
    /// Retain exact current task source.
    /// # Errors
    /// Refuses a stale revision, invalid task source or storage failure.
    pub async fn capture_task_revision(
        &self,
        workspace: &WorkspaceId,
        note: &NoteId,
        expected: Option<i64>,
    ) -> Result<TaskRevision> {
        with_tx!(self, true, tx => capture_revision(&mut tx, workspace, note, expected).await)
    }
    /// Read only the requested historical task revision.
    /// # Errors
    /// Returns corrupt retained-data or storage errors.
    pub async fn task_revision(&self, reference: &TaskRevisionRef) -> Result<Option<TaskRevision>> {
        with_tx!(self, false, tx => Ok(original(&mut tx, reference).await?.map(|r| r.source)))
    }
    /// Atomically persist reviewed task metadata and its exact retained source.
    /// # Errors
    /// Refuses a foreign note lock, stale CAS or invalid requirements.
    pub async fn persist_task_work_definition(
        &self,
        lock: &NoteWriteLock,
        note: &Note,
        expected: i64,
    ) -> Result<TaskRevision> {
        if let Some(task) = &note.metadata.task {
            crate::task_work_definition::validate(task)?;
        }
        match &self.backend {
            crate::Backend::Sqlite(backend) => {
                backend.prepare_task_events(&note.workspace_id).await;
            }
            #[cfg(feature = "postgres")]
            crate::Backend::Postgres(backend) => {
                backend.prepare_task_events(&note.workspace_id).await;
            }
        }
        with_tx!(self, true, tx => {
            let revision = tx.write_note(lock, note, expected).await?;
            capture_revision(&mut tx, &note.workspace_id, &note.id, Some(revision)).await
        })
    }
    /// Insert a new allocation and its original confirmation in one transaction.
    /// # Errors
    /// Refuses stale source/assignment and rolls back the entire allocation.
    pub async fn insert_agent_session_for_confirmed_plan(
        &self,
        session: &AgentSession,
        graph: bool,
        remember: bool,
        expected: &TaskRevisionRef,
    ) -> Result<()> {
        let mut lifecycle = match &self.backend {
            crate::Backend::Sqlite(backend) => backend.repository_lifecycle_write().await?,
            #[cfg(feature = "postgres")]
            crate::Backend::Postgres(backend) => backend.repository_lifecycle_write().await?,
        };
        lifecycle.begin(&[crate::RepositoryLifecycleKey::Agent(session.id.clone())])?;
        with_tx!(self, true, tx => {
            if session.workspace_id != expected.workspace_id || session.task_note_id.as_ref() != Some(&expected.note_id) {
                return Err(invalid("confirmed source must match new allocation"));
            }
            current_original(&mut tx, expected).await?;
            tx.insert_agent(session, graph, remember).await?;
            pin_confirmation(&mut tx, &session.id, expected).await
        })?;
        lifecycle.settle_after_retirement().await?;
        Ok(())
    }
    /// Read the original confirmation without looking up the current task.
    /// # Errors
    /// Returns retained-data or storage errors.
    pub async fn agent_confirmed_task_revision(
        &self,
        agent: &AgentId,
    ) -> Result<Option<TaskRevisionRef>> {
        with_tx!(self, false, tx => Ok(retained::<Confirmation>(&mut tx, "confirmed-plan", agent.as_str()).await?.map(|c| c.reference)))
    }
    /// Verify the same original confirmation still governs this allocation.
    /// # Errors
    /// Refuses changed requirements, assignment ABA, terminal source or missing evidence.
    pub async fn require_agent_confirmed_task_current(
        &self,
        agent: &AgentId,
        expected: &TaskRevisionRef,
    ) -> Result<()> {
        with_tx!(self, false, tx => {
            let pin: Confirmation = retained(&mut tx, "confirmed-plan", agent.as_str()).await?.ok_or_else(|| invalid("confirmed allocation missing"))?;
            if pin.reference != *expected { return Err(invalid("allocation names another confirmed source")); }
            require_confirmation(&mut tx, agent, &pin).await?;
            Ok(())
        })
    }
    /// Observe a durable status/assignment fence before async source observation.
    /// # Errors
    /// Refuses missing/foreign agents or storage failure.
    pub async fn read_work_turn_fence(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
    ) -> Result<WorkTurnFence> {
        with_tx!(self, false, tx => {
            let state = tx.agent(workspace, agent).await?.ok_or_else(|| invalid("turn agent missing"))?;
            validate_agent(&state)?;
            let source_work = if let Some(note) = state.task_note_id {
                tx.note(workspace, &NoteId::from(note)).await?.and_then(|n| n.task_json)
                    .map(|raw| decode::<TaskMetadata>(&raw)).transpose()?
                    .and_then(|t| t.work_definition)
                    .is_some_and(|d| d.purpose == intent_core::work_evidence::planning::TaskWorkPurpose::Source)
            } else { false };
            Ok(WorkTurnFence { workspace_id: workspace.clone(), agent_id: agent.clone(), revision: state.revision, source_work })
        })
    }
    /// Admit original task governance and Active state in the same transaction.
    /// # Errors
    /// Refuses stale fences/source/root, cancellation and conflicting replay.
    pub async fn admit_work_turn(
        &self,
        fence: &WorkTurnFence,
        attempt: &str,
        root: Option<&RootBinding>,
        baseline: Option<&NativeStateRef>,
        timestamp: &str,
    ) -> Result<Option<WorkBinding>> {
        with_tx!(self, true, tx => admit(&mut tx, fence, attempt, root, baseline, timestamp).await)
    }
    /// Read one exact admitted attempt; missing admissions refuse.
    /// # Errors
    /// Refuses missing/foreign attempts or retained-data failures.
    pub async fn work_turn_binding(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        attempt: &str,
    ) -> Result<Option<WorkBinding>> {
        with_tx!(self, false, tx => {
            let admission: Admission = retained(&mut tx, "admission", attempt).await?.ok_or_else(|| invalid("exact turn admission missing"))?;
            if admission.workspace != *workspace || admission.agent != *agent { return Err(invalid("turn admission belongs to another owner")); }
            match admission.binding { Some(id) => binding(&mut tx, &id).await, None => Ok(None) }
        })
    }
    /// Read an immutable binding with separately observed current activity.
    /// # Errors
    /// Returns storage or retained-data failures.
    pub async fn work_binding(&self, id: &OperationId) -> Result<Option<WorkBinding>> {
        with_tx!(self, false, tx => binding(&mut tx, id).await)
    }
    /// Read the original first confirmed admission without retargeting history.
    /// # Errors
    /// Refuses corrupt/foreign retained claims or storage failures.
    pub async fn first_work_binding_for_agent(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
    ) -> Result<Option<WorkBinding>> {
        with_tx!(self, false, tx => {
            let claim: Option<OperationId> = retained(&mut tx, "confirmed-claim", agent.as_str()).await?;
            let Some(claim) = claim else { return Ok(None) };
            let retained = binding(&mut tx, &claim).await?.ok_or_else(|| invalid("first claim lost original binding"))?;
            if retained.admission.workspace_id != *workspace || retained.admission.agent_id != *agent {
                return Err(invalid("first claim belongs to another owner"));
            }
            Ok(Some(retained))
        })
    }
    /// Count at most `limit` actual retained admissions for the original agent.
    /// # Errors
    /// Refuses invalid bounds and storage failure; the result never exceeds the bound.
    pub async fn work_admission_count_up_to(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        limit: u32,
    ) -> Result<u64> {
        if !(1..=50).contains(&limit) {
            return Err(invalid("admission count limit must be between 1 and 50"));
        }
        with_tx!(self, false, tx => u64::try_from(tx.admission_count(workspace, agent, limit).await?).map_err(database))
    }
    /// Bounded indexed contribution observations for one exact original binding.
    /// # Errors
    /// Refuses invalid limits, missing/foreign bindings or an oversized receipt page.
    pub async fn work_contributions_for_binding(
        &self,
        workspace: &WorkspaceId,
        owner: &OperationId,
        limit: u32,
    ) -> Result<Vec<WorkContributionReceipt>> {
        if !(1..=50).contains(&limit) {
            return Err(invalid("contribution limit must be between 1 and 50"));
        }
        with_tx!(self, false, tx => {
            let retained = binding(&mut tx, owner).await?.ok_or_else(|| invalid("contribution binding missing"))?;
            if retained.admission.workspace_id != *workspace { return Err(invalid("contribution binding belongs to another workspace")); }
            let rows = tx.contributions(workspace, owner, limit).await?;
            if rows.iter().map(String::len).sum::<usize>() > 256 * 1024 {
                return Err(Error::Unsupported("contribution page exceeds the explicit byte budget".into()));
            }
            rows.iter().map(|raw| decode(raw)).collect()
        })
    }
    /// Cancel an exact attempt, including one cancelled before admission.
    /// # Errors
    /// Refuses conflicting cancellation ownership and storage failures.
    pub async fn retire_work_turn(
        &self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        attempt: &str,
    ) -> Result<bool> {
        if attempt.is_empty() || attempt.len() > 256 {
            return Err(invalid("bounded exact turn attempt required"));
        }
        with_tx!(self, true, tx => {
            if let Some(admission) = retained::<Admission>(&mut tx, "admission", attempt).await? {
                if admission.workspace != *workspace || admission.agent != *agent {
                    return Err(invalid("turn cancellation belongs to another owner"));
                }
            }
            immutable(&mut tx, "cancelled-turn", attempt, &(workspace, agent)).await?;
            let active: Option<OperationId> = retained::<Option<OperationId>>(&mut tx, "active-binding", agent.as_str()).await?.flatten();
            let matched = active.as_ref().is_some_and(|id| id.as_str() == attempt);
            if matched { tx.active(agent, None).await?; }
            Ok(matched)
        })
    }
    /// Retain verified blob metadata in an immutable owner slot.
    /// # Errors
    /// Refuses malformed references or conflicting length/slot replay.
    pub async fn retain_evidence_blob(
        &self,
        object: &EvidenceBlob,
        owner_kind: &str,
        owner_id: &str,
        slot: &str,
    ) -> Result<()> {
        if i64::try_from(object.length).is_err()
            || object.digest.as_str().len() != 64
            || !object
                .digest
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || owner_kind.is_empty()
            || owner_id.is_empty()
            || slot.is_empty()
            || owner_kind.len() > 256
            || owner_id.len() > 1024
            || slot.len() > 256
        {
            return Err(invalid(
                "bounded immutable evidence owner and SHA-256 required",
            ));
        }
        with_tx!(self, true, tx => {
            immutable(&mut tx, "blob-inventory", object.digest.as_str(), object).await?;
            immutable(&mut tx, "blob-reference", &key(&(owner_kind, owner_id, slot))?, object).await?;
            Ok(())
        })
    }
    /// Look up an immutable owner slot; consumers must verify the blob bytes.
    /// # Errors
    /// Returns storage or retained-data failures.
    pub async fn retained_evidence_blob(
        &self,
        owner_kind: &str,
        owner_id: &str,
        slot: &str,
    ) -> Result<Option<EvidenceBlob>> {
        with_tx!(self, false, tx => retained(&mut tx, "blob-reference", &key(&(owner_kind, owner_id, slot))?).await)
    }
    /// Retain an actual Git primitive observation under its original governance.
    /// # Errors
    /// Refuses missing/foreign bindings, source mismatch or conflicting replay.
    pub async fn retain_work_contribution(
        &self,
        operation: &OperationId,
        original_binding: &WorkBinding,
        root: &RootBinding,
        recording: &RecordedChange,
    ) -> Result<WorkContributionReceipt> {
        if operation.as_str().is_empty()
            || operation.as_str().len() > 256
            || root.kind != VcsKind::Git
            || original_binding.admission.root.as_ref() != Some(root)
            || original_binding.task_revision.workspace_id != root.workspace_id
            || !matches!(&recording.change, NativeChangeRef::Git { repository_id, .. } if repository_id == &root.repository_id)
        {
            return Err(invalid(
                "recorded Git contribution differs from original root and binding",
            ));
        }
        with_tx!(self, true, tx => {
            let original = binding(&mut tx, &original_binding.admission.binding_id).await?.ok_or_else(|| invalid("original recording admission missing"))?;
            if original.command_digest != original_binding.command_digest || original.admission != original_binding.admission || original.task_revision != original_binding.task_revision {
                return Err(invalid("recording supplied another original binding"));
            }
            let scope = ExplanationRoot { repository_id: root.repository_id.clone(), root_id: root.root_id.clone(), root_epoch: root.epoch };
            let receipt_digest = digest(encode(&(operation, &original.admission.binding_id, &original.task_revision, &scope, recording))?.as_bytes());
            if let Some(prior) = retained::<WorkContributionReceipt>(&mut tx, "contribution", operation.as_str()).await? {
                if prior.receipt_digest != receipt_digest { return Err(invalid("conflicting recording contribution replay")); }
                return Ok(prior);
            }
            let result = WorkContributionReceipt { provenance: WorkContributionProvenance::RecordingGovernanceOnlySharedWorkingCopy,
                operation_id: operation.clone(), binding_id: original.admission.binding_id, task_revision: original.task_revision,
                root: scope, recording: recording.clone(), receipt_digest, recorded_at: now_iso() };
            immutable(&mut tx, "contribution", operation.as_str(), &result).await?;
            Ok(result)
        })
    }
    /// Read the exact scoped Git contribution receipt.
    /// # Errors
    /// Returns storage or retained-data failures.
    pub async fn work_contribution_receipt(
        &self,
        workspace: &WorkspaceId,
        operation: &OperationId,
    ) -> Result<Option<WorkContributionReceipt>> {
        with_tx!(self, false, tx => Ok(retained::<WorkContributionReceipt>(&mut tx, "contribution", operation.as_str()).await?
            .filter(|r| r.task_revision.workspace_id == *workspace)))
    }
    /// Check exact retained delivery identity; this is not a delivery guarantee.
    /// # Errors
    /// Returns storage or retained-data failures.
    pub async fn has_evidence_event(&self, event_id: &str) -> Result<bool> {
        with_tx!(self, false, tx => Ok(tx.object("event", event_id).await?.is_some()))
    }
    /// Retain immutable local event payload with a real durable sequence.
    /// # Errors
    /// Refuses conflicting replay, invalid JSON or missing event identity.
    pub async fn enqueue_evidence_event(
        &self,
        event: &NewEvidenceOutboxEvent,
    ) -> Result<EvidenceOutboxEvent> {
        if event.event_id.is_empty()
            || event.event_id.len() > 512
            || event.event_kind.is_empty()
            || event.schema_version == 0
            || event.source_revision.is_empty()
        {
            return Err(invalid("bounded exact event identity and schema required"));
        }
        let _: serde_json::Value = decode(&event.payload_json)?;
        with_tx!(self, true, tx => {
            let created = now_iso();
            let (sequence, created_at) = if let Some((sequence, raw)) = tx.object("event", &event.event_id).await? {
                let (prior, created_at): (NewEvidenceOutboxEvent, String) = decode(&raw)?;
                if prior != *event { return Err(invalid("conflicting event replay")); }
                (sequence, created_at)
            } else { (immutable(&mut tx, "event", &event.event_id, &(event, &created)).await?, created) };
            Ok(EvidenceOutboxEvent { sequence: u64::try_from(sequence).map_err(database)?, event_id: event.event_id.clone(), event_kind: event.event_kind.clone(),
                schema_version: event.schema_version, source_revision: event.source_revision.clone(), object_digest: digest(event.payload_json.as_bytes()),
                payload_json: event.payload_json.clone(), created_at })
        })
    }
}
