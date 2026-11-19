//! Private original-turn handoff for recording governance. This proves which
//! original attempt requested the automatic record, never exhaustive authorship
//! of bytes in a shared working copy. No wire label can construct this carrier.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};

use intent_core::vcs::{ContentDigest, OperationId, RecordedChange, RootBinding, VcsKind};
use intent_core::work_evidence::WorkBinding;
use intent_core::{AgentId, Error, Event, Result, WorkspaceId};
use intent_store::{NewEvent, Store};
use sha2::{Digest, Sha256};

use crate::Services;

const MAX_HANDOFFS: usize = 1_024;
const MAX_EVENT_BYTES: usize = 262_144;

pub(crate) struct OriginalRecordSource {
    pub(crate) binding: WorkBinding,
    pub(crate) task_title: String,
}
impl OriginalRecordSource {
    pub(crate) async fn capture(
        store: &Store,
        workspace: &WorkspaceId,
        agent: &AgentId,
        attempt: &str,
    ) -> Result<Option<Arc<Self>>> {
        let Some(binding) = store.work_turn_binding(workspace, agent, attempt).await? else {
            return Ok(None);
        };
        if !binding.active
            || binding.admission.agent_id != *agent
            || binding.admission.turn_attempt != attempt
            || binding.admission.workspace_id != *workspace
        {
            return Err(Error::InvalidParams(
                "original recording carrier differs from admitted attempt".into(),
            ));
        }
        if !binding
            .admission
            .root
            .as_ref()
            .is_some_and(|root| root.kind == VcsKind::Git)
        {
            return Ok(None);
        }
        let revision = store
            .task_revision(&binding.task_revision)
            .await?
            .ok_or_else(|| {
                Error::InvalidParams("original recording task source is unavailable".into())
            })?;
        Ok(Some(Arc::new(Self {
            binding,
            task_title: revision.title,
        })))
    }
}

pub(crate) struct ObservedRecord {
    pub(crate) root: RootBinding,
    pub(crate) record: RecordedChange,
}

pub(crate) struct IdleRecord {
    pub(crate) source: Arc<OriginalRecordSource>,
    pub(crate) operation: OperationId,
    observed: OnceLock<ObservedRecord>,
    post_effect_error: OnceLock<String>,
    gate: tokio::sync::Mutex<()>,
    finished: AtomicBool,
    claimed: AtomicBool,
    ambiguous: AtomicBool,
}
impl IdleRecord {
    pub(crate) fn validate_request(
        &self,
        root: &RootBinding,
        agent: Option<&AgentId>,
        note: Option<&intent_core::NoteId>,
        user_requested: bool,
        explicit_files: bool,
    ) -> Result<()> {
        if self.ambiguous.load(Ordering::Acquire)
            || self.source.binding.admission.root.as_ref() != Some(root)
            || agent != Some(&self.source.binding.admission.agent_id)
            || note != Some(&self.source.binding.admission.note_id)
            || user_requested
            || explicit_files
        {
            return Err(Error::InvalidParams(
                "original automatic recording scope changed; no new commit admitted".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn note_post_effect_error(&self, error: &str) {
        if self.observed.get().is_some() {
            let _ = self
                .post_effect_error
                .set(error.chars().take(4_096).collect());
        }
    }

    /// Runs synchronously immediately after the actual engine primitive. Its
    /// owned result survives a later status/invalidation/ledger failure.
    pub(crate) fn observe(&self, root: RootBinding, record: RecordedChange) {
        if self.observed.set(ObservedRecord { root, record }).is_err() {
            tracing::error!(operation=%self.operation.as_str(), "automatic record primitive observed twice; refusing a new attribution");
        }
    }
}

tokio::task_local! { static RECORDING: Arc<IdleRecord>; }
pub(crate) fn current() -> Option<Arc<IdleRecord>> {
    RECORDING.try_with(Arc::clone).ok()
}

#[derive(Default, Clone)]
pub(crate) struct OriginalRecordHandoffs(Arc<Mutex<BTreeMap<ContentDigest, Arc<IdleRecord>>>>);

type EventEnvelope<'a> = (
    &'a WorkspaceId,
    &'a str,
    &'a str,
    &'a intent_core::EventActor,
    &'a Option<String>,
    &'a Option<String>,
    &'a Option<String>,
    &'a Option<serde_json::Value>,
    &'a serde_json::Value,
);
fn key(parts: EventEnvelope<'_>) -> Option<ContentDigest> {
    let bytes = serde_json::to_vec(&parts).ok()?;
    if bytes.len() > MAX_EVENT_BYTES {
        return None;
    }
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Some(ContentDigest(hex))
}
fn event_key(event: &Event) -> Option<ContentDigest> {
    key((
        &event.workspace_id,
        &event.timestamp,
        &event.event_type,
        &event.actor,
        &event.session_id,
        &event.correlation_id,
        &event.parent_event_id,
        &event.metadata,
        &event.data,
    ))
}
fn claim_id(operation: &OperationId) -> String {
    format!("auto-record-claim:{}", operation.as_str())
}
fn operation(key: &ContentDigest) -> OperationId {
    OperationId::from_string(format!("git-auto-commit:{}", key.as_str()))
}

impl OriginalRecordHandoffs {
    /// Register the exact local event before append/broadcast. Matching is the
    /// immutable event envelope, never recency or current task/session state.
    pub(crate) fn register(
        &self,
        event: &NewEvent,
        source: Arc<OriginalRecordSource>,
    ) -> Result<()> {
        if event.workspace_id != source.binding.admission.workspace_id
            || event
                .data
                .get("agentId")
                .and_then(serde_json::Value::as_str)
                != Some(source.binding.admission.agent_id.as_str())
            || !super::is_normal_finish_reason(
                event
                    .data
                    .get("finishReason")
                    .and_then(serde_json::Value::as_str),
            )
        {
            return Err(Error::InvalidParams(
                "original automatic record event differs from its private carrier".into(),
            ));
        }
        let key = key((
            &event.workspace_id,
            &event.timestamp,
            &event.event_type,
            &event.actor,
            &event.session_id,
            &event.correlation_id,
            &event.parent_event_id,
            &event.metadata,
            &event.data,
        ))
        .ok_or_else(|| Error::InvalidParams("automatic record event exceeds its bound".into()))?;
        let mut entries = self
            .0
            .lock()
            .map_err(|_| Error::Internal("automatic recording handoff registry poisoned".into()))?;
        if let Some(prior) = entries.get(&key) {
            if prior.source.binding.command_digest != source.binding.command_digest
                || prior.source.binding.admission != source.binding.admission
                || prior.source.binding.task_revision != source.binding.task_revision
            {
                prior.ambiguous.store(true, Ordering::Release);
                return Err(Error::InvalidParams(
                    "conflicting original automatic record event".into(),
                ));
            }
            return Ok(());
        }
        entries.retain(|_, entry| {
            entry.ambiguous.load(Ordering::Acquire) || !entry.finished.load(Ordering::Acquire)
        });
        if entries.len() >= MAX_HANDOFFS {
            return Err(Error::Unsupported(
                "original automatic record handoff budget exhausted; governance remains unknown"
                    .into(),
            ));
        }
        entries.insert(
            key.clone(),
            Arc::new(IdleRecord {
                source,
                operation: operation(&key),
                observed: OnceLock::new(),
                post_effect_error: OnceLock::new(),
                gate: tokio::sync::Mutex::new(()),
                finished: AtomicBool::new(false),
                claimed: AtomicBool::new(false),
                ambiguous: AtomicBool::new(false),
            }),
        );
        Ok(())
    }
    fn get(&self, event: &Event) -> Option<Arc<IdleRecord>> {
        self.0.lock().ok()?.get(&event_key(event)?).cloned()
    }
}

impl Services {
    async fn retain_original_record_delivery_guard(&self, event: &Event) -> Result<()> {
        self.store
            .enqueue_evidence_event(&intent_core::work_evidence::NewEvidenceOutboxEvent {
                event_id: format!("auto-record-delivery:{}", event.id),
                event_kind: "work.autoRecordDeliveryGuard".into(),
                schema_version: 1,
                source_revision: event.id.clone(),
                payload_json: "{\"meaning\":\"suppress-physical-replay-only\"}".into(),
            })
            .await
            .map(|_| ())
    }

    pub(crate) fn capture_original_idle_record(&self, event: &NewEvent) {
        if event.event_type != intent_core::events::AGENT_IDLE {
            return;
        }
        if let Some(source) = crate::agent_manager::work_admission::capture_recording_source() {
            if let Err(error) = self.original_record_handoffs.register(event, source) {
                tracing::warn!(%error, "original automatic recording governance is unavailable");
            }
        }
    }

    pub(crate) async fn handle_idle_record_with_original(&self, event: &Event) {
        if self.original_record_handoffs.get(event).is_none() {
            self.handle_idle_record_with_original_inner(event).await;
            return;
        }
        // A Git primitive already has a shutdown owner, but its original task
        // receipt must survive cancellation of the subscriber/caller as well.
        // Retain this finite original settlement through the same drain while
        // preserving the caller and wire credential rather than elevating them.
        let services = self.clone();
        let event = event.clone();
        let Some(owner) = self
            .store_tasks
            .spawn_draining_with_current_caller(async move {
                services
                    .handle_idle_record_with_original_inner(&event)
                    .await;
            })
        else {
            tracing::warn!("original recording settlement is shutting down; no physical dispatch");
            return;
        };
        if let Err(error) = owner.await {
            tracing::error!(%error, "original recording settlement owner failed; source outcome requires reconciliation");
        }
    }

    async fn handle_idle_record_with_original_inner(&self, event: &Event) {
        // A completed immutable source receipt also guards a repeated event
        // after its in-memory completed handoff was evicted. This is a skip
        // check only; identifiers never mint recording authority.
        let entry = self.original_record_handoffs.get(event);
        let delivery_claimed = match self
            .store
            .has_evidence_event(&format!("auto-record-delivery:{}", event.id))
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                tracing::warn!(%error,"automatic record delivery replay state unavailable; no physical retry");
                return;
            }
        };
        if entry.is_some() && !delivery_claimed {
            if let Err(error) = self.retain_original_record_delivery_guard(event).await {
                tracing::error!(%error,"original delivery replay guard could not persist; no physical dispatch");
                return;
            }
        } else if entry.is_none() && delivery_claimed {
            tracing::warn!(
                "original delivery has no live physical owner; no fallback or physical retry"
            );
            return;
        }
        if let Some(key) = event_key(event) {
            match self
                .store
                .work_contribution_receipt(&event.workspace_id, &operation(&key))
                .await
            {
                Ok(Some(_))
                    if entry
                        .as_ref()
                        .is_none_or(|entry| entry.finished.load(Ordering::Acquire)) =>
                {
                    return;
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error,"automatic record replay state unavailable; refusing physical retry");
                    return;
                }
            }
        }
        let retained_claim = match event_key(event) {
            Some(key) => {
                self.store
                    .has_evidence_event(&claim_id(&operation(&key)))
                    .await
            }
            None => Ok(false),
        };
        let claimed = match retained_claim {
            Ok(claimed) => claimed || delivery_claimed,
            Err(error) => {
                tracing::warn!(%error, "automatic record original claim unavailable; refusing physical retry");
                return;
            }
        };
        let Some(entry) = entry else {
            if claimed {
                tracing::warn!("original auto-record claim has no live physical owner; source outcome stays uncertain, never replay Git");
                return;
            }
            self.handle_agent_idle_auto_commit_unbound(event).await;
            return;
        };
        let _guard = entry.gate.lock().await;
        if entry.ambiguous.load(Ordering::Acquire) {
            let tombstone = intent_core::work_evidence::NewEvidenceOutboxEvent {
                event_id: claim_id(&entry.operation),
                event_kind: "work.autoRecordAmbiguous".into(),
                schema_version: 1,
                source_revision: entry.operation.as_str().into(),
                payload_json: "{\"scope\":\"ambiguous-local-event-envelope\"}".into(),
            };
            if let Err(error) = self.store.enqueue_evidence_event(&tombstone).await {
                tracing::warn!(%error,"ambiguous original recording tombstone could not persist (an existing original claim still suppresses replay)");
            }
            tracing::warn!(operation=%entry.operation.as_str(),"same event envelope has different original turns; refusing association and physical retry");
            return;
        }
        if entry.finished.load(Ordering::Acquire) && entry.observed.get().is_none() {
            return;
        }
        if entry.observed.get().is_none() {
            if claimed || entry.claimed.load(Ordering::Acquire) {
                entry.finished.store(true, Ordering::Release);
                tracing::warn!(operation=%entry.operation.as_str(), "original auto-record claim has no captured primitive; outcome uncertain, refusing physical retry");
                return;
            }
            let binding = &entry.source.binding;
            let payload = match serde_json::to_string(&(
                &entry.operation,
                &binding.admission.binding_id,
                &binding.task_revision,
                &binding.admission.root,
                "recordingGovernanceOnlySharedWorkingCopy",
            )) {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(%error,"automatic record claim serialization failed; no physical dispatch");
                    return;
                }
            };
            let claim = intent_core::work_evidence::NewEvidenceOutboxEvent {
                event_id: claim_id(&entry.operation),
                event_kind: "work.autoRecordClaimed".into(),
                schema_version: 1,
                source_revision: entry.operation.as_str().into(),
                payload_json: payload,
            };
            if let Err(error) = self.store.enqueue_evidence_event(&claim).await {
                tracing::error!(%error,"automatic record original claim could not persist; no physical dispatch");
                return;
            }
            entry.claimed.store(true, Ordering::Release);
            RECORDING
                .scope(
                    Arc::clone(&entry),
                    self.handle_agent_idle_auto_commit_unbound(event),
                )
                .await;
        }
        let Some(observed) = entry.observed.get() else {
            // Skips/errors without a returned actual primitive never create a
            // contribution, and the same idle delivery is not a commit retry.
            entry.finished.store(true, Ordering::Release);
            return;
        };
        if entry.ambiguous.load(Ordering::Acquire) {
            tracing::error!(operation=%entry.operation.as_str(), "physical automatic record completed but its event envelope became ambiguous; no governing association retained");
            return;
        }
        match self
            .store
            .retain_work_contribution(
                &entry.operation,
                &entry.source.binding,
                &observed.root,
                &observed.record,
            )
            .await
        {
            Ok(_) => {
                if let Some(error) = entry.post_effect_error.get() {
                    let payload = serde_json::json!({ "operationId": entry.operation, "bindingId": entry.source.binding.admission.binding_id, "recorded": observed.record, "postEffectError": error }).to_string();
                    let warning = intent_core::work_evidence::NewEvidenceOutboxEvent {
                        event_id: format!("auto-record-post-effect:{}", entry.operation.as_str()),
                        event_kind: "work.autoRecordPostEffectFailure".into(),
                        schema_version: 1,
                        source_revision: entry.operation.as_str().into(),
                        payload_json: payload,
                    };
                    if let Err(error) = self.store.enqueue_evidence_event(&warning).await {
                        tracing::error!(%error,"commit retained but post-effect warning retention is uncertain");
                        return;
                    }
                }
                entry.finished.store(true, Ordering::Release);
            }
            Err(error) => {
                tracing::error!(operation=%entry.operation.as_str(), change=?observed.record.change,%error,"commit physically completed; original governance retention is uncertain; replay may retry ledger retention only");
            }
        }
    }
}
