//! Actual Git/evidence integration regressions for the T1 original-run carrier.

mod post_effect;

use std::future::Future;
use std::sync::Arc;

use intent_core::vcs::{VcsKind, WorkspaceEngine};
use intent_core::work_evidence::planning::{
    TaskFileReference, TaskFileRole, TaskWorkDefinition, TaskWorkPurpose,
};

use super::*;
use crate::auto_commit::recording::OriginalRecordSource;

async fn original_source(
    svc: &Services,
    workspace: &WorkspaceId,
    repo: &GitRepo,
    attempt: &str,
) -> Arc<OriginalRecordSource> {
    let agent = AgentId::from("original-recording-agent");
    if svc.store.get_agent_session_summary(&agent).await.is_err() {
        let mut note = task_note(
            workspace,
            "original-recording-task",
            "Original recording request",
        );
        note.metadata.task = Some(intent_core::TaskMetadata {
            work_definition: Some(TaskWorkDefinition {
                purpose: TaskWorkPurpose::Source,
                criteria: vec![],
                files: vec![TaskFileReference {
                    root_id: "primary".into(),
                    path: "change.txt".into(),
                    role: TaskFileRole::InScope,
                }],
            }),
            ..Default::default()
        });
        svc.store.insert_note(&note).await.unwrap();
        svc.store
            .insert_agent_session(&session(
                agent.as_str(),
                workspace,
                Some(note.id.as_str()),
                false,
                "Original writer",
                true,
            ))
            .await
            .unwrap();
    }
    let root = svc
        .store
        .ensure_vcs_root_binding(workspace, "primary", None, &repo.dir, VcsKind::Git, 1)
        .await
        .unwrap();
    let baseline = intent_git::GitWorkspaceEngine::default()
        .recorded_state(&root)
        .unwrap();
    let fence = svc
        .store
        .read_work_turn_fence(workspace, &agent)
        .await
        .unwrap();
    assert!(svc
        .store
        .admit_work_turn(&fence, attempt, Some(&root), Some(&baseline), &now_iso())
        .await
        .unwrap()
        .is_some());
    OriginalRecordSource::capture(&svc.store, workspace, &agent, attempt)
        .await
        .unwrap()
        .unwrap()
}

fn scope<F: Future>(
    source: &Arc<OriginalRecordSource>,
    future: F,
) -> impl Future<Output = F::Output> {
    crate::agent_manager::work_admission::scope(Some(Arc::clone(source)), future)
}

async fn publish_original_idle(
    svc: &Services,
    workspace: &WorkspaceId,
    source: &Arc<OriginalRecordSource>,
) -> Event {
    let mut subscription =
        svc.event_bus
            .as_ref()
            .unwrap()
            .subscribe(crate::events::SubscriptionFilter {
                event_types: vec![AGENT_IDLE.into()],
                ..Default::default()
            });
    scope(
        source,
        svc.publish_agent_event(
            workspace,
            &AgentId::from("original-recording-agent"),
            AGENT_IDLE,
            json!({"agentId":"original-recording-agent","reason":"stream_complete",
                          "finishReason":"end_turn","status":"idle"}),
        ),
    )
    .await;
    tokio::time::timeout(
        intentd_test_support::test_timeout(std::time::Duration::from_secs(2)),
        subscription.recv(),
    )
    .await
    .unwrap()
    .unwrap()
    .into_iter()
    .find(|event| event.event_type == AGENT_IDLE)
    .unwrap()
}

async fn contributions(
    svc: &Services,
) -> Vec<intent_core::work_explanation::WorkContributionReceipt> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload_json FROM work_t1_evidence WHERE record_kind='contribution' ORDER BY record_sequence")
        .fetch_all(svc.store.read_pool()).await.unwrap();
    rows.into_iter()
        .map(|row| serde_json::from_str(&row).unwrap())
        .collect()
}

fn head(repo: &GitRepo) -> git2::Oid {
    Repository::open(&repo.dir)
        .unwrap()
        .head()
        .unwrap()
        .target()
        .unwrap()
}

#[intent_test_macros::daemon_test]
async fn original_idle_keeps_governance_after_assignment_changes_and_does_not_recommit() {
    let repo = init_git_repo();
    let (_db, svc, workspace) = setup_dirty_workspace(&repo).await;
    let bus = crate::events::EventBus::new(svc.store.clone());
    let svc = svc.with_event_bus(bus);
    let source = original_source(&svc, &workspace, &repo, "original-recording-attempt").await;
    attribute_dirty_change(&svc, &workspace, "original-recording-agent").await;
    attribute_dirty_change(&svc, &workspace, "another-possible-writer").await;
    let later = task_note(&workspace, "later-task", "Later unrelated task");
    svc.store.insert_note(&later).await.unwrap();
    sqlx::query("UPDATE agent_session SET task_note_id=?,name='Renamed later' WHERE id='original-recording-agent'")
        .bind(later.id.as_str()).execute(svc.store.write_pool()).await.unwrap();
    let event = publish_original_idle(&svc, &workspace, &source).await;
    svc.handle_agent_idle_auto_commit(&event).await;
    let receipts = contributions(&svc).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].task_revision.note_id.as_str(),
        "original-recording-task"
    );
    assert_eq!(
        receipts[0].binding_id.as_str(),
        "original-recording-attempt"
    );
    assert_eq!(receipts[0].provenance,
        intent_core::work_explanation::WorkContributionProvenance::RecordingGovernanceOnlySharedWorkingCopy);
    assert_eq!(receipts[0].recording.files, vec!["change.txt"]);
    let (agent, note, message) = last_commit_trailers(&repo.dir);
    assert_eq!(agent.as_deref(), Some("original-recording-agent"));
    assert_eq!(note.as_deref(), Some("original-recording-task"));
    assert!(message.starts_with("Original recording request"));
    let committed = head(&repo);
    std::fs::write(repo.dir.join("change.txt"), "later unrelated edit\n").unwrap();
    svc.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), committed);
    assert_eq!(contributions(&svc).await, receipts);
}

#[intent_test_macros::daemon_test]
async fn actual_commit_ledger_failure_retries_only_retention_and_survives_restart_without_recommit()
{
    let repo = init_git_repo();
    let (_db, svc, workspace) = setup_dirty_workspace(&repo).await;
    let bus = crate::events::EventBus::new(svc.store.clone());
    let svc = svc.with_event_bus(bus);
    let source = original_source(&svc, &workspace, &repo, "retention-retry-attempt").await;
    attribute_dirty_change(&svc, &workspace, "original-recording-agent").await;
    let event = publish_original_idle(&svc, &workspace, &source).await;
    sqlx::query("CREATE TRIGGER refuse_t1_contribution BEFORE INSERT ON work_t1_evidence WHEN NEW.record_kind='contribution' BEGIN SELECT RAISE(ABORT,'injected post-commit retention failure'); END")
        .execute(svc.store.write_pool()).await.unwrap();
    let before = head(&repo);
    svc.handle_agent_idle_auto_commit(&event).await;
    let committed = head(&repo);
    assert_ne!(before, committed);
    assert!(contributions(&svc).await.is_empty());
    sqlx::query("DROP TRIGGER refuse_t1_contribution")
        .execute(svc.store.write_pool())
        .await
        .unwrap();
    std::fs::write(
        repo.dir.join("change.txt"),
        "unrelated bytes remain dirty\n",
    )
    .unwrap();
    svc.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), committed);
    let receipts = contributions(&svc).await;
    assert_eq!(receipts.len(), 1);
    assert!(matches!(&receipts[0].recording.change,
        intent_core::vcs::NativeChangeRef::Git { commit, .. } if commit.as_str()==committed.to_string()));
    let restarted = Services::new_isolated(svc.store.clone())
        .with_auggie_bin(PathBuf::from("/nonexistent/intentd-test/auggie"));
    restarted.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), committed);
    assert_eq!(
        std::fs::read_to_string(repo.dir.join("change.txt")).unwrap(),
        "unrelated bytes remain dirty\n"
    );
}

#[intent_test_macros::daemon_test]
async fn identical_idle_envelopes_from_different_attempts_are_refused_and_remain_refused_on_restart(
) {
    let repo = init_git_repo();
    let (_db, svc, workspace) = setup_dirty_workspace(&repo).await;
    let bus = crate::events::EventBus::new(svc.store.clone());
    let svc = svc.with_event_bus(bus);
    let original = original_source(&svc, &workspace, &repo, "collision-a").await;
    attribute_dirty_change(&svc, &workspace, "original-recording-agent").await;
    let event = publish_original_idle(&svc, &workspace, &original).await;
    svc.store
        .retire_work_turn(
            &workspace,
            &AgentId::from("original-recording-agent"),
            "collision-a",
        )
        .await
        .unwrap();
    let next = original_source(&svc, &workspace, &repo, "collision-b").await;
    let envelope = intent_store::NewEvent {
        workspace_id: event.workspace_id.clone(),
        timestamp: event.timestamp.clone(),
        event_type: event.event_type.clone(),
        actor: event.actor.clone(),
        session_id: event.session_id.clone(),
        correlation_id: event.correlation_id.clone(),
        parent_event_id: event.parent_event_id.clone(),
        metadata: event.metadata.clone(),
        data: event.data.clone(),
    };
    scope(&next, async { svc.capture_original_idle_record(&envelope) }).await;
    scope(&original, async {
        svc.capture_original_idle_record(&envelope);
    })
    .await;
    let before = head(&repo);
    svc.handle_agent_idle_auto_commit(&event).await;
    svc.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), before);
    assert!(contributions(&svc).await.is_empty());
    let restarted = Services::new_isolated(svc.store.clone())
        .with_auggie_bin(PathBuf::from("/nonexistent/intentd-test/auggie"));
    restarted.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), before);
}
