//! Confirmed planning authorization, exact-source identity and atomic-write regressions.

use super::*;
use intent_core::vcs::ContentDigest;
use intent_core::work_evidence::planning::{TaskCriterionRequirement, TaskWorkPurpose};
use intent_core::{with_caller, AgentId, HostRole, TaskMetadata};

async fn task(services: &Services, workspace: &WorkspaceId, note_id: &NoteId) -> Note {
    let lock = services.lock_note_content(workspace, note_id).await;
    let mut note = services.store.get_note(workspace, note_id).await.unwrap();
    note.metadata.task = Some(TaskMetadata::default());
    note.rev = services
        .store
        .update_note_metadata_versioned(&lock, &note, Some(note.rev))
        .await
        .unwrap();
    note
}

async fn human(services: &Services) -> Caller {
    Caller::Wire {
        principal_id: services.store.get_primary_principal().await.unwrap().id,
        host_role: HostRole::Owner,
    }
}

fn declared() -> TaskWorkDefinition {
    TaskWorkDefinition {
        purpose: TaskWorkPurpose::Research,
        criteria: vec![TaskCriterionRequirement {
            index: 0,
            text_digest: ContentDigest("untrusted-client-digest".into()),
            required_kinds: vec!["experiment".into(), "source-review".into()],
        }],
        files: vec![],
    }
}

#[tokio::test]
async fn complete_confirmation_retains_exact_text_and_canonical_required_kind_pins() {
    let (_db, services, workspace, note_id) =
        crate::tests::setup("Keep source body\nunchanged").await;
    let original = task(&services, &workspace, &note_id).await;
    let raw = "  Observe café\nwithout trimming  ";
    let saved = with_caller(
        human(&services).await,
        services.configure_task_work_definition_complete(
            &workspace,
            &note_id,
            original.rev,
            vec![raw.into()],
            Some(declared()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(saved.note.rev, original.rev + 1);
    assert_eq!(saved.note.content, original.content);
    assert_eq!(saved.note.title, original.title);
    let persisted = services.store.get_note(&workspace, &note_id).await.unwrap();
    assert_eq!(saved.note, persisted);
    let source = services
        .store
        .task_revision(&saved.task_revision)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source.reference.rev, persisted.rev);
    assert_eq!(source.criteria[0].text, raw);
    assert_eq!(
        source.criteria[0].text_digest.0,
        "3f4de03e5a8be9f295467ea25abc00425502ac77f1484745a7a03a0eea5e3847"
    );
    assert_eq!(
        source.criteria[0].required_kinds,
        ["experiment", "source-review"]
    );
    let task = persisted.metadata.task.unwrap();
    assert_eq!(source.task_json, serde_json::to_string(&task).unwrap());
    assert_eq!(task.acceptance_criteria, [raw]);
    assert_eq!(
        task.work_definition.unwrap().criteria[0].text_digest,
        source.criteria[0].text_digest
    );
}

#[tokio::test]
async fn source_snapshot_failure_rolls_back_both_criteria_and_definition() {
    let (_db, services, workspace, note_id) = crate::tests::setup("Retained source").await;
    let original = task(&services, &workspace, &note_id).await;
    sqlx::query("CREATE TRIGGER refuse_task_confirmation BEFORE INSERT ON work_t1_evidence WHEN NEW.record_kind='task-revision' BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END")
        .execute(services.store.write_pool()).await.unwrap();
    assert!(with_caller(
        human(&services).await,
        services.configure_task_work_definition_complete(
            &workspace,
            &note_id,
            original.rev,
            vec!["New source".into()],
            Some(declared()),
        )
    )
    .await
    .is_err());
    assert_eq!(
        services.store.get_note(&workspace, &note_id).await.unwrap(),
        original
    );
    let revisions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM work_t1_evidence WHERE record_kind='task-revision'",
    )
    .fetch_one(services.store.read_pool())
    .await
    .unwrap();
    assert_eq!(revisions, 0);
}

#[tokio::test]
async fn stale_and_invalid_drafts_do_not_partially_overwrite_confirmed_source() {
    let (_db, services, workspace, note_id) = crate::tests::setup("Body").await;
    let original = task(&services, &workspace, &note_id).await;
    let caller = human(&services).await;
    let saved = with_caller(
        caller.clone(),
        services.configure_task_work_definition_complete(
            &workspace,
            &note_id,
            original.rev,
            vec!["Reviewed source".into()],
            Some(declared()),
        ),
    )
    .await
    .unwrap();
    assert!(matches!(
        with_caller(
            caller.clone(),
            services.configure_task_work_definition_complete(
                &workspace,
                &note_id,
                original.rev,
                vec!["Stale overwrite".into()],
                None,
            )
        )
        .await,
        Err(Error::Conflict { .. })
    ));
    let mut invalid = declared();
    invalid.criteria[0].required_kinds = vec![];
    assert!(with_caller(
        caller.clone(),
        services.configure_task_work_definition_complete(
            &workspace,
            &note_id,
            saved.note.rev,
            vec!["Invalid overwrite".into()],
            Some(invalid),
        )
    )
    .await
    .is_err());
    assert_eq!(
        services.store.get_note(&workspace, &note_id).await.unwrap(),
        saved.note
    );
    let cleared = with_caller(
        caller,
        services.configure_task_work_definition_complete(
            &workspace,
            &note_id,
            saved.note.rev,
            vec![],
            None,
        ),
    )
    .await
    .unwrap();
    assert!(cleared
        .note
        .metadata
        .task
        .unwrap()
        .work_definition
        .is_none());
    assert!(services
        .store
        .task_revision(&cleared.task_revision)
        .await
        .unwrap()
        .unwrap()
        .criteria
        .is_empty());
    assert!(services
        .store
        .task_revision(&saved.task_revision)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn only_current_human_can_change_governing_requirements_and_stale_edits_do_not_land() {
    let (_db, services, workspace, note_id) = crate::tests::setup("Original plan").await;
    let lock = services.lock_note_content(&workspace, &note_id).await;
    let mut note = services.store.get_note(&workspace, &note_id).await.unwrap();
    note.metadata.task = Some(TaskMetadata::default());
    note.rev = services
        .store
        .update_note_metadata_versioned(&lock, &note, Some(note.rev))
        .await
        .unwrap();
    drop(lock);
    let definition = TaskWorkDefinition {
        purpose: TaskWorkPurpose::Research,
        criteria: vec![],
        files: vec![],
    };
    let agent = Caller::Agent {
        agent_id: AgentId::new(),
    };
    assert!(with_caller(
        agent,
        services.configure_task_work_definition(
            &workspace,
            &note_id,
            note.rev,
            Some(definition.clone())
        )
    )
    .await
    .is_err());
    let caller = Caller::Wire {
        principal_id: services.store.get_primary_principal().await.unwrap().id,
        host_role: HostRole::Owner,
    };
    let updated = with_caller(
        caller.clone(),
        services.configure_task_work_definition(
            &workspace,
            &note_id,
            note.rev,
            Some(definition.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        updated.metadata.task.unwrap().work_definition,
        Some(definition)
    );
    assert!(matches!(
        with_caller(
            caller,
            services.configure_task_work_definition(&workspace, &note_id, note.rev, None)
        )
        .await,
        Err(Error::Conflict { .. })
    ));
    assert!(services
        .store
        .get_note(&workspace, &note_id)
        .await
        .unwrap()
        .metadata
        .task
        .unwrap()
        .work_definition
        .is_some());
}

#[tokio::test]
async fn neither_agents_nor_daemon_identity_can_confirm_an_explicit_draft() {
    let (_db, services, workspace, note_id) = crate::tests::setup("Original plan").await;
    let original = task(&services, &workspace, &note_id).await;
    for caller in [
        Caller::Agent {
            agent_id: AgentId::new(),
        },
        Caller::Daemon,
    ] {
        assert!(matches!(
            with_caller(
                caller,
                services.configure_task_work_definition_complete(
                    &workspace,
                    &note_id,
                    original.rev,
                    vec!["Unapproved source".into()],
                    Some(declared()),
                ),
            )
            .await,
            Err(Error::Forbidden(_))
        ));
        assert_eq!(
            services.store.get_note(&workspace, &note_id).await.unwrap(),
            original
        );
    }
}

#[tokio::test]
async fn completed_and_cancelled_tasks_must_reopen_before_requirements_change() {
    for status in [TaskStatus::Complete, TaskStatus::Cancelled] {
        let (_db, services, workspace, note_id) = crate::tests::setup("Retained plan").await;
        let mut original = task(&services, &workspace, &note_id).await;
        original.metadata.task.as_mut().unwrap().status = status;
        let lock = services.lock_note_content(&workspace, &note_id).await;
        original.rev = services
            .store
            .update_note_metadata_versioned(&lock, &original, Some(original.rev))
            .await
            .unwrap();
        drop(lock);
        assert!(matches!(
            with_caller(
                human(&services).await,
                services.configure_task_work_definition_complete(
                    &workspace,
                    &note_id,
                    original.rev,
                    vec!["Altered terminal source".into()],
                    Some(declared()),
                ),
            )
            .await,
            Err(Error::Forbidden(_))
        ));
        assert_eq!(
            services.store.get_note(&workspace, &note_id).await.unwrap(),
            original
        );
    }
}
