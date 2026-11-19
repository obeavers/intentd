//! Original task/admission/evidence parity, with colliding ids in two tenants.
use crate::harness::parity_test;
use intent_core::vcs::ContentDigest;
use intent_core::work_evidence::NewEvidenceOutboxEvent;
use intent_core::{
    AgentId, AgentSession, AgentStatus, ContentType, Note, NoteId, NoteMetadata, NoteVisibility,
    TaskMetadata, WorkspaceId,
};
use intent_store::{EvidenceBlob, Store};

async fn exercise(store: &Store, tenant: &str) {
    let workspace = WorkspaceId::from("__chief__");
    let note = Note {
        id: NoteId::from("same-task"),
        workspace_id: workspace.clone(),
        title: format!("Original request from {tenant}"),
        content: format!("Only {tenant} owns these bytes"),
        content_type: ContentType::Markdown,
        tags: vec![],
        is_pinned: false,
        is_archived: false,
        is_default: false,
        parent_id: None,
        visibility: NoteVisibility::Workspace,
        metadata: NoteMetadata {
            task: Some(TaskMetadata {
                acceptance_criteria: vec![format!("{tenant} result")],
                ..TaskMetadata::default()
            }),
        },
        created_at: "2026-11-18T23:00:00Z".into(),
        rev: 0,
        updated_at: "2026-11-18T23:00:00Z".into(),
    };
    store.insert_note(&note).await.unwrap();
    let source = store
        .capture_task_revision(&workspace, &note.id, Some(0))
        .await
        .unwrap();
    assert_eq!(source.title, note.title);
    let session = AgentSession {
        id: AgentId::from("same-agent"),
        workspace_id: workspace.clone(),
        name: tenant.into(),
        status: AgentStatus::RuntimeIdle,
        task_note_id: Some(note.id.clone()),
        created_at: note.created_at.clone(),
        updated_at: note.updated_at.clone(),
        ..AgentSession::default()
    };
    store
        .insert_agent_session_for_confirmed_plan(&session, false, true, &source.reference)
        .await
        .unwrap();
    store
        .require_agent_confirmed_task_current(&session.id, &source.reference)
        .await
        .unwrap();
    let fence = store
        .read_work_turn_fence(&workspace, &session.id)
        .await
        .unwrap();
    let admitted = store
        .admit_work_turn(&fence, "same-attempt", None, None, &note.created_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admitted.task_revision, source.reference);
    assert_eq!(
        store
            .first_work_binding_for_agent(&workspace, &session.id)
            .await
            .unwrap()
            .unwrap(),
        admitted
    );
    assert_eq!(
        store
            .work_admission_count_up_to(&workspace, &session.id, 2)
            .await
            .unwrap(),
        1
    );
    let length = u64::try_from(tenant.len()).unwrap();
    let blob = EvidenceBlob {
        digest: ContentDigest("a".repeat(64)),
        length,
    };
    store
        .retain_evidence_blob(&blob, "same-owner", "same-binding", "report")
        .await
        .unwrap();
    assert_eq!(
        store
            .retained_evidence_blob("same-owner", "same-binding", "report")
            .await
            .unwrap(),
        Some(blob)
    );
    let event = NewEvidenceOutboxEvent {
        event_id: "same-event".into(),
        event_kind: "observed".into(),
        schema_version: 1,
        source_revision: source.reference.digest.0.clone(),
        payload_json: serde_json::json!({"tenant":tenant}).to_string(),
    };
    let first = store.enqueue_evidence_event(&event).await.unwrap();
    assert_eq!(first, store.enqueue_evidence_event(&event).await.unwrap());
    store
        .retire_work_turn(&workspace, &session.id, "same-attempt")
        .await
        .unwrap();
    assert!(
        !store
            .first_work_binding_for_agent(&workspace, &session.id)
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        store
            .task_revision(&source.reference)
            .await
            .unwrap()
            .unwrap()
            .title,
        note.title
    );
}

parity_test!(
    original_confirmed_admission_and_blobs_are_tenant_isolated,
    |store, tenant| {
        exercise(&store, tenant).await;
    }
);
