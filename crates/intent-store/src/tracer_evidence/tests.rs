use super::*;
use intent_core::vcs::{GitCommitId, GitTreeId};

const AT: &str = "2026-11-18T23:00:00Z";
struct Fixture {
    directory: tempfile::TempDir,
    store: Store,
    workspace: WorkspaceId,
    note: NoteId,
    revision: TaskRevisionRef,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("store.db"))
        .await
        .unwrap();
    let workspace = WorkspaceId::from("tracer-workspace");
    let note = NoteId::from("tracer-task");
    sqlx::query("INSERT INTO workspace(id,title,branch,status,repository_path,created_at,updated_at) VALUES(?,'Tracer','main','Active','/tmp/owned-tracer',?,?)")
        .bind(workspace.as_str()).bind(AT).bind(AT).execute(store.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO note(id,workspace_id,title,content,task_json,rev,created_at,updated_at) VALUES(?,?,'Original task','Preserve exact task source.',?,0,?,?)")
        .bind(note.as_str()).bind(workspace.as_str())
        .bind(serde_json::to_string(&TaskMetadata { acceptance_criteria: vec!["Fixed test passes".into()], ..TaskMetadata::default() }).unwrap())
        .bind(AT).bind(AT).execute(store.write_pool()).await.unwrap();
    let revision = store
        .capture_task_revision(&workspace, &note, Some(0))
        .await
        .unwrap()
        .reference;
    Fixture {
        directory,
        store,
        workspace,
        note,
        revision,
    }
}
fn session(f: &Fixture, id: &str) -> AgentSession {
    AgentSession {
        id: AgentId::from(id),
        workspace_id: f.workspace.clone(),
        name: id.into(),
        status: AgentStatus::RuntimeIdle,
        task_note_id: Some(f.note.clone()),
        created_at: AT.into(),
        updated_at: AT.into(),
        ..AgentSession::default()
    }
}
async fn insert(f: &Fixture, id: &str) -> AgentSession {
    let s = session(f, id);
    f.store
        .insert_agent_session_for_confirmed_plan(&s, false, false, &f.revision)
        .await
        .unwrap();
    s
}
async fn admit(f: &Fixture, s: &AgentSession, attempt: &str) -> WorkBinding {
    let fence = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    f.store
        .admit_work_turn(&fence, attempt, None, None, AT)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn first_admission_survives_bookkeeping_and_reopen_without_retargeting() {
    let f = fixture().await;
    let s = insert(&f, "agent-original").await;
    sqlx::query("UPDATE note SET task_json=?,rev=rev+1 WHERE workspace_id=? AND id=?")
        .bind(serde_json::json!({"status":"in_progress","acceptanceCriteria":["Fixed test passes"],"assignedAgentIds":[s.id]}).to_string())
        .bind(f.workspace.as_str()).bind(f.note.as_str()).execute(f.store.write_pool()).await.unwrap();
    let original = admit(&f, &s, "original-attempt").await;
    assert_eq!(original.task_revision, f.revision);
    assert_eq!(
        f.store
            .first_work_binding_for_agent(&f.workspace, &s.id)
            .await
            .unwrap()
            .unwrap()
            .admission
            .turn_attempt,
        "original-attempt"
    );
    assert_eq!(
        f.store
            .work_admission_count_up_to(&f.workspace, &s.id, 2)
            .await
            .unwrap(),
        1
    );
    let reopened = Store::open(&f.directory.path().join("store.db"))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .task_revision(&f.revision)
            .await
            .unwrap()
            .unwrap()
            .reference,
        f.revision
    );
    assert_eq!(
        reopened
            .first_work_binding_for_agent(&f.workspace, &s.id)
            .await
            .unwrap()
            .unwrap(),
        original
    );
}

#[tokio::test]
async fn governing_edit_refuses_first_admission_and_atomic_create_rolls_back() {
    let f = fixture().await;
    sqlx::query("UPDATE note SET title='Changed request',rev=rev+1 WHERE workspace_id=? AND id=?")
        .bind(f.workspace.as_str())
        .bind(f.note.as_str())
        .execute(f.store.write_pool())
        .await
        .unwrap();
    let s = session(&f, "must-not-exist");
    assert!(f
        .store
        .insert_agent_session_for_confirmed_plan(&s, false, true, &f.revision)
        .await
        .is_err());
    assert!(f
        .store
        .get_agent_session_without_messages(&s.id)
        .await
        .is_err());
    assert!(f
        .store
        .get_agent_creation_preferences(&f.workspace)
        .await
        .unwrap()
        .as_object()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn failure_after_agent_insert_rolls_back_allocation_and_preferences() {
    let f = fixture().await;
    sqlx::query("CREATE TRIGGER corrupt_new_assignment AFTER INSERT ON agent_session BEGIN UPDATE agent_session SET task_note_id=NULL WHERE id=NEW.id; END")
        .execute(f.store.write_pool()).await.unwrap();
    let s = session(&f, "rolled-back");
    assert!(f
        .store
        .insert_agent_session_for_confirmed_plan(&s, false, true, &f.revision)
        .await
        .is_err());
    assert!(f
        .store
        .get_agent_session_without_messages(&s.id)
        .await
        .is_err());
    assert!(f
        .store
        .get_agent_creation_preferences(&f.workspace)
        .await
        .unwrap()
        .as_object()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn assignment_aba_and_stale_status_fences_refuse_before_active_transition() {
    let f = fixture().await;
    let s = insert(&f, "agent-aba").await;
    let fence = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    sqlx::query("UPDATE agent_session SET task_note_id=NULL WHERE id=?")
        .bind(s.id.as_str())
        .execute(f.store.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE agent_session SET task_note_id=? WHERE id=?")
        .bind(f.note.as_str())
        .bind(s.id.as_str())
        .execute(f.store.write_pool())
        .await
        .unwrap();
    assert!(f
        .store
        .admit_work_turn(&fence, "stale-fence", None, None, AT)
        .await
        .is_err());
    assert!(f
        .store
        .require_agent_confirmed_task_current(&s.id, &f.revision)
        .await
        .is_err());
    let fresh = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    assert!(f
        .store
        .admit_work_turn(&fresh, "changed-assignment", None, None, AT)
        .await
        .is_err());
    assert_eq!(
        f.store
            .get_agent_session_without_messages(&s.id)
            .await
            .unwrap()
            .status,
        AgentStatus::RuntimeIdle
    );
}

#[tokio::test]
async fn exact_attempt_replay_is_idempotent_and_cancel_before_admission_refuses() {
    let f = fixture().await;
    let s = insert(&f, "agent-replay").await;
    let fence = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    let first = f
        .store
        .admit_work_turn(&fence, "once", None, None, AT)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .admit_work_turn(&fence, "once", None, None, AT)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        f.store
            .work_admission_count_up_to(&f.workspace, &s.id, 2)
            .await
            .unwrap(),
        1
    );
    assert!(f
        .store
        .retire_work_turn(&f.workspace, &s.id, "once")
        .await
        .unwrap());
    assert!(
        !f.store
            .work_binding(&OperationId::from_string("once"))
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert!(f
        .store
        .admit_work_turn(&fence, "once", None, None, AT)
        .await
        .is_err());
    f.store
        .retire_work_turn(&f.workspace, &s.id, "cancel-before")
        .await
        .unwrap();
    let fresh = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    assert!(f
        .store
        .admit_work_turn(&fresh, "cancel-before", None, None, AT)
        .await
        .is_err());
}

#[tokio::test]
async fn blob_slots_and_event_replays_keep_original_bytes_and_sequence() {
    let f = fixture().await;
    let blobs = crate::EvidenceBlobStore::open(&f.directory.path().join("blobs")).unwrap();
    let a = blobs.put(b"original observed report").unwrap();
    let b = blobs.put(b"different report").unwrap();
    assert!(f
        .store
        .retain_evidence_blob(
            &EvidenceBlob {
                digest: ContentDigest("f".repeat(64)),
                length: u64::MAX
            },
            "atomic-tracer",
            "overflow",
            "association"
        )
        .await
        .is_err());
    f.store
        .retain_evidence_blob(&a, "atomic-tracer", "original-binding", "association")
        .await
        .unwrap();
    f.store
        .retain_evidence_blob(&a, "atomic-tracer", "original-binding", "association")
        .await
        .unwrap();
    assert!(f
        .store
        .retain_evidence_blob(&b, "atomic-tracer", "original-binding", "association")
        .await
        .is_err());
    assert_eq!(
        blobs
            .read(
                &f.store
                    .retained_evidence_blob("atomic-tracer", "original-binding", "association")
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
        b"original observed report"
    );
    let event = NewEvidenceOutboxEvent {
        event_id: "observed-1".into(),
        event_kind: "test-observation".into(),
        schema_version: 1,
        source_revision: "original".into(),
        payload_json: "{\"exitCode\":0}".into(),
    };
    let first = f.store.enqueue_evidence_event(&event).await.unwrap();
    assert!(first.sequence > 0);
    assert_eq!(f.store.enqueue_evidence_event(&event).await.unwrap(), first);
    let mut changed = event;
    changed.payload_json = "{\"exitCode\":1}".into();
    assert!(f.store.enqueue_evidence_event(&changed).await.is_err());
}

#[tokio::test]
async fn contribution_receipts_remain_original_and_reads_use_owner_index() {
    let f = fixture().await;
    let s = insert(&f, "agent-record").await;
    let root = f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            Path::new("/tmp/owned-tracer"),
            VcsKind::Git,
            1,
        )
        .await
        .unwrap();
    let baseline = NativeStateRef::Git {
        repository_id: root.repository_id.clone(),
        commit: Some(GitCommitId("a".repeat(40))),
        tree: GitTreeId("b".repeat(40)),
    };
    let fence = f
        .store
        .read_work_turn_fence(&f.workspace, &s.id)
        .await
        .unwrap();
    let binding = f
        .store
        .admit_work_turn(&fence, "record-owner", Some(&root), Some(&baseline), AT)
        .await
        .unwrap()
        .unwrap();
    let recording = RecordedChange {
        change: NativeChangeRef::Git {
            repository_id: root.repository_id.clone(),
            commit: GitCommitId("c".repeat(40)),
        },
        files: vec!["src/fees.js".into()],
        index_refresh_error: None,
    };
    let operation = OperationId::from_string("record-1");
    let observed = f
        .store
        .retain_work_contribution(&operation, &binding, &root, &recording)
        .await
        .unwrap();
    f.store
        .retire_work_turn(&f.workspace, &s.id, "record-owner")
        .await
        .unwrap();
    assert_eq!(
        f.store
            .retain_work_contribution(&operation, &binding, &root, &recording)
            .await
            .unwrap(),
        observed
    );
    assert_eq!(
        f.store
            .work_contributions_for_binding(&f.workspace, &binding.admission.binding_id, 2)
            .await
            .unwrap(),
        vec![observed]
    );
    let plans: Vec<(i64,i64,i64,String)> = sqlx::query_as("EXPLAIN QUERY PLAN SELECT payload_json FROM work_t1_evidence WHERE record_kind='contribution' AND owner_id=? AND workspace_id=? ORDER BY record_sequence LIMIT 2")
        .bind(binding.admission.binding_id.as_str()).bind(f.workspace.as_str()).fetch_all(f.store.read_pool()).await.unwrap();
    assert!(plans
        .iter()
        .any(|row| row.3.contains("work_t1_evidence_owner")));
}

#[tokio::test]
async fn workspace_delete_keeps_original_task_and_admission_evidence() {
    let f = fixture().await;
    let session = insert(&f, "retained-after-delete").await;
    let binding = admit(&f, &session, "original-before-delete").await;
    f.store
        .retire_work_turn(&f.workspace, &session.id, "original-before-delete")
        .await
        .unwrap();
    let retained = f
        .store
        .first_work_binding_for_agent(&f.workspace, &session.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!retained.active);

    f.store.delete_workspace(&f.workspace).await.unwrap();

    assert!(f.store.get_workspace(&f.workspace).await.is_err());
    let source = f.store.task_revision(&f.revision).await.unwrap().unwrap();
    assert_eq!(source.reference, f.revision);
    assert_eq!(source.content, "Preserve exact task source.");
    assert_eq!(
        f.store
            .first_work_binding_for_agent(&f.workspace, &session.id)
            .await
            .unwrap(),
        Some(retained)
    );
    assert_eq!(
        f.store
            .work_admission_count_up_to(&f.workspace, &session.id, 2)
            .await
            .unwrap(),
        1
    );
    assert_eq!(binding.task_revision, source.reference);
}

#[tokio::test]
async fn root_incarnation_aba_never_reuses_the_original_binding_epoch() {
    let f = fixture().await;
    let original = f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            Path::new("/tmp/owned-tracer"),
            VcsKind::Git,
            1,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE workspace SET repository_path='/tmp/different-root' WHERE id=?")
        .bind(f.workspace.as_str())
        .execute(f.store.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE workspace SET repository_path='/tmp/owned-tracer' WHERE id=?")
        .bind(f.workspace.as_str())
        .execute(f.store.write_pool())
        .await
        .unwrap();
    assert!(f
        .store
        .vcs_root_binding(&f.workspace, "primary")
        .await
        .is_err());
    assert!(f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            &original.locator,
            VcsKind::Git,
            1
        )
        .await
        .is_err());
}

#[tokio::test]
async fn root_alias_and_locator_drift_refuse_and_native_remains_unsupported() {
    let f = fixture().await;
    let first = f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            Path::new("/tmp/owned-tracer"),
            VcsKind::Git,
            1,
        )
        .await
        .unwrap();
    let agent = insert(&f, "baseline-without-root").await;
    let fence = f
        .store
        .read_work_turn_fence(&f.workspace, &agent.id)
        .await
        .unwrap();
    let baseline = NativeStateRef::Git {
        repository_id: first.repository_id.clone(),
        commit: Some(GitCommitId("a".repeat(40))),
        tree: GitTreeId("b".repeat(40)),
    };
    assert!(f
        .store
        .admit_work_turn(&fence, "rootless-baseline", None, Some(&baseline), AT)
        .await
        .is_err());
    assert_eq!(
        f.store
            .ensure_vcs_root_binding(
                &f.workspace,
                "primary",
                None,
                Path::new("/tmp/owned-tracer"),
                VcsKind::Git,
                1
            )
            .await
            .unwrap(),
        first
    );
    assert!(f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            Some("new-alias"),
            Path::new("/tmp/owned-tracer"),
            VcsKind::Git,
            1
        )
        .await
        .is_err());
    assert!(f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            Path::new("/tmp/other"),
            VcsKind::Git,
            1
        )
        .await
        .is_err());
    assert!(f
        .store
        .ensure_vcs_root_binding(
            &f.workspace,
            "primary",
            None,
            Path::new("/tmp/owned-tracer"),
            VcsKind::Atomic,
            1
        )
        .await
        .is_err());
}

#[tokio::test]
async fn upgrade_from_schema_190_and_current_main_196_keeps_shipped_rows_and_checksums() {
    for version in [190, 196] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upgrade.db");
        let pool = crate::connect_write(&path).await.unwrap();
        let prefix = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                crate::MIGRATOR
                    .iter()
                    .filter(|m| m.version <= version)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        prefix.run(&pool).await.unwrap();
        sqlx::query("INSERT INTO workspace(id,title,branch,status,created_at,updated_at) VALUES('upgrade-workspace','Preserve','main','Active',?,?)").bind(AT).bind(AT).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO agent_session(id,workspace_id,name,status,created_at,updated_at) VALUES('upgrade-agent','upgrade-workspace','Preserve','idle',?,?)").bind(AT).bind(AT).execute(&pool).await.unwrap();
        let before: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .unwrap();
        pool.close().await;
        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            store
                .get_workspace(&WorkspaceId::from("upgrade-workspace"))
                .await
                .unwrap()
                .title,
            "Preserve"
        );
        let after: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT version,checksum FROM _sqlx_migrations WHERE version<=? ORDER BY version",
        )
        .bind(version)
        .fetch_all(store.read_pool())
        .await
        .unwrap();
        assert_eq!(before, after);
        assert!(store
            .read_work_turn_fence(
                &WorkspaceId::from("upgrade-workspace"),
                &AgentId::from("upgrade-agent")
            )
            .await
            .is_ok());
        assert_eq!(
            store.migration_status().await.unwrap().applied.last(),
            Some(&197)
        );
    }
}
