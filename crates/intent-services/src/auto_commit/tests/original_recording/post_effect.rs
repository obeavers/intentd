//! Faults after a real commit must preserve its exact original governing fact.

use super::*;

#[intent_test_macros::daemon_test]
async fn bound_record_retains_actual_receipt_when_index_refresh_is_locked_and_other_work_is_staged()
{
    let repo = init_git_repo();
    let (_db, svc, workspace) = setup_dirty_workspace(&repo).await;
    let bus = crate::events::EventBus::new(svc.store.clone());
    let svc = svc.with_event_bus(bus);
    let source = original_source(&svc, &workspace, &repo, "locked-index-attempt").await;
    attribute_dirty_change(&svc, &workspace, "original-recording-agent").await;
    std::fs::write(
        repo.dir.join("unrelated.txt"),
        "another actor's staged work\n",
    )
    .unwrap();
    intent_git::stage::stage(&repo.dir, &["unrelated.txt".into()]).unwrap();
    let git = Repository::open(&repo.dir).unwrap();
    let parent = git.head().unwrap().target().unwrap();
    let index_before = std::fs::read(git.path().join("index")).unwrap();
    let lock = git.path().join("index.lock");
    // This blocks only the post-commit refresh: path-scoped commit construction
    // uses a separate in-memory tree and must retain its actual successful fact.
    std::fs::write(&lock, "owned by this disposable regression\n").unwrap();
    let event = publish_original_idle(&svc, &workspace, &source).await;
    svc.handle_agent_idle_auto_commit(&event).await;
    let committed = git.head().unwrap().peel_to_commit().unwrap();
    assert_ne!(committed.id(), parent);
    assert_eq!(committed.parent_id(0).unwrap(), parent);
    assert!(committed
        .tree()
        .unwrap()
        .get_name("unrelated.txt")
        .is_none());
    assert_eq!(
        std::fs::read(git.path().join("index")).unwrap(),
        index_before
    );
    assert!(git
        .index()
        .unwrap()
        .get_path(std::path::Path::new("unrelated.txt"), 0)
        .is_some());
    assert_eq!(
        std::fs::read_to_string(&lock).unwrap(),
        "owned by this disposable regression\n"
    );
    let receipts = contributions(&svc).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].binding_id.as_str(), "locked-index-attempt");
    assert_eq!(
        receipts[0].task_revision.note_id.as_str(),
        "original-recording-task"
    );
    assert_eq!(receipts[0].recording.files, vec!["change.txt"]);
    assert!(receipts[0]
        .recording
        .index_refresh_error
        .as_deref()
        .unwrap()
        .contains("locked"));
    assert!(matches!(&receipts[0].recording.change,
        intent_core::vcs::NativeChangeRef::Git { commit, .. }
        if commit.as_str()==committed.id().to_string()));
    svc.handle_agent_idle_auto_commit(&event).await;
    std::fs::remove_file(lock).unwrap();
    svc.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), committed.id());
    assert_eq!(contributions(&svc).await, receipts);
    assert!(git
        .index()
        .unwrap()
        .get_path(std::path::Path::new("unrelated.txt"), 0)
        .is_some());
}

#[intent_test_macros::daemon_test]
async fn bound_record_settlement_survives_caller_abort_after_observation_and_drains_original_receipt(
) {
    use crate::periodic_shutdown_tests::{drain_held, entered, hold};
    let repo = init_git_repo();
    let (_db, svc, workspace) = setup_dirty_workspace(&repo).await;
    let bus = crate::events::EventBus::new(svc.store.clone());
    let svc = svc.with_event_bus(bus);
    let source = original_source(&svc, &workspace, &repo, "cancelled-receiver-attempt").await;
    attribute_dirty_change(&svc, &workspace, "original-recording-agent").await;
    let event = publish_original_idle(&svc, &workspace, &source).await;
    let before = head(&repo);
    let (rx, release) = hold(&svc, "git");
    let services = svc.clone();
    let delivery = event.clone();
    let caller = intent_core::caller::spawn_with_current_caller(async move {
        services.handle_agent_idle_auto_commit(&delivery).await;
    });
    // This actual production seam follows original.observe and precedes the
    // returned Git result, tracked-row bookkeeping and original receipt tail.
    entered(rx).await;
    let committed = head(&repo);
    assert_ne!(committed, before);
    assert!(contributions(&svc).await.is_empty());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    std::fs::write(
        repo.dir.join("change.txt"),
        "new bytes after known commit\n",
    )
    .unwrap();
    drain_held(&svc, release).await;
    let receipts = contributions(&svc).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].binding_id.as_str(),
        "cancelled-receiver-attempt"
    );
    assert_eq!(
        receipts[0].task_revision.note_id.as_str(),
        "original-recording-task"
    );
    assert!(matches!(&receipts[0].recording.change,
        intent_core::vcs::NativeChangeRef::Git { commit, .. } if commit.as_str()==committed.to_string()));
    let restarted = Services::new_isolated(svc.store.clone())
        .with_auggie_bin(PathBuf::from("/nonexistent/intentd-test/auggie"));
    restarted.handle_agent_idle_auto_commit(&event).await;
    assert_eq!(head(&repo), committed);
    assert_eq!(contributions(&svc).await, receipts);
    assert_eq!(
        std::fs::read_to_string(repo.dir.join("change.txt")).unwrap(),
        "new bytes after known commit\n"
    );
}
