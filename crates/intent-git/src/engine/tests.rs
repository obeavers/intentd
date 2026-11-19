use super::*;
use crate::testutil::{checkout_branch, commit_file, create_branch, init_repo, write_file};
use intent_core::vcs::{RecordOutcome, RecordSelection, RecordSkipReason, WorkspaceEngine};
use intent_core::WorkspaceId;

fn binding(path: &Path) -> vcs::RootBinding {
    vcs::RootBinding {
        workspace_id: WorkspaceId::from_string("engine-tests"),
        root_id: "primary".into(),
        repository_id: vcs::RepositoryId::from_string("2cc440f8-299f-4bb2-b315-d0030c2d9c66"),
        kind: VcsKind::Git,
        locator: path.to_path_buf(),
        epoch: 1,
    }
}

fn request(selection: RecordSelection) -> vcs::RecordRequest {
    vcs::RecordRequest {
        message: "feat: engine parity".into(),
        selection,
        agent_id: Some("agent-a".into()),
        linked_note_id: Some("task-a".into()),
    }
}

fn paths(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

#[track_caller]
fn recorded(outcome: RecordOutcome) -> vcs::RecordedChange {
    let RecordOutcome::Recorded(recorded) = outcome else {
        panic!("expected a recorded change, got {outcome:?}");
    };
    recorded
}

fn head(path: &Path) -> String {
    crate::refs::rev_parse(path, "HEAD").unwrap()
}

#[test]
fn status_preserves_staged_double_entries_and_cached_conversion_reports_unknown_conflicts() {
    let dir = init_repo("engine-status");
    commit_file(dir.path(), "a.txt", "base\n");
    write_file(dir.path(), "a.txt", "staged\n");
    crate::stage::stage(dir.path(), &paths(&["a.txt"])).unwrap();
    write_file(dir.path(), "a.txt", "working\n");
    write_file(dir.path(), "new.txt", "new\n");
    let legacy = crate::status::status(dir.path()).unwrap();
    let converted = GitWorkspaceEngine::status_from_git(legacy.clone());
    let status = GitWorkspaceEngine::default()
        .status(&binding(dir.path()))
        .unwrap();
    assert_eq!(converted.files.len(), legacy.files.len());
    assert_eq!(
        status
            .files
            .iter()
            .filter(|file| file.path == "a.txt")
            .count(),
        2
    );
    assert_eq!(converted.conflicts, None);
    assert!(converted.files.iter().all(|file| file.conflicted.is_none()));
    assert_eq!(status.conflicts, Some(0));
    assert!(status
        .files
        .iter()
        .all(|file| file.conflicted == Some(false)));
    assert_eq!(status.branch, legacy.branch);
    assert_eq!(status.has_upstream, legacy.has_upstream);
    assert_eq!(status.unpushed_count, legacy.unpushed_count);
}

#[test]
fn staged_record_preserves_partial_staging_and_does_not_sweep_unstaged_paths() {
    let dir = init_repo("engine-partial-staging");
    commit_file(dir.path(), "a.txt", "base\n");
    write_file(dir.path(), "a.txt", "staged\n");
    GitWorkspaceEngine::default()
        .stage(&binding(dir.path()), &paths(&["a.txt"]))
        .unwrap();
    write_file(dir.path(), "a.txt", "unstaged\n");
    write_file(dir.path(), "other.txt", "other actor\n");
    let outcome = recorded(
        GitWorkspaceEngine::default()
            .record(&binding(dir.path()), &request(RecordSelection::StagedIndex))
            .unwrap(),
    );
    assert_eq!(outcome.files, paths(&["a.txt"]));
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "a.txt").unwrap(),
        "staged\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "unstaged\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "other.txt").unwrap(),
        ""
    );
    let history = crate::history::history(dir.path(), 1).unwrap();
    assert_eq!(history[0].agent_id.as_deref(), Some("agent-a"));
    assert_eq!(history[0].linked_note_id.as_deref(), Some("task-a"));
}

#[test]
fn explicit_record_isolates_other_actors_staged_work() {
    let dir = init_repo("engine-explicit");
    commit_file(dir.path(), "own.txt", "base\n");
    commit_file(dir.path(), "other.txt", "base\n");
    write_file(dir.path(), "other.txt", "other staged\n");
    crate::stage::stage(dir.path(), &paths(&["other.txt"])).unwrap();
    write_file(dir.path(), "own.txt", "own working\n");
    let outcome = recorded(
        GitWorkspaceEngine::default()
            .record(
                &binding(dir.path()),
                &request(RecordSelection::Explicit(paths(&["own.txt"]))),
            )
            .unwrap(),
    );
    assert_eq!(outcome.files, paths(&["own.txt"]));
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "other.txt").unwrap(),
        "base\n"
    );
    assert_eq!(
        crate::commit::staged_paths(dir.path()).unwrap(),
        paths(&["other.txt"])
    );
}

#[test]
fn attributed_record_intersects_dirty_paths_and_preserves_unattributed_staging() {
    let dir = init_repo("engine-attributed");
    commit_file(dir.path(), "own.txt", "base\n");
    commit_file(dir.path(), "stale.txt", "clean\n");
    commit_file(dir.path(), "other.txt", "base\n");
    write_file(dir.path(), "own.txt", "own\n");
    write_file(dir.path(), "other.txt", "other\n");
    crate::stage::stage(dir.path(), &paths(&["other.txt"])).unwrap();
    let outcome = recorded(
        GitWorkspaceEngine::default()
            .record(
                &binding(dir.path()),
                &request(RecordSelection::Attributed(paths(&[
                    "own.txt",
                    "stale.txt",
                ]))),
            )
            .unwrap(),
    );
    assert_eq!(outcome.files, paths(&["own.txt"]));
    assert_eq!(
        crate::commit::staged_paths(dir.path()).unwrap(),
        paths(&["other.txt"])
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "other.txt").unwrap(),
        "base\n"
    );
}

#[test]
fn unattributed_and_empty_records_are_explicit_skips_without_side_effects() {
    let dir = init_repo("engine-skip");
    commit_file(dir.path(), "a.txt", "base\n");
    write_file(dir.path(), "a.txt", "dirty\n");
    let original_head = head(dir.path());
    assert_eq!(
        GitWorkspaceEngine::default()
            .record(
                &binding(dir.path()),
                &request(RecordSelection::Unattributed)
            )
            .unwrap(),
        RecordOutcome::Skipped(RecordSkipReason::MissingAttribution)
    );
    let mut missing_agent = request(RecordSelection::Attributed(paths(&["a.txt"])));
    missing_agent.agent_id = None;
    assert_eq!(
        GitWorkspaceEngine::default()
            .record(&binding(dir.path()), &missing_agent)
            .unwrap(),
        RecordOutcome::Skipped(RecordSkipReason::MissingAttribution)
    );
    assert_eq!(
        GitWorkspaceEngine::default()
            .record(&binding(dir.path()), &request(RecordSelection::StagedIndex))
            .unwrap(),
        RecordOutcome::Skipped(RecordSkipReason::NoChanges)
    );
    assert_eq!(head(dir.path()), original_head);
    assert!(crate::commit::staged_paths(dir.path()).unwrap().is_empty());
}

#[test]
fn diff_scopes_distinguish_index_working_and_full_tree() {
    let dir = init_repo("engine-diffs");
    commit_file(dir.path(), "a.txt", "base\n");
    write_file(dir.path(), "a.txt", "staged\n");
    crate::stage::stage(dir.path(), &paths(&["a.txt"])).unwrap();
    write_file(dir.path(), "a.txt", "working\n");
    let root = binding(dir.path());
    for (scope, old, new) in [
        (vcs::DiffScope::Staged, "base", "staged"),
        (vcs::DiffScope::Unstaged, "staged", "working"),
        (vcs::DiffScope::Working, "base", "working"),
    ] {
        let diff = GitWorkspaceEngine::default()
            .diff_working(&root, scope, None)
            .unwrap();
        assert_eq!(diff.len(), 1);
        let lines = &diff[0].hunks[0].lines;
        assert!(lines
            .iter()
            .any(|line| line.kind == vcs::DiffLineKind::Deletion && line.content.trim() == old));
        assert!(lines
            .iter()
            .any(|line| line.kind == vcs::DiffLineKind::Addition && line.content.trim() == new));
    }
    assert!(GitWorkspaceEngine::default()
        .diff_working(
            &root,
            vcs::DiffScope::Working,
            Some(&paths(&["missing.txt"]))
        )
        .unwrap()
        .is_empty());
}

#[test]
fn missing_foreign_and_wrong_engine_changes_fail_without_mutation() {
    let dir = init_repo("engine-identity");
    commit_file(dir.path(), "a.txt", "base\n");
    let root = binding(dir.path());
    let missing = vcs::NativeChangeRef::Git {
        repository_id: root.repository_id.clone(),
        commit: vcs::GitCommitId::from_string("0000000000000000000000000000000000000001"),
    };
    assert!(matches!(
        GitWorkspaceEngine::default().diff_change(&root, &missing),
        Err(vcs::VcsError::Backend(Error::NotFound(_)))
    ));
    let foreign = vcs::NativeChangeRef::Git {
        repository_id: vcs::RepositoryId::from_string("other-repository"),
        commit: vcs::GitCommitId::from_string(head(dir.path())),
    };
    assert!(matches!(
        GitWorkspaceEngine::default().reset(&root, &foreign, vcs::ResetMode::Hard),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    let symbolic = vcs::NativeChangeRef::Git {
        repository_id: root.repository_id.clone(),
        commit: vcs::GitCommitId::from_string("HEAD"),
    };
    assert!(matches!(
        GitWorkspaceEngine::default().diff_change(&root, &symbolic),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    let mut atomic_root = root;
    atomic_root.kind = VcsKind::Atomic;
    write_file(dir.path(), "a.txt", "working\n");
    assert!(matches!(
        GitWorkspaceEngine::default().stage(&atomic_root, &paths(&["a.txt"])),
        Err(vcs::VcsError::Unsupported { .. })
    ));
    assert!(crate::commit::staged_paths(dir.path()).unwrap().is_empty());
}

#[test]
fn capture_retains_head_index_and_working_overlay_without_changing_live_state() {
    let dir = init_repo("engine-capture");
    commit_file(dir.path(), "a.txt", "base\n");
    write_file(dir.path(), "a.txt", "staged\n");
    crate::stage::stage(dir.path(), &paths(&["a.txt"])).unwrap();
    write_file(dir.path(), "a.txt", "working\n");
    write_file(dir.path(), "untracked.txt", "new\n");
    let root = binding(dir.path());
    let permit = vcs::CapturePermit {
        operation_id: vcs::OperationId::from_string("capture-one"),
        binding_epoch: root.epoch,
        strength: vcs::CaptureStrength::Full,
        excluded_paths: vec![],
    };
    let original_head = head(dir.path());
    let snapshot = GitWorkspaceEngine::default()
        .capture(&root, &permit)
        .unwrap();
    let vcs::NativeStateRef::Git { commit, .. } = snapshot.state else {
        panic!("Git state expected")
    };
    assert_eq!(commit.unwrap().as_str(), original_head);
    let vcs::CapturedWorkingCopy::Git { anchors } = snapshot.working_copy else {
        panic!("Git capture expected")
    };
    assert_eq!(
        crate::show::show_file(dir.path(), anchors.index.as_str(), "a.txt").unwrap(),
        "staged\n"
    );
    let wip = anchors.wip.unwrap();
    assert_eq!(
        crate::show::show_file(dir.path(), wip.as_str(), "a.txt").unwrap(),
        "working\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), wip.as_str(), "untracked.txt").unwrap(),
        "new\n"
    );
    assert_eq!(head(dir.path()), original_head);
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "a.txt").unwrap(),
        "staged\n"
    );
    let mut stale = permit;
    stale.binding_epoch += 1;
    assert!(matches!(
        GitWorkspaceEngine::default().capture(&root, &stale),
        Err(vcs::VcsError::Stale { .. })
    ));
}

#[test]
fn reset_soft_and_hard_and_discard_preserve_git_semantics() {
    let dir = init_repo("engine-reset");
    commit_file(dir.path(), "a.txt", "base\n");
    let root = binding(dir.path());
    let first = vcs::NativeChangeRef::Git {
        repository_id: root.repository_id.clone(),
        commit: vcs::GitCommitId::from_string(head(dir.path())),
    };
    commit_file(dir.path(), "a.txt", "next\n");
    GitWorkspaceEngine::default()
        .reset(&root, &first, vcs::ResetMode::Soft)
        .unwrap();
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "a.txt").unwrap(),
        "base\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "a.txt").unwrap(),
        "next\n"
    );
    write_file(dir.path(), "a.txt", "dirty\n");
    GitWorkspaceEngine::default()
        .discard(&root, &paths(&["a.txt"]))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "next\n"
    );
    GitWorkspaceEngine::default()
        .reset(&root, &first, vcs::ResetMode::Hard)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "base\n"
    );
    assert!(crate::commit::staged_paths(dir.path()).unwrap().is_empty());
}

#[test]
fn rebase_retains_dirty_overlay_with_autostash() {
    let dir = init_repo("engine-rebase");
    commit_file(dir.path(), "base.txt", "base\n");
    let original = crate::status::current_branch_at(dir.path()).unwrap();
    create_branch(dir.path(), "trunk");
    commit_file(dir.path(), "branch.txt", "branch\n");
    checkout_branch(dir.path(), "trunk");
    commit_file(dir.path(), "trunk.txt", "trunk\n");
    checkout_branch(dir.path(), &original);
    write_file(dir.path(), "base.txt", "dirty\n");
    let result = GitWorkspaceEngine::default()
        .rebase(&binding(dir.path()), "trunk")
        .unwrap();
    assert!(result.success);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("base.txt")).unwrap(),
        "dirty\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "trunk.txt").unwrap(),
        "trunk\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "branch.txt").unwrap(),
        "branch\n"
    );
}

#[test]
fn path_attribution_preserves_clean_dirty_unknown_and_lock_order() {
    let dir = init_repo("engine-attribution");
    commit_file(dir.path(), ".gitignore", "ignored/\n");
    commit_file(dir.path(), "a.txt", "base\n");
    commit_file(dir.path(), "b.txt", "base\n");
    write_file(dir.path(), "a.txt", "a\n");
    write_file(dir.path(), "b.txt", "b\n");
    write_file(dir.path(), "ignored/cache", "cache\n");
    git2::Repository::init(dir.path().join("nested")).unwrap();
    write_file(dir.path(), "nested/file", "nested\n");
    assert!(GitWorkspaceEngine::default()
        .is_ignored(dir.path(), "ignored/cache")
        .unwrap());
    assert_eq!(
        GitWorkspaceEngine::default()
            .classify_paths(dir.path(), &paths(&["a.txt", ".gitignore", "nested/file"]))
            .unwrap(),
        vec![
            vcs::PathState::Dirty,
            vcs::PathState::Clean,
            vcs::PathState::Unknown
        ]
    );
    let status = GitWorkspaceEngine::default()
        .status(&binding(dir.path()))
        .unwrap();
    assert_eq!(
        GitWorkspaceEngine::default()
            .lockable_paths(
                dir.path(),
                &status.files,
                &paths(&["b.txt", "a.txt", ".gitignore"])
            )
            .unwrap(),
        paths(&["b.txt", "a.txt"])
    );
}

#[test]
fn merge_requires_full_index_record_and_retains_both_parents() {
    let dir = init_repo("engine-merge");
    commit_file(dir.path(), "base.txt", "base\n");
    let original = crate::status::current_branch_at(dir.path()).unwrap();
    create_branch(dir.path(), "incoming");
    commit_file(dir.path(), "own.txt", "own\n");
    checkout_branch(dir.path(), "incoming");
    commit_file(dir.path(), "incoming.txt", "incoming\n");
    checkout_branch(dir.path(), &original);
    let repo = git2::Repository::open(dir.path()).unwrap();
    let incoming = repo
        .find_branch("incoming", git2::BranchType::Local)
        .unwrap();
    let incoming = repo.reference_to_annotated_commit(incoming.get()).unwrap();
    repo.merge(&[&incoming], None, None).unwrap();
    let before = head(dir.path());
    let root = binding(dir.path());
    assert_eq!(
        GitWorkspaceEngine::default()
            .record(
                &root,
                &request(RecordSelection::Explicit(paths(&["own.txt"])))
            )
            .unwrap(),
        RecordOutcome::Skipped(RecordSkipReason::MergeInProgress)
    );
    assert_eq!(head(dir.path()), before);
    assert!(crate::commit::has_pending_merge(dir.path()).unwrap());
    recorded(
        GitWorkspaceEngine::default()
            .record(&root, &request(RecordSelection::StagedIndex))
            .unwrap(),
    );
    assert_eq!(
        repo.head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .parent_count(),
        2
    );
    assert!(!crate::commit::has_pending_merge(dir.path()).unwrap());
}

#[test]
fn native_status_reports_real_index_conflicts() {
    let dir = init_repo("engine-conflict-status");
    commit_file(dir.path(), "shared.txt", "base\n");
    let original = crate::status::current_branch_at(dir.path()).unwrap();
    create_branch(dir.path(), "incoming");
    commit_file(dir.path(), "shared.txt", "ours\n");
    checkout_branch(dir.path(), "incoming");
    commit_file(dir.path(), "shared.txt", "theirs\n");
    checkout_branch(dir.path(), &original);
    let repo = git2::Repository::open(dir.path()).unwrap();
    let incoming = repo
        .find_branch("incoming", git2::BranchType::Local)
        .unwrap();
    let incoming = repo.reference_to_annotated_commit(incoming.get()).unwrap();
    repo.merge(&[&incoming], None, None).unwrap();
    let status = GitWorkspaceEngine::default()
        .status(&binding(dir.path()))
        .unwrap();
    assert_eq!(status.conflicts, Some(1));
    assert!(status
        .files
        .iter()
        .filter(|file| file.path == "shared.txt")
        .all(|file| file.conflicted == Some(true)));
    assert!(status.files.iter().any(|file| file.path == "shared.txt"));
}

#[test]
fn explicit_submodule_internal_record_refuses_before_mutating_index_or_head() {
    let child = init_repo("engine-submodule-child");
    commit_file(child.path(), "lib.txt", "base\n");
    let parent = init_repo("engine-submodule-parent");
    commit_file(parent.path(), "readme.txt", "base\n");
    crate::testutil::add_submodule(parent.path(), child.path(), "sub");
    write_file(parent.path(), "sub/lib.txt", "dirty\n");
    let repo = git2::Repository::open(parent.path()).unwrap();
    let before_head = head(parent.path());
    let before_index = repo.index().unwrap().write_tree().unwrap();
    let result = GitWorkspaceEngine::default().record(
        &binding(parent.path()),
        &request(RecordSelection::Explicit(paths(&["sub/lib.txt"]))),
    );
    assert!(matches!(result, Err(vcs::VcsError::Backend(_))));
    assert_eq!(head(parent.path()), before_head);
    assert_eq!(repo.index().unwrap().write_tree().unwrap(), before_index);
    assert_eq!(
        std::fs::read_to_string(parent.path().join("sub/lib.txt")).unwrap(),
        "dirty\n"
    );
}

fn capture(engine: &GitWorkspaceEngine, root: &vcs::RootBinding) -> vcs::CapturedState {
    engine
        .capture(
            root,
            &vcs::CapturePermit {
                operation_id: vcs::OperationId::from_string("test-capture"),
                binding_epoch: root.epoch,
                strength: vcs::CaptureStrength::Full,
                excluded_paths: vec![],
            },
        )
        .unwrap()
}

#[test]
fn comparison_reads_retained_working_bytes_after_live_edits() {
    let dir = init_repo("engine-compare-snapshot");
    commit_file(dir.path(), "a.txt", "recorded\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let before = capture(&engine, &root);
    write_file(dir.path(), "a.txt", "captured\n");
    let after = capture(&engine, &root);
    write_file(dir.path(), "a.txt", "later live edit\n");
    let query = vcs::DiffQuery {
        paths: vec![],
        max_bytes: 64_000,
    };
    let page = engine.compare(&before, &after, &query, None).unwrap();
    assert_eq!(page.before, page.after);
    assert_ne!(page.before_capture, page.after_capture);
    assert_eq!(page.files.len(), 1);
    assert!(page.files[0]
        .hunks
        .iter()
        .flat_map(|hunk| &hunk.lines)
        .any(|line| line.kind == vcs::DiffLineKind::Addition && line.content == "captured\n"));
    assert!(!page.files[0]
        .hunks
        .iter()
        .flat_map(|hunk| &hunk.lines)
        .any(|line| line.content.contains("later live edit")));
}

#[test]
fn comparison_pages_bind_query_and_snapshots_and_preserve_every_path() {
    let dir = init_repo("engine-compare-pages");
    commit_file(dir.path(), "seed.txt", "seed\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let before = capture(&engine, &root);
    for n in 0..800 {
        write_file(dir.path(), &format!("files/f{n:04}.txt"), "new content\n");
    }
    let after = capture(&engine, &root);
    let query = vcs::DiffQuery {
        paths: vec![],
        max_bytes: 64_000,
    };
    let first = engine.compare(&before, &after, &query, None).unwrap();
    let token = first.next_token.clone().expect("many files need paging");
    let other_query = vcs::DiffQuery {
        paths: paths(&["seed.txt"]),
        max_bytes: 64_000,
    };
    assert!(matches!(
        engine.compare(&before, &after, &other_query, Some(&token)),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    assert!(matches!(
        GitWorkspaceEngine::default().compare(&before, &after, &query, Some(&token)),
        Err(vcs::VcsError::Unavailable { .. })
    ));
    let mut page = first;
    let mut seen = HashSet::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(json_bytes(&page).unwrap().len() <= 64_000);
        for file in page.files {
            assert!(seen.insert(file.file.path));
        }
        let Some(token) = page.next_token else { break };
        assert!(pages < 100, "comparison must advance the cursor");
        page = engine
            .compare(&before, &after, &query, Some(&token))
            .unwrap();
    }
    assert!(pages > 1);
    assert_eq!(seen.len(), 800);
}

#[test]
fn comparison_reports_oversize_body_without_dropping_the_file() {
    let dir = init_repo("engine-compare-large-file");
    commit_file(dir.path(), "seed.txt", "seed\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let before = capture(&engine, &root);
    write_file(
        dir.path(),
        "large.txt",
        &"a long new line with enough text to exceed the body budget\n".repeat(4000),
    );
    let after = capture(&engine, &root);
    let page = engine
        .compare(
            &before,
            &after,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 64_000,
            },
            None,
        )
        .unwrap();
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].file.path, "large.txt");
    assert_eq!(
        page.files[0].truncated_reason,
        Some(vcs::DiffOmission::FileTooLarge)
    );
    assert!(page.files[0].hunks.is_empty());
    assert!(page.next_token.is_none());
    assert!(json_bytes(&page).unwrap().len() <= 64_000);
}

#[test]
fn unborn_recorded_state_and_capture_do_not_invent_a_head_commit() {
    let dir = init_repo("engine-unborn");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let state = engine.recorded_state(&root).unwrap();
    assert!(
        matches!(&state, vcs::NativeStateRef::Git { commit: None, tree, .. } if tree.as_str() == "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
    );
    let repo = git2::Repository::open(dir.path()).unwrap();
    // libgit2 can synthesize the canonical empty tree on a read even when no
    // loose object exists. Check disk rather than mistaking that read for a write.
    assert!(!repo
        .path()
        .join("objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904")
        .exists());
    let before = capture(&engine, &root);
    write_file(dir.path(), "first.txt", "staged\n");
    crate::stage::stage(dir.path(), &paths(&["first.txt"])).unwrap();
    write_file(dir.path(), "first.txt", "working\n");
    let after = capture(&engine, &root);
    assert_eq!(after.state, state);
    assert!(matches!(
        after.working_copy,
        vcs::CapturedWorkingCopy::GitUnborn { .. }
    ));
    let page = engine
        .compare(
            &before,
            &after,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 64_000,
            },
            None,
        )
        .unwrap();
    assert_eq!(page.files[0].file.path, "first.txt");
    assert!(page.files[0]
        .hunks
        .iter()
        .flat_map(|hunk| &hunk.lines)
        .any(|line| line.content == "working\n"));
    assert!(repo.head().is_err());
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "first.txt").unwrap(),
        "staged\n"
    );
}

#[test]
fn rooted_reads_preserve_binary_bytes_and_frozen_history_inputs() {
    let dir = init_repo("engine-rooted-reads");
    commit_file(dir.path(), "a.txt", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let snapshot = engine
        .capture_history_refresh(&root, None, None)
        .unwrap()
        .unwrap()
        .history;
    let binary = vec![0, 255, 1, 0, 42];
    std::fs::write(dir.path().join("binary"), &binary).unwrap();
    engine.stage(&root, &paths(&["binary"])).unwrap();
    recorded(
        engine
            .record(&root, &request(RecordSelection::StagedIndex))
            .unwrap(),
    );
    assert_eq!(
        engine
            .show_file_bytes(&root, &vcs::RevisionSpec::Head, "binary")
            .unwrap(),
        binary
    );
    let history = engine
        .history(
            &root,
            &vcs::HistoryRead::Snapshot {
                snapshot: snapshot.clone(),
                limit: 10,
                include_older: false,
                include_files: true,
            },
        )
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].change, snapshot.head);
    let details = engine
        .change_details(
            &root,
            &vcs::RevisionSpec::GitRef {
                reference: "HEAD".into(),
            },
        )
        .unwrap();
    assert_eq!(details.files[0].path, "binary");
    assert!(matches!(
        engine.change_details(
            &root,
            &vcs::RevisionSpec::GitRef {
                reference: "missing-ref".into()
            }
        ),
        Err(vcs::VcsError::Backend(Error::NotFound(_)))
    ));
}

#[cfg(unix)]
#[test]
fn materialization_and_portable_closure_reproduce_bytes_without_the_source_repository() {
    let dir = init_repo("engine-closure");
    commit_file(dir.path(), "a.txt", "one\n");
    commit_file(dir.path(), "a.txt", "two\r\n");
    let binary = vec![0, 255, 7, 0];
    std::fs::write(dir.path().join("binary"), &binary).unwrap();
    crate::stage::stage(dir.path(), &paths(&["binary"])).unwrap();
    crate::commit::commit(dir.path(), "feat: binary").unwrap();
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let state = engine.recorded_state(&root).unwrap();
    let target = tempfile::tempdir().unwrap();
    let first = engine
        .materialize(&root, &state, &target.path().join("materialized"))
        .unwrap();
    assert_eq!(
        std::fs::read(first.destination.join("binary")).unwrap(),
        binary
    );
    assert_eq!(
        std::fs::read(first.destination.join("a.txt")).unwrap(),
        crate::show::show_file_bytes(dir.path(), "HEAD", "a.txt").unwrap()
    );
    let closure = engine
        .export_closure(
            &root,
            &state,
            &vcs::RetentionGrant {
                operation_id: vcs::OperationId::from_string("export-one"),
                repository_id: root.repository_id.clone(),
                binding_epoch: root.epoch,
            },
            target.path(),
        )
        .unwrap();
    assert_eq!(closure.changes.len(), 3);
    std::fs::remove_dir_all(dir.path().join(".git")).unwrap();
    let restored = engine
        .restore_closure(&closure, &target.path().join("restored"))
        .unwrap();
    assert_eq!(restored.materialization_id, first.materialization_id);
    assert_eq!(
        std::fs::read(restored.destination.join("binary")).unwrap(),
        binary
    );
    assert_eq!(
        crate::history::history(&restored.destination, 10)
            .unwrap()
            .len(),
        3
    );
}

#[cfg(unix)]
#[test]
fn closure_tampering_and_existing_destinations_are_refused_without_overwriting() {
    let dir = init_repo("engine-closure-refuse");
    commit_file(dir.path(), "a.txt", "source\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let state = engine.recorded_state(&root).unwrap();
    let target = tempfile::tempdir().unwrap();
    let existing = target.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("sentinel"), b"keep").unwrap();
    assert!(engine.materialize(&root, &state, &existing).is_err());
    assert_eq!(std::fs::read(existing.join("sentinel")).unwrap(), b"keep");
    let grant = vcs::RetentionGrant {
        operation_id: vcs::OperationId::from_string("export"),
        repository_id: root.repository_id.clone(),
        binding_epoch: root.epoch,
    };
    let closure = engine
        .export_closure(&root, &state, &grant, target.path())
        .unwrap();
    let pack = closure.spool_path.parent().unwrap().join("objects.pack");
    let mut bytes = std::fs::read(&pack).unwrap();
    bytes[0] ^= 1;
    std::fs::write(pack, bytes).unwrap();
    let destination = target.path().join("tampered");
    assert!(matches!(
        engine.restore_closure(&closure, &destination),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    assert!(!destination.exists());
    let mut different_epoch = grant;
    different_epoch.binding_epoch += 1;
    assert!(matches!(
        engine.export_closure(&root, &state, &different_epoch, target.path()),
        Err(vcs::VcsError::Stale { .. })
    ));
}

#[cfg(unix)]
#[test]
fn materialization_preserves_executable_modes_and_symlinks_and_refuses_symlink_destinations() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = init_repo("engine-materialize-modes");
    commit_file(dir.path(), "run", "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(
        dir.path().join("run"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    symlink("run", dir.path().join("link")).unwrap();
    crate::stage::stage(dir.path(), &paths(&["run", "link"])).unwrap();
    crate::commit::commit(dir.path(), "feat: modes").unwrap();
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let state = engine.recorded_state(&root).unwrap();
    let target = tempfile::tempdir().unwrap();
    let receipt = engine
        .materialize(&root, &state, &target.path().join("checkout"))
        .unwrap();
    assert_ne!(
        std::fs::metadata(receipt.destination.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        std::fs::read_link(receipt.destination.join("link")).unwrap(),
        Path::new("run")
    );
    let redirected = target.path().join("redirected");
    symlink(&receipt.destination, &redirected).unwrap();
    assert!(engine.materialize(&root, &state, &redirected).is_err());
    assert_eq!(
        std::fs::read(receipt.destination.join("run")).unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
}

#[cfg(unix)]
fn frozen_files(
    engine: &GitWorkspaceEngine,
    root: &vcs::RootBinding,
    directory: &Path,
    input: &[(&str, Option<&[u8]>)],
) -> vcs::FrozenSelection {
    let sealed = directory.join("sealed");
    std::fs::create_dir(&sealed).unwrap();
    let mut files = Vec::new();
    for (path, bytes) in input {
        if let Some(bytes) = bytes {
            let full = sealed.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, bytes).unwrap();
        }
        files.push(vcs::FrozenFile {
            path: (*path).into(),
            kind: if bytes.is_some() {
                vcs::FrozenFileKind::Regular
            } else {
                vcs::FrozenFileKind::Deletion
            },
            digest: bytes.map(content_digest),
            length: bytes.map_or(0, |bytes| u64::try_from(bytes.len()).unwrap()),
        });
    }
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let state = engine.recorded_state(root).unwrap();
    let manifest = vcs::FrozenSelectionManifest {
        format_version: 1,
        source_state: state.clone(),
        files,
    };
    let bytes = json_bytes(&manifest).unwrap();
    let manifest_path = directory.join("selection.json");
    std::fs::write(&manifest_path, &bytes).unwrap();
    vcs::FrozenSelection {
        binding: root.clone(),
        selection_id: vcs::SelectionId::from_string("selection-one"),
        source_state: state,
        manifest: content_digest(&bytes),
        manifest_path,
        sealed_source: sealed,
    }
}

#[cfg(unix)]
fn fixed_metadata() -> vcs::FixedRecordMetadata {
    vcs::FixedRecordMetadata {
        operation_id: vcs::OperationId::from_string("operation-one"),
        message: "feat: exact selected bytes".into(),
        author_name: "Intent Test".into(),
        author_email: "intent@example.test".into(),
        timestamp_seconds: 1_700_000_000,
        timezone_offset_minutes: 0,
        attribution_manifest: content_digest(b"attribution-one"),
    }
}

#[cfg(unix)]
#[test]
fn exact_preparation_is_byte_stable_and_admission_preserves_other_selections_and_live_edits() {
    let dir = init_repo("engine-exact-record");
    commit_file(dir.path(), "own.txt", "base\n");
    commit_file(dir.path(), "other.txt", "base\n");
    write_file(dir.path(), "other.txt", "other staged\n");
    crate::stage::stage(dir.path(), &paths(&["other.txt"])).unwrap();
    write_file(dir.path(), "own.txt", "later live edits\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("own.txt", Some(b"selected exact bytes\n"))],
    );
    let before_head = head(dir.path());
    let before_index = std::fs::read(
        git2::Repository::open(dir.path())
            .unwrap()
            .index()
            .unwrap()
            .path()
            .unwrap(),
    )
    .unwrap();
    let first = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    let second = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    assert_eq!(first.change, second.change);
    assert_eq!(first.envelope_digest, second.envelope_digest);
    assert_eq!(
        std::fs::read(&first.spool_path).unwrap(),
        std::fs::read(&second.spool_path).unwrap()
    );
    assert_eq!(head(dir.path()), before_head);
    assert_eq!(
        std::fs::read(
            git2::Repository::open(dir.path())
                .unwrap()
                .index()
                .unwrap()
                .path()
                .unwrap()
        )
        .unwrap(),
        before_index
    );
    let receipt = engine
        .admit_record(&root, &first, &selection.source_state)
        .unwrap();
    assert_eq!(receipt.change, first.change);
    assert!(!receipt.replayed);
    assert!(
        receipt.post_commit_error.is_none(),
        "{:?}",
        receipt.post_commit_error
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "own.txt").unwrap(),
        "selected exact bytes\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("own.txt")).unwrap(),
        "later live edits\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "other.txt").unwrap(),
        "other staged\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "other.txt").unwrap(),
        "base\n"
    );
    let recorded_head = head(dir.path());
    let replay = engine
        .admit_record(&root, &first, &selection.source_state)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(head(dir.path()), recorded_head);
    assert_eq!(crate::history::history(dir.path(), 10).unwrap().len(), 3);
}

#[cfg(unix)]
#[test]
fn exact_admission_rejects_an_advanced_state_without_touching_the_index() {
    let dir = init_repo("engine-exact-stale");
    commit_file(dir.path(), "own.txt", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("own.txt", Some(b"selected\n"))],
    );
    let prepared = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    commit_file(dir.path(), "other.txt", "other actor\n");
    let expected_head = head(dir.path());
    let repo = git2::Repository::open(dir.path()).unwrap();
    let expected_index = std::fs::read(repo.index().unwrap().path().unwrap()).unwrap();
    assert!(matches!(
        engine.admit_record(&root, &prepared, &selection.source_state),
        Err(vcs::VcsError::Stale { .. })
    ));
    assert_eq!(head(dir.path()), expected_head);
    assert_eq!(
        std::fs::read(repo.index().unwrap().path().unwrap()).unwrap(),
        expected_index
    );
}

#[cfg(unix)]
#[test]
fn exact_record_keeps_the_success_receipt_when_index_refresh_fails_then_replays_without_a_second_commit(
) {
    let dir = init_repo("engine-exact-index-repair");
    commit_file(dir.path(), "own.txt", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("own.txt", Some(b"selected\n"))],
    );
    let prepared = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    let repo = git2::Repository::open(dir.path()).unwrap();
    let lock = repo.path().join("index.lock");
    std::fs::write(&lock, b"external lock").unwrap();
    let receipt = engine
        .admit_record(&root, &prepared, &selection.source_state)
        .unwrap();
    assert!(receipt.post_commit_error.is_some());
    let committed = head(dir.path());
    assert_eq!(receipt.change, prepared.change);
    std::fs::remove_file(lock).unwrap();
    let replay = engine
        .admit_record(&root, &prepared, &selection.source_state)
        .unwrap();
    assert!(replay.replayed);
    assert!(
        replay.post_commit_error.is_none(),
        "{:?}",
        replay.post_commit_error
    );
    assert_eq!(head(dir.path()), committed);
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "own.txt").unwrap(),
        "selected\n"
    );
    assert_eq!(crate::history::history(dir.path(), 10).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn exact_record_preserves_a_selected_path_staged_by_someone_after_preparation() {
    let dir = init_repo("engine-exact-selection-race");
    commit_file(dir.path(), "own.txt", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("own.txt", Some(b"selected\n"))],
    );
    let prepared = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    write_file(dir.path(), "own.txt", "another selection\n");
    crate::stage::stage(dir.path(), &paths(&["own.txt"])).unwrap();
    let receipt = engine
        .admit_record(&root, &prepared, &selection.source_state)
        .unwrap();
    assert!(receipt.post_commit_error.is_some());
    assert_eq!(
        crate::show::show_file(dir.path(), "HEAD", "own.txt").unwrap(),
        "selected\n"
    );
    assert_eq!(
        crate::show::show_file(dir.path(), ":0", "own.txt").unwrap(),
        "another selection\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("own.txt")).unwrap(),
        "another selection\n"
    );
}

#[cfg(unix)]
#[test]
fn exact_record_supports_unborn_state_and_selected_deletions_without_payloads() {
    let dir = init_repo("engine-exact-unborn");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    write_file(dir.path(), "nested/first.txt", "first\n");
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("nested/first.txt", Some(b"first\n"))],
    );
    let prepared = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    engine
        .admit_record(&root, &prepared, &selection.source_state)
        .unwrap();
    let repo = git2::Repository::open(dir.path()).unwrap();
    assert_eq!(
        repo.head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .parent_count(),
        0
    );
    std::fs::remove_file(dir.path().join("nested/first.txt")).unwrap();
    let deletion_spool = tempfile::tempdir().unwrap();
    let deletion = frozen_files(
        &engine,
        &root,
        deletion_spool.path(),
        &[("nested/first.txt", None)],
    );
    let mut metadata = fixed_metadata();
    metadata.operation_id = vcs::OperationId::from_string("operation-delete");
    let prepared = engine
        .prepare_record(&deletion, &metadata, deletion_spool.path())
        .unwrap();
    engine
        .admit_record(&root, &prepared, &deletion.source_state)
        .unwrap();
    assert!(
        crate::show::show_file_bytes(dir.path(), "HEAD", "nested/first.txt")
            .unwrap()
            .is_empty()
    );
    assert!(repo.index().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn exact_preparation_and_admission_refuse_changed_or_tampered_payloads() {
    let dir = init_repo("engine-exact-tamper");
    commit_file(dir.path(), "own.txt", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("own.txt", Some(b"selected\n"))],
    );
    std::fs::write(selection.sealed_source.join("own.txt"), b"changed bytes\n").unwrap();
    assert!(matches!(
        engine.prepare_record(&selection, &fixed_metadata(), spool.path()),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    std::fs::write(selection.sealed_source.join("own.txt"), b"selected\n").unwrap();
    let prepared = engine
        .prepare_record(&selection, &fixed_metadata(), spool.path())
        .unwrap();
    let before_head = head(dir.path());
    std::fs::write(&prepared.spool_path, b"{}").unwrap();
    assert!(matches!(
        engine.admit_record(&root, &prepared, &selection.source_state),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    assert_eq!(head(dir.path()), before_head);
}

#[cfg(unix)]
#[test]
fn exact_preparation_never_traverses_a_symlink_parent_outside_the_sealed_source() {
    use std::os::unix::fs::symlink;
    let dir = init_repo("engine-exact-sealed-link");
    commit_file(dir.path(), "seed", "base\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let spool = tempfile::tempdir().unwrap();
    let selection = frozen_files(
        &engine,
        &root,
        spool.path(),
        &[("nested/file.txt", Some(b"selected\n"))],
    );
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("file.txt"),
        b"outside private payload\n",
    )
    .unwrap();
    std::fs::remove_dir_all(selection.sealed_source.join("nested")).unwrap();
    symlink(outside.path(), selection.sealed_source.join("nested")).unwrap();
    let outside_object =
        git2::Oid::hash_object(git2::ObjectType::Blob, b"outside private payload\n").unwrap();
    let repo = git2::Repository::open(dir.path()).unwrap();
    assert!(!repo.odb().unwrap().exists(outside_object));
    assert!(matches!(
        engine.prepare_record(&selection, &fixed_metadata(), spool.path()),
        Err(vcs::VcsError::InvalidInput { .. })
    ));
    assert!(!repo.odb().unwrap().exists(outside_object));
}

#[cfg(unix)]
#[test]
fn native_comparison_retains_mode_and_kind_changes_with_identical_blob_bytes() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = init_repo("engine-typed-mode-diff");
    commit_file(dir.path(), "same", "target");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let before = capture(&engine, &root);
    std::fs::set_permissions(
        dir.path().join("same"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let executable = capture(&engine, &root);
    let query = vcs::DiffQuery {
        paths: vec![],
        max_bytes: 64_000,
    };
    let page = engine.compare(&before, &executable, &query, None).unwrap();
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].file.old_mode, Some(0o100_644));
    assert_eq!(page.files[0].file.new_mode, Some(0o100_755));
    assert_eq!(page.files[0].file.old_object, page.files[0].file.new_object);
    assert!(page.files[0].hunks.is_empty());
    std::fs::remove_file(dir.path().join("same")).unwrap();
    symlink("target", dir.path().join("same")).unwrap();
    let linked = capture(&engine, &root);
    let page = engine.compare(&before, &linked, &query, None).unwrap();
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].file.old_mode, Some(0o100_644));
    assert_eq!(page.files[0].file.new_mode, Some(0o120_000));
    assert_eq!(page.files[0].file.old_object, page.files[0].file.new_object);
    assert!(page.files[0].hunks.is_empty());
}

#[cfg(not(unix))]
#[test]
fn native_durable_operations_refuse_unqualified_platforms_before_filesystem_effects() {
    let dir = init_repo("engine-platform-capabilities");
    commit_file(dir.path(), "seed", "seed\n");
    let root = binding(dir.path());
    let engine = GitWorkspaceEngine::default();
    let capabilities = engine.capabilities();
    assert!(!capabilities.exact_record);
    assert!(!capabilities.materialization);
    assert!(!capabilities.closure_export);
    assert!(!capabilities.closure_restore);
    let state = engine.recorded_state(&root).unwrap();
    let destination = dir.path().join("unqualified-materialization");
    assert!(matches!(
        engine.materialize(&root, &state, &destination),
        Err(vcs::VcsError::Unsupported { .. })
    ));
    assert!(!destination.exists());
}
