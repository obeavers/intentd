use super::*;
use crate::engine::GitWorkspaceEngine;
use intent_core::vcs::WorkspaceEngine;
use std::collections::BTreeMap;

#[cfg(unix)]
#[test]
fn composition_lease_holds_exclusion_until_the_guard_drops() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("composition.lock");
    let owner = open_lock(&path).unwrap();
    let competing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let (competing, error) =
        nix::fcntl::Flock::lock(competing, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .unwrap_err();
    assert_eq!(error, nix::errno::Errno::EWOULDBLOCK);
    drop(owner);
    assert!(
        nix::fcntl::Flock::lock(competing, nix::fcntl::FlockArg::LockExclusiveNonblock).is_ok()
    );
}

struct Fixture {
    source: crate::testutil::TempDir,
    spool: tempfile::TempDir,
    root: vcs::RootBinding,
    base: Oid,
    target: Oid,
}

fn commit(
    repo: &Repository,
    parents: &[Oid],
    message: &str,
    changes: &[(&str, &[u8], u32)],
) -> Oid {
    let mut index = Index::new().unwrap();
    if let Some(parent) = parents.first() {
        index
            .read_tree(&repo.find_commit(*parent).unwrap().tree().unwrap())
            .unwrap();
    }
    for (path, bytes, mode) in changes {
        if *mode == 0 {
            index.remove_path(Path::new(path)).unwrap();
        } else {
            index
                .add(&normal_entry(
                    path.as_bytes().to_vec(),
                    repo.blob(bytes).unwrap(),
                    *mode,
                ))
                .unwrap();
        }
    }
    let tree = index.write_tree_to(repo).unwrap();
    let parents: Vec<_> = parents
        .iter()
        .map(|id| repo.find_commit(*id).unwrap())
        .collect();
    let references: Vec<_> = parents.iter().collect();
    let signature = git2::Signature::new(
        "Original author",
        "author@example.test",
        &git2::Time::new(1, 0),
    )
    .unwrap();
    repo.commit(
        None,
        &signature,
        &signature,
        message,
        &repo.find_tree(tree).unwrap(),
        &references,
    )
    .unwrap()
}

fn fixture() -> Fixture {
    let source = crate::testutil::init_repo("private-composition");
    let repo = Repository::open(source.path()).unwrap();
    let base = commit(
        &repo,
        &[],
        "original base",
        &[
            (
                "shared.txt",
                b"one\ntwo\nthree\nfour\nfive\nsix\n",
                0o100_644,
            ),
            ("mode.txt", b"same bytes\n", 0o100_644),
            ("link", b"destination", 0o100_644),
            ("destination", b"target\n", 0o100_644),
            ("binary.bin", b"\0base\xff", 0o100_644),
        ],
    );
    let target = commit(
        &repo,
        &[base],
        "target context",
        &[("target.txt", b"target context\n", 0o100_644)],
    );
    repo.reference("refs/heads/main", target, true, "fixture target")
        .unwrap();
    repo.set_head("refs/heads/main").unwrap();
    repo.checkout_head(Some(
        git2::build::CheckoutBuilder::new()
            .force()
            .disable_filters(true),
    ))
    .unwrap();
    let root = vcs::RootBinding {
        workspace_id: "composition-workspace".into(),
        root_id: "primary".into(),
        repository_id: vcs::RepositoryId::from_string("composition-repository"),
        kind: vcs::VcsKind::Git,
        locator: source.path().into(),
        epoch: 7,
    };
    Fixture {
        source,
        spool: tempfile::Builder::new()
            .prefix("intent-composition-spool-")
            .tempdir()
            .unwrap(),
        root,
        base,
        target,
    }
}

fn request(
    f: &Fixture,
    repo: &Repository,
    operation: &str,
    changes: &[Oid],
) -> vcs::ComposeRequest {
    vcs::ComposeRequest {
        operation_id: vcs::OperationId::from_string(operation),
        base: state(&f.root, repo, Some(f.base)).unwrap(),
        changes: changes
            .iter()
            .map(|id| change_ref(&f.root, id.to_string()))
            .collect(),
        target: state(&f.root, repo, Some(f.target)).unwrap(),
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut pending = vec![root.to_path_buf()];
    let mut data = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                data.insert(relative, b"directory".to_vec());
                pending.push(path);
            } else if metadata.file_type().is_symlink() {
                use std::os::unix::ffi::OsStrExt;
                data.insert(
                    relative,
                    std::fs::read_link(path)
                        .unwrap()
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                );
            } else {
                data.insert(relative, std::fs::read(path).unwrap());
            }
        }
    }
    data
}

#[test]
fn both_orders_preserve_original_ancestry_and_leave_dirty_source_and_index_unchanged() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let left = commit(
        &repo,
        &[f.base],
        "left original",
        &[("left.txt", b"left\n", 0o100_644)],
    );
    let right = commit(
        &repo,
        &[f.base],
        "right original",
        &[("right.txt", b"right\n", 0o100_644)],
    );
    std::fs::write(f.source.path().join("shared.txt"), "staged user bytes\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("shared.txt")).unwrap();
    index.write().unwrap();
    std::fs::write(f.source.path().join("shared.txt"), "unstaged user bytes\n").unwrap();
    std::fs::write(f.source.path().join("untracked.txt"), "unrelated actor\n").unwrap();
    let before = snapshot(f.source.path());
    let engine = GitWorkspaceEngine::default();
    let first = engine
        .compose(
            &f.root,
            &request(&f, &repo, "left-right", &[left, right]),
            f.spool.path(),
        )
        .unwrap();
    let second = engine
        .compose(
            &f.root,
            &request(&f, &repo, "right-left", &[right, left]),
            f.spool.path(),
        )
        .unwrap();
    assert_eq!(
        first.materialization.materialization_id,
        second.materialization.materialization_id
    );
    assert!(first.candidate.conflicts.is_empty());
    assert_eq!(
        std::fs::read(first.materialization.destination.join("left.txt")).unwrap(),
        b"left\n"
    );
    assert_eq!(
        std::fs::read(first.materialization.destination.join("right.txt")).unwrap(),
        b"right\n"
    );
    assert_eq!(
        std::fs::read(first.materialization.destination.join("shared.txt")).unwrap(),
        b"one\ntwo\nthree\nfour\nfive\nsix\n"
    );
    assert_eq!(snapshot(f.source.path()), before);
    let proof = first.receipt.receipt();
    assert_eq!(
        proof.selected_changes,
        vec![
            change_ref(&f.root, left.to_string()),
            change_ref(&f.root, right.to_string())
        ]
    );
    assert!(!proof.composition_only_changes.is_empty());
    for original in [f.base, f.target, left, right] {
        assert!(proof
            .full_closed_changes
            .contains(&change_ref(&f.root, original.to_string())));
    }
    let candidate = Repository::open(&first.materialization.destination).unwrap();
    assert_eq!(
        candidate.find_commit(left).unwrap().parent_id(0).unwrap(),
        f.base
    );
    assert_eq!(
        candidate.find_commit(right).unwrap().parent_id(0).unwrap(),
        f.base
    );
    for preview in &proof.composition_only_changes {
        assert!(!proof.selected_changes.contains(preview));
        assert!(!proof.dependency_only_changes.contains(preview));
    }
}

#[test]
fn same_file_disjoint_edits_are_native_clean_merges_in_both_orders() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let left = commit(
        &repo,
        &[f.base],
        "first line",
        &[(
            "shared.txt",
            b"ONE\ntwo\nthree\nfour\nfive\nsix\n",
            0o100_644,
        )],
    );
    let right = commit(
        &repo,
        &[f.base],
        "last line",
        &[(
            "shared.txt",
            b"one\ntwo\nthree\nfour\nfive\nSIX\n",
            0o100_644,
        )],
    );
    let engine = GitWorkspaceEngine::default();
    for (operation, changes) in [
        ("lines-left", [left, right]),
        ("lines-right", [right, left]),
    ] {
        let prepared = engine
            .compose(
                &f.root,
                &request(&f, &repo, operation, &changes),
                f.spool.path(),
            )
            .unwrap();
        assert!(prepared.candidate.conflicts.is_empty());
        assert_eq!(
            std::fs::read(prepared.materialization.destination.join("shared.txt")).unwrap(),
            b"ONE\ntwo\nthree\nfour\nfive\nSIX\n"
        );
    }
}

#[test]
fn conflicts_retain_all_native_stages_and_never_become_a_clean_receipt() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let left = commit(
        &repo,
        &[f.base],
        "left conflict",
        &[("shared.txt", b"LEFT\n", 0o100_644)],
    );
    let right = commit(
        &repo,
        &[f.base],
        "right conflict",
        &[("shared.txt", b"RIGHT\n", 0o100_644)],
    );
    let before = snapshot(f.source.path());
    let engine = GitWorkspaceEngine::default();
    let input = request(&f, &repo, "conflicting", &[left, right]);
    let prepared = engine.compose(&f.root, &input, f.spool.path()).unwrap();
    assert_eq!(prepared.candidate.conflicts.len(), 1);
    let conflict = &prepared.candidate.conflicts[0];
    assert_eq!(conflict.path, "shared.txt");
    let Some(vcs::ConflictDetails::Git {
        conflict_kind: vcs::GitConflictKind::Content,
        ancestor: Some(ancestor),
        ours: Some(ours),
        theirs: Some(theirs),
    }) = &conflict.details
    else {
        panic!("exact three native stages required")
    };
    assert_eq!(
        ancestor.object.as_str(),
        repo.find_commit(f.base)
            .unwrap()
            .tree()
            .unwrap()
            .get_name("shared.txt")
            .unwrap()
            .id()
            .to_string()
    );
    assert_eq!(
        ours.object.as_str(),
        repo.find_commit(left)
            .unwrap()
            .tree()
            .unwrap()
            .get_name("shared.txt")
            .unwrap()
            .id()
            .to_string()
    );
    assert_eq!(
        theirs.object.as_str(),
        repo.find_commit(right)
            .unwrap()
            .tree()
            .unwrap()
            .get_name("shared.txt")
            .unwrap()
            .id()
            .to_string()
    );
    assert!(prepared.receipt.receipt().conflict_manifest.is_some());
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&prepared.manifest_path).unwrap()).unwrap();
    assert!(retained.get("conflictManifest").is_some());
    assert!(retained.get("conflictsDigest").is_none());
    let rendered =
        std::fs::read_to_string(prepared.materialization.destination.join("shared.txt")).unwrap();
    assert!(rendered.contains("<<<<<<< target"));
    assert!(rendered.contains("LEFT"));
    assert!(rendered.contains("RIGHT"));
    let repeated = engine.compose(&f.root, &input, f.spool.path()).unwrap();
    assert_eq!(prepared.receipt.receipt(), repeated.receipt.receipt());
    assert_eq!(
        prepared.materialization.destination,
        repeated.materialization.destination
    );
    let diff = engine
        .compare_composition(
            &f.root,
            &prepared,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 480_000,
            },
            None,
        )
        .unwrap();
    assert!(diff.files.iter().any(|file| file.file.path == "shared.txt"));
    assert_eq!(snapshot(f.source.path()), before);
}

#[test]
fn actual_parent_dependencies_are_retained_and_explicit_selected_ancestors_are_not_replayed() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let dependency = commit(
        &repo,
        &[f.base],
        "required parent",
        &[("dependency.txt", b"dependency\n", 0o100_644)],
    );
    let child = commit(
        &repo,
        &[dependency],
        "selected child",
        &[("child.txt", b"child\n", 0o100_644)],
    );
    let engine = GitWorkspaceEngine::default();
    let prepared = engine
        .compose(
            &f.root,
            &request(&f, &repo, "child-only", &[child]),
            f.spool.path(),
        )
        .unwrap();
    assert_eq!(
        prepared.receipt.receipt().dependency_only_changes,
        vec![change_ref(&f.root, dependency.to_string())]
    );
    assert_eq!(
        prepared.candidate.required_dependencies,
        prepared.receipt.receipt().dependency_only_changes
    );
    for (operation, selected) in [
        ("child-parent", [child, dependency]),
        ("parent-child", [dependency, child]),
    ] {
        let other = engine
            .compose(
                &f.root,
                &request(&f, &repo, operation, &selected),
                f.spool.path(),
            )
            .unwrap();
        assert!(other.receipt.receipt().dependency_only_changes.is_empty());
        assert_eq!(
            prepared.materialization.materialization_id,
            other.materialization.materialization_id
        );
    }
    let retained = Repository::open(&prepared.materialization.destination).unwrap();
    assert_eq!(
        retained.find_commit(child).unwrap().parent_id(0).unwrap(),
        dependency
    );
}

#[test]
fn tracked_binary_empty_executable_and_symlink_modes_remain_typed() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let changes = commit(
        &repo,
        &[f.base],
        "typed files",
        &[
            ("mode.txt", b"same bytes\n", 0o100_755),
            ("link", b"destination", 0o120_000),
            ("binary.bin", b"\0changed\xff\r\n", 0o100_644),
            ("empty", b"", 0o100_644),
        ],
    );
    let engine = GitWorkspaceEngine::default();
    let prepared = engine
        .compose(
            &f.root,
            &request(&f, &repo, "modes", &[changes]),
            f.spool.path(),
        )
        .unwrap();
    assert!(
        std::fs::symlink_metadata(prepared.materialization.destination.join("link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_link(prepared.materialization.destination.join("link")).unwrap(),
        Path::new("destination")
    );
    assert_ne!(
        std::fs::metadata(prepared.materialization.destination.join("mode.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        std::fs::read(prepared.materialization.destination.join("binary.bin")).unwrap(),
        b"\0changed\xff\r\n"
    );
    assert!(
        std::fs::read(prepared.materialization.destination.join("empty"))
            .unwrap()
            .is_empty()
    );
    let diff = engine
        .compare_composition(
            &f.root,
            &prepared,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 480_000,
            },
            None,
        )
        .unwrap();
    let mode = diff
        .files
        .iter()
        .find(|file| file.file.path == "mode.txt")
        .unwrap();
    assert_eq!(
        (mode.file.old_mode, mode.file.new_mode),
        (Some(0o100_644), Some(0o100_755))
    );
    let link = diff
        .files
        .iter()
        .find(|file| file.file.path == "link")
        .unwrap();
    assert_eq!(
        (link.file.old_mode, link.file.new_mode),
        (Some(0o100_644), Some(0o120_000))
    );
    assert!(
        diff.files
            .iter()
            .find(|file| file.file.path == "binary.bin")
            .unwrap()
            .file
            .is_binary
    );
}

#[test]
fn missing_refs_foreign_scope_and_unaccepted_inherited_baseline_leave_target_untouched() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let dependency = commit(
        &repo,
        &[f.base],
        "unaccepted inherited",
        &[("parent.txt", b"parent", 0o100_644)],
    );
    let child = commit(
        &repo,
        &[dependency],
        "child",
        &[("child.txt", b"child", 0o100_644)],
    );
    let before = snapshot(f.source.path());
    let engine = GitWorkspaceEngine::default();
    let mut input = request(&f, &repo, "blocked", &[child]);
    input.base = state(&f.root, &repo, Some(dependency)).unwrap();
    assert!(matches!(
        engine.compose(&f.root, &input, f.spool.path()),
        Err(vcs::VcsError::PolicyBlocked {
            reason: vcs::CompositionBlock::InheritedBaselineRequired,
            ..
        })
    ));
    input = request(&f, &repo, "missing", &[]);
    input.changes = vec![change_ref(&f.root, "f".repeat(40))];
    assert!(engine.compose(&f.root, &input, f.spool.path()).is_err());
    input = request(&f, &repo, "foreign", &[child]);
    let vcs::NativeChangeRef::Git { repository_id, .. } = &mut input.changes[0] else {
        unreachable!()
    };
    *repository_id = vcs::RepositoryId::from_string("foreign");
    assert!(engine.compose(&f.root, &input, f.spool.path()).is_err());
    assert_eq!(snapshot(f.source.path()), before);
}

#[test]
fn portable_receipt_and_closure_restore_after_all_original_sources_are_removed() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let left = commit(
        &repo,
        &[f.base],
        "portable source",
        &[("portable.txt", b"retained bytes\n", 0o100_644)],
    );
    let engine = GitWorkspaceEngine::default();
    let mut prepared = engine
        .compose(
            &f.root,
            &request(&f, &repo, "portable", &[left]),
            f.spool.path(),
        )
        .unwrap();
    let receipt = prepared.receipt.receipt().clone();
    drop(repo);
    std::fs::remove_dir_all(f.source.path()).unwrap();
    let destination = tempfile::Builder::new()
        .prefix("intent-portable-composition-")
        .tempdir()
        .unwrap();
    let restored = engine
        .restore_closure(&prepared.closure, &destination.path().join("restored"))
        .unwrap();
    assert_eq!(restored.state, receipt.candidate_state);
    assert_eq!(restored.materialization_id, receipt.materialization_id);
    let retained_receipt: NativeCompositionReceipt = serde_json::from_slice(
        &read(
            &prepared
                .manifest_path
                .parent()
                .unwrap()
                .join("receipt.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(retained_receipt, receipt);
    let original_private = prepared.materialization.destination.clone();
    prepared.materialization.destination = restored.destination;
    std::fs::remove_dir_all(original_private).unwrap();
    assert_eq!(
        std::fs::read(prepared.materialization.destination.join("portable.txt")).unwrap(),
        b"retained bytes\n"
    );
    let diff = engine
        .compare_composition(
            &f.root,
            &prepared,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 480_000,
            },
            None,
        )
        .unwrap();
    assert!(diff
        .files
        .iter()
        .any(|file| file.file.path == "portable.txt"));
}

#[test]
fn operation_replay_and_epoch_fences_reject_new_meanings_without_overwriting_a_candidate() {
    let f = fixture();
    let repo = Repository::open(f.source.path()).unwrap();
    let left = commit(&repo, &[f.base], "left", &[("left", b"left", 0o100_644)]);
    let right = commit(&repo, &[f.base], "right", &[("right", b"right", 0o100_644)]);
    let engine = GitWorkspaceEngine::default();
    let mut input = request(&f, &repo, "fixed-operation", &[left]);
    let prepared = engine.compose(&f.root, &input, f.spool.path()).unwrap();
    let before = snapshot(prepared.manifest_path.parent().unwrap());
    input.changes = vec![change_ref(&f.root, right.to_string())];
    assert!(engine.compose(&f.root, &input, f.spool.path()).is_err());
    assert_eq!(snapshot(prepared.manifest_path.parent().unwrap()), before);
    let mut rebound = f.root.clone();
    rebound.epoch += 1;
    assert!(matches!(
        engine.compare_composition(
            &rebound,
            &prepared,
            &vcs::DiffQuery {
                paths: vec![],
                max_bytes: 480_000
            },
            None
        ),
        Err(vcs::VcsError::Stale { .. })
    ));
}
use std::path::PathBuf;
