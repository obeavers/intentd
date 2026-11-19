use super::*;
use crate::engine::GitWorkspaceEngine;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct Fixture {
    directory: tempfile::TempDir,
    root: vcs::RootBinding,
    spool: PathBuf,
    engine: GitWorkspaceEngine,
    candidate: vcs::PreparedComposition,
}
fn commit(repo: &Repository, message: &str) -> Oid {
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    let signature = repo.signature().unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parent.iter().collect::<Vec<_>>(),
    )
    .unwrap()
}
fn permit(root: &vcs::RootBinding, operation: &str) -> (vcs::WriteBarrierPermit, Arc<AtomicBool>) {
    let live = Arc::new(AtomicBool::new(true));
    (
        vcs::WriteBarrierPermit::from_admitted_write_barrier(
            root.clone(),
            vcs::OperationId::from_string(operation),
            live.clone(),
        )
        .unwrap(),
        live,
    )
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let repo = Repository::init(&path).unwrap();
    repo.config()
        .unwrap()
        .set_str("user.name", "Adoption fixture")
        .unwrap();
    repo.config()
        .unwrap()
        .set_str("user.email", "adoption@example.test")
        .unwrap();
    std::fs::write(path.join("tracked.txt"), b"before\n").unwrap();
    std::fs::write(path.join("delete.txt"), b"remove me\n").unwrap();
    let base = commit(&repo, "actual base");
    let root = vcs::RootBinding {
        workspace_id: "adoption-workspace".into(),
        root_id: "primary".into(),
        repository_id: vcs::RepositoryId("actual-adoption-repository".into()),
        kind: vcs::VcsKind::Git,
        locator: path.canonicalize().unwrap(),
        epoch: 1,
    };
    let engine = GitWorkspaceEngine::default();
    let before = engine.recorded_state(&root).unwrap();
    std::fs::write(path.join("tracked.txt"), b"after\n").unwrap();
    std::fs::write(path.join("added.txt"), b"new exact bytes\0binary").unwrap();
    std::fs::remove_file(path.join("delete.txt")).unwrap();
    let selected = commit(&repo, "original selected edit");
    repo.set_head_detached(base).unwrap();
    repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .unwrap();
    let spool = directory.path().join("spool");
    private_directory(&spool).unwrap();
    let candidate = engine
        .compose(
            &root,
            &vcs::ComposeRequest {
                operation_id: vcs::OperationId::from_string("actual-composition"),
                base: before.clone(),
                changes: vec![super::super::change_ref(&root, selected.to_string())],
                target: before,
            },
            &spool,
        )
        .unwrap();
    Fixture {
        directory,
        root,
        spool,
        engine,
        candidate,
    }
}
fn prepared(
    f: &Fixture,
    operation: &str,
) -> (
    vcs::PreparedTargetCapture,
    vcs::PreparedAdoption,
    vcs::AdoptionAuthorization,
    vcs::WriteBarrierPermit,
    Arc<AtomicBool>,
) {
    let (capture_barrier, _) = permit(&f.root, &format!("capture-{operation}"));
    let capture = capture_target(&f.root, &capture_barrier, &f.spool).unwrap();
    let adoption = prepare(
        &f.root,
        &capture,
        &f.candidate,
        &vcs::OperationId::from_string(operation),
        &f.spool,
    )
    .unwrap();
    let authorization = vcs::AdoptionAuthorization::from_accepted_store_decision(
        vcs::AdoptionAuthorizationReceipt {
            decision_operation_id: vcs::OperationId::from_string(format!("decision-{operation}")),
            decision_receipt_digest: content_digest(b"actual accepted test decision"),
            offer_id: format!("offer-{operation}"),
            offer_digest: content_digest(b"exact offered candidate"),
            candidate_id: "candidate-1".into(),
            preparation: adoption.receipt().clone(),
        },
    )
    .unwrap();
    let (barrier, live) = permit(&f.root, operation);
    (capture, adoption, authorization, barrier, live)
}

#[test]
fn exact_adoption_writes_only_changed_paths_and_completed_replay_never_reapplies() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let (capture, prepared, authorization, barrier, _) = prepared(&f, "adopt-once");
    let operation = prepared.manifest_path().parent().unwrap();
    for directory in [
        capture.manifest_path().parent().unwrap().to_path_buf(),
        operation.to_path_buf(),
        operation.join("composition"),
    ] {
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700,
            "retained native custody directory is not private: {}",
            directory.display()
        );
    }
    let first = apply(&f.root, &barrier, &prepared, &authorization).unwrap();
    assert!(!first.replayed());
    assert_eq!(
        f.engine.recorded_state(&f.root).unwrap(),
        f.candidate.candidate.state
    );
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        b"after\n"
    );
    assert!(!f.root.locator.join("delete.txt").exists());
    assert_eq!(
        std::fs::read(f.root.locator.join("added.txt")).unwrap(),
        b"new exact bytes\0binary"
    );
    let retained = std::fs::read(first.receipt_path()).unwrap();
    std::fs::write(f.root.locator.join("tracked.txt"), b"later actor work\n").unwrap();
    let replay = read_receipt(
        &f.root,
        &prepared,
        &authorization.clone().into_reconciliation_only(),
    )
    .unwrap();
    assert!(replay.replayed());
    assert_eq!(std::fs::read(replay.receipt_path()).unwrap(), retained);
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        b"later actor work\n"
    );
    assert_eq!(first.receipt(), replay.receipt());
}

#[test]
fn fresh_capture_digest_is_stable_but_index_overlay_and_head_changes_refuse_before_effects() {
    let f = fixture();
    let (capture, prepared, authorization, barrier, _) = prepared(&f, "guarded");
    let (other, _) = permit(&f.root, "another-capture");
    let fresh = capture_target(&f.root, &other, &f.spool).unwrap();
    assert_eq!(
        capture.receipt().capture_digest,
        fresh.receipt().capture_digest
    );
    std::fs::write(
        f.root.locator.join("tracked.txt"),
        b"other actor dirty bytes\n",
    )
    .unwrap();
    assert!(matches!(
        apply(&f.root, &barrier, &prepared, &authorization),
        Err(vcs::VcsError::Stale { .. })
    ));
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        b"other actor dirty bytes\n"
    );
    assert!(!prepared
        .manifest_path()
        .parent()
        .unwrap()
        .join("journal.json")
        .exists());
    let repo = Repository::open(&f.root.locator).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("tracked.txt")).unwrap();
    index.write().unwrap();
    let (dirty_barrier, _) = permit(&f.root, "dirty-selection");
    let dirty = capture_target(&f.root, &dirty_barrier, &f.spool).unwrap();
    assert!(!dirty.receipt().clean);
    assert!(prepare(
        &f.root,
        &dirty,
        &f.candidate,
        &vcs::OperationId::from_string("must-not-prepare"),
        &f.spool
    )
    .is_err());
}

#[test]
fn closed_or_foreign_barriers_and_reconciliation_only_authorizations_cannot_write() {
    let f = fixture();
    let (_, prepared, authorization, barrier, live) = prepared(&f, "closed");
    live.store(false, Ordering::Release);
    assert!(apply(&f.root, &barrier, &prepared, &authorization).is_err());
    let (active, _) = permit(&f.root, "closed");
    assert!(apply(
        &f.root,
        &active,
        &prepared,
        &authorization.into_reconciliation_only()
    )
    .is_err());
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        b"before\n"
    );
    assert!(!prepared
        .manifest_path()
        .parent()
        .unwrap()
        .join("journal.json")
        .exists());
}

#[test]
fn racing_path_write_retains_actual_preimage_and_never_claims_a_terminal_receipt() {
    let f = fixture();
    let (_, prepared, authorization, barrier, _) = prepared(&f, "racing");
    let mut raced = false;
    let result = apply_checked(&f.root, &barrier, &prepared, &authorization, |phase| {
        if phase == "before-path-exchange" && !raced {
            raced = true;
            std::fs::write(
                f.root.locator.join("added.txt"),
                b"racing newly created file\n",
            )
            .unwrap();
        }
        Ok(())
    });
    assert!(matches!(result, Err(vcs::VcsError::Uncertain { .. })));
    assert_eq!(
        std::fs::read(f.root.locator.join("added.txt")).unwrap(),
        b"racing newly created file\n"
    );
    assert!(read_receipt(&f.root, &prepared, &authorization).is_err());
    assert!(reconcile(&f.root, &barrier, &prepared, &authorization).is_err());
}

#[test]
fn lost_terminal_write_can_be_proven_by_inspection_without_reapplying_files() {
    let f = fixture();
    let (_, prepared, authorization, barrier, _) = prepared(&f, "lost-terminal");
    let result = apply_checked(&f.root, &barrier, &prepared, &authorization, |phase| {
        if phase == "reference-complete" {
            Err(invalid("simulated receipt tail loss"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(vcs::VcsError::Uncertain { .. })));
    assert!(read_receipt(&f.root, &prepared, &authorization).is_err());
    let index = std::fs::read(f.root.locator.join(".git/index")).unwrap();
    let bytes = std::fs::read(f.root.locator.join("tracked.txt")).unwrap();
    let inspection = reconcile(
        &f.root,
        &barrier,
        &prepared,
        &authorization.clone().into_reconciliation_only(),
    )
    .unwrap();
    assert!(inspection.replayed());
    assert_eq!(
        std::fs::read(f.root.locator.join(".git/index")).unwrap(),
        index
    );
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        bytes
    );
}

#[test]
fn immutable_commands_and_terminal_receipts_reopen_after_original_target_disappears() {
    let f = fixture();
    let (capture, prepared, authorization, barrier, _) = prepared(&f, "portable-fact");
    let effect = apply(&f.root, &barrier, &prepared, &authorization).unwrap();
    std::fs::remove_dir_all(&f.root.locator).unwrap();
    let captured = reopen_capture(&f.root, capture.manifest_path()).unwrap();
    assert_eq!(captured.receipt(), capture.receipt());
    let reopened = reopen_preparation(&f.root, prepared.manifest_path()).unwrap();
    let retained = read_receipt(
        &f.root,
        &reopened,
        &authorization.into_reconciliation_only(),
    )
    .unwrap();
    assert_eq!(effect.receipt(), retained.receipt());
}

#[test]
fn successful_cas_fact_survives_later_ref_and_working_file_drift_without_a_complete_claim() {
    let f = fixture();
    let (_, prepared, authorization, barrier, _) = prepared(&f, "cas-before-drift");
    let mut foreign = None;
    let result = apply_checked(&f.root, &barrier, &prepared, &authorization, |phase| {
        if phase == "cas-fact-retained" {
            let repo = Repository::open(&f.root.locator).unwrap();
            let parent = repo.head().unwrap().peel_to_commit().unwrap();
            let blob = repo.blob(b"later external writer\n").unwrap();
            let mut tree = repo.treebuilder(Some(&parent.tree().unwrap())).unwrap();
            tree.insert("tracked.txt", blob, 0o100_644).unwrap();
            let tree = repo.find_tree(tree.write().unwrap()).unwrap();
            let signature = repo.signature().unwrap();
            let changed = repo
                .commit(
                    None,
                    &signature,
                    &signature,
                    "external ref advancement",
                    &tree,
                    &[&parent],
                )
                .unwrap();
            repo.reference(
                "HEAD",
                changed,
                true,
                "external ref writer after actual adoption CAS",
            )
            .unwrap();
            std::fs::write(
                f.root.locator.join("tracked.txt"),
                b"later external writer\n",
            )
            .unwrap();
            foreign = Some(changed);
        }
        Ok(())
    });
    assert!(matches!(result, Err(vcs::VcsError::Uncertain { .. })));
    let progress = read_progress(
        &f.root,
        &prepared,
        &authorization.clone().into_reconciliation_only(),
    )
    .unwrap();
    assert_eq!(
        progress.receipt().observation,
        vcs::AdoptionProgressObservation::CasReturnedSuccess
    );
    assert_eq!(
        progress.receipt().authorization.preparation.before,
        prepared.receipt().before
    );
    assert_eq!(
        progress.receipt().authorization.preparation.after,
        f.candidate.candidate.state
    );
    assert!(read_receipt(&f.root, &prepared, &authorization).is_err());
    assert!(reconcile(
        &f.root,
        &barrier,
        &prepared,
        &authorization.clone().into_reconciliation_only()
    )
    .is_err());
    assert!(apply(&f.root, &barrier, &prepared, &authorization).is_err());
    assert_eq!(
        Repository::open(&f.root.locator)
            .unwrap()
            .head()
            .unwrap()
            .target(),
        foreign
    );
    assert_eq!(
        std::fs::read(f.root.locator.join("tracked.txt")).unwrap(),
        b"later external writer\n"
    );
    assert_eq!(
        progress.receipt(),
        read_progress(&f.root, &prepared, &authorization)
            .unwrap()
            .receipt()
    );
}

#[test]
fn tracked_modes_symlink_bytes_and_unrelated_ignored_artifacts_are_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = fixture();
    let repo = Repository::open(&f.root.locator).unwrap();
    let base = repo.head().unwrap().target().unwrap();
    let before = f.engine.recorded_state(&f.root).unwrap();
    std::fs::remove_file(f.root.locator.join("tracked.txt")).unwrap();
    std::os::unix::fs::symlink(
        "unresolved-relative-target",
        f.root.locator.join("tracked.txt"),
    )
    .unwrap();
    std::fs::write(f.root.locator.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        f.root.locator.join("run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let selected = commit(&repo, "actual symlink and executable");
    repo.set_head_detached(base).unwrap();
    repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .unwrap();
    f.candidate = f
        .engine
        .compose(
            &f.root,
            &vcs::ComposeRequest {
                operation_id: vcs::OperationId::from_string("modes-composition"),
                base: before.clone(),
                changes: vec![super::super::change_ref(&f.root, selected.to_string())],
                target: before,
            },
            &f.spool,
        )
        .unwrap();
    std::fs::write(repo.commondir().join("info/exclude"), b"ignored.runtime\n").unwrap();
    std::fs::write(
        f.root.locator.join("ignored.runtime"),
        b"server output before\n",
    )
    .unwrap();
    let untouched = std::fs::metadata(f.root.locator.join("delete.txt"))
        .unwrap()
        .ino();
    let (_, prepared, authorization, barrier, _) = prepared(&f, "mode-adoption");
    std::fs::write(
        f.root.locator.join("ignored.runtime"),
        b"latest server output\n",
    )
    .unwrap();
    apply(&f.root, &barrier, &prepared, &authorization).unwrap();
    assert_eq!(
        std::fs::read_link(f.root.locator.join("tracked.txt")).unwrap(),
        Path::new("unresolved-relative-target")
    );
    assert_ne!(
        std::fs::metadata(f.root.locator.join("run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        std::fs::read(f.root.locator.join("ignored.runtime")).unwrap(),
        b"latest server output\n"
    );
    assert_eq!(
        std::fs::metadata(f.root.locator.join("delete.txt"))
            .unwrap()
            .ino(),
        untouched
    );
}

#[test]
fn ignored_symlink_parent_and_assume_unchanged_never_import_foreign_bytes() {
    let f = fixture();
    let repo = Repository::open(&f.root.locator).unwrap();
    let original = f.root.locator.join("dir");
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("file"), b"inside tracked bytes\n").unwrap();
    commit(&repo, "tracked nested baseline");
    let mut index = repo.index().unwrap();
    let mut entry = index.get_path(Path::new("dir/file"), 0).unwrap();
    entry.flags |= 0x8000;
    index.add(&entry).unwrap();
    index.write().unwrap();
    std::fs::write(repo.commondir().join("info/exclude"), b"dir\n").unwrap();
    let outside = f.directory.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let secret = b"FOREIGN bytes must never enter the target ODB - assume unchanged witness\n";
    std::fs::write(outside.join("file"), secret).unwrap();
    std::fs::rename(&original, f.directory.path().join("original-directory")).unwrap();
    std::os::unix::fs::symlink(&outside, &original).unwrap();
    let foreign = Oid::hash_object(git2::ObjectType::Blob, secret).unwrap();
    assert!(!repo.odb().unwrap().exists(foreign));
    let (barrier, _) = permit(&f.root, "no-foreign-capture");
    assert!(capture_target(&f.root, &barrier, &f.spool).is_err());
    assert!(
        !repo.odb().unwrap().exists(foreign),
        "no outside payload can be persisted before dirty refusal"
    );
    assert_eq!(std::fs::read(outside.join("file")).unwrap(), secret);
}

#[test]
fn parent_swap_between_listing_and_open_is_refused_by_the_actual_reader() {
    let f = fixture();
    let repo = Repository::open(&f.root.locator).unwrap();
    let original = f.root.locator.join("dir");
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("file"), b"safe original\n").unwrap();
    commit(&repo, "nested race baseline");
    let outside = f.directory.path().join("racing-outside");
    std::fs::create_dir(&outside).unwrap();
    let secret = b"FOREIGN parent-swap bytes must never be read or persisted\n";
    std::fs::write(outside.join("file"), secret).unwrap();
    let foreign = Oid::hash_object(git2::ObjectType::Blob, secret).unwrap();
    let mut swapped = false;
    let result =
        observation::read_target_checked(&repo, &f.root, &policy(&repo).unwrap(), |path| {
            if path == "dir" && !swapped {
                swapped = true;
                std::fs::rename(&original, f.directory.path().join("original-before-swap"))
                    .unwrap();
                std::os::unix::fs::symlink(&outside, &original).unwrap();
            }
        });
    assert!(swapped);
    assert!(result.is_err());
    assert!(!repo.odb().unwrap().exists(foreign));
    assert_eq!(std::fs::read(outside.join("file")).unwrap(), secret);
}

#[test]
fn regular_to_fifo_swap_between_stat_and_open_refuses_without_waiting_for_a_writer() {
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;
    let f = fixture();
    let root = fs::directory(&f.root.locator).unwrap();
    let path = f.root.locator.join("tracked.txt");
    let swapped_path = path.clone();
    let (completed, observed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = fs::payload_at_checked(&root, &fs::name("tracked.txt").unwrap(), || {
            std::fs::remove_file(&swapped_path).unwrap();
            let path = std::ffi::CString::new(swapped_path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        });
        completed.send(result).unwrap();
    });
    let received =
        observed.recv_timeout(intentd_test_support::test_timeout(Duration::from_secs(5)));
    if received.is_err() {
        // Rescue a regressed blocking reader so a failing test owns no stuck
        // worker. O_RDWR|O_NONBLOCK opens a FIFO without another endpoint.
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
                .unwrap(),
        );
        let _ = observed.recv_timeout(intentd_test_support::test_timeout(Duration::from_secs(5)));
    }
    worker.join().unwrap();
    assert!(
        received.is_ok(),
        "actual payload open waited for a FIFO writer"
    );
    assert!(
        received.unwrap().is_err(),
        "a changed nonregular leaf cannot become a payload"
    );
}
