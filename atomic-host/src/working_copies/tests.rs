use super::*;
use intent_atomic_proto::baselines::{BaselinePolicy, ImportBaselineRequest};

#[path = "native_grants.rs"]
mod native_grants;

struct Fixture {
    directory: tempfile::TempDir,
    host: Host,
    binding: StoreBinding,
    baseline: BaselineRef,
    root: PathBuf,
}
fn fixture() -> Fixture {
    fixture_with_ignore_target(None)
}

fn fixture_with_ignore_target(ignore_target: Option<&Path>) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap();
    let config = crate::HostConfig {
        stores_dir: path.join("stores"),
        config_dir: path.join("config"),
        spool_dir: path.join("spool"),
    };
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    let host = Host::new(config).unwrap();
    host.reconcile().unwrap();
    host.initialize_store(&binding, "working-copy-fixture")
        .unwrap();
    let root = path.join("working");
    let git = git2::Repository::init(&root).unwrap();
    if let Some(target) = ignore_target {
        std::os::unix::fs::symlink(target, root.join(".gitignore")).unwrap();
    } else {
        std::fs::write(root.join(".gitignore"), b"node_modules/\ntarget/\n").unwrap();
    }
    std::fs::write(root.join("source.rs"), b"fn original() {}\n").unwrap();
    let mut index = git.index().unwrap();
    index.add_path(Path::new(".gitignore")).unwrap();
    index.add_path(Path::new("source.rs")).unwrap();
    index.write().unwrap();
    let tree = git.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Working fixture", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "frozen source",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "working-baseline".into(),
            binding: binding.clone(),
            source_path: root.clone(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap()
        .baseline;
    std::fs::create_dir(root.join("node_modules")).unwrap();
    std::fs::create_dir(root.join("target")).unwrap();
    std::fs::write(
        root.join("node_modules/cache.bin"),
        b"ignored dependency cache\0\xff",
    )
    .unwrap();
    std::fs::write(
        root.join("target/warm-build"),
        b"ignored compilation output",
    )
    .unwrap();
    std::fs::write(root.join(".env"), b"never disclose credential").unwrap();
    Fixture {
        directory,
        host,
        binding,
        baseline,
        root,
    }
}

#[test]
fn tracked_symlink_ignore_control_refuses_before_loading_its_host_target() {
    let canary = tempfile::tempdir().unwrap();
    let outside = canary
        .path()
        .canonicalize()
        .unwrap()
        .join("host-private-ignore");
    std::fs::write(&outside, b"host-only canary\0\xff").unwrap();
    let f = fixture_with_ignore_target(Some(&outside));
    let error = f
        .host
        .register_working_copy_capture(&f.binding, &f.baseline, &f.root, "unsafe-tracked-ignore")
        .err()
        .unwrap();
    assert!(matches!(
        error,
        HostError::Unsupported("warm-copy ignore controls must be ordinary files")
    ));
    assert_eq!(std::fs::read(outside).unwrap(), b"host-only canary\0\xff");
}

#[test]
fn untracked_nonregular_ignore_control_refuses_before_ignore_discovery() {
    let f = fixture();
    std::fs::create_dir(f.root.join(".ignore")).unwrap();
    let error = f
        .host
        .register_working_copy_capture(&f.binding, &f.baseline, &f.root, "unsafe-directory-ignore")
        .err()
        .unwrap();
    assert!(matches!(
        error,
        HostError::Unsupported("warm-copy ignore controls must be ordinary files")
    ));
}

#[test]
fn regular_ignore_rules_remain_active_while_excluded_metadata_is_pruned() {
    let f = fixture();
    let outside = f.directory.path().join("excluded-host-canary");
    std::fs::write(&outside, b"private canary").unwrap();
    let metadata = f.root.join(".atomic");
    std::fs::create_dir(&metadata).unwrap();
    let malformed = metadata.join(".ignore");
    std::fs::write(&malformed, b"[z-a]\n").unwrap();
    // Establish that descending into this writable metadata fixture would load
    // a real invalid ignore rule. No unsupported filenames or protected paths.
    let mut parser = ignore::gitignore::GitignoreBuilder::new(&metadata);
    assert!(parser.add(&malformed).is_some());
    std::os::unix::fs::symlink(&outside, metadata.join(".gitignore")).unwrap();
    // node_modules/target contain relevant untracked files: the regular root
    // .gitignore must still hide them. Excluded trees must never be descended.
    f.host
        .register_working_copy_capture(
            &f.binding,
            &f.baseline,
            &f.root,
            "regular-ignore-private-exclusions",
        )
        .unwrap();
    assert_eq!(std::fs::read(outside).unwrap(), b"private canary");
}

#[test]
fn malformed_relevant_ignore_policy_refuses_without_claiming_a_clean_parent() {
    let f = fixture();
    std::fs::write(f.root.join(".ignore"), b"[z-a]\n").unwrap();
    let error = f
        .host
        .register_working_copy_capture(
            &f.binding,
            &f.baseline,
            &f.root,
            "malformed-relevant-ignore",
        )
        .err()
        .unwrap();
    assert!(
        matches!(error, HostError::Native(message) if message.starts_with("working ignore policy:"))
    );
}
fn capture_owner(f: &Fixture) -> WorkingCopyOwner {
    let owner = f
        .host
        .register_working_copy_capture(&f.binding, &f.baseline, &f.root, "workspace-working-copy")
        .unwrap();
    let turn = owner
        .try_begin_turn("fixture-selection-reader", "fixture-selection-observation")
        .unwrap();
    turn.admit_writer().unwrap().set_selection(None).unwrap();
    drop(turn);
    owner
}

#[test]
fn dirty_parent_and_relevant_untracked_files_refuse_before_child_exists() {
    let f = fixture();
    let owner = capture_owner(&f);
    std::fs::write(f.root.join("source.rs"), b"unrecorded parent edit").unwrap();
    let error = f
        .host
        .capture_warm_child(
            owner.close_for_capture().unwrap(),
            "dirty",
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(error.to_string().contains("inherited-baseline-required"));
    std::fs::write(f.root.join("source.rs"), b"fn original() {}\n").unwrap();
    std::fs::write(f.root.join("new-source.rs"), b"relevant untracked").unwrap();
    assert!(f
        .host
        .capture_warm_child(
            owner.close_for_capture().unwrap(),
            "untracked",
            Duration::from_secs(1)
        )
        .unwrap_err()
        .to_string()
        .contains("relevant untracked"));
}

#[test]
fn exact_original_turn_and_writer_owners_close_late_admission_and_drain() {
    let f = fixture();
    let owner = capture_owner(&f);
    let turn = owner.try_begin_turn("agent", "original-attempt").unwrap();
    let writer = turn.admit_writer().unwrap();
    let closure = owner.close_for_capture().unwrap();
    assert!(turn.admit_writer().is_err());
    assert!(owner.try_begin_turn("agent", "replacement").is_err());
    drop(turn);
    assert!(
        closure.drain(Duration::ZERO).is_err(),
        "retiring a turn cannot release its admitted native primitive"
    );
    drop(writer);
    closure.drain(Duration::from_secs(1)).unwrap();
    drop(closure);
    let replacement = owner.try_begin_turn("agent", "replacement").unwrap();
    drop(replacement);
    let same = capture_owner(&f);
    assert!(
        Arc::ptr_eq(&owner.0, &same.0),
        "one physical allocation has one shared barrier"
    );
}

#[test]
fn active_selection_refuses_a_child_instead_of_substituting_checkpoint() {
    let f = fixture();
    let owner = capture_owner(&f);
    let turn = owner.try_begin_turn("agent", "selecting").unwrap();
    let writer = turn.admit_writer().unwrap();
    writer.set_selection(Some(&"1".repeat(64))).unwrap();
    drop(writer);
    drop(turn);
    assert!(f
        .host
        .capture_warm_child(
            owner.close_for_capture().unwrap(),
            "selected",
            Duration::from_secs(1)
        )
        .unwrap_err()
        .to_string()
        .contains("selection"));
}

#[test]
fn missing_selection_observation_never_becomes_an_empty_selection() {
    let f = fixture();
    let owner = f
        .host
        .register_working_copy_capture(&f.binding, &f.baseline, &f.root, "unobserved-working-copy")
        .unwrap();
    let error = f
        .host
        .capture_warm_child(
            owner.close_for_capture().unwrap(),
            "unknown-selection",
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(matches!(error, HostError::Unsupported(_)));
    assert!(error
        .to_string()
        .contains("selection observation is unavailable"));
    assert!(!f
        .host
        .config
        .spool_dir
        .join("working-copy-captures")
        .exists());
}

#[test]
fn warm_copy_preserves_ignored_bytes_and_source_or_refuses_unsupported_cow() {
    let f = fixture();
    let owner = capture_owner(&f);
    let original = manifest::scan(&f.root).unwrap();
    let head = git2::Repository::open(&f.root)
        .unwrap()
        .head()
        .unwrap()
        .target()
        .unwrap();
    let result = f.host.capture_warm_child(
        owner.close_for_capture().unwrap(),
        "warm",
        Duration::from_secs(1),
    );
    let capture = match result {
        Ok(capture) => capture,
        Err(HostError::Unsupported(reason)) => {
            #[cfg(target_os = "macos")]
            panic!("APFS positive warm-copy qualification refused: {reason}");
            #[cfg(not(target_os = "macos"))]
            {
                assert!(reason.contains("copy-on-write") || reason.contains("reflink"));
                assert_eq!(manifest::scan(&f.root).unwrap(), original);
                return;
            }
        }
        Err(error) => panic!("actual warm clone failed: {error}"),
    };
    assert_eq!(manifest::scan(&capture.path).unwrap(), original);
    assert_eq!(
        std::fs::read(capture.path.join("node_modules/cache.bin")).unwrap(),
        b"ignored dependency cache\0\xff"
    );
    assert_eq!(
        std::fs::read(capture.path.join("target/warm-build")).unwrap(),
        b"ignored compilation output"
    );
    assert!(!capture.path.join(".git").exists());
    assert!(!capture.path.join(".env").exists());
    assert_eq!(manifest::scan(&f.root).unwrap(), original);
    assert!(f.root.join(".env").exists());
    assert_eq!(
        git2::Repository::open(&f.root)
            .unwrap()
            .head()
            .unwrap()
            .target()
            .unwrap(),
        head
    );
    let replay = f
        .host
        .capture_warm_child(
            owner.close_for_capture().unwrap(),
            "warm",
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(capture, replay);
    std::fs::write(capture.path.join("source.rs"), b"child edit").unwrap();
    assert_eq!(
        std::fs::read(f.root.join("source.rs")).unwrap(),
        b"fn original() {}\n"
    );
    assert!(
        f.host
            .capture_warm_child(
                owner.close_for_capture().unwrap(),
                "warm",
                Duration::from_secs(1)
            )
            .is_err(),
        "tampered published copy is not accepted by replay"
    );
    assert!(f.directory.path().exists());
}

#[test]
fn capture_manifest_never_follows_a_working_symlink_outside_root() {
    let f = fixture();
    let outside = f.directory.path().join("outside-secret");
    std::fs::write(&outside, b"outside bytes").unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("target/outside-link")).unwrap();
    let entries = manifest::scan(&f.root).unwrap();
    let link = entries
        .iter()
        .find(|entry| entry.path == "target/outside-link")
        .unwrap();
    assert_eq!(link.kind, manifest::Kind::Symlink);
    assert_ne!(link.sha256, hash(b"outside bytes"));
    let file = manifest::open_root(&f.root).unwrap();
    assert!(manifest::open_beneath(&file, "target/outside-link", false).is_err());
}

#[test]
fn pinned_pointer_is_discovered_only_in_tree_and_private_writer_refuses_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().canonicalize().unwrap();
    let root = parent.join("private-working");
    let outside = parent.join("external-pointer");
    durable::private_dir(&root).unwrap();
    durable::private_dir(&outside).unwrap();
    let pointer = atomic_repository::RemoteSandboxPointer {
        repository: atomic_repository::RemoteRepositoryRef {
            authority: "isolated-fixture".into(),
            repository_id: "1".repeat(64),
        },
        view: "read-only-view".into(),
        view_id: None,
        token: "test-fixture-token-never-a-native-execution-grant".into(),
    };
    write_private_sandbox_pointer(&outside, &pointer).unwrap();
    assert!(
        atomic_repository::find_remote_sandbox(&root).is_none(),
        "the pinned discovery API has no external pointer argument"
    );
    let path = write_private_sandbox_pointer(&root, &pointer).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        atomic_repository::find_remote_sandbox(&root).unwrap().1,
        pointer
    );
    assert!(
        write_private_sandbox_pointer(&root, &pointer).is_err(),
        "existing credentials never overwrite implicitly"
    );
    std::fs::remove_file(&path).unwrap();
    let secret = parent.join("outside-secret");
    std::fs::write(&secret, b"keep exact bytes").unwrap();
    std::os::unix::fs::symlink(&secret, &path).unwrap();
    assert!(write_private_sandbox_pointer(&root, &pointer).is_err());
    assert_eq!(std::fs::read(secret).unwrap(), b"keep exact bytes");
}

#[test]
fn unmanaged_write_during_copy_retains_uncertainty_and_closes_original_owner() {
    let f = fixture();
    let owner = capture_owner(&f);
    let result = f.host.capture_warm_child_with(
        owner.close_for_capture().unwrap(),
        "unmanaged-race",
        Duration::from_secs(1),
        |_| {
            std::fs::write(f.root.join("source.rs"), b"late unmanaged write").unwrap();
        },
    );
    if matches!(result, Err(HostError::Unsupported(_))) {
        return;
    }
    assert!(matches!(result, Err(HostError::Uncertain(_))));
    assert!(owner.try_begin_turn("agent", "late-replacement").is_err());
    let journals = f.host.config.spool_dir.join("working-copy-captures");
    let journal: CaptureJournal =
        durable::read_json(&journals.join(format!("{}.json", hash(b"unmanaged-race")))).unwrap();
    assert_eq!(journal.phase, CapturePhase::Uncertain);
    assert!(journal.receipt.is_none());
}
