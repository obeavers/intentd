//! Real process boundary: the daemon client never links native Atomic. Fixture
//! initialization occurs through the Rust owner before the actual child starts.
#![cfg(unix)]

use std::{
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use atomic_core::{change::ChangeHeader, Base32};
use atomic_repository::{InsertOptions, Repository};
use intent_atomic::{
    composition::{AtomicCompositionClient, AtomicCompositionPreparation},
    spool::Spool,
    HostLaunchConfig, HostSupervisor,
};
use intent_atomic_host::{Host, HostConfig};
use intent_atomic_proto::{
    baselines::{BaselinePolicy, ImportBaselineRequest},
    closures::{BaselineClosure, ClosureScope, ExportBaselineClosureRequest},
    composition::{
        CaptureCompositionTargetRequest, ExactCompositionChange, PrivateCompositionInput,
    },
    Command, Reply, StateToken, StoreBinding,
};
use intent_core::vcs::{NativeChangeRef, RepositoryId, RootBinding, VcsKind};

struct Fixture {
    _directory: tempfile::TempDir,
    daemon: PathBuf,
    stores: PathBuf,
    binding: StoreBinding,
    root: RootBinding,
    baseline: BaselineClosure,
    expected: StateToken,
    selected: ExactCompositionChange,
    source_manifest: String,
    source_changes: usize,
    git_head: git2::Oid,
}

fn private(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn state(repository: &Repository, view: &str) -> StateToken {
    StateToken {
        view: view.into(),
        effective_state: repository
            .sandbox_effective_state(view)
            .unwrap()
            .to_base32(),
        own_merkle: repository.get_view_info(view).unwrap().state_base32(),
    }
}
fn git_source(path: &Path) -> (git2::Repository, String) {
    let repository = git2::Repository::init(path).unwrap();
    let mut index = git2::Index::new().unwrap();
    for (name, mode, bytes) in [
        (
            "shared",
            0o100_644,
            b"one\ntwo\nthree\nfour\nfive\nsix\n".as_slice(),
        ),
        ("binary", 0o100_644, [0, 255, 1].as_slice()),
        (
            "executable",
            0o100_755,
            b"#!/bin/sh\r\necho exact\r\n".as_slice(),
        ),
        ("empty", 0o100_644, b"".as_slice()),
        ("link", 0o120_000, b"executable".as_slice()),
    ] {
        let id = repository.blob(bytes).unwrap();
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode,
                uid: 0,
                gid: 0,
                file_size: u32::try_from(bytes.len()).unwrap(),
                id,
                flags: 0,
                flags_extended: 0,
                path: name.as_bytes().to_vec(),
            })
            .unwrap();
    }
    let tree = repository
        .find_tree(index.write_tree_to(&repository).unwrap())
        .unwrap();
    let signature = git2::Signature::new(
        "IPC fixture",
        "fixture@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    let commit = repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "exact baseline",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    drop(tree);
    (repository, commit)
}
fn edit(repository: &Repository, view: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    let file = repository
        .record_foreign_modified_file_on_view_excluding(
            "shared",
            b"one\ntwo\nthree\nfour\nfive\nsix\n",
            bytes,
            false,
            view,
            &[],
        )
        .unwrap();
    let (change, _) = repository
        .assemble_and_hash(view, ChangeHeader::new(format!("fixture {view}")), &[file])
        .unwrap();
    let mut bytes = Vec::new();
    let hash = change.serialize(&mut bytes).unwrap();
    repository.import_change_bytes(&hash, &bytes).unwrap();
    repository
        .insert_change(&hash, InsertOptions::default().view(view))
        .unwrap();
    (hash.to_base32(), bytes)
}
fn fixture() -> Fixture {
    let directory = tempfile::Builder::new()
        .prefix("intent-ipc-")
        .tempdir_in("/tmp")
        .unwrap();
    let base = directory.path().canonicalize().unwrap();
    let daemon = base.join("daemon");
    private(&daemon);
    let owner = daemon.join("atomic");
    private(&owner);
    let stores = base.join("stores");
    let host = Host::new(HostConfig {
        stores_dir: stores.clone(),
        config_dir: owner.join("config"),
        spool_dir: owner.join("spool"),
    })
    .unwrap();
    host.reconcile().unwrap();
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: stores.join(&repository_id).join("native"),
        repository_id: repository_id.clone(),
        binding_epoch: 1,
    };
    host.initialize_store(&binding, "ipc-initialize").unwrap();
    let source_path = base.join("git");
    let (git, commit) = git_source(&source_path);
    let git_head = git.head().unwrap().target().unwrap();
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "ipc-import".into(),
            binding: binding.clone(),
            source_path: source_path.clone(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    let scope = ClosureScope {
        workspace_id: "persisted-fixture-workspace".into(),
        root_id: "primary".into(),
        repository_id: repository_id.clone(),
        binding_epoch: 1,
    };
    let closure = host
        .export_baseline_closure(&ExportBaselineClosureRequest {
            operation_id: "ipc-export".into(),
            scope,
            capture_revision: 1,
            baseline: baseline.baseline.clone(),
        })
        .unwrap();
    drop(host);
    // The fixture uses real exact object imports to enroll the original source.
    // No initialization, owner bypass or fake proof is added to the protocol.
    let frozen = Repository::open_readonly_without_migration(
        stores
            .join(&repository_id)
            .join("baselines")
            .join(&baseline.baseline.baseline_id)
            .join("native"),
    )
    .unwrap();
    let manifest = frozen.view_manifest(frozen.current_view()).unwrap();
    let mut source = Repository::open(&binding.store_path).unwrap();
    for hash in &manifest.changes {
        let bytes = std::fs::read(frozen.change_store().change_path(hash)).unwrap();
        source.import_change_bytes(hash, &bytes).unwrap();
    }
    source.apply_view_manifest(&manifest).unwrap();
    let parent = source.current_view().to_owned();
    for name in ["left", "right", "target"] {
        source.create_view_from(name, &parent).unwrap();
    }
    let (left, left_bytes) = edit(&source, "left", b"LEFT\ntwo\nthree\nfour\nfive\nsix\n");
    let (right, _) = edit(&source, "right", b"one\ntwo\nthree\nfour\nfive\nRIGHT\n");
    let right = atomic_core::Hash::from_base32(right.as_bytes()).unwrap();
    source
        .insert_change(&right, InsertOptions::default().view("target"))
        .unwrap();
    let working_copy = source.require_working_copy_id().unwrap();
    source.set_current_view(working_copy, "target").unwrap();
    let expected = state(&source, "target");
    let source_manifest = source.view_manifest("target").unwrap().to_text();
    let source_changes = source.count_changes().unwrap();
    let selected = ExactCompositionChange {
        hash: left,
        bytes: Spool::open(&owner.join("spool"))
            .unwrap()
            .retain(&left_bytes)
            .unwrap(),
    };
    drop(source);
    drop(frozen);
    drop(git);
    Fixture {
        _directory: directory,
        daemon,
        stores,
        binding,
        root: RootBinding {
            workspace_id: "persisted-fixture-workspace".into(),
            root_id: "primary".into(),
            repository_id: RepositoryId::from_string(repository_id),
            kind: VcsKind::Atomic,
            locator: source_path,
            epoch: 1,
        },
        baseline: closure,
        expected,
        selected,
        source_manifest,
        source_changes,
        git_head,
    }
}

async fn exercise(
    supervisor: Arc<HostSupervisor>,
    root: RootBinding,
    binding: StoreBinding,
    baseline: BaselineClosure,
    expected: StateToken,
    selected: ExactCompositionChange,
) {
    assert!(matches!(
        supervisor.request(Command::Ping).await.unwrap(),
        Reply::Pong
    ));
    assert!(supervisor.recovery_ready().await);
    assert!(matches!(
        supervisor
            .request(Command::OpenStore {
                binding: binding.clone()
            })
            .await
            .unwrap(),
        Reply::StoreOpened { .. }
    ));
    let Reply::State {
        binding: actual,
        state: observed,
    } = supervisor
        .request(Command::ReadState {
            binding: binding.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("actual state reply required");
    };
    assert_eq!(actual, binding);
    assert_eq!(observed, expected);
    let client = AtomicCompositionClient::new(supervisor.clone());
    let captured = client
        .capture_target(
            &root,
            CaptureCompositionTargetRequest {
                operation_id: "ipc-target".into(),
                scope: baseline.scope.clone(),
                binding: binding.clone(),
                view: "target".into(),
                expected_state: expected.clone(),
            },
        )
        .await
        .unwrap();
    let input = PrivateCompositionInput {
        operation_id: "ipc-compose".into(),
        scope: baseline.scope.clone(),
        target: baseline.clone(),
        inherited_baseline: baseline,
        expected_target: expected.clone(),
        captured_target: Some(captured),
        target_changes: Vec::new(),
        selected_changes: vec![selected.hash.clone()],
        available_changes: vec![selected.clone()],
    };
    let AtomicCompositionPreparation::Prepared {
        composition,
        native,
    } = client.compose(&root, input.clone()).await.unwrap()
    else {
        panic!("actual native composition proof required");
    };
    assert_eq!(composition.receipt.receipt().root, root);
    assert_eq!(native.target_state, expected);
    assert_ne!(
        native.private_target_state.effective_state,
        native.target_state.effective_state
    );
    assert_eq!(
        std::fs::read(composition.materialization.destination.join("shared")).unwrap(),
        b"LEFT\ntwo\nthree\nfour\nfive\nRIGHT\n"
    );
    assert_eq!(
        std::fs::read(composition.materialization.destination.join("binary")).unwrap(),
        [0, 255, 1]
    );
    assert_eq!(
        std::fs::read(composition.materialization.destination.join("executable")).unwrap(),
        b"#!/bin/sh\r\necho exact\r\n"
    );
    assert_eq!(
        std::fs::metadata(composition.materialization.destination.join("executable"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read_link(composition.materialization.destination.join("link")).unwrap(),
        Path::new("executable")
    );
    assert!(composition.candidate.conflicts.is_empty());
    assert_eq!(
        composition.receipt.receipt().selected_changes,
        vec![NativeChangeRef::Atomic {
            repository_id: root.repository_id.clone(),
            change: identity(&selected.hash)
        }]
    );
    assert!(composition.receipt.receipt().full_closed_changes.len() >= 3);
    let spool = Spool::open(&supervisor.spool_path()).unwrap();
    let mut exact = spool
        .open_verified(&native.state_manifest, 16 * 1024 * 1024)
        .unwrap();
    let mut bytes = Vec::new();
    exact.read_to_end(&mut bytes).unwrap();
    let manifest: intent_atomic_proto::composition::CompositionStateManifest =
        serde_json::from_slice(&bytes).unwrap();
    for object in &manifest.exact_objects {
        spool
            .open_verified(&object.bytes, 512 * 1024 * 1024)
            .unwrap();
    }
    assert!(
        composition.selection_path.is_file()
            && composition.manifest_path.is_file()
            && composition.closure.spool_path.is_file()
    );
    let AtomicCompositionPreparation::Prepared {
        composition: replayed,
        ..
    } = client.compose(&root, input).await.unwrap()
    else {
        panic!("replay must retain native proof");
    };
    assert_eq!(composition.receipt.receipt(), replayed.receipt.receipt());
    assert_eq!(composition.materialization, replayed.materialization);
    let Reply::State { state: after, .. } = supervisor
        .request(Command::ReadState { binding })
        .await
        .unwrap()
    else {
        panic!("original state remains readable");
    };
    assert_eq!(after, expected);
}
fn identity(value: &str) -> intent_core::vcs::AtomicChangeHash {
    intent_core::vcs::AtomicChangeHash::from_string(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_client_captures_and_composes_without_mutating_source() {
    let f = fixture();
    let diagnostic_path = f.daemon.join("actual-host-stderr.log");
    std::fs::write(&diagnostic_path, b"").unwrap();
    std::fs::set_permissions(&diagnostic_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrapper = f.daemon.join("launch-actual-host");
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec {} \"$@\" 2>{}\n",
            quote(Path::new(env!("CARGO_BIN_EXE_intent-atomic-host"))),
            quote(&diagnostic_path)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut launch = HostLaunchConfig::new(wrapper, f.daemon.clone(), f.stores.clone());
    launch.startup_timeout = Duration::from_secs(30);
    launch.request_timeout = Duration::from_secs(60);
    let supervisor = Arc::new(HostSupervisor::new(launch).unwrap());
    // Join captures assertion panics so shutdown/reap still runs before failure.
    let outcome = tokio::spawn(exercise(
        supervisor.clone(),
        f.root.clone(),
        f.binding.clone(),
        f.baseline.clone(),
        f.expected.clone(),
        f.selected.clone(),
    ))
    .await;
    let shutdown = supervisor.shutdown().await;
    let mut diagnostic = Vec::new();
    std::fs::File::open(&diagnostic_path)
        .unwrap()
        .take(65_536)
        .read_to_end(&mut diagnostic)
        .unwrap();
    let diagnostic = String::from_utf8_lossy(&diagnostic);
    assert!(
        shutdown.is_ok(),
        "{shutdown:?}; actual host stderr: {diagnostic}"
    );
    assert!(
        outcome.is_ok(),
        "{outcome:?}; actual host stderr: {diagnostic}"
    );
    assert!(!supervisor.recovery_ready().await);
    let source = Repository::open_readonly_without_migration(&f.binding.store_path).unwrap();
    assert_eq!(state(&source, "target"), f.expected);
    assert_eq!(
        source.view_manifest("target").unwrap().to_text(),
        f.source_manifest
    );
    assert_eq!(source.count_changes().unwrap(), f.source_changes);
    let git = git2::Repository::open(&f.root.locator).unwrap();
    assert_eq!(git.head().unwrap().target().unwrap(), f.git_head);
    assert!(!f.binding.store_path.join("shared").exists());
}
