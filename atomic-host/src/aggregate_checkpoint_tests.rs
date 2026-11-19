//! Actual native baseline + aggregate recovery, with all source stores removed.
//! This qualifies the frozen-baseline overlay profile, not arbitrary view graphs.

use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use intent_atomic::checkpoint::{
    capture_frozen_components, observe_closed_working_manifest, AggregateCaptureRequest,
    AuthorshipBoundary, AuthorshipCompleteness, CheckpointProfile, CheckpointSelection,
    EvidenceDocument, ValidatedCheckpoint,
};
use intent_atomic::spool::Spool;
use intent_atomic_proto::baselines::{
    BaselinePolicy, ImportBaselineRequest, MaterializeBaselineRequest,
};
use intent_atomic_proto::closures::{
    ClosureScope, ExportBaselineClosureRequest, RestoreBaselineClosureRequest,
};
use intent_atomic_proto::recording::{SelectedFile, SelectedFileKind};
use intent_atomic_proto::StoreBinding;
use sha2::{Digest, Sha256};

use crate::{durable, Host, HostConfig};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn host(root: &Path) -> Host {
    durable::private_dir(root).unwrap();
    let host = Host::new(HostConfig {
        stores_dir: root.join("stores"),
        config_dir: root.join("config"),
        spool_dir: root.join("spool"),
    })
    .unwrap();
    host.reconcile().unwrap();
    host
}

fn source_commit(root: &Path) -> (git2::Repository, String) {
    let git = git2::Repository::init(root).unwrap();
    let mut index = git2::Index::new().unwrap();
    for (path, mode, bytes) in [
        ("keep.txt", 0o100_644, b"base\r\n".as_slice()),
        ("deleted.txt", 0o100_644, b"delete".as_slice()),
        ("run", 0o100_755, b"#!/bin/sh\n".as_slice()),
        ("binary", 0o100_644, [0, 255, 1].as_slice()),
        ("empty", 0o100_644, b"".as_slice()),
        ("link", 0o120_000, b"keep.txt".as_slice()),
    ] {
        let id = git.blob(bytes).unwrap();
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
                path: path.as_bytes().to_vec(),
            })
            .unwrap();
    }
    let tree = git.find_tree(index.write_tree_to(&git).unwrap()).unwrap();
    let signature =
        git2::Signature::now("Aggregate checkpoint", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(Some("HEAD"), &signature, &signature, "source", &tree, &[])
        .unwrap()
        .to_string();
    drop(tree);
    (git, commit)
}

fn make_working(root: &Path) {
    durable::private_dir(root).unwrap();
    for (path, bytes) in [
        ("keep.txt", b"dirty\r\n".as_slice()),
        ("run", b"#!/bin/sh\n".as_slice()),
        ("binary", [0, 255, 1].as_slice()),
        ("empty", b"".as_slice()),
    ] {
        std::fs::write(root.join(path), bytes).unwrap();
    }
    std::fs::set_permissions(root.join("run"), std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink("keep.txt", root.join("link")).unwrap();
    std::fs::create_dir(root.join("target")).unwrap();
    std::fs::write(root.join("target/cache.bin"), [4, 5, 0, 255]).unwrap();
    std::fs::create_dir(root.join("target/empty-directory")).unwrap();
    std::fs::create_dir(root.join(".vault")).unwrap();
    std::fs::write(root.join(".vault/user-notes.md"), b"ordinary user source").unwrap();
    std::fs::create_dir_all(root.join("nested/.intent")).unwrap();
    std::fs::write(
        root.join("nested/.intent/content"),
        b"preserved nested source",
    )
    .unwrap();
}

fn assert_working(root: &Path) {
    assert_eq!(std::fs::read(root.join("keep.txt")).unwrap(), b"dirty\r\n");
    assert!(!root.join("deleted.txt").exists());
    assert_eq!(std::fs::read(root.join("binary")).unwrap(), vec![0, 255, 1]);
    assert_eq!(std::fs::read(root.join("empty")).unwrap(), Vec::<u8>::new());
    assert_eq!(
        std::fs::read_link(root.join("link")).unwrap(),
        Path::new("keep.txt")
    );
    assert_eq!(
        std::fs::metadata(root.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read(root.join("target/cache.bin")).unwrap(),
        vec![4, 5, 0, 255]
    );
    assert!(root.join("target/empty-directory").is_dir());
    assert_eq!(
        std::fs::read(root.join(".vault/user-notes.md")).unwrap(),
        b"ordinary user source"
    );
    assert_eq!(
        std::fs::read(root.join("nested/.intent/content")).unwrap(),
        b"preserved nested source"
    );
}

#[test]
fn aggregate_native_roundtrip_survives_deleting_git_stores_working_copy_and_old_spool() {
    let source_directory = tempfile::tempdir().unwrap();
    let source_root = source_directory.path().canonicalize().unwrap();
    let source_host_path = source_root.join("source-host");
    let source = host(&source_host_path);
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        repository_id: repository_id.clone(),
        binding_epoch: 1,
        store_path: source.config.stores_dir.join(&repository_id).join("native"),
    };
    source
        .initialize_store(&binding, "aggregate-initialize")
        .unwrap();
    let (git, commit) = source_commit(&source_root.join("git"));
    let baseline = source
        .import_baseline(&ImportBaselineRequest {
            operation_id: "aggregate-import".into(),
            binding,
            source_path: git.workdir().unwrap().to_owned(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    let export = ExportBaselineClosureRequest {
        operation_id: "aggregate-export".into(),
        scope: ClosureScope {
            workspace_id: "original-workspace".into(),
            root_id: "primary".into(),
            repository_id,
            binding_epoch: 1,
        },
        capture_revision: 9,
        baseline: baseline.baseline.clone(),
    };
    let closure = source.export_baseline_closure(&export).unwrap();
    let materialized = source
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "aggregate-base-files".into(),
            baseline: baseline.baseline.clone(),
        })
        .unwrap();
    let working = source_root.join("closed-working");
    make_working(&working);
    let selection = CheckpointSelection::Known {
        selection_id: "selected-original-source".into(),
        files: vec![
            SelectedFile {
                path: "keep.txt".into(),
                kind: SelectedFileKind::Regular,
                length: 7,
                sha256: hash(b"dirty\r\n"),
            },
            SelectedFile {
                path: "deleted.txt".into(),
                kind: SelectedFileKind::Deletion,
                length: 0,
                sha256: hash(&[]),
            },
        ],
    };
    let documents = vec![
        EvidenceDocument {
            kind: "task-source".into(),
            logical_id: "retained-task-revision".into(),
            bytes: br#"{"revision":9,"text":"original task"}"#.to_vec(),
        },
        EvidenceDocument {
            kind: "provenance".into(),
            logical_id: "retained-original-turn".into(),
            bytes: vec![0, 255, 19],
        },
    ];
    let captured = capture_frozen_components(
        AggregateCaptureRequest {
            profile: CheckpointProfile::FrozenBaselineOverlay,
            export,
            sealed_source: working.clone(),
            expected_working_manifest: observe_closed_working_manifest(&working).unwrap(),
            expected_state: baseline.native_state,
            selection: selection.clone(),
            selection_contents: vec![],
            ignored_paths: vec!["target".into()],
            task_intent_links: vec![],
            authorship_boundaries: vec![AuthorshipBoundary {
                paths: vec!["keep.txt".into()],
                authors: vec![],
                completeness: AuthorshipCompleteness::Unknown,
            }],
            evidence_documents: documents.clone(),
            inherited: vec![],
        },
        closure,
        materialized.path,
        &source.config.spool_dir,
    )
    .unwrap();
    let mut bytes = Vec::new();
    Spool::open(&source.config.spool_dir)
        .unwrap()
        .open_verified(&captured.payload, 512 * 1024 * 1024)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    drop(git);
    drop(source);
    std::fs::remove_dir_all(&source_host_path).unwrap();
    std::fs::remove_dir_all(source_root.join("git")).unwrap();
    std::fs::remove_dir_all(&working).unwrap();
    assert!(!source_host_path.exists());
    assert!(!working.exists());

    let target_directory = tempfile::tempdir().unwrap();
    let target_root = target_directory.path().canonicalize().unwrap();
    let target = host(&target_root.join("target-host"));
    let archive =
        ValidatedCheckpoint::read(&bytes, &captured.reference, &captured.reference.scope).unwrap();
    let mut restored_closure = archive.native_closure().frozen_baseline().unwrap().clone();
    restored_closure.payload = Spool::open(&target.config.spool_dir)
        .unwrap()
        .retain_closure(archive.native_closure_bytes())
        .unwrap();
    let restored_native = target
        .restore_baseline_closure(&RestoreBaselineClosureRequest {
            operation_id: "aggregate-native-restore".into(),
            expected_scope: captured.reference.scope.clone(),
            closure: restored_closure,
        })
        .unwrap();
    let restored_baseline = target
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "aggregate-restored-base".into(),
            baseline: restored_native.baseline.clone(),
        })
        .unwrap();
    let prepared = archive
        .restore_files(
            "aggregate-private-restore".into(),
            &restored_native,
            restored_baseline.path.clone(),
            &target_root.join("restores"),
        )
        .unwrap();
    assert_working(&prepared.path);
    assert_eq!(prepared.selection, selection);
    assert_eq!(prepared.evidence_documents, documents);
    assert_eq!(
        prepared.evidence.authorship_boundaries[0].completeness,
        AuthorshipCompleteness::Unknown
    );
    assert_eq!(prepared.reference, captured.reference);
    let replay = ValidatedCheckpoint::read(&bytes, &captured.reference, &captured.reference.scope)
        .unwrap()
        .restore_files(
            "aggregate-private-restore".into(),
            &restored_native,
            restored_baseline.path,
            &target_root.join("restores"),
        )
        .unwrap();
    assert_eq!(replay.path, prepared.path);
    assert_working(&replay.path);
}

#[test]
fn aggregate_invalid_native_component_refuses_before_native_restore() {
    // Aggregate integrity is independent of native import; a caller cannot
    // substitute a different native payload while retaining the aggregate ref.
    let reference = intent_atomic::checkpoint::AggregateCheckpointRef {
        format: 2,
        reader_version: intent_atomic::checkpoint::AGGREGATE_READER_VERSION,
        scope: ClosureScope {
            workspace_id: "workspace".into(),
            root_id: "root".into(),
            repository_id: uuid::Uuid::new_v4().to_string(),
            binding_epoch: 1,
        },
        capture_revision: 1,
        length: 4,
        sha256: hash(b"code"),
    };
    assert!(ValidatedCheckpoint::read(b"evil", &reference, &reference.scope).is_err());
}
