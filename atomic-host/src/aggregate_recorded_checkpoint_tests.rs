//! Actual recorded graph/conflict + independently frozen working/work state.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use atomic_core::change::{ChangeHeader, InodeAttr, InodeKind};
use atomic_core::output::memory::Memory;
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use atomic_core::Hash;
use atomic_repository::{InsertOptions, RecordOptions, Repository, TrackingOptions};
use intent_atomic::checkpoint::{
    capture_recorded_components, observe_closed_working_manifest, AuthorshipBoundary,
    AuthorshipCompleteness, CheckpointCode, CheckpointSelection, EvidenceDocument,
    PreparedCheckpointCode, RecordedAggregateCaptureRequest, SelectedContent, ValidatedCheckpoint,
};
use intent_atomic::spool::Spool;
use intent_atomic_proto::closures::ClosureScope;
use intent_atomic_proto::recorded_closures::{
    ExportRecordedClosureRequest, RestoreRecordedClosureRequest,
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
    assert!(host.reconcile().unwrap().ready);
    host
}

fn add(repository: &Repository, view: &str, path: &str, bytes: &[u8]) -> Hash {
    let memory = Memory::new();
    memory.add_file(path, bytes);
    let mut file = record_added_file(
        &memory,
        &DetectedFile::added(path),
        &RecordingOptions::new(),
    )
    .unwrap();
    file.set_attr(InodeAttr::Kind(InodeKind::Regular));
    file.set_attr(InodeAttr::Mode(0o644));
    let (change, _) = repository
        .assemble_and_hash(
            view,
            ChangeHeader::new(format!("aggregate {view} {path}")),
            &[file],
        )
        .unwrap();
    let mut bytes = Vec::new();
    let hash = change.serialize(&mut bytes).unwrap();
    repository.import_change_bytes(&hash, &bytes).unwrap();
    repository
        .insert_change(&hash, InsertOptions::default().view(view))
        .unwrap();
    hash
}

#[test]
fn recorded_aggregate_roundtrip_keeps_conflict_graph_dirty_overlay_and_independent_selection_after_all_sources_deleted(
) {
    let source_directory = tempfile::tempdir().unwrap();
    let source_root = source_directory.path().canonicalize().unwrap();
    let source = host(&source_root.join("source-host"));
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        repository_id: repository_id.clone(),
        binding_epoch: 4,
        store_path: source.config.stores_dir.join(&repository_id).join("native"),
    };
    source
        .initialize_store(&binding, "aggregate-recorded-initialize")
        .unwrap();
    source.open_store(&binding).unwrap();
    let store = source.cached_store(&binding).unwrap();
    let mut repository =
        Repository::open_with_pristine(&binding.store_path, store.shared_pristine()).unwrap();
    let parent = repository.current_view().to_owned();
    for view in ["left", "right", "target/nested"] {
        repository.create_view_from(view, &parent).unwrap();
    }
    let working_copy = repository.require_working_copy_id().unwrap();
    repository.set_current_view(working_copy, "left").unwrap();
    let empty = repository.root().join("recorded-empty");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o755)).unwrap();
    repository
        .add_directory(working_copy, "recorded-empty", TrackingOptions::default())
        .unwrap();
    let empty_record = repository
        .record(
            working_copy,
            ChangeHeader::new("keep explicit recorded empty directory"),
            RecordOptions::new()
                .with_all(true)
                .sync_vault(false)
                .enrich_kg(false)
                .update_file_index(false),
        )
        .unwrap();
    std::fs::remove_dir(&empty).unwrap();
    let recorded = add(&repository, "left", "recorded.txt", b"recorded original\n");
    let deleted = add(&repository, "left", "deleted.txt", b"selected deletion\n");
    let left = add(&repository, "left", "same.txt", b"left graph side\n");
    let right = add(&repository, "right", "same.txt", b"right graph side\n");
    for contribution in [*empty_record.hash(), recorded, deleted, left, right] {
        repository
            .insert_change(
                &contribution,
                InsertOptions::default().view("target/nested"),
            )
            .unwrap();
    }
    let scope = ClosureScope {
        workspace_id: "original-workspace".into(),
        root_id: "primary".into(),
        repository_id,
        binding_epoch: 4,
    };
    let export = ExportRecordedClosureRequest {
        operation_id: "aggregate-recorded-export".into(),
        scope: scope.clone(),
        capture_revision: 27,
        binding,
        view: "target/nested".into(),
        expected_state: crate::native::snapshot_state(&repository, "target/nested").unwrap(),
    };
    let original_source_state = export.expected_state.clone();
    let closure = source.export_recorded_closure(&export).unwrap();
    assert!(closure.conflict.is_some());
    let original_project = closure.project_id.clone();
    let base = source
        .restore_recorded_closure(&RestoreRecordedClosureRequest {
            operation_id: "aggregate-recorded-base".into(),
            expected_scope: scope.clone(),
            closure: closure.clone(),
        })
        .unwrap();
    let markers = std::fs::read(base.path.join("same.txt")).unwrap();
    assert!(base.path.join("recorded-empty").is_dir());
    assert_eq!(
        std::fs::read(base.path.join("deleted.txt")).unwrap(),
        b"selected deletion\n"
    );
    let working = source_root.join("sealed-working");
    durable::private_dir(&working).unwrap();
    std::fs::create_dir(working.join("recorded-empty")).unwrap();
    std::fs::set_permissions(
        working.join("recorded-empty"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(working.join("same.txt"), &markers).unwrap();
    std::fs::write(
        working.join("recorded.txt"),
        b"later dirty working bytes\r\n",
    )
    .unwrap();
    std::fs::create_dir(working.join("ignored")).unwrap();
    std::fs::write(working.join("ignored/cache.bin"), [0, 255, 7]).unwrap();
    std::fs::write(working.join("run"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(working.join("run"), std::fs::Permissions::from_mode(0o750)).unwrap();
    std::os::unix::fs::symlink("recorded.txt", working.join("link")).unwrap();
    let selected_bytes = b"recorded original\n".to_vec();
    let selection = CheckpointSelection::Known {
        selection_id: "original-independent-selection".into(),
        files: vec![
            SelectedFile {
                path: "recorded.txt".into(),
                kind: SelectedFileKind::Regular,
                length: selected_bytes.len() as u64,
                sha256: hash(&selected_bytes),
            },
            SelectedFile {
                path: "deleted.txt".into(),
                kind: SelectedFileKind::Deletion,
                length: 0,
                sha256: hash(&[]),
            },
        ],
    };
    let documents = vec![EvidenceDocument {
        kind: "provenance".into(),
        logical_id: "retained-original-work".into(),
        bytes: br#"{"authorship":"unknown","readiness":"unknown"}"#.to_vec(),
    }];
    let captured = capture_recorded_components(
        RecordedAggregateCaptureRequest {
            export,
            sealed_source: working.clone(),
            expected_working_manifest: observe_closed_working_manifest(&working).unwrap(),
            selection: selection.clone(),
            selection_contents: vec![SelectedContent {
                path: "recorded.txt".into(),
                bytes: selected_bytes.clone(),
            }],
            ignored_paths: vec!["ignored".into()],
            task_intent_links: vec![],
            authorship_boundaries: vec![AuthorshipBoundary {
                paths: vec!["recorded.txt".into()],
                authors: vec![],
                completeness: AuthorshipCompleteness::Unknown,
            }],
            evidence_documents: documents.clone(),
            inherited: vec![],
        },
        closure,
        &base,
        &source.config.spool_dir,
    )
    .unwrap();
    assert!(matches!(
        captured.manifest.native_closure,
        CheckpointCode::RecordedView { .. }
    ));
    let mut bytes = Vec::new();
    Spool::open(&source.config.spool_dir)
        .unwrap()
        .open_verified(&captured.payload, 512 * 1024 * 1024)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    drop(repository);
    drop(store);
    drop(source);
    drop(source_directory);
    assert!(
        !source_root.exists(),
        "all source stores, native attempts, working files and spool were deleted"
    );
    let target_directory = tempfile::tempdir().unwrap();
    let target_root = target_directory.path().canonicalize().unwrap();
    let target = host(&target_root.join("target"));
    let archive = ValidatedCheckpoint::read(&bytes, &captured.reference, &scope).unwrap();
    let imported = archive.native_closure().recorded_view().unwrap().clone();
    let mut payload = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target.config.spool_dir.join(&imported.payload.name))
        .unwrap();
    payload.write_all(archive.native_closure_bytes()).unwrap();
    payload.sync_all().unwrap();
    let restore = RestoreRecordedClosureRequest {
        operation_id: "aggregate-recorded-native-restore".into(),
        expected_scope: scope.clone(),
        closure: imported,
    };
    let restored = target.restore_recorded_closure(&restore).unwrap();
    assert_eq!(restored.source_state, original_source_state);
    assert_eq!(
        restored.restored_state.own_merkle,
        original_source_state.own_merkle
    );
    assert_eq!(restored.project_id, original_project);
    let native = Repository::open_readonly_without_migration(&restored.native_path).unwrap();
    let conflicts = native
        .capture_view_conflict_set("target/nested")
        .unwrap()
        .unwrap();
    assert!(conflicts.side_changes().contains(&left));
    assert!(conflicts.side_changes().contains(&right));
    let prepared = archive
        .restore_recorded_files(
            "aggregate-recorded-working-restore".into(),
            &restored,
            &target_root.join("restores"),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(prepared.path.join("same.txt")).unwrap(),
        markers
    );
    assert_eq!(
        std::fs::read(prepared.path.join("recorded.txt")).unwrap(),
        b"later dirty working bytes\r\n"
    );
    assert!(!prepared.path.join("deleted.txt").exists());
    assert!(prepared.path.join("recorded-empty").is_dir());
    assert_eq!(
        std::fs::read(prepared.path.join("ignored/cache.bin")).unwrap(),
        [0, 255, 7]
    );
    assert_eq!(
        std::fs::metadata(prepared.path.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    assert_eq!(
        std::fs::read_link(prepared.path.join("link")).unwrap(),
        Path::new("recorded.txt")
    );
    assert_eq!(prepared.selection, selection);
    assert_eq!(
        prepared.selection_contents,
        vec![SelectedContent {
            path: "recorded.txt".into(),
            bytes: selected_bytes
        }]
    );
    assert_eq!(prepared.evidence_documents, documents);
    assert_eq!(
        prepared.evidence.authorship_boundaries[0].completeness,
        AuthorshipCompleteness::Unknown
    );
    assert!(
        matches!(&prepared.native_code, PreparedCheckpointCode::RecordedView { receipt } if receipt.as_ref() == &restored)
    );
    assert_eq!(std::fs::read(&prepared.archive_path).unwrap(), bytes);
    drop(native);
    assert_eq!(target.restore_recorded_closure(&restore).unwrap(), restored);
    let replay = ValidatedCheckpoint::read(&bytes, &captured.reference, &scope)
        .unwrap()
        .restore_recorded_files(
            "aggregate-recorded-working-restore".into(),
            &restored,
            &target_root.join("restores"),
        )
        .unwrap();
    assert_eq!(replay.path, prepared.path);
}
