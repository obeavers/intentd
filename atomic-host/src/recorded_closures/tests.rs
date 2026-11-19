use super::*;
use atomic_core::change::{ChangeHeader, InodeAttr, InodeKind};
use atomic_core::output::memory::Memory;
use atomic_core::pristine::{StoredConflict, StoredConflictKind};
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use atomic_core::MutTxnT;
use atomic_repository::{InsertOptions, RecordOptions, TrackingOptions};
use intent_atomic_proto::{closures::ClosureScope, StoreBinding};

struct Fixture {
    directory: tempfile::TempDir,
    host: Host,
    binding: StoreBinding,
    source: Repository,
}

fn new_host(root: &Path) -> Host {
    durable::private_dir(root).unwrap();
    let host = Host::new(crate::HostConfig {
        stores_dir: root.join("stores"),
        config_dir: root.join("config"),
        spool_dir: root.join("spool"),
    })
    .unwrap();
    assert!(host.reconcile().unwrap().ready);
    host
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let host = new_host(&root.join("source-host"));
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        repository_id: repository_id.clone(),
        binding_epoch: 1,
        store_path: host.config.stores_dir.join(repository_id).join("native"),
    };
    host.initialize_store(&binding, "recorded-initialize")
        .unwrap();
    host.open_store(&binding).unwrap();
    let store = host.cached_store(&binding).unwrap();
    let mut source =
        Repository::open_with_pristine(&binding.store_path, store.shared_pristine()).unwrap();
    let parent = source.current_view().to_owned();
    for view in ["left", "right", "target/nested"] {
        source.create_view_from(view, &parent).unwrap();
    }
    Fixture {
        directory,
        host,
        binding,
        source,
    }
}

fn add(f: &Fixture, view: &str, path: &str, bytes: &[u8], extra_known: Option<Hash>) -> Hash {
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
    let (mut change, _) = f
        .source
        .assemble_and_hash(
            view,
            ChangeHeader::new(format!("recorded {view} {path}")),
            &[file],
        )
        .unwrap();
    if let Some(hash) = extra_known {
        change.hashed.extra_known.push(hash);
    }
    let mut content = Vec::new();
    let hash = change.serialize(&mut content).unwrap();
    f.source.import_change_bytes(&hash, &content).unwrap();
    f.source
        .insert_change(&hash, InsertOptions::default().view(view))
        .unwrap();
    hash
}

fn request(f: &Fixture, operation: &str, view: &str) -> ExportRecordedClosureRequest {
    ExportRecordedClosureRequest {
        operation_id: operation.into(),
        scope: ClosureScope {
            workspace_id: "original-workspace".into(),
            root_id: "primary".into(),
            repository_id: f.binding.repository_id.clone(),
            binding_epoch: f.binding.binding_epoch,
        },
        capture_revision: 12,
        binding: f.binding.clone(),
        view: view.into(),
        expected_state: crate::native::snapshot_state(&f.source, view).unwrap(),
    }
}

fn append_unrepresented_conflict_row(repository: &Repository, view: &str) {
    let mut transaction = repository.pristine().write_txn().unwrap();
    let view = transaction.get_view(view).unwrap().unwrap();
    let (inode, mut rows) = transaction
        .iter_conflicts(view.id)
        .unwrap()
        .into_iter()
        .next()
        .expect("fixture must retain a real graph-backed conflict");
    rows.push(StoredConflict {
        kind: StoredConflictKind::Name,
        path: "unrepresented-conflict.txt".into(),
        line: Some(1),
        sides: Vec::new(),
    });
    transaction.put_conflicts(view.id, inode, &rows).unwrap();
    transaction.commit().unwrap();
}

#[test]
fn exact_recorded_conflict_closure_restores_both_sides_after_all_sources_are_deleted() {
    let f = fixture();
    let left = add(&f, "left", "same.txt", b"left side\n", None);
    let right = add(&f, "right", "same.txt", b"right side\n", None);
    for hash in [left, right] {
        f.source
            .insert_change(&hash, InsertOptions::default().view("target/nested"))
            .unwrap();
    }
    let request = request(&f, "recorded-conflict-export", "target/nested");
    let original = crate::native::snapshot_views(&f.source, "target/nested").unwrap();
    let source_project = f.source.project_identity().unwrap().unwrap();
    assert!(!f.source.root().join("same.txt").exists());
    let closure = f.host.export_recorded_closure(&request).unwrap();
    assert_eq!(f.host.export_recorded_closure(&request).unwrap(), closure);
    assert_eq!(
        crate::native::snapshot_views(&f.source, "target/nested").unwrap(),
        original
    );
    assert!(
        !f.source.root().join("same.txt").exists(),
        "export must not materialize into canonical source"
    );
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    let packed = decode(&raw, &closure).unwrap();
    let conflict = packed
        .conflict
        .as_ref()
        .expect("both sides must be captured as actual native conflict");
    assert!(conflict.side_changes().contains(&left));
    assert!(conflict.side_changes().contains(&right));
    assert!(conflict.files.iter().any(|file| file.path == b"same.txt"));
    let expected_file = packed
        .header
        .files
        .entries
        .iter()
        .find(|file| file.path == "same.txt")
        .unwrap()
        .clone();
    let expected_conflicts = conflict.canonical_bytes().unwrap();
    let old_root = f.directory.path().canonicalize().unwrap();
    drop(f);
    assert!(!old_root.exists());

    let target_directory = tempfile::tempdir().unwrap();
    let root = target_directory.path().canonicalize().unwrap();
    let target = new_host(&root.join("target-host"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let restore = RestoreRecordedClosureRequest {
        operation_id: "recorded-conflict-restore".into(),
        expected_scope: closure.scope.clone(),
        closure: imported,
    };
    let receipt = target.restore_recorded_closure(&restore).unwrap();
    assert_eq!(receipt.source_state, closure.source_state);
    assert_eq!(
        receipt.restored_state.own_merkle,
        closure.source_state.own_merkle
    );
    assert_eq!(
        receipt.project_identity_hash,
        source_project.hash.to_base32()
    );
    let content = std::fs::read(receipt.path.join("same.txt")).unwrap();
    assert_eq!(digest(&content), expected_file.sha256);
    let marker = String::from_utf8(content).unwrap();
    assert!(
        marker.contains("left side") && marker.contains("right side") && marker.contains(">>>>>>>")
    );
    let restored = Repository::open_readonly_without_migration(&receipt.native_path).unwrap();
    let conflict = restored
        .capture_view_conflict_set("target/nested")
        .unwrap()
        .unwrap();
    assert_eq!(conflict.canonical_bytes().unwrap(), expected_conflicts);
    assert_eq!(
        restored.project_identity().unwrap().unwrap().object,
        source_project.object
    );
    drop(restored);
    assert_eq!(target.restore_recorded_closure(&restore).unwrap(), receipt);
    assert_eq!(
        std::fs::read(receipt.path.join("same.txt")).unwrap(),
        marker.as_bytes()
    );
}

#[test]
fn mixed_graph_and_unrepresented_conflict_rows_refuse_export_and_replay() {
    let mut f = fixture();
    let view = "target/nested";
    let left = add(&f, "left", "same.txt", b"left side\n", None);
    let right = add(&f, "right", "same.txt", b"right side\n", None);
    for hash in [left, right] {
        f.source
            .insert_change(&hash, InsertOptions::default().view(view))
            .unwrap();
    }
    let working_copy = f.source.require_working_copy_id().unwrap();
    f.source.set_current_view(working_copy, view).unwrap();
    let expected_conflicts = materialize_and_conflicts(&f.source, None)
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let (files, contents, directories) = collect_files(&f.source).unwrap();
    copy_materialization(
        &f.source,
        &f.directory.path().join("fixture-source-files"),
        &files,
        &contents,
        &directories,
    )
    .unwrap();
    let closure = f
        .host
        .export_recorded_closure(&request(&f, "recorded-mixed-before-tamper", view))
        .unwrap();
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    append_unrepresented_conflict_row(&f.source, view);
    assert_eq!(
        f.source
            .capture_view_conflict_set(view)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected_conflicts,
        "native capture omits the extra persisted row despite another valid conflict"
    );
    assert!(matches!(
        f.host
            .export_recorded_closure(&request(&f, "recorded-mixed-after-tamper", view)),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f.source.root().join("same.txt").exists());

    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let restore = RestoreRecordedClosureRequest {
        operation_id: "recorded-mixed-row-replay".into(),
        expected_scope: closure.scope,
        closure: imported,
    };
    let receipt = target.restore_recorded_closure(&restore).unwrap();
    let original_bytes = std::fs::read(receipt.path.join("same.txt")).unwrap();
    let repository = Repository::open_existing(&receipt.native_path).unwrap();
    append_unrepresented_conflict_row(&repository, view);
    assert_eq!(
        repository
            .capture_view_conflict_set(view)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected_conflicts
    );
    let original_rows = {
        let transaction = repository.pristine().read_txn().unwrap();
        let view = transaction.get_view(view).unwrap().unwrap();
        transaction.iter_conflicts(view.id).unwrap()
    };
    drop(repository);
    assert!(matches!(
        target.restore_recorded_closure(&restore),
        Err(HostError::Unsupported(_))
    ));
    assert_eq!(
        std::fs::read(receipt.path.join("same.txt")).unwrap(),
        original_bytes
    );
    let repository = Repository::open_readonly_without_migration(&receipt.native_path).unwrap();
    let transaction = repository.pristine().read_txn().unwrap();
    let view = transaction.get_view(view).unwrap().unwrap();
    assert_eq!(
        transaction.iter_conflicts(view.id).unwrap(),
        original_rows,
        "replay must refuse without repairing or dropping the extra persisted row"
    );
}

#[test]
fn ordinary_recorded_view_restores_without_conflicts_or_git_dependencies() {
    let f = fixture();
    let hash = add(
        &f,
        "left",
        "nested/file.txt",
        b"actual native contribution\r\n",
        None,
    );
    let closure = f
        .host
        .export_recorded_closure(&request(&f, "recorded-ordinary", "left"))
        .unwrap();
    assert_eq!(closure.conflict, None);
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    let old_root = f.directory.path().canonicalize().unwrap();
    drop(f);
    assert!(!old_root.exists());
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let receipt = target
        .restore_recorded_closure(&RestoreRecordedClosureRequest {
            operation_id: "recorded-ordinary-restore".into(),
            expected_scope: closure.scope,
            closure: imported,
        })
        .unwrap();
    assert_eq!(
        std::fs::read(receipt.path.join("nested/file.txt")).unwrap(),
        b"actual native contribution\r\n"
    );
    let repository = Repository::open_readonly_without_migration(&receipt.native_path).unwrap();
    assert!(crate::native::snapshot_views(&repository, "left")
        .unwrap()
        .2
        .contains(&hash));
    assert!(repository
        .capture_view_conflict_set("left")
        .unwrap()
        .is_none());
}

#[test]
fn corrupted_objects_foreign_epoch_and_mutated_operation_refuse_before_destination() {
    let f = fixture();
    add(&f, "left", "file", b"source\n", None);
    let closure = f
        .host
        .export_recorded_closure(&request(&f, "recorded-invalid", "left"))
        .unwrap();
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let mut restore = RestoreRecordedClosureRequest {
        operation_id: "must-not-create".into(),
        expected_scope: closure.scope.clone(),
        closure: imported,
    };
    restore.expected_scope.binding_epoch += 1;
    assert!(matches!(
        target.restore_recorded_closure(&restore),
        Err(HostError::StaleBinding)
    ));
    restore.expected_scope = closure.scope;
    restore.closure.operation_id.push_str("-foreign");
    assert!(target.restore_recorded_closure(&restore).is_err());
    restore.closure.operation_id = closure.operation_id;
    let mut corrupted = raw;
    *corrupted.last_mut().unwrap() ^= 1;
    std::fs::write(
        target.config.spool_dir.join(&restore.closure.payload.name),
        corrupted,
    )
    .unwrap();
    assert!(target.restore_recorded_closure(&restore).is_err());
    assert!(!target.config.spool_dir.join("recorded-restores").exists());
    assert!(!target
        .config
        .config_dir
        .join("recorded-closure-operations")
        .exists());
}

#[test]
fn unsafe_view_names_and_missing_native_conflict_sides_refuse_before_destination() {
    let f = fixture();
    let left = add(&f, "left", "same", b"left\n", None);
    let right = add(&f, "right", "same", b"right\n", None);
    for hash in [left, right] {
        f.source
            .insert_change(&hash, InsertOptions::default().view("target/nested"))
            .unwrap();
    }
    let source_request = request(&f, "recorded-unsafe", "target/nested");
    let closure = f.host.export_recorded_closure(&source_request).unwrap();
    let parsed = decode(&read_payload(&f.host, &closure.payload).unwrap(), &closure).unwrap();
    let mut header = parsed.header.clone();
    let mut root = parsed.views[0].clone();
    root.name = "../../escape".into();
    header.views[0] = root.to_text();
    if header.views.len() > 1 {
        let mut leaf = parsed.views[1].clone();
        leaf.parent = Some(root.name);
        header.views[1] = leaf.to_text();
    }
    let conflicts = parsed.conflict.as_ref().unwrap().canonical_bytes().unwrap();
    let raw = encode(&header, &parsed.objects, &conflicts).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut unsafe_receipt =
        receipt_for(&source_request, &header, &parsed.objects, &conflicts).unwrap();
    unsafe_receipt.payload = retain(&target, &raw).unwrap();
    assert!(target
        .restore_recorded_closure(&RestoreRecordedClosureRequest {
            operation_id: "unsafe-view".into(),
            expected_scope: closure.scope.clone(),
            closure: unsafe_receipt
        })
        .is_err());
    assert!(!target.config.spool_dir.join("recorded-restores").exists());
    let mut bad_conflicts = parsed.conflict.unwrap();
    bad_conflicts.files[0].entries[0].sides.clear();
    bad_conflicts.files[0].entries[0].claimants.clear();
    let corrupt = bad_conflicts.canonical_bytes().unwrap();
    let object_set = parsed.objects.iter().map(|(hash, _)| *hash).collect();
    assert!(validate_conflict(
        &corrupt,
        parsed.header.conflict.as_ref().unwrap(),
        &object_set
    )
    .is_err());
}

#[test]
fn unsupported_attributes_and_external_native_knowledge_are_not_silently_dropped() {
    let f = fixture();
    add(
        &f,
        "left",
        ".gitattributes",
        b"* filter=unqualified\n",
        None,
    );
    assert!(matches!(
        f.host
            .export_recorded_closure(&request(&f, "recorded-attributes", "left")),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f.source.root().join(".gitattributes").exists());
    let external = Hash::of(b"not in visible dependency closure");
    add(&f, "right", "known", b"known source", Some(external));
    assert!(matches!(
        f.host
            .export_recorded_closure(&request(&f, "recorded-external-context", "right")),
        Err(HostError::Unsupported(_))
    ));
}

#[test]
fn explicit_native_empty_directories_survive_source_deletion() {
    let mut f = fixture();
    let working_copy = f.source.require_working_copy_id().unwrap();
    f.source.set_current_view(working_copy, "left").unwrap();
    let empty = f.source.root().join("kept-empty");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o755)).unwrap();
    f.source
        .add_directory(working_copy, "kept-empty", TrackingOptions::default())
        .unwrap();
    let recorded = f
        .source
        .record(
            working_copy,
            ChangeHeader::new("keep explicit native empty directory"),
            RecordOptions::new()
                .with_all(true)
                .sync_vault(false)
                .enrich_kg(false)
                .update_file_index(false),
        )
        .unwrap();
    assert!(recorded.change().hunks().iter().any(|operation| matches!(operation, atomic_core::change::GraphOp::DirAdd { path, .. } if path == "kept-empty")));
    std::fs::remove_dir(&empty).unwrap();
    let closure = f
        .host
        .export_recorded_closure(&request(&f, "recorded-empty-directory", "left"))
        .unwrap();
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    let decoded = decode(&raw, &closure).unwrap();
    assert_eq!(
        decoded.header.directories,
        vec![DirectoryEntry {
            path: "kept-empty".into(),
            mode: 0o755
        }]
    );
    let original_root = f.directory.path().to_owned();
    drop(f);
    assert!(!original_root.exists());
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let restore = RestoreRecordedClosureRequest {
        operation_id: "recorded-empty-directory-restore".into(),
        expected_scope: closure.scope,
        closure: imported,
    };
    let receipt = target.restore_recorded_closure(&restore).unwrap();
    let restored = receipt.path.join("kept-empty");
    assert!(restored.is_dir());
    assert_eq!(std::fs::read_dir(&restored).unwrap().count(), 0);
    assert_eq!(
        std::fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(target.restore_recorded_closure(&restore).unwrap(), receipt);
}

#[test]
fn original_named_conflict_presentation_is_exact_or_explicitly_refused() {
    let f = fixture();
    let left = add(&f, "left", "same", b"left\n", None);
    let right = add(&f, "right", "same", b"right\n", None);
    for hash in [right, left] {
        f.source
            .insert_change(&hash, InsertOptions::default().view("target/nested"))
            .unwrap();
    }
    let (original, _, directories) = collect_files_on(&f.source, "target/nested").unwrap();
    match f.host.export_recorded_closure(&request(
        &f,
        "recorded-reversed-conflict",
        "target/nested",
    )) {
        Ok(receipt) => {
            let decoded =
                decode(&read_payload(&f.host, &receipt.payload).unwrap(), &receipt).unwrap();
            assert_eq!(
                files_digest(&decoded.header.files, &decoded.header.directories).unwrap(),
                files_digest(&original, &directories).unwrap()
            );
        }
        Err(HostError::Unsupported(_)) => {}
        Err(error) => panic!("unexpected export refusal: {error:?}"),
    }
    assert!(!f.source.root().join("same").exists());
}

#[test]
fn completed_restore_replay_refuses_native_parent_symlinks_and_common_store_pointers() {
    let f = fixture();
    add(&f, "left", "nested/file.txt", b"native source\n", None);
    let closure = f
        .host
        .export_recorded_closure(&request(&f, "recorded-no-repair", "left"))
        .unwrap();
    let raw = read_payload(&f.host, &closure.payload).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut imported = closure.clone();
    imported.payload = retain(&target, &raw).unwrap();
    let restore = RestoreRecordedClosureRequest {
        operation_id: "recorded-no-repair-restore".into(),
        expected_scope: closure.scope,
        closure: imported,
    };
    let receipt = target.restore_recorded_closure(&restore).unwrap();
    let outside = directory.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let sentinel = outside.join("file.txt");
    std::fs::write(&sentinel, b"outside untouched\n").unwrap();
    std::os::unix::fs::symlink(&outside, receipt.native_path.join("nested")).unwrap();
    assert!(target.restore_recorded_closure(&restore).is_err());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"outside untouched\n");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    std::fs::remove_file(receipt.native_path.join("nested")).unwrap();
    std::fs::write(
        receipt.native_path.join(".atomic/repository"),
        outside.to_string_lossy().as_bytes(),
    )
    .unwrap();
    assert!(target.restore_recorded_closure(&restore).is_err());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"outside untouched\n");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    std::fs::remove_file(receipt.native_path.join(".atomic/repository")).unwrap();
    assert_eq!(target.restore_recorded_closure(&restore).unwrap(), receipt);
}

#[test]
fn case_insensitive_native_metadata_aliases_are_rejected_before_destination() {
    for path in [
        ".ATOMIC/payload",
        "nested/.Atomic-Sandbox/payload",
        ".GIT/config",
    ] {
        assert!(!safe_file(path));
    }
    let f = fixture();
    add(&f, "left", "ordinary", b"safe", None);
    let source_request = request(&f, "recorded-metadata-alias", "left");
    let closure = f.host.export_recorded_closure(&source_request).unwrap();
    let parsed = decode(&read_payload(&f.host, &closure.payload).unwrap(), &closure).unwrap();
    let mut header = parsed.header;
    header.files.entries[0].path = ".ATOMIC/atomic.redb".into();
    header.directories = vec![DirectoryEntry {
        path: ".ATOMIC".into(),
        mode: 0o755,
    }];
    let bytes = encode(&header, &parsed.objects, &[]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = new_host(&directory.path().canonicalize().unwrap().join("target"));
    let mut corrupt = receipt_for(&source_request, &header, &parsed.objects, &[]).unwrap();
    corrupt.payload = retain(&target, &bytes).unwrap();
    assert!(target
        .restore_recorded_closure(&RestoreRecordedClosureRequest {
            operation_id: "metadata-alias-refused".into(),
            expected_scope: closure.scope,
            closure: corrupt
        })
        .is_err());
    assert!(!target.config.spool_dir.join("recorded-restores").exists());
}
