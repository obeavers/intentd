use super::*;
use intent_atomic_proto::baselines::{BaselinePolicy, ImportBaselineRequest};
use intent_atomic_proto::execution::WarmWorkingCopyCapture;
use intent_atomic_proto::recording::{PrepareRecordRequest, RecordPreparation};
use intent_atomic_proto::sealed_record_source::RecordSourceFile;
use intent_atomic_proto::{StateToken, StoreBinding};
use std::path::PathBuf;

fn descriptor(path: &str, kind: SelectedFileKind, bytes: &[u8]) -> SelectedFile {
    SelectedFile {
        path: path.into(),
        kind,
        length: bytes.len() as u64,
        sha256: hash(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn payload(root: &Path, files: &[(SelectedFile, Vec<u8>)]) -> SpoolRef {
    let payload = RecordSourcePayload {
        version: RECORD_SOURCE_PAYLOAD_VERSION,
        files: files
            .iter()
            .map(|(file, bytes)| RecordSourceFile {
                file: file.clone(),
                content_hex: hex(bytes),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let reference = SpoolRef {
        name: format!("selected-{}.json", hash(&bytes)),
        length: bytes.len() as u64,
        sha256: hash(&bytes),
    };
    std::fs::write(root.join(&reference.name), bytes).unwrap();
    reference
}

fn dummy_request(root: &Path) -> SealRecordSourceRequest {
    let binding = StoreBinding {
        repository_id: uuid::Uuid::new_v4().to_string(),
        binding_epoch: 1,
        store_path: root.join("native"),
    };
    let files = vec![(
        descriptor("binary.bin", SelectedFileKind::Regular, b"\0\xff\r\n"),
        b"\0\xff\r\n".to_vec(),
    )];
    SealRecordSourceRequest {
        operation_id: "seal-source-fixture".into(),
        scope: intent_atomic_proto::closures::ClosureScope {
            workspace_id: "source-fixture-workspace".into(),
            root_id: "source-fixture-root".into(),
            repository_id: binding.repository_id.clone(),
            binding_epoch: 1,
        },
        binding: binding.clone(),
        expected_state: StateToken {
            view: "main".into(),
            effective_state: "untrusted".into(),
            own_merkle: "untrusted".into(),
        },
        capture: WarmWorkingCopyCapture {
            operation_id: "capture".into(),
            repository_id: binding.repository_id.clone(),
            binding_epoch: 1,
            parent_working_copy_id: "working".into(),
            parent_root: root.join("parent"),
            capture_generation: 1,
            selection_digest: None,
            baseline: intent_atomic_proto::baselines::BaselineRef {
                repository_id: binding.repository_id,
                binding_epoch: 1,
                baseline_id: "a".repeat(64),
            },
            baseline_manifest_digest: "b".repeat(64),
            working_digest: "c".repeat(64),
            path: root.join("capture"),
            copied_entries: 1,
            copied_bytes: 4,
            mechanism: "untrusted-fixture".into(),
        },
        selection_digest: "d".repeat(64),
        files: files.iter().map(|(file, _)| file.clone()).collect(),
        payload: payload(root, &files),
    }
}

#[test]
fn payload_keeps_raw_bytes_and_refuses_changed_descriptors_or_payload_hash() {
    let root = tempfile::tempdir().unwrap();
    let request = dummy_request(root.path());
    validate_descriptors(&request).unwrap();
    let selected = selected_payload(root.path(), &request).unwrap();
    assert_eq!(selected[0].bytes, b"\0\xff\r\n");
    let mut changed = request.clone();
    changed.files[0].sha256 = "f".repeat(64);
    assert!(selected_payload(root.path(), &changed).is_err());
    let mut changed = request.clone();
    changed.payload.sha256 = "e".repeat(64);
    assert!(selected_payload(root.path(), &changed).is_err());
    let mut changed = request;
    changed.files[0].path = "../outside".into();
    assert!(validate_descriptors(&changed).is_err());
}

#[test]
fn payload_refuses_path_overlap_native_metadata_and_alias_spool_entries() {
    let root = tempfile::tempdir().unwrap();
    let mut request = dummy_request(root.path());
    request.files.push(descriptor(
        "binary.bin/nested",
        SelectedFileKind::Regular,
        b"",
    ));
    assert!(validate_descriptors(&request).is_err());
    request.files.pop();
    request.files[0].path = ".atomic/atomic.redb".into();
    assert!(validate_descriptors(&request).is_err());
    let mut request = dummy_request(root.path());
    let original = root.path().join(&request.payload.name);
    let alias = root.path().join("payload-alias.json");
    std::fs::hard_link(&original, &alias).unwrap();
    request.payload.name = "payload-alias.json".into();
    assert!(selected_payload(root.path(), &request).is_err());
}

#[test]
fn selected_component_case_aliases_and_symlink_ignore_controls_refuse() {
    let root = tempfile::tempdir().unwrap();
    let mut request = dummy_request(root.path());
    request.files = vec![
        descriptor("A/x", SelectedFileKind::Regular, b""),
        descriptor("a/y", SelectedFileKind::Regular, b""),
    ];
    assert!(validate_descriptors(&request).is_err());
    let files = vec![(
        descriptor(".gitignore", SelectedFileKind::Symlink, b"/host/private"),
        b"/host/private".to_vec(),
    )];
    request.files = files.iter().map(|(file, _)| file.clone()).collect();
    request.payload = payload(root.path(), &files);
    assert!(selected_payload(root.path(), &request).is_err());
}

struct Fixture {
    _directory: tempfile::TempDir,
    host: Host,
    binding: StoreBinding,
    root: PathBuf,
    baseline: intent_atomic_proto::baselines::BaselineReceipt,
    expected_state: StateToken,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let host = Host::new(crate::HostConfig {
        stores_dir: base.join("stores"),
        config_dir: base.join("config"),
        spool_dir: base.join("spool"),
    })
    .unwrap();
    host.reconcile().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        repository_id: id.clone(),
        binding_epoch: 1,
        store_path: base.join("stores").join(id).join("native"),
    };
    host.initialize_store(&binding, "initialize-sealer-target")
        .unwrap();
    let root = base.join("parent");
    let git = git2::Repository::init(&root).unwrap();
    std::fs::write(root.join("source.txt"), b"original\r\n").unwrap();
    std::fs::write(root.join("delete.txt"), b"delete me").unwrap();
    let mut index = git.index().unwrap();
    index
        .add_all(
            ["source.txt", "delete.txt"],
            git2::IndexAddOption::DEFAULT,
            None,
        )
        .unwrap();
    index.write().unwrap();
    let tree = git.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Source fixture", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "immutable source",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    drop(tree);
    drop(git);
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "sealer-baseline".into(),
            binding: binding.clone(),
            source_path: root.clone(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    host.open_store(&binding).unwrap();
    let canonical = host.cached_store(&binding).unwrap();
    let frozen = host.baseline_store(&baseline.baseline).unwrap();
    let (_, views, objects) =
        crate::native::snapshot_views(&frozen.repository, &baseline.native_state.view).unwrap();
    let mut repository =
        Repository::open_with_pristine(&binding.store_path, canonical.shared_pristine()).unwrap();
    for object in objects {
        let bytes = std::fs::read(frozen.repository.change_store().change_path(&object)).unwrap();
        repository.import_change_bytes(&object, &bytes).unwrap();
    }
    for view in &views {
        repository.apply_view_manifest(view).unwrap();
    }
    // Consume a canonical-local ID outside the captured ancestry. The fresh
    // source must have a different effective token while preserving exact views.
    repository
        .create_view_from("unrelated-draft-id", &baseline.native_state.view)
        .unwrap();
    repository
        .create_draft_view("first-source-draft", &baseline.native_state.view)
        .unwrap();
    repository
        .set_view_scope(
            "first-source-draft",
            atomic_core::pristine::ViewScope::Draft,
        )
        .unwrap();
    let expected_state = crate::recording::state(&repository, "first-source-draft").unwrap();
    let (_, draft_views, _) =
        crate::native::snapshot_views(&repository, "first-source-draft").unwrap();
    let draft = draft_views.last().unwrap();
    assert!(draft.changes.is_empty());
    assert_eq!(
        draft.parent.as_deref(),
        Some(baseline.native_state.view.as_str())
    );
    drop(repository);
    drop(frozen);
    drop(canonical);
    Fixture {
        _directory: directory,
        host,
        binding,
        root,
        baseline,
        expected_state,
    }
}

fn capture_request(f: &Fixture) -> Result<SealRecordSourceRequest> {
    let owner = f.host.register_working_copy_capture(
        &f.binding,
        &f.baseline.baseline,
        &f.root,
        "sealer-original-working-copy",
    )?;
    let turn = owner.try_begin_turn("fixture", "observe-exact-selection")?;
    turn.admit_writer()?.set_selection(None)?;
    drop(turn);
    let capture = f.host.capture_warm_child(
        owner.close_for_capture()?,
        "sealer-real-warm-capture",
        intentd_test_support::test_timeout(std::time::Duration::from_secs(5)),
    )?;
    let capture = WarmWorkingCopyCapture {
        operation_id: capture.operation_id,
        repository_id: capture.repository_id,
        binding_epoch: capture.binding_epoch,
        parent_working_copy_id: capture.parent_working_copy_id,
        parent_root: capture.parent_root,
        capture_generation: capture.capture_generation,
        selection_digest: capture.selection_digest,
        baseline: capture.baseline,
        baseline_manifest_digest: capture.baseline_manifest_digest,
        working_digest: capture.working_digest,
        path: capture.path,
        copied_entries: capture.copied_entries,
        copied_bytes: capture.copied_bytes,
        mechanism: capture.mechanism,
    };
    let bytes = b"changed\r\n\0\xff".to_vec();
    let files = vec![
        (
            descriptor("source.txt", SelectedFileKind::Regular, &bytes),
            bytes,
        ),
        (
            descriptor("delete.txt", SelectedFileKind::Deletion, b""),
            Vec::new(),
        ),
        (
            descriptor("new.bin", SelectedFileKind::Executable, b"\0\xfe"),
            b"\0\xfe".to_vec(),
        ),
        (
            descriptor("link", SelectedFileKind::Symlink, b"source.txt"),
            b"source.txt".to_vec(),
        ),
    ];
    Ok(SealRecordSourceRequest {
        operation_id: "seal-real-selected-source".into(),
        scope: intent_atomic_proto::closures::ClosureScope {
            workspace_id: "source-fixture-workspace".into(),
            root_id: "source-fixture-root".into(),
            repository_id: f.binding.repository_id.clone(),
            binding_epoch: 1,
        },
        binding: f.binding.clone(),
        expected_state: f.expected_state.clone(),
        capture,
        selection_digest: "a".repeat(64),
        files: files.iter().map(|(file, _)| file.clone()).collect(),
        payload: payload(&f.host.config.spool_dir, &files),
    })
}

#[test]
fn actual_private_native_source_seals_or_explicitly_refuses_unqualified_warm_copy() {
    let f = fixture();
    let request = match capture_request(&f) {
        Ok(request) => request,
        Err(HostError::Unsupported(reason)) => {
            assert!(reason.contains("clone") || reason.contains("reflink"));
            assert!(!f.host.config.spool_dir.join("record-sources").exists());
            return;
        }
        Err(error) => panic!("actual warm capture failed: {error}"),
    };
    let baseline_native = f
        .host
        .baseline_root(&f.baseline.baseline)
        .unwrap()
        .join("native");
    let before = tree_digest(&baseline_native).unwrap();
    let receipt = f.host.seal_record_source(&request).unwrap();
    assert!(receipt.matches_request(&request));
    assert_eq!(
        std::fs::read(receipt.sealed_source.join("source.txt")).unwrap(),
        b"changed\r\n\0\xff"
    );
    assert!(!receipt.sealed_source.join("delete.txt").exists());
    assert_eq!(
        std::fs::read_link(receipt.sealed_source.join("link")).unwrap(),
        Path::new("source.txt")
    );
    let private = Repository::open_readonly_without_migration(&receipt.sealed_source).unwrap();
    assert_eq!(
        crate::recording::state(&private, &request.expected_state.view).unwrap(),
        receipt.sealed_state
    );
    drop(private);
    assert_eq!(tree_digest(&baseline_native).unwrap(), before);
    assert_eq!(f.host.seal_record_source(&request).unwrap(), receipt);
    let prepare = PrepareRecordRequest {
        operation_id: "prepare-real-sealed-source".into(),
        binding: request.binding.clone(),
        sealed_source: receipt.sealed_source.clone(),
        expected_state: request.expected_state.clone(),
        files: request.files.clone(),
        message: "Private selection".into(),
        author_name: "Intent fixture".into(),
        author_email: None,
        unix_seconds: 1_800_000_000,
        context_json: "{}".into(),
    };
    assert!(matches!(
        f.host.prepare_exact_record(&prepare).unwrap(),
        RecordPreparation::Prepared { .. }
    ));
    assert_eq!(tree_digest(&baseline_native).unwrap(), before);
    let mut changed = request.clone();
    changed.selection_digest = "b".repeat(64);
    assert!(f.host.seal_record_source(&changed).is_err());
    std::fs::write(receipt.sealed_source.join("source.txt"), b"tampered").unwrap();
    assert!(f.host.seal_record_source(&request).is_err());
}

#[test]
fn forged_capture_cannot_create_private_sealed_native_source() {
    let f = fixture();
    let mut request = dummy_request(&f.host.config.spool_dir);
    request.binding = f.binding.clone();
    request.scope.repository_id = f.binding.repository_id.clone();
    request.capture.repository_id = f.binding.repository_id.clone();
    request.capture.baseline = f.baseline.baseline.clone();
    request.expected_state = f.expected_state.clone();
    assert!(f.host.seal_record_source(&request).is_err());
    let source = f
        .host
        .config
        .spool_dir
        .join("record-sources")
        .join(hash(request.operation_id.as_bytes()))
        .join("source");
    assert!(!source.exists());
}

#[test]
fn actual_empty_own_draft_capture_translates_only_through_retained_host_journal() {
    let f = fixture();
    let mut request = dummy_request(&f.host.config.spool_dir);
    request.operation_id = "real-empty-own-draft-source".into();
    request.binding = f.binding.clone();
    request.scope.repository_id = f.binding.repository_id.clone();
    request.expected_state = f.expected_state.clone();
    // This is a native reconstruction/record test. It uses a real captured Draft
    // and never manufactures a warm-copy, process-exit or callback-drain proof.
    let captured = f
        .host
        .capture_composition_target(&CaptureCompositionTargetRequest {
            operation_id: "real-empty-own-draft-capture".into(),
            scope: request.scope.clone(),
            binding: request.binding.clone(),
            view: request.expected_state.view.clone(),
            expected_state: request.expected_state.clone(),
        })
        .unwrap();
    let directory = f.host.config.spool_dir.join("record-sources");
    durable::private_dir(&directory).unwrap();
    let operation = directory.join(hash(request.operation_id.as_bytes()));
    durable::private_dir(&operation).unwrap();
    let source = operation.join("source");
    let local = f
        .host
        .instantiate_record_source(&request, &captured, &source, &f.baseline.policy)
        .unwrap();
    assert_eq!(local.view, request.expected_state.view);
    assert_ne!(
        local.effective_state,
        request.expected_state.effective_state
    );
    assert_eq!(local.own_merkle, request.expected_state.own_merkle);
    assert_eq!(
        std::fs::read(source.join("source.txt")).unwrap(),
        b"original\r\n"
    );
    let selected = selected_payload(&f.host.config.spool_dir, &request).unwrap();
    for entry in &selected {
        write_entry(
            &source.join(&entry.file.path),
            entry.file.kind,
            &entry.bytes,
        )
        .unwrap();
    }
    verify_source(&source, &local, &selected).unwrap();
    sync_source(&source).unwrap();
    let command_digest = hash(&serde_json::to_vec(&request).unwrap());
    let receipt = SealedRecordSource {
        host: HostIdentity::default(),
        operation_id: request.operation_id.clone(),
        binding: request.binding.clone(),
        scope: request.scope.clone(),
        expected_state: request.expected_state.clone(),
        sealed_state: local.clone(),
        capture_operation_id: request.capture.operation_id.clone(),
        baseline_manifest_digest: request.capture.baseline_manifest_digest.clone(),
        selection_digest: request.selection_digest.clone(),
        payload: request.payload.clone(),
        sealed_source: source.clone(),
        file_count: request.files.len() as u64,
        total_bytes: request.files.iter().map(|file| file.length).sum(),
        command_digest: command_digest.clone(),
    };
    // Persist the actual native capture/source observations. The typed public sealer
    // additionally checks its real warm baseline prerequisite, tested separately.
    let journal = Journal {
        version: 1,
        command_digest,
        phase: Phase::Published,
        directory: Some(durable::identity(&source, true).unwrap()),
        database: Some(durable::identity(&source.join(".atomic/atomic.redb"), false).unwrap()),
        source_digest: Some(tree_digest(&source).unwrap()),
        receipt: Some(receipt),
        captured_target: Some(captured),
        files_digest: hash(&serde_json::to_vec(&request.files).unwrap()),
    };
    durable::write_json(
        &directory.join(format!("{}.json", hash(request.operation_id.as_bytes()))),
        &journal,
        false,
    )
    .unwrap();
    let record = PrepareRecordRequest {
        operation_id: "record-real-empty-own-draft".into(),
        binding: request.binding.clone(),
        sealed_source: source,
        expected_state: request.expected_state.clone(),
        files: request.files.clone(),
        message: "First Draft contribution".into(),
        author_name: "Intent native fixture".into(),
        author_email: None,
        unix_seconds: 1_800_000_000,
        context_json: "{}".into(),
    };
    assert_eq!(
        f.host.sealed_record_local_state(&record).unwrap(),
        Some(local)
    );
    let RecordPreparation::Prepared { record: prepared } =
        f.host.prepare_exact_record(&record).unwrap()
    else {
        panic!("actual selected bytes must record")
    };
    assert_eq!(prepared.expected_state, request.expected_state);
    assert_eq!(prepared.recorded_paths, ["binary.bin"]);
    let admitted = f.host.admit_exact_record(&prepared).unwrap();
    assert_eq!(admitted.before, request.expected_state);
    assert_eq!(admitted.after.view, request.expected_state.view);
    assert_ne!(admitted.after.own_merkle, admitted.before.own_merkle);
    let mut foreign = record;
    foreign.files[0].sha256 = "f".repeat(64);
    assert!(f.host.sealed_record_local_state(&foreign).is_err());
}
