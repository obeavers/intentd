use super::*;
use intent_atomic_proto::baselines::{
    BaselinePolicy, BaselineReceipt, BaselineRef, BaselineStorage,
};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    base: PathBuf,
    working: PathBuf,
    spool: PathBuf,
    closure: BaselineClosure,
    request: AggregateCaptureRequest,
}

fn put(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let base = root.join("baseline");
    let working = root.join("closed-working");
    let spool = root.join("spool");
    std::fs::create_dir(&base).unwrap();
    std::fs::create_dir(&working).unwrap();
    for (path, bytes) in [
        ("tracked.txt", b"base\r\n".as_slice()),
        ("deleted.txt", b"removed".as_slice()),
        ("file-to-directory", b"old".as_slice()),
    ] {
        put(&base, path, bytes);
        put(&working, path, bytes);
    }
    put(&base, "directory-to-file/old", b"old child");
    put(&working, "directory-to-file/old", b"old child");
    put(&working, "tracked.txt", b"dirty\r\n");
    std::fs::remove_file(working.join("deleted.txt")).unwrap();
    std::fs::remove_file(working.join("file-to-directory")).unwrap();
    put(&working, "file-to-directory/child", b"new child");
    std::fs::remove_dir_all(working.join("directory-to-file")).unwrap();
    put(&working, "directory-to-file", b"replacement file");
    put(&working, "target/ignored.bin", &[0, 255, 1, 0]);
    put(&working, "untracked-empty", b"");
    put(
        &working,
        ".vault/user-notes.md",
        b"user vault is ordinary source",
    );
    put(
        &working,
        "nested/.intent/content",
        b"user directory must survive",
    );
    put(&working, "run", b"#!/bin/sh\n");
    std::fs::set_permissions(working.join("run"), std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::create_dir(working.join("ignored-empty-directory")).unwrap();
    symlink("tracked.txt", working.join("link")).unwrap();
    for entry in fs::snapshot(&base).unwrap().entries {
        if entry.kind == FileKind::Directory {
            std::fs::set_permissions(
                base.join(entry.path),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }
    let baseline = fs::snapshot(&base).unwrap();
    let native_manifest_digest = native_manifest_digest(&baseline.entries).unwrap();
    let state = StateToken {
        view: "frozen-baseline".into(),
        effective_state: "A".repeat(52),
        own_merkle: "B".repeat(52),
    };
    let reference = BaselineRef {
        repository_id: uuid::Uuid::new_v4().to_string(),
        binding_epoch: 3,
        baseline_id: "c".repeat(64),
    };
    let scope = ClosureScope {
        workspace_id: "original-workspace".into(),
        root_id: "primary".into(),
        repository_id: reference.repository_id.clone(),
        binding_epoch: reference.binding_epoch,
    };
    let payload = Spool::open(&spool)
        .unwrap()
        .retain_closure(b"fixture native closure; codec tests do not qualify native restore")
        .unwrap();
    let closure = BaselineClosure {
        format: CLOSURE_FORMAT,
        profile: ClosureProfile::FrozenBaseline,
        host: HostIdentity::default(),
        scope: scope.clone(),
        capture_revision: 7,
        baseline: BaselineReceipt {
            baseline: reference.clone(),
            host: HostIdentity::default(),
            source_commit: "d".repeat(40),
            source_tree: "e".repeat(40),
            previous: None,
            storage: BaselineStorage::FullReimport,
            native_state: state.clone(),
            materialization_id: digest(
                &serde_json::to_vec(&(MATERIALIZER_VERSION, &native_manifest_digest)).unwrap(),
            ),
            manifest_digest: native_manifest_digest,
            file_count: baseline
                .entries
                .iter()
                .filter(|entry| entry.kind != FileKind::Directory)
                .count() as u64,
            total_bytes: baseline.entries.iter().map(|entry| entry.length).sum(),
            policy: BaselinePolicy::default(),
        },
        payload,
        object_count: 1,
    };
    let source = fs::snapshot(&working).unwrap();
    let tracked = source
        .entries
        .iter()
        .find(|entry| entry.path == "tracked.txt")
        .unwrap();
    let request = AggregateCaptureRequest {
        profile: CheckpointProfile::FrozenBaselineOverlay,
        export: ExportBaselineClosureRequest {
            operation_id: "capture-original".into(),
            scope,
            capture_revision: 7,
            baseline: reference,
        },
        sealed_source: working.clone(),
        expected_working_manifest: file_digest(&source.entries).unwrap(),
        expected_state: state,
        selection: CheckpointSelection::Known {
            selection_id: "original-selection".into(),
            files: vec![
                SelectedFile {
                    path: tracked.path.clone(),
                    kind: SelectedFileKind::Regular,
                    length: tracked.length,
                    sha256: tracked.sha256.clone(),
                },
                SelectedFile {
                    path: "deleted.txt".into(),
                    kind: SelectedFileKind::Deletion,
                    length: 0,
                    sha256: digest(&[]),
                },
            ],
        },
        selection_contents: vec![],
        ignored_paths: vec!["target".into(), "ignored-empty-directory".into()],
        task_intent_links: vec![],
        authorship_boundaries: vec![AuthorshipBoundary {
            paths: vec!["tracked.txt".into()],
            authors: vec![],
            completeness: AuthorshipCompleteness::Unknown,
        }],
        evidence_documents: vec![
            EvidenceDocument {
                kind: "task-source".into(),
                logical_id: "original-task-revision".into(),
                bytes: br#"{"revision":7,"text":"original source"}"#.to_vec(),
            },
            EvidenceDocument {
                kind: "provenance".into(),
                logical_id: "original-turn".into(),
                bytes: vec![0, 255, 7],
            },
        ],
        inherited: vec![InheritedCheckpointRef {
            scope: closure.scope.clone(),
            capture_revision: 2,
            archive_sha256: "1".repeat(64),
        }],
    };
    Fixture {
        _directory: directory,
        root,
        base,
        working,
        spool,
        closure,
        request,
    }
}

fn capture(f: &Fixture) -> CapturedCheckpoint {
    capture_frozen_components(
        f.request.clone(),
        f.closure.clone(),
        f.base.clone(),
        &f.spool,
    )
    .unwrap()
}

fn bytes(f: &Fixture, captured: &CapturedCheckpoint) -> Vec<u8> {
    let mut file = Spool::open(&f.spool)
        .unwrap()
        .open_verified(&captured.payload, MAX_ARCHIVE)
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn unchecked(
    manifest: &AggregateManifest,
    objects: &BTreeMap<String, Vec<u8>>,
) -> (Vec<u8>, AggregateCheckpointRef) {
    let header = serde_json::to_vec(manifest).unwrap();
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&header);
    for object in objects.values() {
        bytes.extend_from_slice(object);
    }
    let reference = AggregateCheckpointRef {
        format: AGGREGATE_CHECKPOINT_FORMAT,
        reader_version: AGGREGATE_READER_VERSION,
        scope: manifest.scope.clone(),
        capture_revision: manifest.capture_revision,
        length: bytes.len() as u64,
        sha256: digest(&bytes),
    };
    (bytes, reference)
}

#[test]
fn aggregate_overlay_roundtrip_preserves_raw_files_selection_and_unknown_evidence() {
    let f = fixture();
    let captured = capture(&f);
    let archive = decode(
        &bytes(&f, &captured),
        &captured.reference,
        &captured.reference.scope,
    )
    .unwrap();
    assert!(captured
        .manifest
        .overlay
        .upserts
        .iter()
        .any(|entry| entry.file.path == "target/ignored.bin"
            && entry.tracking == TrackingKind::Ignored));
    assert_eq!(
        archive.manifest.evidence.authorship_boundaries[0].completeness,
        AuthorshipCompleteness::Unknown
    );
    let expected = fs::snapshot(&f.working).unwrap();
    let restored = archive
        .restore_files(
            "restore-original".into(),
            &f.closure.baseline,
            f.base.clone(),
            &f.root.join("restores"),
        )
        .unwrap();
    assert_eq!(fs::snapshot(&restored.path).unwrap(), expected);
    assert_eq!(restored.selection, f.request.selection);
    assert_eq!(restored.evidence_documents, f.request.evidence_documents);
    assert_eq!(
        std::fs::read_link(restored.path.join("link")).unwrap(),
        Path::new("tracked.txt")
    );
    assert_eq!(
        std::fs::metadata(restored.path.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    assert!(!restored.path.join("deleted.txt").exists());
    assert_eq!(
        std::fs::read(restored.path.join("target/ignored.bin")).unwrap(),
        vec![0, 255, 1, 0]
    );
    assert!(restored.path.join("ignored-empty-directory").is_dir());
    assert_eq!(
        std::fs::read(restored.path.join(".vault/user-notes.md")).unwrap(),
        b"user vault is ordinary source"
    );
    assert_eq!(
        std::fs::read(restored.path.join("nested/.intent/content")).unwrap(),
        b"user directory must survive"
    );
    let replay = decode(
        &bytes(&f, &captured),
        &captured.reference,
        &captured.reference.scope,
    )
    .unwrap()
    .restore_files(
        "restore-original".into(),
        &f.closure.baseline,
        f.base.clone(),
        &f.root.join("restores"),
    )
    .unwrap();
    assert_eq!(replay.path, restored.path);
}

#[test]
fn immutable_capture_replay_survives_reopen_and_refuses_different_evidence() {
    let f = fixture();
    let first = capture(&f);
    let repeated = capture(&f);
    assert_eq!(first.reference, repeated.reference);
    assert_eq!(first.payload, repeated.payload);
    let retained = bytes(&f, &first);
    let mut changed = f.request.clone();
    changed.evidence_documents[0].bytes.push(b'!');
    assert!(
        capture_frozen_components(changed, f.closure.clone(), f.base.clone(), &f.spool).is_err()
    );
    assert_eq!(bytes(&f, &first), retained);
}

#[test]
fn selected_bytes_and_selected_deletion_survive_later_working_edits_and_recreation() {
    let mut f = fixture();
    let original_selection = f.request.selection.clone();
    f.request.selection_contents = vec![SelectedContent {
        path: "tracked.txt".into(),
        bytes: b"dirty\r\n".to_vec(),
    }];
    put(&f.working, "tracked.txt", b"later working edit\n");
    put(
        &f.working,
        "deleted.txt",
        b"recreated after selection froze",
    );
    f.request.expected_working_manifest = observe_closed_working_manifest(&f.working).unwrap();
    let captured = capture(&f);
    let raw = bytes(&f, &captured);
    let restored = decode(&raw, &captured.reference, &captured.reference.scope)
        .unwrap()
        .restore_files(
            "restore-independent-selection".into(),
            &f.closure.baseline,
            f.base.clone(),
            &f.root.join("restores"),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(restored.path.join("tracked.txt")).unwrap(),
        b"later working edit\n"
    );
    assert_eq!(
        std::fs::read(restored.path.join("deleted.txt")).unwrap(),
        b"recreated after selection froze"
    );
    assert_eq!(restored.selection, original_selection);
    assert_eq!(restored.selection_contents, f.request.selection_contents);
    assert_eq!(std::fs::read(&restored.archive_path).unwrap(), raw);
    let selected = restored
        .path
        .parent()
        .unwrap()
        .join("selection-objects")
        .join(digest(b"dirty\r\n"));
    assert_eq!(std::fs::read(selected).unwrap(), b"dirty\r\n");
}

#[tokio::test]
async fn recorded_aggregate_restore_uses_the_typed_native_owner_and_separates_fresh_ids() {
    use std::os::unix::fs::DirBuilderExt;

    // Transport-only fixtures do not qualify native object restoration; the
    // atomic-host aggregate fixture supplies that independent native proof.
    let f = fixture();
    for entry in fs::snapshot(&f.base).unwrap().entries {
        if entry.kind == FileKind::Directory {
            std::fs::set_permissions(
                f.base.join(entry.path),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }
    let native_files = fs::snapshot(&f.base).unwrap();
    let manifest_digest = recorded_manifest_digest(&native_files.entries).unwrap();
    let code_bytes = b"recorded transport fixture; not native qualification";
    let code_hash = digest(code_bytes);
    let payload = Spool::open(&f.spool)
        .unwrap()
        .retain_named(&format!("recorded-{code_hash}.bin"), code_bytes)
        .unwrap();
    let source_state = StateToken {
        view: "target/nested".into(),
        effective_state: "original-numeric-view-ids".into(),
        own_merkle: "original-own-merkle".into(),
    };
    let closure = RecordedClosure {
        format: RECORDED_CLOSURE_FORMAT,
        reader_version: RECORDED_CLOSURE_READER,
        profile: RecordedClosureProfile::RecordedViewExact,
        operation_id: f.request.export.operation_id.clone(),
        host: HostIdentity::default(),
        scope: f.request.export.scope.clone(),
        capture_revision: f.request.export.capture_revision,
        source_state: source_state.clone(),
        project_id: "original-project".into(),
        project_identity_hash: "original-project-object".into(),
        view_manifest_digest: "a".repeat(64),
        materialization_manifest_digest: manifest_digest.clone(),
        materialization_id: digest(
            &serde_json::to_vec(&(
                "intent-recorded-materialization",
                RECORDED_MATERIALIZER_VERSION,
                manifest_digest,
            ))
            .unwrap(),
        ),
        conflict: None,
        object_count: 1,
        payload,
    };
    let base_receipt = recorded_transport_receipt(
        &closure,
        "capture-native",
        f.root.join("native"),
        f.base.clone(),
    );
    let original = f.request.clone();
    let captured = capture_recorded_components(
        RecordedAggregateCaptureRequest {
            export: ExportRecordedClosureRequest {
                operation_id: original.export.operation_id,
                scope: original.export.scope,
                capture_revision: original.export.capture_revision,
                binding: intent_atomic_proto::StoreBinding {
                    repository_id: closure.scope.repository_id.clone(),
                    binding_epoch: closure.scope.binding_epoch,
                    store_path: f.root.join("source-native"),
                },
                view: source_state.view.clone(),
                expected_state: source_state.clone(),
            },
            sealed_source: original.sealed_source,
            expected_working_manifest: original.expected_working_manifest,
            selection: original.selection,
            selection_contents: original.selection_contents,
            ignored_paths: original.ignored_paths,
            task_intent_links: original.task_intent_links,
            authorship_boundaries: original.authorship_boundaries,
            evidence_documents: original.evidence_documents,
            inherited: original.inherited,
        },
        closure,
        &base_receipt,
        &f.spool,
    )
    .unwrap();
    let archive_bytes = bytes(&f, &captured);
    let config = crate::HostLaunchConfig::new(
        f.root.join("never-executed"),
        f.root.join("transport-data"),
        f.root.join("transport-stores"),
    );
    let spool = f.root.join("transport-data/atomic/spool");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&spool)
        .unwrap();
    let (sender, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let mut streams = Vec::new();
    let mut peers = Vec::new();
    for _ in 0..5 {
        let (client, server) = tokio::io::duplex(65_536);
        streams.push(client);
        peers.push(tokio::spawn(recorded_aggregate_peer(
            server,
            spool.clone(),
            native_files.clone(),
            sender.clone(),
        )));
    }
    let control = streams.remove(0);
    let supervisor = Arc::new(
        HostSupervisor::with_test_transport(config, control, streams)
            .await
            .unwrap(),
    );
    let client = AtomicCheckpointClient::new(supervisor, f.root.join("typed-restores")).unwrap();
    let restored = client
        .restore(
            "typed-recorded-restore".into(),
            captured.reference.clone(),
            captured.reference.scope.clone(),
            archive_bytes,
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(restored.path.join("tracked.txt")).unwrap(),
        b"dirty\r\n"
    );
    let PreparedCheckpointCode::RecordedView { receipt } = &restored.native_code else {
        panic!("recorded profile was substituted");
    };
    assert_eq!(receipt.source_state, source_state);
    assert_eq!(receipt.restored_state.own_merkle, source_state.own_merkle);
    assert_ne!(
        receipt.restored_state.effective_state,
        source_state.effective_state
    );
    let mut recorded = 0;
    while let Ok(command) = observed.try_recv() {
        match command {
            Command::RestoreRecordedClosure { .. } => recorded += 1,
            Command::RestoreBaselineClosure { .. }
            | Command::ExportBaselineClosure { .. }
            | Command::MaterializeBaseline { .. } => {
                panic!("recorded checkpoint dispatched a baseline operation")
            }
            _ => {}
        }
    }
    assert_eq!(recorded, 1);
    for peer in peers {
        peer.abort();
    }
}

async fn recorded_aggregate_peer(
    mut stream: tokio::io::DuplexStream,
    spool: PathBuf,
    files: fs::Snapshot,
    observed: tokio::sync::mpsc::UnboundedSender<Command>,
) {
    use intent_atomic_proto::{Outcome, RecoveryReport, Reply, Request, Response};
    loop {
        let request: Request = match crate::codec::read_frame(&mut stream).await {
            Ok(request) => request,
            Err(_) => return,
        };
        let _ = observed.send(request.command.clone());
        let reply = match request.command {
            Command::Handshake { identity } => Reply::Handshake { identity },
            Command::Reconcile => Reply::Reconciled {
                recovery: RecoveryReport {
                    ready: true,
                    unresolved_operation_ids: vec![],
                },
            },
            Command::Ping => Reply::Pong,
            Command::RestoreRecordedClosure { request } => {
                let root = spool
                    .join("recorded-restores")
                    .join(digest(request.operation_id.as_bytes()))
                    .join(format!("attempt-{}", uuid::Uuid::new_v4()));
                let native = root.join("native");
                let output = root.join("files");
                std::fs::create_dir_all(&native).unwrap();
                std::fs::create_dir(&output).unwrap();
                for entry in &files.entries {
                    if entry.kind == FileKind::Directory {
                        std::fs::create_dir_all(output.join(&entry.path)).unwrap();
                        std::fs::set_permissions(
                            output.join(&entry.path),
                            std::fs::Permissions::from_mode(entry.mode),
                        )
                        .unwrap();
                    } else {
                        put(&output, &entry.path, &files.contents[&entry.path]);
                    }
                }
                Reply::RecordedClosureRestored {
                    receipt: Box::new(recorded_transport_receipt(
                        &request.closure,
                        &request.operation_id,
                        native,
                        output,
                    )),
                }
            }
            other => panic!("unexpected aggregate host command: {other:?}"),
        };
        if crate::codec::write_frame(
            &mut stream,
            &Response {
                id: request.id,
                outcome: Outcome::Success(Box::new(reply)),
            },
        )
        .await
        .is_err()
        {
            return;
        }
    }
}

fn recorded_transport_receipt(
    closure: &RecordedClosure,
    operation: &str,
    native_path: PathBuf,
    path: PathBuf,
) -> RecordedClosureRestore {
    let mut receipt = RecordedClosureRestore {
        operation_id: operation.into(),
        host: HostIdentity::default(),
        scope: closure.scope.clone(),
        capture_revision: closure.capture_revision,
        source_state: closure.source_state.clone(),
        restored_state: StateToken {
            view: closure.source_state.view.clone(),
            own_merkle: closure.source_state.own_merkle.clone(),
            effective_state: "fresh-numeric-view-ids".into(),
        },
        project_id: closure.project_id.clone(),
        project_identity_hash: closure.project_identity_hash.clone(),
        view_manifest_digest: closure.view_manifest_digest.clone(),
        materialization_manifest_digest: closure.materialization_manifest_digest.clone(),
        materialization_id: closure.materialization_id.clone(),
        native_conflict_hash: closure
            .conflict
            .as_ref()
            .map(|conflict| conflict.native_hash.clone()),
        object_count: closure.object_count,
        native_path,
        path,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = digest(&serde_json::to_vec(&receipt).unwrap());
    receipt
}

#[test]
fn same_length_native_baseline_corruption_refuses_before_aggregate_publish() {
    let f = fixture();
    put(&f.base, "tracked.txt", b"evil\r\n");
    assert!(capture_frozen_components(
        f.request.clone(),
        f.closure.clone(),
        f.base.clone(),
        &f.spool
    )
    .is_err());
    assert!(!std::fs::read_dir(&f.spool).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("aggregate-")));
}

#[test]
fn original_capture_operation_cannot_be_reused_with_another_revision() {
    let mut f = fixture();
    let captured = capture(&f);
    let original = bytes(&f, &captured);
    f.closure.capture_revision += 1;
    f.request.export.capture_revision += 1;
    assert!(capture_frozen_components(
        f.request.clone(),
        f.closure.clone(),
        f.base.clone(),
        &f.spool
    )
    .is_err());
    assert_eq!(bytes(&f, &captured), original);
}

#[test]
fn changed_source_or_selection_refuses_without_retaining_an_aggregate() {
    let f = fixture();
    put(
        &f.working,
        "target/ignored.bin",
        b"changed after original source fence",
    );
    assert!(capture_frozen_components(
        f.request.clone(),
        f.closure.clone(),
        f.base.clone(),
        &f.spool
    )
    .is_err());
    assert!(!std::fs::read_dir(&f.spool).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("aggregate-")));
}

#[test]
fn corrupt_object_traversal_mismatched_profile_and_foreign_epoch_refuse_before_restore() {
    let f = fixture();
    let captured = capture(&f);
    let raw = bytes(&f, &captured);
    let archive = decode(&raw, &captured.reference, &captured.reference.scope).unwrap();
    let mut corrupt = raw.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode(&corrupt, &captured.reference, &captured.reference.scope).is_err());
    let mut scope = captured.reference.scope.clone();
    scope.binding_epoch += 1;
    assert!(decode(&raw, &captured.reference, &scope).is_err());
    let mut manifest = archive.manifest.clone();
    manifest.overlay.upserts[0].file.path = "../escape".into();
    let (bad, reference) = unchecked(&manifest, &archive.objects);
    assert!(decode(&bad, &reference, &reference.scope).is_err());
    manifest = archive.manifest.clone();
    manifest.reader_version += 1;
    let (bad, reference) = unchecked(&manifest, &archive.objects);
    assert!(decode(&bad, &reference, &reference.scope).is_err());
    manifest = archive.manifest;
    manifest.profile = CheckpointProfile::RecordedView;
    let (bad, reference) = unchecked(&manifest, &archive.objects);
    assert!(matches!(
        decode(&bad, &reference, &reference.scope),
        Err(HostError::Protocol(_))
    ));
    assert!(!f.root.join("restores").exists());
    assert!(!f.root.parent().unwrap().join("escape").exists());
}

#[test]
fn changed_private_restore_is_not_repaired_or_followed() {
    let f = fixture();
    let captured = capture(&f);
    let raw = bytes(&f, &captured);
    let restored = decode(&raw, &captured.reference, &captured.reference.scope)
        .unwrap()
        .restore_files(
            "restore-owned".into(),
            &f.closure.baseline,
            f.base.clone(),
            &f.root.join("restores"),
        )
        .unwrap();
    std::fs::write(restored.path.join("tracked.txt"), b"unexpected user edit").unwrap();
    assert!(decode(&raw, &captured.reference, &captured.reference.scope)
        .unwrap()
        .restore_files(
            "restore-owned".into(),
            &f.closure.baseline,
            f.base.clone(),
            &f.root.join("restores")
        )
        .is_err());
    assert_eq!(
        std::fs::read(restored.path.join("tracked.txt")).unwrap(),
        b"unexpected user edit"
    );
    let outside = f.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    put(&outside, "sentinel", b"preserve");
    std::fs::rename(&restored.path, restored.path.with_file_name("old-files")).unwrap();
    symlink(&outside, &restored.path).unwrap();
    assert!(decode(&raw, &captured.reference, &captured.reference.scope)
        .unwrap()
        .restore_files(
            "restore-owned".into(),
            &f.closure.baseline,
            f.base.clone(),
            &f.root.join("restores")
        )
        .is_err());
    assert_eq!(
        std::fs::read(outside.join("sentinel")).unwrap(),
        b"preserve"
    );
    assert_eq!(std::fs::read_dir(outside).unwrap().count(), 1);
}

#[tokio::test]
async fn invalid_archive_does_not_start_host_or_create_any_destination() {
    let f = fixture();
    let captured = capture(&f);
    let host = Arc::new(
        HostSupervisor::new(crate::HostLaunchConfig::new(
            f.root.join("must-not-execute"),
            f.root.join("daemon-not-created"),
            f.root.join("stores-not-created"),
        ))
        .unwrap(),
    );
    let client = AtomicCheckpointClient::new(host, f.root.join("restores-not-created")).unwrap();
    assert!(client
        .restore(
            "invalid".into(),
            captured.reference.clone(),
            captured.reference.scope.clone(),
            b"invalid bytes".to_vec()
        )
        .await
        .is_err());
    assert!(!f.root.join("daemon-not-created").exists());
    assert!(!f.root.join("stores-not-created").exists());
    assert!(!f.root.join("restores-not-created").exists());
}

#[test]
fn fifo_and_parent_symlinks_refuse_without_reading_external_bytes() {
    let f = fixture();
    let fifo =
        std::ffi::CString::new(f.working.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the terminated private fixture path and mode are valid.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(fs::snapshot(&f.working).is_err());
    std::fs::remove_file(f.working.join("fifo")).unwrap();
    symlink(&f.working, f.root.join("redirect")).unwrap();
    assert!(fs::snapshot(&f.root.join("redirect")).is_err());
}

#[test]
fn unowned_engine_metadata_refuses_capture_instead_of_silently_omitting_bytes() {
    let f = fixture();
    put(&f.working, "nested/.git/config", b"unowned nested metadata");
    assert!(observe_closed_working_manifest(&f.working).is_err());
    assert!(capture_frozen_components(
        f.request.clone(),
        f.closure.clone(),
        f.base.clone(),
        &f.spool
    )
    .is_err());
    assert!(!std::fs::read_dir(&f.spool).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("aggregate-")));
}
