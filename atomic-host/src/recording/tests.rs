use super::*;
use crate::HostConfig;
use intent_atomic_proto::recording::{SelectedFile, SelectedFileKind};
use intent_atomic_proto::StoreBinding;

pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) host: Host,
    pub(super) request: PrepareRecordRequest,
}

pub(super) fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).unwrap();
    let config = HostConfig {
        stores_dir: directory_path.join("stores"),
        config_dir: directory_path.join("config"),
        spool_dir: directory_path.join("spool"),
    };
    let id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        repository_id: id.clone(),
        binding_epoch: 1,
        store_path: config.stores_dir.join(id).join("native"),
    };
    let host = Host::new(config).unwrap();
    assert!(host.reconcile().unwrap().ready);
    host.initialize_store(&binding, "initialize-record-target")
        .unwrap();
    host.open_store(&binding).unwrap();
    let target = host.cached_store(&binding).unwrap();
    target
        .repository()
        .set_view_scope(
            target.repository().current_view(),
            atomic_core::pristine::ViewScope::Draft,
        )
        .unwrap();
    drop(target);
    let source = host.config.spool_dir.join("sealed-source");
    durable::private_dir(&source).unwrap();
    let repository = Repository::init(&source).unwrap();
    repository
        .set_view_scope(
            repository.current_view(),
            atomic_core::pristine::ViewScope::Draft,
        )
        .unwrap();
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .unwrap();
    let bytes = b"exact line one\r\nexact line two\r\n";
    std::fs::write(source.join("input.txt"), bytes).unwrap();
    let working_copy = repository.require_working_copy_id().unwrap();
    repository.add_batch(working_copy, &["input.txt"]).unwrap();
    let expected_state = state(&repository, repository.current_view()).unwrap();
    assert_eq!(
        expected_state,
        host.cached_store(&binding).unwrap().state().unwrap()
    );
    drop(repository);
    let request = PrepareRecordRequest {
        operation_id: "exact-record-operation".into(),
        binding,
        sealed_source: source,
        expected_state,
        files: vec![SelectedFile {
            path: "input.txt".into(),
            kind: SelectedFileKind::Regular,
            length: u64::try_from(bytes.len()).unwrap(),
            sha256: digest(bytes),
        }],
        message: "Fixed record metadata".into(),
        author_name: "Intent qualification".into(),
        author_email: Some("qualification@example.test".into()),
        unix_seconds: 1_800_000_000,
        context_json: "{\"workBinding\":\"frozen-turn\",\"taskRevision\":\"frozen-source\"}".into(),
    };
    Fixture {
        directory,
        host,
        request,
    }
}

pub(super) fn prepared(fixture: &Fixture) -> PreparedNativeRecord {
    let RecordPreparation::Prepared { record } =
        fixture.host.prepare_exact_record(&fixture.request).unwrap()
    else {
        panic!("fixture must record a change")
    };
    *record
}

#[test]
fn actual_record_preparation_repeats_original_bytes_and_never_saves_or_applies() {
    let f = fixture();
    let repo = Repository::open_readonly_without_migration(&f.request.sealed_source).unwrap();
    let before = state(&repo, &f.request.expected_state.view).unwrap();
    let count = repo.count_changes().unwrap();
    let first = assemble(&repo, &f.request).unwrap().unwrap();
    let second = assemble(&repo, &f.request).unwrap().unwrap();
    assert_eq!(first.change_hash, second.change_hash);
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(first.metadata_digest, second.metadata_digest);
    assert_eq!(state(&repo, &before.view).unwrap(), before);
    assert_eq!(repo.count_changes().unwrap(), count);
    assert!(!native_object_path(&repo, &first.change_hash)
        .unwrap()
        .exists());
    assert_eq!(
        std::fs::read(f.request.sealed_source.join("input.txt")).unwrap(),
        b"exact line one\r\nexact line two\r\n"
    );
    drop(repo);
    let record = prepared(&f);
    assert_eq!(
        verified_spool(&f.host.config.spool_dir, &record.bytes).unwrap(),
        first.bytes
    );
    assert_eq!(record.change_hash, first.change_hash);
    assert_eq!(record.metadata_digest, first.metadata_digest);
    assert_eq!(record, prepared(&f));
}

#[test]
fn durable_ingress_inserts_original_encoding_once_and_preserves_raw_crlf_bytes() {
    let f = fixture();
    let record = prepared(&f);
    let exact = verified_spool(&f.host.config.spool_dir, &record.bytes).unwrap();
    let receipt = f.host.admit_exact_record(&record).unwrap();
    assert!(!receipt.replayed);
    assert_ne!(receipt.before, receipt.after);
    let repository = f.host.cached_store(&record.binding).unwrap();
    assert_eq!(
        std::fs::read(native_object_path(repository.repository(), &record.change_hash).unwrap())
            .unwrap(),
        exact
    );
    assert_eq!(
        repository
            .repository()
            .get_file_content_on_view("input.txt", &record.expected_state.view)
            .unwrap()
            .unwrap(),
        b"exact line one\r\nexact line two\r\n"
    );
    let count = repository
        .repository()
        .get_view_info(&record.expected_state.view)
        .unwrap()
        .change_count;
    let repeated = f.host.admit_exact_record(&record).unwrap();
    assert!(repeated.replayed);
    assert_eq!(repeated.after, receipt.after);
    assert_eq!(
        repository
            .repository()
            .get_view_info(&record.expected_state.view)
            .unwrap()
            .change_count,
        count
    );
    assert!(f.host.unresolved_records().unwrap().is_empty());
}

#[test]
fn whole_file_record_preserves_binary_empty_executable_and_symlink_inputs() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = fixture();
    let repository = Repository::open(&f.request.sealed_source).unwrap();
    let inputs = [
        (
            "binary.bin",
            SelectedFileKind::Regular,
            b"\0\xffraw\r\n".as_slice(),
        ),
        ("empty.txt", SelectedFileKind::Regular, b"".as_slice()),
        (
            "tool.sh",
            SelectedFileKind::Executable,
            b"#!/bin/sh\nexit 0\n".as_slice(),
        ),
        ("link", SelectedFileKind::Symlink, b"input.txt".as_slice()),
    ];
    for (path, kind, bytes) in inputs {
        let full = f.request.sealed_source.join(path);
        if kind == SelectedFileKind::Symlink {
            std::os::unix::fs::symlink("input.txt", full).unwrap();
        } else {
            std::fs::write(&full, bytes).unwrap();
            if kind == SelectedFileKind::Executable {
                std::fs::set_permissions(full, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        f.request.files.push(SelectedFile {
            path: path.into(),
            kind,
            length: u64::try_from(bytes.len()).unwrap(),
            sha256: digest(bytes),
        });
    }
    repository
        .add_batch(
            repository.require_working_copy_id().unwrap(),
            &["binary.bin", "empty.txt", "tool.sh", "link"],
        )
        .unwrap();
    drop(repository);
    let record = prepared(&f);
    f.host.admit_exact_record(&record).unwrap();
    let store = f.host.cached_store(&record.binding).unwrap();
    let mut actual = std::collections::BTreeMap::new();
    store
        .repository()
        .materialize_view_entries(&record.expected_state.view, |entry| {
            if entry.kind != atomic_repository::ViewEntryKind::Directory {
                actual.insert(entry.path, (entry.kind, entry.mode, entry.content));
            }
            Ok::<_, HostError>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(actual.len(), f.request.files.len());
    for file in &f.request.files {
        let (kind, mode, bytes) = actual.get(&file.path).unwrap();
        assert_eq!(digest(bytes), file.sha256);
        if file.kind == SelectedFileKind::Symlink {
            assert_eq!(*kind, atomic_repository::ViewEntryKind::Symlink);
        } else {
            assert_eq!(*kind, atomic_repository::ViewEntryKind::File);
            assert_eq!(
                *mode,
                if file.kind == SelectedFileKind::Executable {
                    0o755
                } else {
                    0o644
                }
            );
        }
    }
}

#[test]
fn stale_expectation_and_tampered_prepared_bytes_refuse_before_membership() {
    let mut f = fixture();
    let first = prepared(&f);
    f.request.operation_id = "second-operation-with-same-old-state".into();
    let second = prepared(&f);
    f.host.admit_exact_record(&first).unwrap();
    let before = f
        .host
        .cached_store(&first.binding)
        .unwrap()
        .state()
        .unwrap();
    assert!(matches!(
        f.host.admit_exact_record(&second),
        Err(HostError::Invalid(_))
    ));
    assert_eq!(
        f.host
            .cached_store(&first.binding)
            .unwrap()
            .state()
            .unwrap(),
        before
    );
    let mut forged = first.clone();
    forged.bytes.sha256 = "0".repeat(64);
    assert!(f.host.admit_exact_record(&forged).is_err());
    let payload = spool_path(&f.host.config.spool_dir, &second.bytes).unwrap();
    std::fs::write(payload, b"false serialized record").unwrap();
    assert!(f.host.admit_exact_record(&second).is_err());
}

#[test]
fn filtered_sources_and_changed_frozen_inputs_never_prepare_a_record() {
    let f = fixture();
    std::fs::write(
        f.request.sealed_source.join(".gitattributes"),
        "* text eol=lf\n",
    )
    .unwrap();
    assert!(matches!(
        f.host.prepare_exact_record(&f.request),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f
        .host
        .record_journal_path(&f.request.operation_id)
        .unwrap()
        .exists());
    std::fs::remove_file(f.request.sealed_source.join(".gitattributes")).unwrap();
    std::fs::write(f.request.sealed_source.join("input.txt"), b"other bytes").unwrap();
    assert!(f.host.prepare_exact_record(&f.request).is_err());
    assert_eq!(
        f.host
            .cached_store(&f.request.binding)
            .unwrap()
            .state()
            .unwrap(),
        f.request.expected_state
    );
}

#[test]
fn no_change_preparation_is_durable_without_inventing_a_change_hash() {
    let mut f = fixture();
    f.request.files = vec![SelectedFile {
        path: "absent.txt".into(),
        kind: SelectedFileKind::Deletion,
        length: 0,
        sha256: digest(b""),
    }];
    let observed = f.host.prepare_exact_record(&f.request).unwrap();
    assert!(matches!(observed, RecordPreparation::NoChanges { .. }));
    assert!(!f
        .host
        .record_journal_path(&f.request.operation_id)
        .unwrap()
        .exists());
    std::fs::write(
        f.request.sealed_source.join("absent.txt"),
        b"created after the frozen observation",
    )
    .unwrap();
    assert_eq!(f.host.prepare_exact_record(&f.request).unwrap(), observed);
    let before = f
        .host
        .cached_store(&f.request.binding)
        .unwrap()
        .state()
        .unwrap();
    f.request.context_json = "{\"different\":true}".into();
    assert!(f.host.prepare_exact_record(&f.request).is_err());
    assert_eq!(
        f.host
            .cached_store(&f.request.binding)
            .unwrap()
            .state()
            .unwrap(),
        before
    );
    let config = f.host.config.clone();
    drop(f.host);
    let host = Host::new(config).unwrap();
    assert!(host.reconcile().unwrap().ready);
    host.open_store(&f.request.binding).unwrap();
    f.request.context_json =
        "{\"workBinding\":\"frozen-turn\",\"taskRevision\":\"frozen-source\"}".into();
    assert_eq!(host.prepare_exact_record(&f.request).unwrap(), observed);
}

#[test]
fn ignored_changed_selection_cannot_become_a_false_no_change_receipt() {
    let mut f = fixture();
    std::fs::write(f.request.sealed_source.join(".gitignore"), b"*.bin\n").unwrap();
    std::fs::write(
        f.request.sealed_source.join("new.bin"),
        b"selected actual bytes",
    )
    .unwrap();
    f.request.files = vec![SelectedFile {
        path: "new.bin".into(),
        kind: SelectedFileKind::Regular,
        length: 21,
        sha256: digest(b"selected actual bytes"),
    }];
    assert!(matches!(
        f.host.prepare_exact_record(&f.request),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f
        .host
        .record_journal_path(&f.request.operation_id)
        .unwrap()
        .exists());
}

#[test]
fn a_record_cannot_silently_omit_one_ignored_changed_selected_file() {
    let mut f = fixture();
    std::fs::write(f.request.sealed_source.join(".gitignore"), b"*.bin\n").unwrap();
    std::fs::write(f.request.sealed_source.join("new.bin"), b"selected").unwrap();
    f.request.files.push(SelectedFile {
        path: "new.bin".into(),
        kind: SelectedFileKind::Regular,
        length: 8,
        sha256: digest(b"selected"),
    });
    assert!(matches!(
        f.host.prepare_exact_record(&f.request),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f
        .host
        .record_journal_path(&f.request.operation_id)
        .unwrap()
        .exists());
}

#[test]
fn a_symlink_ignore_control_refuses_before_native_status_can_read_outside_source() {
    let f = fixture();
    let outside = f.directory.path().join("host-only-ignore-canary");
    std::fs::write(&outside, b"host credential canary").unwrap();
    std::os::unix::fs::symlink(&outside, f.request.sealed_source.join(".gitignore")).unwrap();
    assert!(matches!(
        f.host.prepare_exact_record(&f.request),
        Err(HostError::Unsupported(_))
    ));
    assert!(!f
        .host
        .record_journal_path(&f.request.operation_id)
        .unwrap()
        .exists());
    assert_eq!(std::fs::read(outside).unwrap(), b"host credential canary");
}

#[test]
fn startup_never_recovers_ready_when_terminal_object_or_membership_disappeared() {
    for damage in ["corrupt-object", "missing-object", "removed-membership"] {
        let f = fixture();
        let record = prepared(&f);
        let receipt = f.host.admit_exact_record(&record).unwrap();
        let journal_path = f.host.record_journal_path(&record.operation_id).unwrap();
        let historical = std::fs::read(&journal_path).unwrap();
        let store = f.host.cached_store(&record.binding).unwrap();
        if damage == "corrupt-object" {
            std::fs::write(
                native_object_path(store.repository(), &record.change_hash).unwrap(),
                b"corrupt native envelope",
            )
            .unwrap();
        } else if damage == "missing-object" {
            std::fs::remove_file(
                native_object_path(store.repository(), &record.change_hash).unwrap(),
            )
            .unwrap();
        } else {
            let hash = Hash::from_base32(record.change_hash.as_bytes()).unwrap();
            store
                .repository()
                .unrecord(
                    &hash,
                    atomic_repository::UnrecordOptions::default().view(&record.expected_state.view),
                )
                .unwrap();
        }
        drop(store);
        let config = f.host.config.clone();
        drop(f.host);
        let host = Host::new(config).unwrap();
        match host.reconcile() {
            Ok(recovery) => {
                assert!(!recovery.ready);
                assert_eq!(recovery.unresolved_operation_ids, vec![record.operation_id]);
            }
            Err(error) => assert!(matches!(
                error.failure().code,
                intent_atomic_proto::FailureCode::Unavailable
                    | intent_atomic_proto::FailureCode::Uncertain
                    | intent_atomic_proto::FailureCode::RecoveryRequired
            )),
        }
        assert_eq!(std::fs::read(&journal_path).unwrap(), historical);
        let retained: RecordJournal = durable::read_json(&journal_path).unwrap();
        assert_eq!(retained.receipt.unwrap(), receipt);
    }
}

#[derive(Serialize, Deserialize)]
struct CrashInput {
    stores: PathBuf,
    config: PathBuf,
    spool: PathBuf,
    prepared: PreparedNativeRecord,
    phase: RecordPhase,
}

#[test]
#[ignore = "subprocess entry point, invoked with a private fixture"]
fn crash_worker() {
    let path = std::env::var_os("INTENT_EXACT_RECORD_CRASH_INPUT").expect("private crash fixture");
    let input: CrashInput = durable::read_json(Path::new(&path)).unwrap();
    let host = Host::new(HostConfig {
        stores_dir: input.stores,
        config_dir: input.config,
        spool_dir: input.spool,
    })
    .unwrap();
    host.reconcile().unwrap();
    host.open_store(&input.prepared.binding).unwrap();
    let _ = host.admit_exact_record_observed(&input.prepared, |phase| {
        if phase == input.phase {
            std::process::exit(86);
        }
        Ok(())
    });
    panic!("requested crash boundary was not reached");
}

#[test]
fn process_crash_after_import_and_membership_reuses_the_same_record_identity() {
    for phase in [
        RecordPhase::Importing,
        RecordPhase::ObjectDurable,
        RecordPhase::MembershipKnown,
    ] {
        let f = fixture();
        let record = prepared(&f);
        let input = CrashInput {
            stores: f.host.config.stores_dir.clone(),
            config: f.host.config.config_dir.clone(),
            spool: f.host.config.spool_dir.clone(),
            prepared: record.clone(),
            phase,
        };
        let fixture_path = f.directory.path().join("crash-input.json");
        durable::write_json(&fixture_path, &input, false).unwrap();
        drop(f.host);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recording::tests::crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("INTENT_EXACT_RECORD_CRASH_INPUT", &fixture_path)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        let host = Host::new(HostConfig {
            stores_dir: input.stores,
            config_dir: input.config,
            spool_dir: input.spool,
        })
        .unwrap();
        host.reconcile().unwrap();
        assert_eq!(
            host.unresolved_records().unwrap(),
            vec![record.operation_id.clone()]
        );
        host.open_store(&record.binding).unwrap();
        let receipt = host.admit_exact_record(&record).unwrap();
        assert_eq!(receipt.change_hash, record.change_hash);
        assert_eq!(receipt.encoding_sha256, record.bytes.sha256);
        let store = host.cached_store(&record.binding).unwrap();
        assert_eq!(
            store
                .repository()
                .get_view_info(&record.expected_state.view)
                .unwrap()
                .change_count,
            1
        );
        assert!(host.unresolved_records().unwrap().is_empty());
    }
}
