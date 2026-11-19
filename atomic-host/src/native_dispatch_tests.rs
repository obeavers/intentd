//! Exercise the actual framed private dispatcher, without an OS socket or a
//! substitute native implementation. Process recovery reuses the existing real
//! record crash worker and the exact retained envelope.

use super::*;
use atomic_core::pristine::ViewScope;
use atomic_repository::Repository;
use intent_atomic_proto::intents::DeclareNativeTurnRequest;
use intent_atomic_proto::recording::{
    PrepareRecordRequest, RecordPreparation, SelectedFile, SelectedFileKind,
};
use intent_atomic_proto::{Outcome, Request, Response};
use std::io::Cursor;

#[track_caller]
fn exchange(
    host: &Host,
    session: &mut Session,
    command: Command,
) -> std::result::Result<Reply, HostFailure> {
    let request = Request { id: 17, command };
    let bytes = serde_json::to_vec(&request).unwrap();
    let mut frame = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    let mut output = Vec::new();
    assert_eq!(
        transport::serve_frame(host, session, &mut Cursor::new(frame), &mut output).unwrap(),
        Some(false)
    );
    let length = u32::from_be_bytes(output[..4].try_into().unwrap());
    assert_eq!(usize::try_from(length).unwrap(), output.len() - 4);
    let response: Response = serde_json::from_slice(&output[4..]).unwrap();
    assert_eq!(response.id, request.id);
    match response.outcome {
        Outcome::Success(reply) => {
            assert!(
                reply.matches_command(&request.command),
                "reply did not bind the original request"
            );
            Ok(*reply)
        }
        Outcome::Failure(failure) => Err(failure),
    }
}

fn connected(host: &Host) -> Session {
    let mut session = Session::default();
    exchange(
        host,
        &mut session,
        Command::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .unwrap();
    exchange(host, &mut session, Command::Reconcile).unwrap();
    session
}

#[test]
fn framed_store_initialization_is_explicit_owned_and_replay_bound() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let config = HostConfig {
        stores_dir: root.join("stores"),
        config_dir: root.join("config"),
        spool_dir: root.join("spool"),
    };
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    let host = Host::new(config).unwrap();
    let mut session = connected(&host);
    assert!(exchange(
        &host,
        &mut session,
        Command::OpenStore {
            binding: binding.clone()
        }
    )
    .is_err());
    assert!(!binding.store_path.exists());
    let command = Command::InitializeStore {
        binding: binding.clone(),
        operation_id: "wire-initialize-store".into(),
    };
    let initialized = exchange(&host, &mut session, command.clone()).unwrap();
    assert_eq!(exchange(&host, &mut session, command).unwrap(), initialized);
    assert!(binding.store_path.join(".atomic/atomic.redb").is_file());
    exchange(
        &host,
        &mut session,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    assert!(matches!(
        exchange(
            &host,
            &mut session,
            Command::ReadNativeProject {
                binding: binding.clone()
            }
        )
        .unwrap(),
        Reply::NativeProject { .. }
    ));
    let mut conflicting = binding;
    conflicting.binding_epoch += 1;
    assert!(exchange(
        &host,
        &mut session,
        Command::InitializeStore {
            binding: conflicting,
            operation_id: "wire-initialize-store".into()
        }
    )
    .is_err());
}

#[test]
fn framed_projection_refuses_unrecovered_peers_and_retains_exact_replay() {
    let (_directory, host, request) = intents::tests::fixture();
    let command = Command::ProjectTaskIntent {
        request: Box::new(request.clone()),
    };
    let mut session = Session::default();
    assert_eq!(
        exchange(&host, &mut session, command.clone())
            .unwrap_err()
            .code,
        FailureCode::IncompatibleHost
    );
    let mut old = HostIdentity::default();
    old.contract_version -= 1;
    assert_eq!(
        exchange(&host, &mut session, Command::Handshake { identity: old })
            .unwrap_err()
            .code,
        FailureCode::IncompatibleHost
    );
    exchange(
        &host,
        &mut session,
        Command::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .unwrap();
    assert_eq!(
        exchange(&host, &mut session, command.clone())
            .unwrap_err()
            .code,
        FailureCode::RecoveryRequired
    );
    exchange(&host, &mut session, Command::Reconcile).unwrap();
    assert!(matches!(
        exchange(
            &host,
            &mut session,
            Command::ReadNativeProject {
                binding: request.binding.clone()
            }
        )
        .unwrap(),
        Reply::NativeProject { .. }
    ));
    let before = host
        .cached_store(&request.binding)
        .unwrap()
        .state()
        .unwrap();
    let projected = exchange(&host, &mut session, command.clone()).unwrap();
    assert_eq!(exchange(&host, &mut session, command).unwrap(), projected);
    let Reply::TaskIntentProjected { receipt } = projected else {
        panic!("actual projection required")
    };
    assert!(host.config.spool_dir.join(&receipt.artifact.name).is_file());
    let mut conflicting = request.clone();
    conflicting.root_id = "different-original-root".into();
    assert_eq!(
        exchange(
            &host,
            &mut session,
            Command::ProjectTaskIntent {
                request: Box::new(conflicting)
            }
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidRequest
    );
    assert_eq!(
        host.cached_store(&request.binding)
            .unwrap()
            .state()
            .unwrap(),
        before
    );
}

#[test]
fn framed_declaration_and_freeze_use_the_actual_native_turn() {
    let (_directory, host, request, projection, freeze) = intents::tests::declared_turn_fixture();
    let mut session = connected(&host);
    let declaration = DeclareNativeTurnRequest {
        operation_id: "declare-frozen-turn".into(),
        binding: request.binding.clone(),
        projection: projection.projection,
        native_intent_id: freeze.native_intent_id.clone(),
        session_id: freeze.session_id.clone(),
        expected_turn: freeze.expected_turn,
    };
    assert!(matches!(
        exchange(
            &host,
            &mut session,
            Command::DeclareNativeTurn {
                request: declaration
            }
        )
        .unwrap(),
        Reply::NativeTurnDeclared { .. }
    ));
    let command = Command::FreezeNativeTurn {
        request: freeze.clone(),
    };
    let frozen = exchange(&host, &mut session, command.clone()).unwrap();
    assert_eq!(exchange(&host, &mut session, command).unwrap(), frozen);
    let Reply::NativeTurnFrozen { receipt } = frozen else {
        panic!("actual freeze required")
    };
    host.validate_native_turn_freeze(&receipt).unwrap();
    let store = host.cached_store(&request.binding).unwrap();
    let native =
        atomic_agent::turn::SessionStore::new(store.repository().dot_dir().join("sessions"))
            .unwrap();
    assert!(native
        .bind_turn_intent(
            &receipt.session_id,
            Some(receipt.turn),
            &receipt.native_intent_id
        )
        .unwrap_err()
        .to_string()
        .contains("governing intent is frozen"));
    let mut conflicting = freeze;
    conflicting.work_binding_id = "different-original-work".into();
    assert_eq!(
        exchange(
            &host,
            &mut session,
            Command::FreezeNativeTurn {
                request: conflicting
            }
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidRequest
    );
}

#[test]
fn framed_bound_record_keeps_the_original_freeze_on_a_real_no_change_result() {
    let (_directory, host, request, _projection, freeze) = intents::tests::frozen_turn_fixture();
    let mut session = connected(&host);
    let target = host.cached_store(&freeze.binding).unwrap();
    target
        .repository()
        .set_view_scope(target.repository().current_view(), ViewScope::Draft)
        .unwrap();
    let source = host.config.spool_dir.join("wire-bound-no-change");
    durable::private_dir(&source).unwrap();
    let repository = Repository::init(&source).unwrap();
    repository
        .set_view_scope(repository.current_view(), ViewScope::Draft)
        .unwrap();
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .unwrap();
    drop(repository);
    let record = PrepareRecordRequest {
        operation_id: freeze.operation_id.clone(),
        binding: request.binding,
        sealed_source: source,
        expected_state: target.state().unwrap(),
        files: vec![SelectedFile {
            path: "absent.txt".into(),
            kind: SelectedFileKind::Deletion,
            length: 0,
            sha256: format!("{:x}", Sha256::digest(b"")),
        }],
        message: "Original frozen task".into(),
        author_name: "Intent dispatch fixture".into(),
        author_email: None,
        unix_seconds: 1_800_000_000,
        context_json: "{\"intentHostBinding\":\"caller supplied claims\"}".into(),
    };
    let command = Command::PrepareBoundExactRecord {
        request: Box::new(record.clone()),
        freeze: Box::new(freeze.clone()),
    };
    let Reply::ExactRecordPrepared { outcome } =
        exchange(&host, &mut session, command.clone()).unwrap()
    else {
        panic!("real preparation required")
    };
    assert!(matches!(*outcome, RecordPreparation::NoChanges { .. }));
    assert!(matches!(
        exchange(&host, &mut session, command).unwrap(),
        Reply::ExactRecordPrepared { .. }
    ));
    host.validate_native_turn_freeze(&freeze).unwrap();
    let mut forged = freeze;
    forged.work_binding_id = "different-source-authority".into();
    assert_eq!(
        exchange(
            &host,
            &mut session,
            Command::PrepareBoundExactRecord {
                request: Box::new(record),
                freeze: Box::new(forged)
            }
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidRequest
    );
}

fn record_request(host: &Host, binding: &StoreBinding) -> PrepareRecordRequest {
    let store = host.cached_store(binding).unwrap();
    store
        .repository()
        .set_view_scope(store.repository().current_view(), ViewScope::Draft)
        .unwrap();
    let source = host.config.spool_dir.join("wire-sealed-source");
    durable::private_dir(&source).unwrap();
    let repository = Repository::init(&source).unwrap();
    repository
        .set_view_scope(repository.current_view(), ViewScope::Draft)
        .unwrap();
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .unwrap();
    let bytes = b"actual framed native record\r\n";
    std::fs::write(source.join("input.txt"), bytes).unwrap();
    let working_copy = repository.require_working_copy_id().unwrap();
    repository.add_batch(working_copy, &["input.txt"]).unwrap();
    let expected_state = recording::state(&repository, repository.current_view()).unwrap();
    assert_eq!(expected_state, store.state().unwrap());
    PrepareRecordRequest {
        operation_id: "wire-exact-record".into(),
        binding: binding.clone(),
        sealed_source: source,
        expected_state,
        files: vec![SelectedFile {
            path: "input.txt".into(),
            kind: SelectedFileKind::Regular,
            length: u64::try_from(bytes.len()).unwrap(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }],
        message: "Original framed record".into(),
        author_name: "Intent dispatch fixture".into(),
        author_email: None,
        unix_seconds: 1_800_000_000,
        context_json: "{}".into(),
    }
}

#[test]
fn framed_exact_admission_recovers_only_the_same_retained_operation_after_process_exit() {
    for phase in ["importing", "objectDurable", "membershipKnown"] {
        let (directory, host, projection) = intents::tests::fixture();
        let request = record_request(&host, &projection.binding);
        let mut session = connected(&host);
        let Reply::ExactRecordPrepared { outcome } = exchange(
            &host,
            &mut session,
            Command::PrepareExactRecord {
                request: Box::new(request),
            },
        )
        .unwrap() else {
            panic!("preparation required")
        };
        let RecordPreparation::Prepared { record } = *outcome else {
            panic!("native bytes required")
        };
        let config = host.config.clone();
        let input = directory.path().join("wire-crash-input.json");
        durable::write_json(&input, &serde_json::json!({"stores":config.stores_dir,"config":config.config_dir,"spool":config.spool_dir,"prepared":record,"phase":phase}), false).unwrap();
        drop(host);
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "recording::tests::crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("INTENT_EXACT_RECORD_CRASH_INPUT", input);
        let mut process = intentd_test_support::GuardedChild::spawn(&mut command).unwrap();
        let exit = process
            .wait_with_timeout(intentd_test_support::test_timeout(
                std::time::Duration::from_secs(60),
            ))
            .unwrap()
            .expect("native crash worker exit");
        assert_eq!(exit.code(), Some(86));
        let host = Host::new(config).unwrap();
        let mut session = Session::default();
        exchange(
            &host,
            &mut session,
            Command::Handshake {
                identity: HostIdentity::default(),
            },
        )
        .unwrap();
        assert_eq!(
            exchange(
                &host,
                &mut session,
                Command::AdmitExactRecord {
                    prepared: record.clone()
                }
            )
            .unwrap_err()
            .code,
            FailureCode::RecoveryRequired
        );
        let Reply::Reconciled { recovery } =
            exchange(&host, &mut session, Command::Reconcile).unwrap()
        else {
            panic!("recovery report required")
        };
        assert!(!recovery.ready);
        assert_eq!(
            recovery.unresolved_operation_ids.as_slice(),
            std::slice::from_ref(&record.operation_id)
        );
        assert_eq!(
            exchange(
                &host,
                &mut session,
                Command::ReadNativeProject {
                    binding: record.binding.clone()
                }
            )
            .unwrap_err()
            .code,
            FailureCode::RecoveryRequired
        );
        let mut foreign = (*record).clone();
        foreign.operation_id = "different-operation".into();
        assert_eq!(
            exchange(
                &host,
                &mut session,
                Command::AdmitExactRecord {
                    prepared: Box::new(foreign)
                }
            )
            .unwrap_err()
            .code,
            FailureCode::RecoveryRequired
        );
        let mut forged = (*record).clone();
        forged.selection_digest = "different-retained-selection".into();
        assert_eq!(
            exchange(
                &host,
                &mut session,
                Command::AdmitExactRecord {
                    prepared: Box::new(forged)
                }
            )
            .unwrap_err()
            .code,
            FailureCode::InvalidRequest
        );
        let Reply::ExactRecordAdmitted { receipt } = exchange(
            &host,
            &mut session,
            Command::AdmitExactRecord {
                prepared: record.clone(),
            },
        )
        .unwrap() else {
            panic!("original admission required")
        };
        assert_eq!(receipt.change_hash, record.change_hash);
        assert_eq!(receipt.encoding_sha256, record.bytes.sha256);
        // A mutation receipt does not silently promote this connection's
        // recovery state. Reconciliation must explicitly observe completion.
        assert_eq!(
            exchange(
                &host,
                &mut session,
                Command::ReadNativeProject {
                    binding: record.binding.clone()
                }
            )
            .unwrap_err()
            .code,
            FailureCode::RecoveryRequired
        );
        assert!(
            matches!(exchange(&host, &mut session, Command::Reconcile).unwrap(), Reply::Reconciled { recovery } if recovery.ready)
        );
        assert!(matches!(
            exchange(
                &host,
                &mut session,
                Command::ReadNativeProject {
                    binding: record.binding.clone()
                }
            )
            .unwrap(),
            Reply::NativeProject { .. }
        ));
        let Reply::ExactRecordAdmitted { receipt: replayed } = exchange(
            &host,
            &mut session,
            Command::AdmitExactRecord { prepared: record },
        )
        .unwrap() else {
            panic!("retained receipt required")
        };
        assert!(replayed.replayed);
        assert_eq!(replayed.change_hash, receipt.change_hash);
        assert_eq!(replayed.after, receipt.after);
    }
}

#[test]
fn framed_control_and_triage_keep_evidence_distinct_from_reviewer_authority() {
    let (_directory, host, request) = triage::tests::fixture();
    let mut session = connected(&host);
    let Reply::NativeControlCaptured { snapshot } = exchange(
        &host,
        &mut session,
        Command::CaptureNativeControl {
            request: intent_atomic_proto::triage::CaptureNativeControlRequest {
                operation_id: request.control_snapshot.operation_id.clone(),
                binding: request.binding.clone(),
                projections: request.projections.clone(),
            },
        },
    )
    .unwrap() else {
        panic!("exact control snapshot required")
    };
    assert_eq!(snapshot, request.control_snapshot);
    let command = Command::PrepareNativeTriage {
        request: Box::new(request),
    };
    let result = exchange(&host, &mut session, command.clone()).unwrap();
    assert_eq!(exchange(&host, &mut session, command).unwrap(), result);
    let Reply::NativeTriagePrepared { outcome } = result else {
        panic!("native triage required")
    };
    let intent_atomic_proto::triage::NativeTriagePreparation::Produced { receipt } = *outcome
    else {
        panic!("actual signed report required")
    };
    assert_eq!(
        receipt.authority,
        intent_atomic_proto::triage::NativeEvidenceAuthority::EvidenceOnly
    );
    assert_eq!(
        receipt.reviewer_execution,
        intent_atomic_proto::triage::ReviewerExecutionAvailability::Unavailable
    );
    assert!(host.config.spool_dir.join(&receipt.report.name).is_file());
    assert!(host
        .config
        .spool_dir
        .join(&receipt.evidence.document.name)
        .is_file());
}
