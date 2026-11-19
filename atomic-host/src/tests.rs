use super::*;

use intent_atomic_proto::{Outcome, Request, Response, MAX_FRAME_BYTES};
use std::io::Cursor;

fn fixture() -> (tempfile::TempDir, Arc<Host>, StoreBinding) {
    let directory = tempfile::tempdir().unwrap();
    let config = HostConfig {
        stores_dir: directory.path().join("stores"),
        config_dir: directory.path().join("config"),
        spool_dir: directory.path().join("spool"),
    };
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    let host = Arc::new(Host::new(config).unwrap());
    assert!(host.reconcile().unwrap().ready);
    (directory, host, binding)
}

fn session(host: &Host) -> Session {
    let mut session = Session::default();
    host.handle(
        &mut session,
        Command::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .unwrap();
    host.handle(&mut session, Command::Reconcile).unwrap();
    session
}

#[test]
fn handshake_and_recovery_are_required_per_connection() {
    let (_directory, host, binding) = fixture();
    let mut new = Session::default();
    assert_eq!(
        host.handle(&mut new, Command::Ping).unwrap_err().code,
        FailureCode::IncompatibleHost
    );
    let mut identity = HostIdentity::default();
    identity.store_format += 1;
    assert_eq!(
        host.handle(&mut new, Command::Handshake { identity })
            .unwrap_err()
            .code,
        FailureCode::IncompatibleHost
    );
    host.handle(
        &mut new,
        Command::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .unwrap();
    assert_eq!(
        host.handle(&mut new, Command::OpenStore { binding })
            .unwrap_err()
            .code,
        FailureCode::RecoveryRequired
    );
    assert!(
        matches!(host.handle(&mut new, Command::Reconcile).unwrap(), Reply::Reconciled { recovery } if recovery.ready)
    );
}

#[test]
fn missing_native_store_is_not_initialized_or_reported_empty() {
    let (_directory, host, binding) = fixture();
    let mut connection = session(&host);
    assert!(host
        .handle(
            &mut connection,
            Command::OpenStore {
                binding: binding.clone()
            }
        )
        .is_err());
    assert!(!binding.store_path.exists());
    assert!(host
        .handle(&mut connection, Command::ReadState { binding })
        .is_err());
}

#[test]
fn native_store_reopens_with_exact_identity_and_one_cached_handle() {
    let (_directory, host, binding) = fixture();
    host.initialize_store(&binding, "initialize-a").unwrap();
    let mut connection = session(&host);
    host.handle(
        &mut connection,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    let first = host.cached_store(&binding).unwrap();
    host.handle(
        &mut connection,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    let second = host.cached_store(&binding).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let state = first.state().unwrap();
    assert!(!state.view.is_empty());
    assert!(!state.effective_state.is_empty());
    assert!(!state.own_merkle.is_empty());
    // Reconciliation of a live host must reuse its handle, never reopen redb.
    assert!(host.reconcile().unwrap().ready);
    assert_eq!(state, second.state().unwrap());
    drop(first);
    drop(second);
    host.handle(
        &mut connection,
        Command::CloseStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    host.handle(
        &mut connection,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    assert_eq!(host.cached_store(&binding).unwrap().state().unwrap(), state);
}

#[test]
fn stale_epoch_and_outside_namespace_refuse_before_opening() {
    let (directory, host, binding) = fixture();
    host.initialize_store(&binding, "initialize-identity")
        .unwrap();
    let mut connection = session(&host);
    let mut stale = binding.clone();
    stale.binding_epoch += 1;
    assert_eq!(
        host.handle(&mut connection, Command::OpenStore { binding: stale })
            .unwrap_err()
            .code,
        FailureCode::StaleBinding
    );
    let mut outside = binding;
    outside.store_path = directory.path().join("outside");
    assert_eq!(
        host.handle(
            &mut connection,
            Command::OpenStore {
                binding: outside.clone()
            }
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidRequest
    );
    assert!(!outside.store_path.exists());
}

#[test]
fn replaced_native_directory_is_not_adopted_under_old_identity() {
    let (_directory, host, binding) = fixture();
    host.initialize_store(&binding, "initialize-replaced")
        .unwrap();
    let mut connection = session(&host);
    std::fs::rename(
        &binding.store_path,
        binding.store_path.with_file_name("retained-original"),
    )
    .unwrap();
    native::initialize(&binding).unwrap();
    assert_eq!(
        host.handle(&mut connection, Command::OpenStore { binding })
            .unwrap_err()
            .code,
        FailureCode::StaleBinding
    );
}

#[test]
fn proven_interrupted_initialization_reconciles_without_reinitializing() {
    let (_directory, host, binding) = fixture();
    let operation = "initialize-interrupted";
    assert!(host
        .initialize_observed(&binding, operation, |phase| {
            if phase == InitPhase::EffectKnown {
                Err(HostError::Uncertain(operation.into()))
            } else {
                Ok(())
            }
        })
        .is_err());
    assert!(!binding
        .store_path
        .parent()
        .unwrap()
        .join("identity.json")
        .exists());
    let before = durable::identity(&binding.store_path.join(".atomic/atomic.redb"), false).unwrap();
    let config = host.config.clone();
    drop(host);
    let restarted = Host::new(config).unwrap();
    assert!(restarted.reconcile().unwrap().ready);
    assert_eq!(
        before,
        durable::identity(&binding.store_path.join(".atomic/atomic.redb"), false).unwrap()
    );
    restarted.initialize_store(&binding, operation).unwrap();
    let mut connection = session(&restarted);
    restarted
        .handle(&mut connection, Command::OpenStore { binding })
        .unwrap();
}

#[test]
fn unproved_interrupted_initialization_remains_uncertain_and_closes_admission() {
    let (_directory, host, binding) = fixture();
    assert!(host
        .initialize_observed(&binding, "initialize-no-proof", |phase| {
            if phase == InitPhase::Running {
                Err(HostError::Uncertain("initialize-no-proof".into()))
            } else {
                Ok(())
            }
        })
        .is_err());
    let config = host.config.clone();
    drop(host);
    let restarted = Host::new(config).unwrap();
    let report = restarted.reconcile().unwrap();
    assert!(!report.ready);
    assert_eq!(report.unresolved_operation_ids, ["initialize-no-proof"]);
    let mut connection = session(&restarted);
    assert_eq!(
        restarted
            .handle(
                &mut connection,
                Command::OpenStore {
                    binding: binding.clone()
                }
            )
            .unwrap_err()
            .code,
        FailureCode::RecoveryRequired
    );
    assert!(matches!(
        restarted.initialize_store(&binding, "new-attempt"),
        Err(HostError::RecoveryRequired)
    ));
    assert!(!binding.store_path.exists());
}

#[test]
fn operation_identity_cannot_replay_another_immutable_command() {
    let (_directory, host, binding) = fixture();
    host.initialize_store(&binding, "one-operation").unwrap();
    let mut changed = binding;
    changed.binding_epoch += 1;
    assert!(matches!(
        host.initialize_store(&changed, "one-operation"),
        Err(HostError::Invalid("conflicting operation replay"))
    ));
}

#[test]
fn frames_are_bounded_and_reply_ids_are_retained_without_a_socket() {
    let (_directory, host, _) = fixture();
    let mut session = Session::default();
    for length in [0_u32, u32::try_from(MAX_FRAME_BYTES + 1).unwrap()] {
        let mut reader = Cursor::new(length.to_be_bytes());
        assert!(transport::serve_frame(&host, &mut session, &mut reader, &mut Vec::new()).is_err());
    }
    let request = Request {
        id: 42,
        command: Command::Handshake {
            identity: HostIdentity::default(),
        },
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let mut frame = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    frame.extend(bytes);
    let mut output = Vec::new();
    assert_eq!(
        transport::serve_frame(&host, &mut session, &mut Cursor::new(frame), &mut output).unwrap(),
        Some(false)
    );
    let response: Response = serde_json::from_slice(&output[4..]).unwrap();
    assert_eq!(response.id, 42);
    assert!(matches!(
        response.outcome,
        Outcome::Success(reply) if matches!(reply.as_ref(), Reply::Handshake { .. })
    ));
}

#[test]
fn native_reads_do_not_take_the_writer_lane() {
    let (_directory, host, binding) = fixture();
    host.initialize_store(&binding, "initialize-reader")
        .unwrap();
    let mut connection = session(&host);
    host.handle(
        &mut connection,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    // This deterministic check would deadlock if a read ever shared the writer
    // guard. It needs no elapsed-time assertion or scheduling delay.
    let _writer = host.writer.lock().unwrap();
    assert!(matches!(
        host.handle(&mut connection, Command::ReadState { binding })
            .unwrap(),
        Reply::State { .. }
    ));
}
