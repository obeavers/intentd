use super::*;
use crate::HostConfig;
use intent_atomic_proto::baselines::{BaselinePolicy, ImportBaselineRequest};

struct Fixture {
    _directory: tempfile::TempDir,
    host: Host,
    request: RegisterWorkingCopyCaptureRequest,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap();
    let config = HostConfig {
        stores_dir: path.join("stores"),
        config_dir: path.join("config"),
        spool_dir: path.join("spool"),
    };
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = intent_atomic_proto::StoreBinding {
        store_path: config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    let host = Host::new(config).unwrap();
    host.reconcile().unwrap();
    host.initialize_store(&binding, "capture-transport-fixture")
        .unwrap();
    let root = path.join("working");
    let git = git2::Repository::init(&root).unwrap();
    std::fs::write(root.join("source.rs"), b"fn unchanged() {}\n").unwrap();
    let mut index = git.index().unwrap();
    index.add_path(Path::new("source.rs")).unwrap();
    index.write().unwrap();
    let tree = git.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::now("Capture fixture", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "frozen capture source",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "capture-transport-baseline".into(),
            binding: binding.clone(),
            source_path: root.clone(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap()
        .baseline;
    drop(tree);
    drop(index);
    drop(git);
    Fixture {
        _directory: directory,
        host,
        request: RegisterWorkingCopyCaptureRequest {
            operation_id: "register-original-owner".into(),
            binding,
            baseline,
            working_root: root,
            working_copy_id: "original-working-copy".into(),
        },
    }
}

fn capture_request(
    registration: WorkingCopyCaptureRegistration,
) -> CaptureRegisteredWorkingCopyRequest {
    CaptureRegisteredWorkingCopyRequest {
        operation_id: "capture-original-owner".into(),
        registration,
        drain_timeout_ms: 0,
    }
}

#[test]
fn exact_registration_replay_preserves_one_original_owner() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let replay = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    assert_eq!(registration, replay);
    let turn = f
        .host
        .admit_registered_working_copy_turn(&registration, "agent", "original")
        .unwrap();
    assert!(f
        .host
        .admit_registered_working_copy_turn(&replay, "agent", "replacement")
        .is_err());
    let mut changed = f.request.clone();
    changed.operation_id = "different-registration-operation".into();
    assert!(f
        .host
        .register_transport_working_copy_capture(&changed)
        .is_err());
    drop(turn);
    f.host
        .admit_registered_working_copy_turn(&replay, "agent", "after-original-exit")
        .unwrap();
}

#[test]
fn serialized_registration_neither_observes_selection_nor_mints_an_owner() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let request = capture_request(registration.clone());
    assert!(matches!(
        f.host.capture_registered_working_copy(&request),
        Err(HostError::Unsupported(reason)) if reason.contains("selection observation")
    ));
    assert!(!f
        .host
        .config
        .spool_dir
        .join("working-copy-captures")
        .exists());
    let mut forged = registration;
    forged.registration_id = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        f.host
            .capture_registered_working_copy(&capture_request(forged)),
        Err(HostError::StaleBinding)
    ));
    let mut extended = serde_json::to_value(request).unwrap();
    extended["selectionObservedEmpty"] = true.into();
    assert!(serde_json::from_value::<CaptureRegisteredWorkingCopyRequest>(extended).is_err());
}

#[test]
fn vanished_caller_and_retired_turn_do_not_release_the_actual_writer() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let request = capture_request(registration.clone());
    let turn = f
        .host
        .admit_registered_working_copy_turn(&registration, "agent", "physical-turn")
        .unwrap();
    let writer = turn.admit_writer().unwrap();
    writer.set_selection(None).unwrap();
    drop(registration);
    assert!(f
        .host
        .capture_registered_working_copy(&request)
        .unwrap_err()
        .to_string()
        .contains("did not quiesce"));
    drop(turn);
    assert!(f
        .host
        .capture_registered_working_copy(&request)
        .unwrap_err()
        .to_string()
        .contains("did not quiesce"));
    drop(writer);
    f.host
        .admit_registered_working_copy_turn(
            &request.registration,
            "agent",
            "physical-exit-observed",
        )
        .unwrap();
    assert!(!f
        .host
        .config
        .spool_dir
        .join("working-copy-captures")
        .exists());
}

#[test]
fn registration_operation_cannot_move_to_another_physical_root() {
    let f = fixture();
    f.host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let mut moved = f.request.clone();
    moved.working_root = f
        .request
        .working_root
        .with_file_name("another-working-copy");
    std::fs::create_dir(&moved.working_root).unwrap();
    std::fs::write(moved.working_root.join("source.rs"), b"fn unchanged() {}\n").unwrap();
    assert!(matches!(
        f.host.register_transport_working_copy_capture(&moved),
        Err(HostError::StaleBinding)
    ));
}

#[test]
fn replaced_root_and_changed_epoch_refuse_the_retained_registration() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let mut stale = registration.clone();
    stale.binding.binding_epoch += 1;
    assert!(f
        .host
        .capture_registered_working_copy(&capture_request(stale))
        .is_err());
    std::fs::rename(
        &f.request.working_root,
        f.request.working_root.with_file_name("old-physical-root"),
    )
    .unwrap();
    std::fs::create_dir(&f.request.working_root).unwrap();
    assert!(matches!(
        f.host
            .capture_registered_working_copy(&capture_request(registration)),
        Err(HostError::StaleBinding)
    ));
    assert!(f
        .host
        .register_transport_working_copy_capture(&f.request)
        .is_err());
}

#[test]
fn restart_retains_uncertainty_instead_of_recreating_empty_runtime_custody() {
    let Fixture {
        _directory,
        host,
        request,
    } = fixture();
    let registration = host
        .register_transport_working_copy_capture(&request)
        .unwrap();
    let old_turn = host
        .admit_registered_working_copy_turn(&registration, "agent", "precrash-physical-turn")
        .unwrap();
    let config = host.config.clone();
    drop(host);
    let restarted = Host::new(config).unwrap();
    restarted.reconcile().unwrap();
    assert!(matches!(
        restarted.register_transport_working_copy_capture(&request),
        Err(HostError::Uncertain(_))
    ));
    assert!(matches!(
        restarted.capture_registered_working_copy(&capture_request(registration)),
        Err(HostError::StaleBinding)
    ));
    let mut replacement = request;
    replacement.operation_id = "replacement-does-not-clear-old-custody".into();
    assert!(matches!(
        restarted.register_transport_working_copy_capture(&replacement),
        Err(HostError::Uncertain(_))
    ));
    drop(old_turn);
}

#[test]
fn changed_durable_registration_never_replaces_a_runtime_owner() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let entry = f.host.registered_capture_entry(&registration).unwrap();
    let mut changed = entry.journal.clone();
    changed.registration.working_copy_id = "forged-durable-owner".into();
    durable::write_json(&entry.paths[0], &changed, true).unwrap();
    assert!(matches!(
        f.host
            .capture_registered_working_copy(&capture_request(registration)),
        Err(HostError::StaleBinding)
    ));
}

#[test]
fn excessive_drain_bound_refuses_before_capture_creation() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let mut request = capture_request(registration);
    request.drain_timeout_ms = MAX_CAPTURE_DRAIN_MILLIS + 1;
    assert!(matches!(
        f.host.capture_registered_working_copy(&request),
        Err(HostError::Invalid(_))
    ));
    assert!(!f
        .host
        .config
        .spool_dir
        .join("working-copy-captures")
        .exists());
}

#[test]
fn deleting_all_indexes_cannot_republish_the_same_operation_with_a_new_identity() {
    let f = fixture();
    let registration = f
        .host
        .register_transport_working_copy_capture(&f.request)
        .unwrap();
    let turn = f
        .host
        .admit_registered_working_copy_turn(&registration, "agent", "retained-original-turn")
        .unwrap();
    let entry = f.host.registered_capture_entry(&registration).unwrap();
    for path in &entry.paths {
        std::fs::remove_file(path).unwrap();
    }
    assert!(f
        .host
        .register_transport_working_copy_capture(&f.request)
        .is_err());
    assert_eq!(
        f.host
            .working_copy_transport
            .state
            .lock()
            .unwrap()
            .entries
            .len(),
        1
    );
    assert!(entry.owner.try_begin_turn("agent", "replacement").is_err());
    drop(turn);
}
