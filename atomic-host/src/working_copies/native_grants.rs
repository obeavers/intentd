//! Real upstream handlers on an independent fixture. Their per-request opens
//! are not integrated into Host's one shared canonical native handle.

use std::sync::{Arc, Mutex};

use atomic_core::kg::project_id::MintReason;
use atomic_core::pristine::ViewTxnT;
use atomic_repository::Repository;
use chrono::{DateTime, Utc};
use libatomic::atomic::sandbox_service_server::SandboxService;
use libatomic::atomic::{GetFileStatesRequest, RepositoryRef, SubmitChangeRequest, ViewRef};
use libatomic::daemon::sandbox_grants::{
    grant_capabilities, view_ref_id, GrantRequest, InMemorySandboxGrants, SandboxGrants,
    SANDBOX_TOKEN_METADATA,
};
use libatomic::daemon::services_sandbox::SandboxImpl;
use libatomic::daemon::state::DaemonState;

struct Fixture {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    service: SandboxImpl,
    registry: Arc<InMemorySandboxGrants>,
    clock: Arc<Mutex<DateTime<Utc>>>,
    repository: RepositoryRef,
    token: Vec<u8>,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("isolated-native-grant-qualification");
    let mut repository = Repository::init(&root).unwrap();
    repository
        .ensure_project_identity(MintReason::Upgrade)
        .unwrap();
    repository.create_view("only-this-view").unwrap();
    repository.create_view("private-other-view").unwrap();
    let view_id = repository
        .pristine()
        .read_txn()
        .unwrap()
        .get_view("only-this-view")
        .unwrap()
        .unwrap()
        .id;
    drop(repository);
    let clock = Arc::new(Mutex::new(
        DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let current = Arc::clone(&clock);
    let registry = Arc::new(InMemorySandboxGrants::with_clock(Arc::new(move || {
        *current.lock().unwrap()
    })));
    let state = Arc::new(DaemonState::new().with_sandbox_grants(registry.clone()));
    let handle = state.register(root.clone());
    let repository = handle.repository_ref();
    let (token, _) = registry
        .open(GrantRequest {
            repository_id: repository.repository_id.clone(),
            view: "only-this-view".into(),
            view_id: Some(view_id),
            acting_as: None,
            capabilities: grant_capabilities(&["sandbox.read".into()]).unwrap(),
            ttl_secs: 1,
        })
        .unwrap();
    Fixture {
        _directory: directory,
        root,
        service: SandboxImpl { state },
        registry,
        clock,
        repository,
        token,
    }
}

fn request<T>(body: T, token: &[u8]) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request.metadata_mut().insert_bin(
        SANDBOX_TOKEN_METADATA,
        tonic::metadata::MetadataValue::from_bytes(token),
    );
    request
}
fn read(f: &Fixture, view: &str) -> tonic::Request<GetFileStatesRequest> {
    request(
        GetFileStatesRequest {
            repository: Some(f.repository.clone()),
            target: Some(ViewRef {
                name: Some(view.into()),
                view_id: view_ref_id(view),
            }),
            ..Default::default()
        },
        &f.token,
    )
}

#[tokio::test]
async fn actual_native_handlers_refuse_foreign_view_and_submission_without_capability() {
    let f = fixture();
    f.service
        .get_file_states(read(&f, "only-this-view"))
        .await
        .unwrap();
    let error = f
        .service
        .get_file_states(read(&f, "private-other-view"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let other = fixture();
    let foreign = f
        .service
        .state
        .register(other.root.clone())
        .repository_ref();
    let error = f
        .service
        .get_file_states(request(
            GetFileStatesRequest {
                repository: Some(foreign),
                target: Some(ViewRef {
                    name: Some("only-this-view".into()),
                    view_id: view_ref_id("only-this-view"),
                }),
                ..Default::default()
            },
            &f.token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    let error = f
        .service
        .submit_change(request(
            SubmitChangeRequest {
                repository: Some(f.repository.clone()),
                target: Some(ViewRef {
                    name: Some("only-this-view".into()),
                    view_id: view_ref_id("only-this-view"),
                }),
                ..Default::default()
            },
            &f.token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(error.message().contains("sandbox.submit"));
    assert!(grant_capabilities(&["repository.write".into()]).is_err());
}

#[tokio::test]
async fn actual_native_handler_rechecks_revocation_and_server_clock_expiry() {
    let expired = fixture();
    *expired.clock.lock().unwrap() += chrono::Duration::seconds(2);
    assert_eq!(
        expired
            .service
            .get_file_states(read(&expired, "only-this-view"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let revoked = fixture();
    revoked
        .registry
        .close(&revoked.repository.repository_id, "only-this-view")
        .unwrap();
    assert_eq!(
        revoked
            .service
            .get_file_states(read(&revoked, "only-this-view"))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}

#[tokio::test]
async fn native_view_delete_recreate_cannot_reuse_an_old_named_grant() {
    let f = fixture();
    f.service
        .get_file_states(read(&f, "only-this-view"))
        .await
        .unwrap();
    let mut repository = Repository::open(&f.root).unwrap();
    repository.delete_view("only-this-view").unwrap();
    repository.create_view("only-this-view").unwrap();
    drop(repository);
    let error = f
        .service
        .get_file_states(read(&f, "only-this-view"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(error.message().contains("issued for"));
}

#[tokio::test]
async fn native_handler_revalidates_expiry_after_waiting_for_real_repository_gate() {
    let f = fixture();
    let handle = f.service.state.resolve(&f.repository).unwrap();
    let gate = handle.exclusive().await;
    let service = SandboxImpl {
        state: Arc::clone(&f.service.state),
    };
    let request = read(&f, "only-this-view");
    let (queued, seen) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        queued.send(()).unwrap();
        service.get_file_states(request).await
    });
    seen.await.unwrap();
    assert!(!task.is_finished());
    *f.clock.lock().unwrap() += chrono::Duration::seconds(2);
    drop(gate);
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}
