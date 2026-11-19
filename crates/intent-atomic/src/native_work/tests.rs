use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use intent_atomic_proto::intents::{IntentProjectionRef, NativeIntentPins};
use intent_atomic_proto::{Outcome, Request, Response};
use intent_core::{
    vcs::{ContentDigest, RepositoryId, VcsKind},
    work_evidence::TaskRevisionRef,
};

use super::*;

fn fixture(root: &Path) -> ProjectionSource {
    ProjectionSource {
        root: RootBinding {
            workspace_id: "workspace".into(),
            root_id: "root".into(),
            repository_id: RepositoryId::from_string("repository"),
            kind: VcsKind::Atomic,
            locator: root.join("workspace"),
            epoch: 7,
        },
        host_binding: StoreBinding {
            repository_id: "repository".into(),
            binding_epoch: 7,
            store_path: root.join("stores/repository"),
        },
        native_binding: TaskNativeBinding {
            binding_id: OperationId::from_string("native-reservation"),
            workspace_id: "workspace".into(),
            note_id: "task".into(),
            repository_id: RepositoryId::from_string("repository"),
            native_project_id: "native-project".into(),
            native_project_identity_hash: "native-project-hash".into(),
            native_intent_id: "native-intent".into(),
            canonical_resource: "urn:atomic:intent:native-intent".into(),
            display_key: "TASK-1".into(),
            create_operation: OperationId::from_string("reserve-operation"),
            create_request_digest: ContentDigest::from_string("1".repeat(64)),
            reserved_at: "2026-11-14T00:00:00Z".into(),
        },
        source: TaskRevision {
            reference: TaskRevisionRef {
                workspace_id: "workspace".into(),
                note_id: "task".into(),
                rev: 3,
                digest: ContentDigest::from_string("2".repeat(64)),
                projection_schema_version: 1,
            },
            title: "original title".into(),
            content: "original source".into(),
            task_json: "{\"status\":\"in-progress\"}".into(),
            criteria: vec![],
            created_at: "2026-11-14T00:00:00Z".into(),
        },
        operation: OperationId::from_string("projection-operation"),
        projection_revision: 1,
        previous: None,
    }
}

fn publish(root: &Path, name: String, bytes: &[u8]) -> SpoolRef {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(&name))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    SpoolRef {
        name,
        length: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn receipt(
    root: &Path,
    source: &ProjectionSource,
    request: &ProjectTaskIntentRequest,
) -> IntentProjectionReceipt {
    let key = digest(request.operation_id.as_bytes());
    let task_source = publish(
        root,
        format!("native-task-{key}.json"),
        &serde_json::to_vec(&source.source).unwrap(),
    );
    let artifact = publish(
        root,
        format!("native-intent-{key}.md"),
        b"original native artifact",
    );
    IntentProjectionReceipt {
        host: intent_atomic_proto::HostIdentity::default(),
        binding: request.binding.clone(),
        identity: request.identity.clone(),
        projection: IntentProjectionRef {
            operation_id: request.operation_id.clone(),
            projection_revision: request.projection_revision,
            task_revision: request.task_revision.clone(),
            pins: NativeIntentPins {
                source_sha256: artifact.sha256.clone(),
                parsed_source_hash: format!("blake3:{}", "3".repeat(64)),
                canonical_content_hash: format!("blake3:{}", "4".repeat(64)),
                substance_hash: format!("blake3:{}", "5".repeat(64)),
            },
        },
        request_digest: digest(
            &serde_json::to_vec(&intent_atomic_proto::intents::projection_command_identity(
                request,
            ))
            .unwrap(),
        ),
        projection_version: intent_atomic_proto::intents::INTENT_PROJECTION_VERSION,
        control_working_copy_id: "control".into(),
        control_view: "intent-owner-control".into(),
        vault_path: "intents/native-intent/intent.md".into(),
        vault_manifest_merkle: "manifest".into(),
        task_source,
        artifact,
        observed_unix_seconds: 1,
    }
}

#[test]
fn owned_projection_keeps_the_original_task_when_the_live_source_is_edited() {
    let temp = tempfile::tempdir().unwrap();
    let spool = Spool::open(&temp.path().join("spool")).unwrap();
    let mut live = fixture(temp.path());
    let source = ProjectionSource::capture(live.input());
    let request = prepare_task_projection(&spool, source.input()).unwrap();
    let envelope = retain(&spool, &request).unwrap();
    let pending = OwnedTaskProjection {
        source,
        request,
        envelope,
    };
    let original_bytes = read(&spool, &pending.request.source, MAX_METADATA).unwrap();
    live.source.title = "edited later".into();
    live.source.reference.rev += 1;
    live.root.epoch += 1;
    assert_eq!(pending.request.task_revision.rev, 3);
    assert_eq!(pending.source.root.epoch, 7);
    assert_eq!(pending.source.source.title, "original title");
    assert_eq!(
        read(&spool, &pending.request.source, MAX_METADATA).unwrap(),
        original_bytes
    );
    assert_eq!(
        read(&spool, &pending.envelope, MAX_METADATA).unwrap(),
        serde_json::to_vec(pending.request()).unwrap()
    );
}

#[test]
fn projection_receipt_requires_exact_source_bytes_and_original_request_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("spool");
    let spool = Spool::open(&root).unwrap();
    let source = fixture(temp.path());
    let request = prepare_task_projection(&spool, source.input()).unwrap();
    let original = receipt(&root, &source, &request);
    let retained = retain_projection_receipt(&spool, source.input(), &request, &original).unwrap();
    assert_eq!(retained.projection.task_revision, source.source.reference);
    let mut changed = original.clone();
    changed.projection.task_revision.rev += 1;
    assert!(retain_projection_receipt(&spool, source.input(), &request, &changed).is_err());
    std::fs::write(
        root.join(&original.artifact.name),
        b"changed native artifact",
    )
    .unwrap();
    assert!(retain_projection_receipt(&spool, source.input(), &request, &original).is_err());
}

#[derive(Clone, Copy)]
enum PeerBehavior {
    Normal,
    ForeignPreparation,
    StallPreparation,
    FailSpoolAfterAdmission,
    FailSpoolAfterSessionBegin,
    FailSpoolAfterSessionClose,
}

struct TransportFixture {
    directory: tempfile::TempDir,
    source: ProjectionSource,
    client: Arc<AtomicNativeWorkClient>,
    observed: tokio::sync::mpsc::UnboundedReceiver<Command>,
    peers: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for TransportFixture {
    fn drop(&mut self) {
        for peer in &self.peers {
            peer.abort();
        }
    }
}

async fn transport_fixture(behavior: PeerBehavior) -> TransportFixture {
    use std::os::unix::fs::DirBuilderExt;
    let directory = tempfile::tempdir().unwrap();
    let source = fixture(directory.path());
    let config = crate::HostLaunchConfig::new(
        directory.path().join("never-executed"),
        directory.path().join("data"),
        directory.path().join("stores"),
    );
    let spool_root = directory.path().join("data/atomic/spool");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&spool_root)
        .unwrap();
    let (sender, observed) = tokio::sync::mpsc::unbounded_channel();
    let mut streams = Vec::new();
    let mut peers = Vec::new();
    for _ in 0..5 {
        let (client, server) = tokio::io::duplex(65_536);
        streams.push(client);
        peers.push(tokio::spawn(native_peer(
            server,
            source.clone(),
            spool_root.clone(),
            behavior,
            sender.clone(),
        )));
    }
    let control = streams.remove(0);
    let supervisor = HostSupervisor::with_test_transport(config, control, streams)
        .await
        .unwrap();
    TransportFixture {
        directory,
        source,
        client: Arc::new(AtomicNativeWorkClient::new(Arc::new(supervisor))),
        observed,
        peers,
    }
}

async fn native_peer(
    mut stream: tokio::io::DuplexStream,
    source: ProjectionSource,
    spool_root: std::path::PathBuf,
    behavior: PeerBehavior,
    observed: tokio::sync::mpsc::UnboundedSender<Command>,
) {
    loop {
        let request: Request = match crate::codec::read_frame(&mut stream).await {
            Ok(request) => request,
            Err(_) => return,
        };
        observed.send(request.command.clone()).unwrap();
        let reply = match request.command {
            Command::Handshake { identity } => Reply::Handshake { identity },
            Command::Reconcile => Reply::Reconciled {
                recovery: RecoveryReport {
                    ready: true,
                    unresolved_operation_ids: vec![],
                },
            },
            Command::Ping => Reply::Pong,
            Command::OpenStore { binding } => Reply::StoreOpened { binding },
            Command::InitializeStore {
                binding,
                operation_id,
            } => Reply::StoreInitialized {
                binding,
                operation_id,
            },
            Command::ReadNativeProject { binding } => Reply::NativeProject {
                identity: NativeProjectIdentity {
                    host: intent_atomic_proto::HostIdentity::default(),
                    binding,
                    project_id: source.native_binding.native_project_id.clone(),
                    project_identity_hash: source
                        .native_binding
                        .native_project_identity_hash
                        .clone(),
                },
            },
            Command::ProjectTaskIntent { request } => Reply::TaskIntentProjected {
                receipt: Box::new(receipt(&spool_root, &source, &request)),
            },
            Command::PrepareExactRecord { request }
            | Command::PrepareBoundExactRecord { request, .. } => {
                if matches!(behavior, PeerBehavior::StallPreparation) {
                    std::future::pending::<()>().await;
                }
                let mut prepared = mock_record(&Spool::open(&spool_root).unwrap(), &request);
                if matches!(behavior, PeerBehavior::ForeignPreparation) {
                    prepared.operation_id = "foreign-operation".into();
                }
                Reply::ExactRecordPrepared {
                    outcome: Box::new(
                        intent_atomic_proto::recording::RecordPreparation::Prepared {
                            record: Box::new(prepared),
                        },
                    ),
                }
            }
            Command::AdmitExactRecord { prepared } => {
                if matches!(behavior, PeerBehavior::FailSpoolAfterAdmission) {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&spool_root, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                Reply::ExactRecordAdmitted {
                    receipt: intent_atomic_proto::recording::NativeRecordReceipt {
                        operation_id: prepared.operation_id,
                        change_hash: prepared.change_hash,
                        encoding_sha256: prepared.bytes.sha256,
                        encoding_length: prepared.bytes.length,
                        before: prepared.expected_state.clone(),
                        after: intent_atomic_proto::StateToken {
                            view: prepared.expected_state.view,
                            effective_state: "actual-mock-after".into(),
                            own_merkle: "actual-mock-own".into(),
                        },
                        replayed: false,
                    },
                }
            }
            Command::BeginNativeSession { request } => {
                if matches!(behavior, PeerBehavior::FailSpoolAfterSessionBegin) {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&spool_root, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                Reply::NativeSessionBegan {
                    receipt: intent_atomic_proto::sessions::NativeSessionReceipt {
                        host: intent_atomic_proto::HostIdentity::default(),
                        binding: request.binding.clone(),
                        operation_id: request.operation_id.clone(),
                        session_id: request.session_id.clone(),
                        work_binding_id: request.work_binding_id.clone(),
                        turn_attempt: request.turn_attempt.clone(),
                        agent_id: request.agent_id.clone(),
                        turn: 1,
                        command_digest: digest(&serde_json::to_vec(&request).unwrap()),
                        native_session_sha256: "6".repeat(64),
                        provider_custody_verified: false,
                    },
                }
            }
            Command::CloseNativeSession { request } => {
                if matches!(behavior, PeerBehavior::FailSpoolAfterSessionClose) {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&spool_root, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                Reply::NativeSessionClosed {
                    receipt: intent_atomic_proto::sessions::NativeSessionCloseReceipt {
                        host: intent_atomic_proto::HostIdentity::default(),
                        binding: request.session.binding.clone(),
                        operation_id: request.operation_id.clone(),
                        session_id: request.session.session_id.clone(),
                        begin_operation_id: request.session.operation_id.clone(),
                        turn: 1,
                        command_digest: digest(&serde_json::to_vec(&request).unwrap()),
                        native_session_sha256: "7".repeat(64),
                        provider_custody_verified: false,
                    },
                }
            }
            unexpected => panic!("unexpected mock native command: {unexpected:?}"),
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

fn record_request(
    source: &ProjectionSource,
    spool_root: &Path,
) -> intent_atomic_proto::recording::PrepareRecordRequest {
    intent_atomic_proto::recording::PrepareRecordRequest {
        operation_id: "owned-record".into(),
        binding: source.host_binding.clone(),
        sealed_source: spool_root.join("sealed/source"),
        expected_state: intent_atomic_proto::StateToken {
            view: "draft".into(),
            effective_state: "before".into(),
            own_merkle: "own".into(),
        },
        files: vec![intent_atomic_proto::recording::SelectedFile {
            path: "src/file.rs".into(),
            kind: intent_atomic_proto::recording::SelectedFileKind::Regular,
            length: 3,
            sha256: digest(b"new"),
        }],
        message: "original".into(),
        author_name: "author".into(),
        author_email: None,
        unix_seconds: 1,
        context_json: "{}".into(),
    }
}

fn mock_record(
    spool: &Spool,
    request: &intent_atomic_proto::recording::PrepareRecordRequest,
) -> intent_atomic_proto::recording::PreparedNativeRecord {
    let selection = digest(&serde_json::to_vec(&request.files).unwrap());
    // Alphabetical object order mirrors the independent host's default serde_json
    // profile, while this workspace enables preserve_order.
    let metadata = serde_json::json!({"bindingEpoch":request.binding.binding_epoch,
        "context":serde_json::from_str::<serde_json::Value>(&request.context_json).unwrap(),
        "operationId":request.operation_id,"policyVersion":1,"repositoryId":request.binding.repository_id,"selectionDigest":selection});
    intent_atomic_proto::recording::PreparedNativeRecord {
        operation_id: request.operation_id.clone(),
        host: intent_atomic_proto::HostIdentity::default(),
        binding: request.binding.clone(),
        expected_state: request.expected_state.clone(),
        command_digest: digest(&serde_json::to_vec(request).unwrap()),
        selection_digest: selection,
        metadata_digest: digest(&serde_json::to_vec(&metadata).unwrap()),
        change_hash: format!("{}A", "B".repeat(51)),
        bytes: spool.retain(b"mock-actual-native-encoding").unwrap(),
        recorded_paths: vec!["src/file.rs".into()],
        deleted_paths: vec![],
    }
}

#[tokio::test]
async fn actual_typed_projection_client_retains_original_source_and_native_envelope() {
    let fixture = transport_fixture(PeerBehavior::Normal).await;
    fixture
        .client
        .initialize_store(&fixture.source.host_binding, "initialization")
        .await
        .unwrap();
    let identity = fixture
        .client
        .project_identity(&fixture.source.root, &fixture.source.host_binding)
        .await
        .unwrap();
    assert_eq!(
        identity.project_id,
        fixture.source.native_binding.native_project_id
    );
    let pending = fixture
        .client
        .prepare_projection(fixture.source.input())
        .await
        .unwrap();
    let retained = fixture.client.project(&pending).await.unwrap();
    assert_eq!(retained.projection.operation_id, fixture.source.operation);
    let bytes = fixture
        .client
        .read_retained(&retained.task_source, MAX_METADATA)
        .await
        .unwrap();
    assert_eq!(bytes, serde_json::to_vec(&fixture.source.source).unwrap());
    assert!(
        fixture
            .client
            .read_retained(&retained.native_receipt, MAX_METADATA)
            .await
            .unwrap()
            .len()
            > bytes.len()
    );
}

#[tokio::test]
async fn actual_typed_record_client_refuses_a_foreign_preparation_receipt() {
    let fixture = transport_fixture(PeerBehavior::ForeignPreparation).await;
    let pending = fixture
        .client
        .retain_record(record_request(
            &fixture.source,
            &fixture.client.host.spool_path(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        fixture.client.prepare_record(&pending).await,
        Err(crate::HostError::Protocol(_))
    ));
    assert_eq!(pending.request().operation_id, "owned-record");
    assert!(!fixture
        .client
        .read_retained(pending.envelope(), MAX_METADATA)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn actual_typed_record_client_returns_known_fact_after_spool_retention_failure() {
    let fixture = transport_fixture(PeerBehavior::FailSpoolAfterAdmission).await;
    let pending = fixture
        .client
        .retain_record(record_request(
            &fixture.source,
            &fixture.client.host.spool_path(),
        ))
        .await
        .unwrap();
    let crate::recording::OwnedPreparedRecordOutcome::Prepared(prepared) =
        fixture.client.prepare_record(&pending).await.unwrap()
    else {
        panic!("expected prepared record");
    };
    let admitted = fixture.client.admit_record(&prepared).await.unwrap();
    assert_eq!(admitted.receipt.operation_id, "owned-record");
    assert_eq!(
        admitted.receipt.encoding_sha256,
        prepared.prepared().bytes.sha256
    );
    assert!(admitted.envelope.is_none());
    assert!(admitted.post_effect_retention_error.is_some());
}

#[tokio::test]
async fn cancelled_actual_typed_client_keeps_its_exact_pending_record() {
    let mut fixture = transport_fixture(PeerBehavior::StallPreparation).await;
    let pending = fixture
        .client
        .retain_record(record_request(
            &fixture.source,
            &fixture.client.host.spool_path(),
        ))
        .await
        .unwrap();
    let expected = fixture
        .client
        .read_retained(pending.envelope(), MAX_METADATA)
        .await
        .unwrap();
    let client = fixture.client.clone();
    let sent = pending.clone();
    let task = tokio::spawn(async move { client.prepare_record(&sent).await });
    while !matches!(
        fixture.observed.recv().await.unwrap(),
        Command::PrepareExactRecord { .. }
    ) {}
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert_eq!(
        fixture
            .client
            .read_retained(pending.envelope(), MAX_METADATA)
            .await
            .unwrap(),
        expected
    );
    assert_eq!(pending.request().operation_id, "owned-record");
}

#[tokio::test]
async fn record_preparation_restores_from_verified_bytes_without_starting_a_host() {
    let fixture = transport_fixture(PeerBehavior::Normal).await;
    let pending = fixture
        .client
        .retain_record(record_request(
            &fixture.source,
            &fixture.client.host.spool_path(),
        ))
        .await
        .unwrap();
    let crate::recording::OwnedPreparedRecordOutcome::Prepared(prepared) =
        fixture.client.prepare_record(&pending).await.unwrap()
    else {
        panic!("expected prepared record");
    };
    let root = fixture.directory.path();
    let fresh_host = Arc::new(
        HostSupervisor::new(crate::HostLaunchConfig::new(
            root.join("must-not-start"),
            root.join("data"),
            root.join("stores"),
        ))
        .unwrap(),
    );
    let fresh = AtomicNativeWorkClient::new(fresh_host.clone());
    let crate::recording::OwnedPreparedRecordOutcome::Prepared(restored) = fresh
        .restore_record_preparation(pending.envelope(), prepared.envelope())
        .await
        .unwrap()
    else {
        panic!("expected restored original preparation");
    };
    assert_eq!(restored.prepared(), prepared.prepared());
    assert!(!fresh_host.recovery_ready().await);
    assert!(!fresh_host.socket_path().exists());
    std::fs::write(
        fresh_host.spool_path().join(&prepared.envelope().name),
        b"changed after restart",
    )
    .unwrap();
    assert!(fresh
        .restore_record_preparation(pending.envelope(), prepared.envelope())
        .await
        .is_err());
}

fn session_request(
    source: &ProjectionSource,
) -> intent_atomic_proto::sessions::BeginNativeSessionRequest {
    intent_atomic_proto::sessions::BeginNativeSessionRequest {
        operation_id: "session-allocation".into(),
        binding: source.host_binding.clone(),
        session_id: "fresh-native-session".into(),
        work_binding_id: "work-binding".into(),
        turn_attempt: "original-attempt".into(),
        agent_id: "original-agent".into(),
        agent_name: "Agent".into(),
    }
}

#[tokio::test]
async fn actual_typed_session_metadata_never_proves_provider_custody() {
    let fixture = transport_fixture(PeerBehavior::Normal).await;
    let pending = fixture
        .client
        .retain_session_begin(session_request(&fixture.source))
        .await
        .unwrap();
    let begun = fixture.client.begin_session(&pending).await.unwrap();
    assert_eq!(begun.receipt.session_id, "fresh-native-session");
    assert!(begun.envelope.is_some());
    assert!(!begun.receipt.provider_custody_verified);
    let close = fixture
        .client
        .retain_session_close(intent_atomic_proto::sessions::CloseNativeSessionRequest {
            operation_id: "session-close".into(),
            session: begun.receipt,
        })
        .await
        .unwrap();
    let closed = fixture.client.close_session(&close).await.unwrap();
    assert_eq!(closed.receipt.begin_operation_id, "session-allocation");
    assert!(closed.envelope.is_some());
    assert!(!closed.receipt.provider_custody_verified);
}

#[tokio::test]
async fn native_session_begin_fact_survives_post_effect_retention_failure() {
    let fixture = transport_fixture(PeerBehavior::FailSpoolAfterSessionBegin).await;
    let pending = fixture
        .client
        .retain_session_begin(session_request(&fixture.source))
        .await
        .unwrap();
    let begun = fixture.client.begin_session(&pending).await.unwrap();
    assert_eq!(begun.receipt.session_id, "fresh-native-session");
    assert!(begun.envelope.is_none());
    assert!(begun.post_effect_retention_error.is_some());
    assert!(!begun.receipt.provider_custody_verified);
}

#[tokio::test]
async fn native_session_close_fact_survives_post_effect_retention_failure() {
    let fixture = transport_fixture(PeerBehavior::FailSpoolAfterSessionClose).await;
    let pending = fixture
        .client
        .retain_session_begin(session_request(&fixture.source))
        .await
        .unwrap();
    let begun = fixture.client.begin_session(&pending).await.unwrap();
    let close = fixture
        .client
        .retain_session_close(intent_atomic_proto::sessions::CloseNativeSessionRequest {
            operation_id: "session-close".into(),
            session: begun.receipt,
        })
        .await
        .unwrap();
    let closed = fixture.client.close_session(&close).await.unwrap();
    assert_eq!(closed.receipt.begin_operation_id, "session-allocation");
    assert!(closed.envelope.is_none());
    assert!(closed.post_effect_retention_error.is_some());
    assert!(!closed.receipt.provider_custody_verified);
}
