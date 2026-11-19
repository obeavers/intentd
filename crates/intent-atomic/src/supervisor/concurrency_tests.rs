use super::*;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use intent_atomic_proto::{
    FailureCode, HostFailure, Outcome, RecoveryReport, Request, Response, StateToken, StoreBinding,
};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};

use crate::codec;

struct Event {
    connection: usize,
    command: Command,
    reply: oneshot::Sender<Outcome>,
}
impl Event {
    fn respond(self, reply: Reply) {
        let _ = self.reply.send(Outcome::Success(Box::new(reply)));
    }
    fn reject(self, code: FailureCode) {
        let _ = self.reply.send(Outcome::Failure(HostFailure {
            code,
            message: "fixture refusal".into(),
            operation_id: None,
        }));
    }
}

async fn reply(stream: &mut DuplexStream, id: u64, reply: Reply) {
    codec::write_frame(
        stream,
        &Response {
            id,
            outcome: Outcome::Success(Box::new(reply)),
        },
    )
    .await
    .unwrap();
}

async fn peer(
    mut stream: DuplexStream,
    connection: usize,
    events: mpsc::UnboundedSender<Event>,
) -> usize {
    let handshake: Request = codec::read_frame(&mut stream).await.unwrap();
    assert!(
        matches!(handshake.command, Command::Handshake { identity } if identity == HostIdentity::default())
    );
    reply(
        &mut stream,
        handshake.id,
        Reply::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .await;
    let reconcile: Request = codec::read_frame(&mut stream).await.unwrap();
    assert_eq!(reconcile.command, Command::Reconcile);
    reply(
        &mut stream,
        reconcile.id,
        Reply::Reconciled {
            recovery: RecoveryReport {
                ready: true,
                unresolved_operation_ids: vec![],
            },
        },
    )
    .await;
    let mut count = 0;
    while let Ok(request) = codec::read_frame::<_, Request>(&mut stream).await {
        count += 1;
        let (send, receive) = oneshot::channel();
        if events
            .send(Event {
                connection,
                command: request.command,
                reply: send,
            })
            .is_err()
        {
            break;
        }
        let Ok(outcome) = receive.await else {
            break;
        };
        if codec::write_frame(
            &mut stream,
            &Response {
                id: request.id,
                outcome,
            },
        )
        .await
        .is_err()
        {
            break;
        }
    }
    count
}

struct Fixture {
    _directory: tempfile::TempDir,
    supervisor: Arc<HostSupervisor>,
    generation: Arc<Generation>,
    events: mpsc::UnboundedReceiver<Event>,
    sender: mpsc::UnboundedSender<Event>,
    peers: Vec<Option<tokio::task::JoinHandle<usize>>>,
}

async fn generation(
    sender: &mpsc::UnboundedSender<Event>,
    first_index: usize,
) -> (Arc<Generation>, Vec<Option<tokio::task::JoinHandle<usize>>>) {
    let mut clients = Vec::new();
    let mut peers = Vec::new();
    for index in first_index..=first_index + READ_CONNECTIONS {
        let (client, server) = tokio::io::duplex(65_536);
        peers.push(Some(tokio::spawn(peer(server, index, sender.clone()))));
        clients.push(
            HostClient::connect(WireStream::Duplex(client), &HostIdentity::default())
                .await
                .unwrap(),
        );
    }
    let control = clients.remove(0);
    (Arc::new(Generation::new(control, clients)), peers)
}

async fn fixture() -> Fixture {
    let directory = tempfile::Builder::new()
        .prefix("intent-host-lanes-")
        .tempdir()
        .unwrap();
    let supervisor = Arc::new(
        HostSupervisor::new(HostLaunchConfig::new(
            directory.path().join("never-executed"),
            directory.path().join("data"),
            directory.path().join("stores"),
        ))
        .unwrap(),
    );
    let (sender, events) = mpsc::unbounded_channel();
    let (generation, peers) = generation(&sender, 0).await;
    {
        let mut runtime = supervisor.runtime.lock().await;
        runtime.generation = Some(generation.clone());
        runtime.injected_transport = true;
    }
    Fixture {
        _directory: directory,
        supervisor,
        generation,
        events,
        sender,
        peers,
    }
}

impl Fixture {
    fn request(&self, command: Command) -> tokio::task::JoinHandle<Result<Reply>> {
        let supervisor = self.supervisor.clone();
        tokio::spawn(async move { supervisor.request(command).await })
    }

    async fn event(&mut self) -> Event {
        tokio::time::timeout(
            intentd_test_support::test_timeout(Duration::from_secs(10)),
            self.events.recv(),
        )
        .await
        .expect("protocol progress without releasing the held writer")
        .expect("fixture event")
    }

    async fn finish(mut self) -> usize {
        let already_stopped = self.supervisor.shutting_down.load(Ordering::Acquire);
        let supervisor = self.supervisor.clone();
        let shutdown = tokio::spawn(async move { supervisor.shutdown().await });
        if !already_stopped {
            let event = self.event().await;
            assert_eq!(event.command, Command::Shutdown);
            event.respond(Reply::Shutdown);
        }
        tokio::time::timeout(
            intentd_test_support::test_timeout(Duration::from_secs(10)),
            shutdown,
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let mut requests = 0;
        for peer in self.peers.into_iter().flatten() {
            requests += tokio::time::timeout(
                intentd_test_support::test_timeout(Duration::from_secs(10)),
                peer,
            )
            .await
            .unwrap()
            .unwrap();
        }
        requests
    }
}

fn binding() -> StoreBinding {
    StoreBinding {
        repository_id: "owned-repository".into(),
        binding_epoch: 7,
        store_path: "/owned/native".into(),
    }
}
fn state_reply() -> Reply {
    Reply::State {
        binding: binding(),
        state: StateToken {
            view: "draft".into(),
            effective_state: "effective-seven".into(),
            own_merkle: "own-seven".into(),
        },
    }
}
async fn pending<F: Future>(mut future: Pin<&mut F>) -> bool {
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await
}

#[tokio::test]
async fn read_completes_while_writer_is_held_and_second_writer_cannot_dispatch() {
    let mut f = fixture().await;
    let writer = f.request(Command::OpenStore { binding: binding() });
    let held = f.event().await;
    assert_eq!(held.connection, 0);
    assert!(matches!(held.command, Command::OpenStore { .. }));
    let reader = f.request(Command::ReadState { binding: binding() });
    let read = f.event().await;
    assert_ne!(read.connection, held.connection);
    assert!(matches!(read.command, Command::ReadState { .. }));
    read.respond(state_reply());
    assert!(matches!(
        reader.await.unwrap().unwrap(),
        Reply::State { .. }
    ));
    assert!(
        !writer.is_finished(),
        "the actual writer response is still held"
    );
    let supervisor = f.supervisor.clone();
    let mut next = Box::pin(async move {
        supervisor
            .request(Command::CloseStore { binding: binding() })
            .await
    });
    assert!(pending(next.as_mut()).await);
    assert!(matches!(
        f.events.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    held.respond(Reply::StoreOpened { binding: binding() });
    writer.await.unwrap().unwrap();
    let next = tokio::spawn(next);
    let event = f.event().await;
    assert_eq!(event.connection, 0);
    assert!(matches!(event.command, Command::CloseStore { .. }));
    event.respond(Reply::StoreClosed { binding: binding() });
    next.await.unwrap().unwrap();
    assert_eq!(f.finish().await, 4); // three operations and explicit shutdown
}

#[tokio::test]
async fn concurrent_read_capacity_is_bounded_without_reusing_an_inflight_stream() {
    let mut f = fixture().await;
    let mut readers = Vec::new();
    let mut held = Vec::new();
    let mut connections = std::collections::BTreeSet::new();
    for _ in 0..READ_CONNECTIONS {
        readers.push(f.request(Command::ReadState { binding: binding() }));
    }
    for _ in 0..READ_CONNECTIONS {
        let event = f.event().await;
        assert!(matches!(event.command, Command::ReadState { .. }));
        assert!(connections.insert(event.connection));
        held.push(event);
    }
    assert_eq!(f.supervisor.read_slots.available_permits(), 0);
    let supervisor = f.supervisor.clone();
    let mut fifth = Box::pin(async move {
        supervisor
            .request(Command::ReadState { binding: binding() })
            .await
    });
    assert!(pending(fifth.as_mut()).await);
    assert!(matches!(
        f.events.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    held.pop().unwrap().respond(state_reply());
    let fifth = tokio::spawn(fifth);
    let resumed = f.event().await;
    assert!(connections.contains(&resumed.connection));
    resumed.respond(state_reply());
    for event in held {
        event.respond(state_reply());
    }
    for reader in readers {
        reader.await.unwrap().unwrap();
    }
    fifth.await.unwrap().unwrap();
    assert_eq!(f.finish().await, READ_CONNECTIONS + 2);
}

#[tokio::test]
async fn cancelling_one_reader_preserves_other_reads_beside_the_active_writer() {
    let mut f = fixture().await;
    let writer = f.request(Command::OpenStore { binding: binding() });
    let held_writer = f.event().await;
    let cancelled = f.request(Command::ReadState { binding: binding() });
    let held_reader = f.event().await;
    let cancelled_connection = held_reader.connection;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(f.generation.ready());
    assert_eq!(f.generation.idle_count().unwrap(), READ_CONNECTIONS - 1);
    let other = f.request(Command::ReadState { binding: binding() });
    let event = f.event().await;
    assert!(matches!(event.command, Command::ReadState { .. }));
    assert_ne!(event.connection, cancelled_connection);
    event.respond(state_reply());
    other.await.unwrap().unwrap();
    assert!(!writer.is_finished());
    held_reader.respond(state_reply());
    let closed = f.peers[cancelled_connection].take().unwrap();
    assert_eq!(
        closed.await.unwrap(),
        1,
        "a cancelled read is never replayed"
    );
    held_writer.respond(Reply::StoreOpened { binding: binding() });
    writer.await.unwrap().unwrap();
    assert_eq!(f.finish().await, 3); // cancelled peer's one request already counted
}

#[tokio::test]
async fn an_old_generation_response_cannot_escape_into_the_new_generation() {
    let mut f = fixture().await;
    let reader = f.request(Command::ReadState { binding: binding() });
    let held = f.event().await;
    let old = f.generation.clone();
    old.stop();
    *old.control.lock().await = None;
    let (replacement, peers) = generation(&f.sender, f.peers.len()).await;
    f.peers.extend(peers);
    f.supervisor.runtime.lock().await.generation = Some(replacement.clone());
    f.generation = replacement;
    held.respond(state_reply());
    assert!(matches!(
        reader.await.unwrap(),
        Err(HostError::ConnectionUncertain)
    ));
    let new_reader = f.request(Command::ReadState { binding: binding() });
    let event = f.event().await;
    assert!(event.connection > READ_CONNECTIONS);
    assert!(matches!(event.command, Command::ReadState { .. }));
    event.respond(state_reply());
    new_reader.await.unwrap().unwrap();
    assert_eq!(f.finish().await, 3);
}

#[tokio::test]
async fn recovery_refusal_fences_both_lanes_without_implicit_read_reconciliation() {
    let mut f = fixture().await;
    let reader = f.request(Command::ReadState { binding: binding() });
    f.event().await.reject(FailureCode::RecoveryRequired);
    assert!(matches!(
        reader.await.unwrap(),
        Err(HostError::RecoveryRequired)
    ));
    assert!(!f.supervisor.recovery_ready().await);
    assert!(matches!(
        f.supervisor
            .request(Command::ReadState { binding: binding() })
            .await,
        Err(HostError::RecoveryRequired)
    ));
    assert!(matches!(
        f.supervisor
            .request(Command::OpenStore { binding: binding() })
            .await,
        Err(HostError::RecoveryRequired)
    ));
    assert!(matches!(
        f.events.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(f.finish().await, 2);
}

fn prepared_record() -> intent_atomic_proto::recording::PreparedNativeRecord {
    intent_atomic_proto::recording::PreparedNativeRecord {
        operation_id: "original-exact-record".into(),
        host: HostIdentity::default(),
        binding: binding(),
        expected_state: StateToken {
            view: "draft".into(),
            effective_state: "before-effective".into(),
            own_merkle: "before-own".into(),
        },
        command_digest: "a".repeat(64),
        selection_digest: "b".repeat(64),
        metadata_digest: "c".repeat(64),
        change_hash: "D".repeat(52),
        bytes: intent_atomic_proto::SpoolRef {
            name: "prepared-record.payload".into(),
            length: 17,
            sha256: "d".repeat(64),
        },
        recorded_paths: vec!["src/lib.rs".into()],
        deleted_paths: vec![],
    }
}

fn native_admission(prepared: &intent_atomic_proto::recording::PreparedNativeRecord) -> Reply {
    Reply::ExactRecordAdmitted {
        receipt: intent_atomic_proto::recording::NativeRecordReceipt {
            operation_id: prepared.operation_id.clone(),
            change_hash: prepared.change_hash.clone(),
            encoding_sha256: prepared.bytes.sha256.clone(),
            encoding_length: prepared.bytes.length,
            before: prepared.expected_state.clone(),
            after: StateToken {
                view: prepared.expected_state.view.clone(),
                effective_state: "after-effective".into(),
                own_merkle: "after-own".into(),
            },
            replayed: false,
        },
    }
}

#[tokio::test]
async fn exact_admission_can_finish_the_blocked_operation_without_reopening_other_work() {
    let mut f = fixture().await;
    let prepared = prepared_record();
    let reconcile = f.request(Command::Reconcile);
    let event = f.event().await;
    assert_eq!(event.command, Command::Reconcile);
    event.respond(Reply::Reconciled {
        recovery: RecoveryReport {
            ready: false,
            unresolved_operation_ids: vec![prepared.operation_id.clone()],
        },
    });
    reconcile.await.unwrap().unwrap();
    assert!(f.generation.blocked());
    assert!(matches!(
        f.supervisor
            .request(Command::OpenStore { binding: binding() })
            .await,
        Err(HostError::RecoveryRequired)
    ));
    let expected = native_admission(&prepared);
    let admission = f.request(Command::AdmitExactRecord {
        prepared: Box::new(prepared),
    });
    let event = f.event().await;
    assert!(matches!(event.command, Command::AdmitExactRecord { .. }));
    event.respond(expected.clone());
    assert_eq!(admission.await.unwrap().unwrap(), expected);
    assert!(
        !f.supervisor.recovery_ready().await,
        "a known effect is not a recovery acknowledgement"
    );
    assert!(matches!(
        f.supervisor
            .request(Command::ReadState { binding: binding() })
            .await,
        Err(HostError::RecoveryRequired)
    ));
    assert!(matches!(
        f.events.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(f.finish().await, 3);
}

#[tokio::test]
async fn known_native_admission_survives_generation_replacement_as_a_historical_effect() {
    let mut f = fixture().await;
    let prepared = prepared_record();
    let expected = native_admission(&prepared);
    let admission = f.request(Command::AdmitExactRecord {
        prepared: Box::new(prepared),
    });
    let held = f.event().await;
    let old = f.generation.clone();
    old.stop();
    let (replacement, peers) = generation(&f.sender, f.peers.len()).await;
    f.peers.extend(peers);
    f.supervisor.runtime.lock().await.generation = Some(replacement.clone());
    f.generation = replacement;
    held.respond(expected.clone());
    assert_eq!(admission.await.unwrap().unwrap(), expected);
    drop(old);
    assert_eq!(f.finish().await, 2);
}

#[tokio::test]
async fn shutdown_wakes_queued_reads_and_never_dispatches_them_after_the_fence() {
    let mut f = fixture().await;
    let mut readers = Vec::new();
    let mut held = Vec::new();
    for _ in 0..READ_CONNECTIONS {
        readers.push(f.request(Command::ReadState { binding: binding() }));
    }
    for _ in 0..READ_CONNECTIONS {
        held.push(f.event().await);
    }
    let supervisor = f.supervisor.clone();
    let mut queued = Box::pin(async move {
        supervisor
            .request(Command::ReadState { binding: binding() })
            .await
    });
    assert!(pending(queued.as_mut()).await);
    let supervisor = f.supervisor.clone();
    let shutdown = tokio::spawn(async move { supervisor.shutdown().await });
    let event = f.event().await;
    assert_eq!(event.command, Command::Shutdown);
    event.respond(Reply::Shutdown);
    shutdown.await.unwrap().unwrap();
    assert!(matches!(queued.await, Err(HostError::ShuttingDown)));
    for event in held {
        event.respond(state_reply());
    }
    for reader in readers {
        assert!(matches!(
            reader.await.unwrap(),
            Err(HostError::ShuttingDown)
        ));
    }
    assert!(matches!(
        f.supervisor
            .request(Command::ReadState { binding: binding() })
            .await,
        Err(HostError::ShuttingDown)
    ));
    assert!(matches!(
        f.events.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(f.finish().await, READ_CONNECTIONS + 1);
}
