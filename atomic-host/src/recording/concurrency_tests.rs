use super::tests::{fixture, prepared};
use super::*;
use std::sync::mpsc::{self, Receiver, Sender};

use intent_atomic_proto::knowledge::{CodeQuery, CodeQueryRequest, CodeQueryResult};
use intent_atomic_proto::{Command, FailureCode, Reply, StoreBinding};

use crate::Session;

struct Release(Sender<()>);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[track_caller]
fn wait<T>(receiver: &Receiver<T>) -> T {
    receiver
        .recv_timeout(intentd_test_support::test_timeout(Duration::from_secs(10)))
        .expect("progress while the native writer is held")
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

#[track_caller]
fn read(host: &Host, session: &mut Session, binding: &StoreBinding) -> StateToken {
    let Reply::State {
        binding: found,
        state,
    } = host
        .handle(
            session,
            Command::ReadState {
                binding: binding.clone(),
            },
        )
        .unwrap()
    else {
        panic!("actual state reply required")
    };
    assert_eq!(&found, binding);
    state
}

#[track_caller]
fn query(host: &Host, session: &mut Session, request: &CodeQueryRequest) -> CodeQueryResult {
    let Reply::CodeQuery { result } = host
        .handle(
            session,
            Command::QueryCode {
                request: request.clone(),
            },
        )
        .unwrap()
    else {
        panic!("actual derived query reply required")
    };
    result
}

#[test]
fn real_handler_reads_and_derived_queries_complete_during_owned_record_boundaries() {
    for boundary in [RecordPhase::ObjectDurable, RecordPhase::MembershipKnown] {
        let f = fixture();
        let (_source, _unused_host, import, _git) = crate::knowledge::tests::fixture();
        let index = f.host.import_derived(&import).unwrap();
        let query_request = crate::knowledge::tests::query(
            &index,
            CodeQuery::Search {
                pattern: "RecordedNeedle".into(),
                literal: true,
            },
            &["src/public"],
        );
        let record = prepared(&f);
        let mut initial = session(&f.host);
        let before = read(&f.host, &mut initial, &record.binding);
        let before_query = query(&f.host, &mut initial, &query_request);
        assert_eq!(before_query.facts.len(), 2);
        let mut observing = session(&f.host);
        let mut mutation = session(&f.host);
        let host = &f.host;
        std::thread::scope(|scope| {
            let (entered_send, entered) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let release = Release(release);
            let (written_send, written) = mpsc::channel();
            let recording = &record;
            scope.spawn(move || {
                let outcome = host.admit_exact_record_observed(recording, |phase| {
                    if phase == boundary {
                        entered_send.send(()).unwrap();
                        let _ = released.recv();
                    }
                    Ok(())
                });
                written_send.send(outcome).unwrap();
            });
            wait(&entered);
            assert!(!*f.host.recovered.lock().unwrap());
            assert!(*f.host.live_writer.lock().unwrap());
            let (observed_send, observed) = mpsc::channel();
            let query_request = &query_request;
            let binding = &record.binding;
            scope.spawn(move || {
                let state = read(host, &mut observing, binding);
                let query = query(host, &mut observing, query_request);
                observed_send.send((state, query)).unwrap();
            });
            let (during, during_query) = wait(&observed);
            assert_eq!(during_query, before_query);
            if boundary == RecordPhase::ObjectDurable {
                assert_eq!(during, before);
            } else {
                assert_ne!(during, before);
            }
            let native = f.host.cached_store(&record.binding).unwrap();
            assert_eq!(
                during.own_merkle,
                native
                    .repository()
                    .get_view_info(&during.view)
                    .unwrap()
                    .state_base32()
            );
            assert_eq!(
                during.effective_state,
                native
                    .repository()
                    .sandbox_effective_state(&during.view)
                    .unwrap()
                    .to_base32()
            );
            assert!(matches!(written.try_recv(), Err(mpsc::TryRecvError::Empty)));
            let blocked = f
                .host
                .handle(
                    &mut mutation,
                    Command::CloseStore {
                        binding: record.binding.clone(),
                    },
                )
                .unwrap_err();
            assert_eq!(blocked.code, FailureCode::RecoveryRequired);
            drop(release);
            let receipt = wait(&written).unwrap();
            let after = read(&f.host, &mut initial, &record.binding);
            assert_eq!(after, receipt.after);
            if boundary == RecordPhase::MembershipKnown {
                assert_eq!(during, after);
            }
            assert_eq!(query(&f.host, &mut initial, query_request), before_query);
        });
        assert!(*f.host.recovered.lock().unwrap());
        assert!(!*f.host.live_writer.lock().unwrap());
    }
}

#[test]
fn failed_owner_closes_handler_reads_until_its_exact_operation_is_reconciled() {
    let f = fixture();
    let (_source, _unused_host, import, _git) = crate::knowledge::tests::fixture();
    let index = f.host.import_derived(&import).unwrap();
    let query_request = crate::knowledge::tests::query(
        &index,
        CodeQuery::Search {
            pattern: "RecordedNeedle".into(),
            literal: true,
        },
        &["src/public"],
    );
    let record = prepared(&f);
    let mut reader = session(&f.host);
    assert!(f
        .host
        .admit_exact_record_observed(&record, |phase| {
            if phase == RecordPhase::ObjectDurable {
                return Err(HostError::Uncertain(record.operation_id.clone()));
            }
            Ok(())
        })
        .is_err());
    assert!(!*f.host.live_writer.lock().unwrap());
    assert!(!*f.host.recovered.lock().unwrap());
    for command in [
        Command::ReadState {
            binding: record.binding.clone(),
        },
        Command::QueryCode {
            request: query_request.clone(),
        },
    ] {
        assert_eq!(
            f.host.handle(&mut reader, command).unwrap_err().code,
            FailureCode::RecoveryRequired
        );
    }
    assert!(matches!(
        f.host.query_code(&query_request),
        Err(HostError::RecoveryRequired)
    ));
    let recovery = f.host.reconcile().unwrap();
    assert!(!recovery.ready);
    assert_eq!(
        recovery.unresolved_operation_ids,
        vec![record.operation_id.clone()]
    );
    let receipt = f.host.admit_exact_record(&record).unwrap();
    assert_eq!(read(&f.host, &mut reader, &record.binding), receipt.after);
    assert_eq!(query(&f.host, &mut reader, &query_request).facts.len(), 2);
}

#[test]
fn one_native_snapshot_never_mixes_own_and_effective_state_across_a_commit() {
    let f = fixture();
    let record = prepared(&f);
    let store = f.host.cached_store(&record.binding).unwrap();
    let before = store.state().unwrap();
    let host = &f.host;
    std::thread::scope(|scope| {
        let (entered_send, entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let release = Release(release);
        let (observed_send, observed) = mpsc::channel();
        let repository = store.repository();
        let view = &before.view;
        scope.spawn(move || {
            let state = crate::native::snapshot_state_observed(repository, view, || {
                entered_send.send(()).unwrap();
                let _ = released.recv();
            });
            observed_send.send(state).unwrap();
        });
        wait(&entered);
        let (written_send, written) = mpsc::channel();
        let record = &record;
        scope.spawn(move || {
            written_send.send(host.admit_exact_record(record)).unwrap();
        });
        let receipt = wait(&written).unwrap();
        assert_ne!(receipt.after, before);
        drop(release);
        assert_eq!(wait(&observed).unwrap(), before);
        let after = store.state().unwrap();
        assert_eq!(after, receipt.after);
        assert_eq!(
            after.own_merkle,
            store
                .repository()
                .get_view_info(&after.view)
                .unwrap()
                .state_base32()
        );
        assert_eq!(
            after.effective_state,
            store
                .repository()
                .sandbox_effective_state(&after.view)
                .unwrap()
                .to_base32()
        );
    });
}

#[test]
fn lifted_snapshot_identity_matches_the_pinned_native_ancestor_and_scope_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let mut repository = Repository::init(directory.path()).unwrap();
    let parent = repository.current_view().to_string();
    repository.create_draft_view("child", &parent).unwrap();
    repository.create_draft_view("grandchild", "child").unwrap();
    for view in [parent.as_str(), "child", "grandchild"] {
        let snapshot = crate::native::snapshot_state(&repository, view).unwrap();
        assert_eq!(
            snapshot.effective_state,
            repository
                .sandbox_effective_state(view)
                .unwrap()
                .to_base32()
        );
        assert_eq!(
            snapshot.own_merkle,
            repository.get_view_info(view).unwrap().state_base32()
        );
    }
}
