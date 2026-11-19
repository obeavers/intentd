//! Mechanical grant qualification against real native freeze, capture and read
//! primitives. These fixtures do not manufacture Intent task authorization.

use super::*;

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use atomic_core::change::{ChangeHeader, InodeAttr, InodeKind};
use atomic_core::output::memory::Memory;
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use atomic_repository::InsertOptions;
use intent_atomic_proto::baselines::{BaselinePolicy, ImportBaselineRequest};
use intent_atomic_proto::execution::{ExecutionClaim, WarmWorkingCopyCapture};

const SOURCE: &[u8] = b"fn original() {}\n";
const IGNORE: &[u8] = b"target/\n";

struct Fixture {
    _directory: tempfile::TempDir,
    host: Host,
    request: IssueExecutionGrantRequest,
}

#[cfg_attr(
    target_os = "macos",
    expect(
        clippy::unnecessary_wraps,
        reason = "Linux qualification explicitly returns None when reflink is unavailable; macOS requires actual CoW success"
    )
)]
fn fixture() -> Option<Fixture> {
    let (directory, host, projected, _projection, freeze) =
        crate::intents::tests::frozen_turn_fixture();
    let root = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("working-source");
    let git = git2::Repository::init(&root).unwrap();
    std::fs::write(root.join(".gitignore"), IGNORE).unwrap();
    std::fs::write(root.join("source.rs"), SOURCE).unwrap();
    let mut index = git.index().unwrap();
    index.add_path(Path::new(".gitignore")).unwrap();
    index.add_path(Path::new("source.rs")).unwrap();
    index.write().unwrap();
    let tree = git.find_tree(index.write_tree().unwrap()).unwrap();
    let signature = git2::Signature::new(
        "Native grant fixture",
        "fixture@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    let commit = git
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "exact grant source",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "native-grant-baseline".into(),
            binding: projected.binding.clone(),
            source_path: root.clone(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();

    // Import the same recorded files through the actual public code primitives
    // into Host's existing canonical handle, rather than opening a second one.
    let store = host.cached_store(&projected.binding).unwrap();
    let repository = store.repository();
    let view = repository.current_view().to_owned();
    let memory = Memory::new();
    let mut files = Vec::new();
    for (path, bytes) in [(".gitignore", IGNORE), ("source.rs", SOURCE)] {
        memory.add_file(path, bytes);
        let mut file = record_added_file(
            &memory,
            &DetectedFile::added(path),
            &RecordingOptions::new(),
        )
        .unwrap();
        file.set_attr(InodeAttr::Kind(InodeKind::Regular));
        file.set_attr(InodeAttr::Mode(0o644));
        files.push(file);
    }
    let (change, _) = repository
        .assemble_and_hash(&view, ChangeHeader::new("exact grant baseline"), &files)
        .unwrap();
    let mut bytes = Vec::new();
    let change_hash = change.serialize(&mut bytes).unwrap();
    repository
        .import_change_bytes(&change_hash, &bytes)
        .unwrap();
    repository
        .insert_change(&change_hash, InsertOptions::default().view(&view))
        .unwrap();
    let expected_state = view_state(&store, &view).unwrap().1;
    drop(store);

    std::fs::create_dir(root.join("target")).unwrap();
    std::fs::write(root.join("target/warm-output"), b"retained ignored output").unwrap();
    std::fs::write(root.join(".env"), b"credential must never enter capture").unwrap();
    let owner = host
        .register_working_copy_capture(
            &projected.binding,
            &baseline.baseline,
            &root,
            "native-grant-parent",
        )
        .unwrap();
    let turn = owner
        .try_begin_turn("native-grant-agent", "selection-observation")
        .unwrap();
    let writer = turn.admit_writer().unwrap();
    writer.set_selection(None).unwrap();
    drop(writer);
    drop(turn);
    let capture = match host.capture_warm_child(
        owner.close_for_capture().unwrap(),
        "native-grant-capture",
        intentd_test_support::test_timeout(Duration::from_secs(10)),
    ) {
        Ok(capture) => capture,
        Err(HostError::Unsupported(reason)) => {
            #[cfg(target_os = "macos")]
            panic!("actual APFS native grant capture is required: {reason}");
            #[cfg(not(target_os = "macos"))]
            {
                assert!(reason.contains("copy-on-write") || reason.contains("reflink"));
                eprintln!("native mechanical grant qualification unavailable: {reason}");
                return None;
            }
        }
        Err(error) => panic!("actual native grant capture failed: {error}"),
    };
    host.validate_child_capture(&capture).unwrap();
    assert!(!capture.path.join(".env").exists());
    assert_eq!(
        std::fs::read(capture.path.join("target/warm-output")).unwrap(),
        b"retained ignored output"
    );
    let capture: WarmWorkingCopyCapture =
        serde_json::from_value(serde_json::to_value(capture).unwrap()).unwrap();
    let request = IssueExecutionGrantRequest {
        operation_id: "native-grant-issue".into(),
        binding: projected.binding,
        claim: ExecutionClaim {
            grant_id: "original-native-grant".into(),
            revision: 1,
            work_binding_id: freeze.work_binding_id.clone(),
            workspace_id: freeze.projection.task_revision.workspace_id.clone(),
            root_id: projected.root_id,
            root_locator: root,
            agent_id: "native-grant-agent".into(),
            attempt_id: "native-grant-attempt".into(),
            task_revision: freeze.projection.task_revision.clone(),
            expires_at_unix_ms: now_ms().unwrap().checked_add(600_000).unwrap(),
            path_prefixes: vec!["source.rs".into()],
            capabilities: vec![ExecutionCapability::ReadSource],
        },
        view,
        expected_state,
        freeze,
        capture,
    };
    Some(Fixture {
        _directory: directory,
        host,
        request,
    })
}

fn read_request(issued: &NativeExecutionGrantIssued) -> ReadGrantedFileRequest {
    ReadGrantedFileRequest {
        request_id: "exact-native-read".into(),
        grant_id: issued.receipt.claim.grant_id.clone(),
        grant_receipt_digest: hash(&serde_json::to_vec(&issued.receipt).unwrap()),
        token: issued.token.clone(),
        path: "source.rs".into(),
    }
}

fn close_request(issued: &NativeExecutionGrantIssued) -> CloseExecutionGrantRequest {
    let read = read_request(issued);
    CloseExecutionGrantRequest {
        grant_id: read.grant_id,
        grant_receipt_digest: read.grant_receipt_digest,
        token: read.token,
    }
}

#[track_caller]
fn assert_source(receipt: &GrantedFileReceipt, issued: &NativeExecutionGrantIssued) {
    assert_eq!(receipt.content_hex, hex(SOURCE));
    assert_eq!(receipt.content_sha256, hash(SOURCE));
    assert_eq!(receipt.kind, GrantedFileKind::Regular);
    assert_eq!(receipt.basis, GrantedReadBasis::PinnedGrantManifest);
    assert_eq!(receipt.grant_state, issued.receipt.native_state);
}

#[track_caller]
fn wait<T>(receiver: &Receiver<T>) -> T {
    receiver
        .recv_timeout(intentd_test_support::test_timeout(Duration::from_secs(10)))
        .expect("actual native grant worker must make progress")
}

struct Release(Sender<()>);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[test]
fn real_native_freeze_capture_and_registry_bound_read_refuse_forged_scope_and_proofs() {
    let Some(f) = fixture() else { return };
    let mut forged = f.request.clone();
    forged.freeze.native_intent_id.push_str("-forged");
    assert!(f.host.issue_native_execution_grant(&forged).is_err());
    let mut forged = f.request.clone();
    forged.capture.working_digest = "0".repeat(64);
    assert!(f.host.issue_native_execution_grant(&forged).is_err());
    let mut forged = f.request.clone();
    forged.claim.capabilities = vec![ExecutionCapability::TaskMutation];
    assert!(f.host.issue_native_execution_grant(&forged).is_err());
    let mut forged = f.request.clone();
    forged.expected_state.own_merkle.push_str("-forged");
    assert!(f.host.issue_native_execution_grant(&forged).is_err());
    let mut forged = f.request.clone();
    forged.claim.task_revision.rev += 1;
    assert!(f.host.issue_native_execution_grant(&forged).is_err());

    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    assert_eq!(
        issued,
        f.host.issue_native_execution_grant(&f.request).unwrap()
    );
    let native = f
        .host
        .native_grants
        .registry
        .resolve(issued.token.as_bytes())
        .unwrap();
    assert_eq!(native.view, f.request.view);
    assert_eq!(native.view_id, Some(issued.receipt.native_view_id));
    assert_eq!(
        hex(&native.repository_id),
        issued.receipt.native_repository_id
    );
    assert_eq!(
        native.capabilities,
        grant_capabilities(&["sandbox.read".into()]).unwrap()
    );
    assert!(!native.allows("sandbox.submit"));
    assert!(!format!("{issued:?}").contains(&issued.token));
    let journal = std::fs::read(f.host.grant_journal(&f.request.operation_id).unwrap()).unwrap();
    assert!(!String::from_utf8(journal).unwrap().contains(&issued.token));
    let read = read_request(&issued);
    assert_source(&f.host.read_native_granted_file(&read).unwrap(), &issued);
    for path in [
        ".gitignore",
        "../source.rs",
        "source.rs/../.gitignore",
        "source.rs/missing",
    ] {
        let mut forged = read.clone();
        forged.path = path.into();
        assert!(f.host.read_native_granted_file(&forged).is_err(), "{path}");
    }
    let mut forged = read.clone();
    forged.token.push_str("-forged");
    assert!(f.host.read_native_granted_file(&forged).is_err());
    let mut forged = read.clone();
    forged.grant_receipt_digest = "0".repeat(64);
    assert!(f.host.read_native_granted_file(&forged).is_err());
    let mut forged = read;
    forged.grant_id = "unissued-native-grant".into();
    assert!(f.host.read_native_granted_file(&forged).is_err());
    f.host
        .close_native_execution_grant(&close_request(&issued))
        .unwrap();
}

#[test]
fn shared_handle_read_completes_while_host_writer_and_actual_native_write_transaction_are_held() {
    let Some(f) = fixture() else { return };
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let request = read_request(&issued);
    let store = f.host.cached_store(&f.request.binding).unwrap();
    std::thread::scope(|scope| {
        let writer = f.host.writer.lock().unwrap();
        let native_writer = store.repository().pristine().write_txn().unwrap();
        let (send, received) = mpsc::channel();
        let host = &f.host;
        scope.spawn(move || send.send(host.read_native_granted_file(&request)).unwrap());
        let observation =
            received.recv_timeout(intentd_test_support::test_timeout(Duration::from_secs(10)));
        // Release locks before asserting so a failing regression can still join
        // its worker and report the failed progress assertion without hanging.
        drop(native_writer);
        drop(writer);
        assert_source(
            &observation
                .expect("read must finish while both writers are held")
                .unwrap(),
            &issued,
        );
    });
    f.host
        .close_native_execution_grant(&close_request(&issued))
        .unwrap();
}

#[test]
fn real_close_revokes_admission_then_drains_the_original_counted_read_worker() {
    let Some(f) = fixture() else { return };
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let request = read_request(&issued);
    let close = close_request(&issued);
    std::thread::scope(|scope| {
        let (entered_send, entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let release = Release(release);
        let (read_send, read) = mpsc::channel();
        let host = &f.host;
        let original_read = request.clone();
        scope.spawn(move || {
            let result = host.read_native_granted_file_observed(&original_read, || {
                entered_send.send(()).unwrap();
                let _ = released.recv();
            });
            read_send.send(result).unwrap();
        });
        wait(&entered);
        let (revoked_send, revoked) = mpsc::channel();
        let (closed_send, closed) = mpsc::channel();
        scope.spawn(move || {
            let result = host.close_native_execution_grant_observed(&close, || {
                revoked_send.send(()).unwrap();
            });
            closed_send.send(result).unwrap();
        });
        wait(&revoked);
        assert!(f
            .host
            .native_grants
            .registry
            .resolve(issued.token.as_bytes())
            .is_err());
        assert!(f.host.read_native_granted_file(&request).is_err());
        assert!(matches!(closed.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let entry = f
            .host
            .native_grants
            .entries
            .lock()
            .unwrap()
            .get(&request.grant_id)
            .unwrap()
            .clone();
        let admission = entry.state.lock().unwrap();
        assert!(admission.closed);
        assert_eq!(admission.readers, 1);
        assert!(admission.store.is_some());
        drop(admission);
        drop(release);
        assert_source(&wait(&read).unwrap(), &issued);
        assert!(wait(&closed).unwrap().admitted_reads_drained);
        let admission = entry.state.lock().unwrap();
        assert_eq!(admission.readers, 0);
        assert!(admission.store.is_none());
        assert!(admission.token.is_none());
    });
}

#[test]
fn old_close_cannot_revoke_a_replacement_grant_for_the_same_native_view() {
    let Some(f) = fixture() else { return };
    let original = f.host.issue_native_execution_grant(&f.request).unwrap();
    let old_read = read_request(&original);
    let old_close = close_request(&original);
    let mut replacement = f.request.clone();
    replacement.operation_id = "replacement-native-issue".into();
    replacement.claim.grant_id = "replacement-native-grant".into();
    replacement.claim.attempt_id = "replacement-native-attempt".into();
    assert!(f.host.issue_native_execution_grant(&replacement).is_err());
    let mut forged = old_close.clone();
    forged.token.push_str("-forged");
    assert!(f.host.close_native_execution_grant(&forged).is_err());
    assert_source(
        &f.host.read_native_granted_file(&old_read).unwrap(),
        &original,
    );
    f.host.close_native_execution_grant(&old_close).unwrap();
    assert!(f.host.read_native_granted_file(&old_read).is_err());
    let replacement = f.host.issue_native_execution_grant(&replacement).unwrap();
    assert_ne!(original.token, replacement.token);
    assert_ne!(
        original.receipt.native_grant_id,
        replacement.receipt.native_grant_id
    );
    assert!(
        f.host
            .close_native_execution_grant(&old_close)
            .unwrap()
            .admitted_reads_drained
    );
    assert!(f
        .host
        .native_grants
        .registry
        .resolve(replacement.token.as_bytes())
        .is_ok());
    assert_source(
        &f.host
            .read_native_granted_file(&read_request(&replacement))
            .unwrap(),
        &replacement,
    );
    f.host
        .close_native_execution_grant(&close_request(&replacement))
        .unwrap();
}

#[test]
fn replay_refuses_deleted_closed_or_natively_revoked_grant_state() {
    let Some(f) = fixture() else { return };
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let path = f.host.grant_journal(&f.request.operation_id).unwrap();
    let mut journal: Journal = durable::read_json(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(f.host.issue_native_execution_grant(&f.request).is_err());
    assert!(f
        .host
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    durable::write_json(&path, &journal, false).unwrap();
    journal.closed = true;
    durable::write_json(&path, &journal, true).unwrap();
    assert!(f.host.issue_native_execution_grant(&f.request).is_err());
    assert!(f
        .host
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    journal.closed = false;
    durable::write_json(&path, &journal, true).unwrap();
    let native = f
        .host
        .native_grants
        .registry
        .resolve(issued.token.as_bytes())
        .unwrap();
    assert!(f
        .host
        .native_grants
        .registry
        .close(&native.repository_id, &native.view)
        .unwrap());
    assert!(f.host.issue_native_execution_grant(&f.request).is_err());
    assert!(f
        .host
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    f.host
        .close_native_execution_grant(&close_request(&issued))
        .unwrap();
}

#[test]
fn actual_native_registry_expiry_refuses_reads_and_issue_replay_without_sleeping() {
    let Some(mut f) = fixture() else { return };
    let clock = Arc::new(Mutex::new(chrono::Utc::now()));
    let current = Arc::clone(&clock);
    f.host.native_grants.registry =
        InMemorySandboxGrants::with_clock(Arc::new(move || *current.lock().unwrap()));
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let native = f
        .host
        .native_grants
        .registry
        .resolve(issued.token.as_bytes())
        .unwrap();
    assert!(issued.receipt.native_expires_at_unix_ms < f.request.claim.expires_at_unix_ms);
    assert_source(
        &f.host
            .read_native_granted_file(&read_request(&issued))
            .unwrap(),
        &issued,
    );
    *clock.lock().unwrap() = native.expires;
    assert!(f
        .host
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    assert!(f.host.issue_native_execution_grant(&f.request).is_err());
    f.host
        .close_native_execution_grant(&close_request(&issued))
        .unwrap();
}

#[test]
fn replaced_capture_root_cannot_attach_to_an_existing_native_lease() {
    let Some(f) = fixture() else { return };
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let path = &f.request.capture.path;
    std::fs::rename(path, path.with_file_name("retained-original-capture")).unwrap();
    std::fs::create_dir(path).unwrap();
    std::fs::write(path.join("source.rs"), SOURCE).unwrap();
    assert!(f
        .host
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    assert!(f.host.issue_native_execution_grant(&f.request).is_err());
    f.host
        .close_native_execution_grant(&close_request(&issued))
        .unwrap();
}

#[test]
fn restart_retires_unreconstructible_native_tokens_and_ignores_orphan_journal_temporaries() {
    let Some(f) = fixture() else { return };
    let issued = f.host.issue_native_execution_grant(&f.request).unwrap();
    let journal_path = f.host.grant_journal(&f.request.operation_id).unwrap();
    let journal_bytes = std::fs::read(&journal_path).unwrap();
    let root = journal_path.parent().unwrap();
    std::fs::write(root.join(".pending-truncated"), b"{").unwrap();
    std::fs::write(root.join(".pending-complete"), journal_bytes).unwrap();
    assert!(f.host.reconcile().unwrap().ready);
    assert_source(
        &f.host
            .read_native_granted_file(&read_request(&issued))
            .unwrap(),
        &issued,
    );
    let Fixture {
        _directory,
        host,
        request,
    } = f;
    let config = host.config.clone();
    drop(host);
    let restarted = Host::new(config).unwrap();
    assert!(restarted.reconcile().unwrap().ready);
    restarted.open_store(&request.binding).unwrap();
    assert!(restarted.native_grants.entries.lock().unwrap().is_empty());
    assert!(restarted
        .native_grants
        .registry
        .resolve(issued.token.as_bytes())
        .is_err());
    assert!(restarted
        .read_native_granted_file(&read_request(&issued))
        .is_err());
    assert!(restarted.issue_native_execution_grant(&request).is_err());
    let journal: Journal = durable::read_json(&journal_path).unwrap();
    assert!(journal.closed);
    assert!(journal_path
        .parent()
        .unwrap()
        .join(".pending-truncated")
        .exists());
    assert!(journal_path
        .parent()
        .unwrap()
        .join(".pending-complete")
        .exists());
}
