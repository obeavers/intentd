use super::*;
use crate::{codec, native_work::read, spool::Spool, HostClient};
use intent_atomic_proto::{
    recording::SelectedFile, HostIdentity, Outcome, RecoveryReport, Request, Response, StateToken,
    StoreBinding,
};
use tokio::io::DuplexStream;

fn request(root: &std::path::Path) -> PrepareRecordRequest {
    PrepareRecordRequest {
        operation_id: "original-record".into(),
        binding: StoreBinding {
            repository_id: "repository".into(),
            binding_epoch: 7,
            store_path: root.join("stores/repository"),
        },
        sealed_source: root.join("sealed/source"),
        expected_state: StateToken {
            view: "draft".into(),
            effective_state: "state-before".into(),
            own_merkle: "own-before".into(),
        },
        files: vec![SelectedFile {
            path: "src/file.rs".into(),
            kind: SelectedFileKind::Regular,
            length: 3,
            sha256: digest(b"new"),
        }],
        message: "original message".into(),
        author_name: "original author".into(),
        author_email: None,
        unix_seconds: 1,
        context_json: "{\"task\":\"original\"}".into(),
    }
}

fn prepared(request: &PrepareRecordRequest, spool: &Spool) -> PreparedNativeRecord {
    let selection = digest(&serde_json::to_vec(&request.files).unwrap());
    let metadata_digest = native_metadata_digest(request, &selection).unwrap();
    PreparedNativeRecord {
        operation_id: request.operation_id.clone(),
        host: HostIdentity::default(),
        binding: request.binding.clone(),
        expected_state: request.expected_state.clone(),
        command_digest: digest(&serde_json::to_vec(request).unwrap()),
        selection_digest: selection,
        metadata_digest,
        change_hash: format!("{}A", "B".repeat(51)),
        bytes: spool.retain(b"original-native-encoding").unwrap(),
        recorded_paths: vec!["src/file.rs".into()],
        deleted_paths: vec![],
    }
}

#[test]
fn native_metadata_hash_is_independent_from_daemon_json_insertion_order() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = request(temp.path());
    request.context_json = "{\"z\":{\"last\":1,\"first\":2},\"a\":0}".into();
    let expected = format!("{{\"bindingEpoch\":7,\"context\":{{\"a\":0,\"z\":{{\"first\":2,\"last\":1}}}},\"operationId\":\"original-record\",\"policyVersion\":1,\"repositoryId\":\"repository\",\"selectionDigest\":\"{}\"}}", "a".repeat(64));
    assert_eq!(
        native_metadata_digest(&request, &"a".repeat(64)).unwrap(),
        digest(expected.as_bytes())
    );
}

#[test]
fn changed_no_change_identity_never_replaces_original_operation() {
    let temp = tempfile::tempdir().unwrap();
    let request = request(temp.path());
    let mut outcome = RecordPreparation::NoChanges {
        operation_id: request.operation_id.clone(),
        command_digest: digest(&serde_json::to_vec(&request).unwrap()),
        expected_state: request.expected_state.clone(),
        selection_digest: digest(&serde_json::to_vec(&request.files).unwrap()),
    };
    validate_preparation(&request, &outcome).unwrap();
    let RecordPreparation::NoChanges { operation_id, .. } = &mut outcome else {
        unreachable!()
    };
    *operation_id = "replacement-record".into();
    assert!(validate_preparation(&request, &outcome).is_err());
}

#[test]
fn prepared_native_reply_cannot_substitute_metadata_paths_or_encoding() {
    let temp = tempfile::tempdir().unwrap();
    let spool = Spool::open(&temp.path().join("spool")).unwrap();
    let request = request(temp.path());
    let original = prepared(&request, &spool);
    validate_preparation(
        &request,
        &RecordPreparation::Prepared {
            record: Box::new(original.clone()),
        },
    )
    .unwrap();
    let mut changed = original.clone();
    changed.metadata_digest = "0".repeat(64);
    assert!(validate_preparation(
        &request,
        &RecordPreparation::Prepared {
            record: Box::new(changed)
        }
    )
    .is_err());
    let mut changed = original.clone();
    changed.recorded_paths.push("src/foreign.rs".into());
    assert!(validate_preparation(
        &request,
        &RecordPreparation::Prepared {
            record: Box::new(changed)
        }
    )
    .is_err());
    let receipt = NativeRecordReceipt {
        operation_id: original.operation_id.clone(),
        change_hash: original.change_hash.clone(),
        encoding_sha256: original.bytes.sha256.clone(),
        encoding_length: original.bytes.length,
        before: original.expected_state.clone(),
        after: StateToken {
            view: "draft".into(),
            effective_state: "after".into(),
            own_merkle: "after-own".into(),
        },
        replayed: false,
    };
    validate_admission(&original, &receipt).unwrap();
    let mut changed = receipt;
    changed.encoding_sha256 = "1".repeat(64);
    assert!(validate_admission(&original, &changed).is_err());
}

#[test]
fn a_record_cannot_select_a_foreign_source_or_hidden_native_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = request(temp.path());
    validate_request(&request, temp.path()).unwrap();
    request.files[0].path = "src/../.atomic/atomic.redb".into();
    assert!(validate_request(&request, temp.path()).is_err());
    request.files[0].path = "src/file.rs".into();
    request.sealed_source = temp.path().parent().unwrap().join("foreign-source");
    assert!(validate_request(&request, temp.path()).is_err());
}

#[test]
fn post_effect_spool_failure_cannot_erase_a_known_native_membership_fact() {
    let temp = tempfile::tempdir().unwrap();
    let spool = Spool::open(&temp.path().join("spool")).unwrap();
    let request = request(temp.path());
    let prepared = prepared(&request, &spool);
    let receipt = NativeRecordReceipt {
        operation_id: prepared.operation_id.clone(),
        change_hash: prepared.change_hash.clone(),
        encoding_sha256: prepared.bytes.sha256.clone(),
        encoding_length: prepared.bytes.length,
        before: prepared.expected_state.clone(),
        after: StateToken {
            view: "draft".into(),
            effective_state: "known-after".into(),
            own_merkle: "known-own".into(),
        },
        replayed: false,
    };
    validate_admission(&prepared, &receipt).unwrap();
    let result = admission_fact(
        receipt.clone(),
        Err(crate::HostError::InvalidSpool(
            "disk unavailable after native record",
        )),
    );
    assert_eq!(result.receipt, receipt);
    assert!(result.envelope.is_none());
    assert!(result
        .post_effect_retention_error
        .as_deref()
        .unwrap()
        .contains("disk unavailable"));
}

async fn reply(stream: &mut DuplexStream, request: Request, reply: Reply) {
    codec::write_frame(
        stream,
        &Response {
            id: request.id,
            outcome: Outcome::Success(Box::new(reply)),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_waiter_retains_exact_command_and_does_not_send_another_record() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("spool");
    let spool = Spool::open(&root).unwrap();
    let request = request(temp.path());
    let bytes = serde_json::to_vec(&request).unwrap();
    let envelope = spool.retain(&bytes).unwrap();
    let pending = OwnedRecordPreparation {
        request,
        envelope,
        freeze: None,
    };
    let retained = pending.clone();
    let (client, mut server) = tokio::io::duplex(65_536);
    let (admitted, sent) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut client = HostClient::connect(client, &HostIdentity::default())
            .await
            .unwrap();
        let request = retained.request.clone();
        let result = client
            .request(Command::PrepareExactRecord {
                request: Box::new(request),
            })
            .await;
        drop(retained);
        result
    });
    let handshake: Request = codec::read_frame(&mut server).await.unwrap();
    reply(
        &mut server,
        handshake,
        Reply::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .await;
    let recovery: Request = codec::read_frame(&mut server).await.unwrap();
    reply(
        &mut server,
        recovery,
        Reply::Reconciled {
            recovery: RecoveryReport {
                ready: true,
                unresolved_operation_ids: vec![],
            },
        },
    )
    .await;
    let actual: Request = codec::read_frame(&mut server).await.unwrap();
    let Command::PrepareExactRecord { request: actual } = actual.command else {
        panic!("wrong actual command")
    };
    assert_eq!(*actual, pending.request);
    admitted.send(()).unwrap();
    sent.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(codec::read_frame::<_, Request>(&mut server).await.is_err());
    assert_eq!(read(&spool, &pending.envelope, 48_000).unwrap(), bytes);
    assert_eq!(pending.request().operation_id, "original-record");
}
