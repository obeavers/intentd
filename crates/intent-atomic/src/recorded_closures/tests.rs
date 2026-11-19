use super::*;
use intent_atomic_proto::{
    closures::ClosureScope, recorded_closures::RECORDED_CLOSURE_READER, StateToken, StoreBinding,
};

fn closure() -> RecordedClosure {
    let bytes = b"recorded payload fixture; not native qualification";
    let sha256 = digest(bytes);
    RecordedClosure {
        format: RECORDED_CLOSURE_FORMAT,
        reader_version: RECORDED_CLOSURE_READER,
        profile: RecordedClosureProfile::RecordedViewExact,
        operation_id: "original-export".into(),
        host: HostIdentity::default(),
        scope: ClosureScope {
            workspace_id: "original-workspace".into(),
            root_id: "primary".into(),
            repository_id: uuid::Uuid::new_v4().to_string(),
            binding_epoch: 7,
        },
        capture_revision: 19,
        source_state: StateToken {
            view: "target/nested".into(),
            effective_state: "A".repeat(52),
            own_merkle: "B".repeat(52),
        },
        project_id: "PROJECT".into(),
        project_identity_hash: "PROJECT-HASH".into(),
        view_manifest_digest: "a".repeat(64),
        materialization_manifest_digest: "b".repeat(64),
        materialization_id: "c".repeat(64),
        conflict: None,
        object_count: 2,
        payload: SpoolRef {
            name: format!("recorded-{sha256}.bin"),
            length: bytes.len() as u64,
            sha256,
        },
    }
}

fn receipt(
    request: &RestoreRecordedClosureRequest,
    spool: &std::path::Path,
) -> RecordedClosureRestore {
    let closure = &request.closure;
    let root = spool
        .join("recorded-restores")
        .join(digest(request.operation_id.as_bytes()))
        .join(format!("attempt-{}", uuid::Uuid::new_v4()));
    let mut receipt = RecordedClosureRestore {
        operation_id: request.operation_id.clone(),
        host: HostIdentity::default(),
        scope: request.expected_scope.clone(),
        capture_revision: closure.capture_revision,
        source_state: closure.source_state.clone(),
        restored_state: StateToken {
            effective_state: "C".repeat(52),
            ..closure.source_state.clone()
        },
        project_id: closure.project_id.clone(),
        project_identity_hash: closure.project_identity_hash.clone(),
        view_manifest_digest: closure.view_manifest_digest.clone(),
        materialization_manifest_digest: closure.materialization_manifest_digest.clone(),
        materialization_id: closure.materialization_id.clone(),
        native_conflict_hash: None,
        object_count: closure.object_count,
        native_path: root.join("native"),
        path: root.join("files"),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = digest(&serde_json::to_vec(&receipt).unwrap());
    receipt
}

#[test]
fn private_restore_retains_original_fence_and_refuses_foreign_scope_or_output() {
    let directory = tempfile::tempdir().unwrap();
    let spool = directory.path().canonicalize().unwrap().join("spool");
    let closure = closure();
    let request = RestoreRecordedClosureRequest {
        operation_id: "original-restore".into(),
        expected_scope: closure.scope.clone(),
        closure,
    };
    let original = receipt(&request, &spool);
    assert_ne!(
        original.source_state.effective_state,
        original.restored_state.effective_state
    );
    validate_restore(&request, &original, &spool).unwrap();
    let mut changed = original.clone();
    changed.source_state = changed.restored_state.clone();
    assert!(validate_restore(&request, &changed, &spool).is_err());
    changed = original.clone();
    changed.scope.binding_epoch += 1;
    assert!(validate_restore(&request, &changed, &spool).is_err());
    changed = original.clone();
    changed.native_path = directory.path().join("foreign/native");
    changed.path = directory.path().join("foreign/files");
    changed.receipt_digest.clear();
    changed.receipt_digest = digest(&serde_json::to_vec(&changed).unwrap());
    assert!(validate_restore(&request, &changed, &spool).is_err());
}

#[tokio::test]
async fn corrupt_import_or_unsafe_view_refuses_before_host_start_or_spool_creation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let host = Arc::new(
        HostSupervisor::new(crate::HostLaunchConfig::new(
            root.join("must-not-execute"),
            root.join("daemon-not-created"),
            root.join("stores-not-created"),
        ))
        .unwrap(),
    );
    let spool = host.spool_path();
    let client = AtomicRecordedClosureClient::new(host);
    let closure = closure();
    assert!(client
        .stage_received(closure.clone(), b"different bytes".to_vec())
        .await
        .is_err());
    let request = ExportRecordedClosureRequest {
        operation_id: "unsafe".into(),
        scope: closure.scope.clone(),
        capture_revision: 1,
        binding: StoreBinding {
            repository_id: closure.scope.repository_id.clone(),
            binding_epoch: closure.scope.binding_epoch,
            store_path: root.join("stores/not-opened"),
        },
        view: "../../outside".into(),
        expected_state: StateToken {
            view: "../../outside".into(),
            ..closure.source_state
        },
    };
    assert!(client.prepare_export(request).await.is_err());
    assert!(!spool.exists());
    assert!(!root.join("daemon-not-created").exists());
    assert!(!root.join("stores-not-created").exists());
}

#[test]
fn unknown_reader_host_and_payload_aliases_are_explicit_refusals() {
    let original = closure();
    validate_closure(&original).unwrap();
    let mut changed = original.clone();
    changed.reader_version += 1;
    assert!(validate_closure(&changed).is_err());
    changed = original.clone();
    changed.host.contract_version += 1;
    assert!(validate_closure(&changed).is_err());
    changed = original;
    changed.payload.name = "../foreign.payload".into();
    assert!(validate_closure(&changed).is_err());
}
