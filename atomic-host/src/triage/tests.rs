use super::*;
use atomic_core::change::ChangeHeader;
use intent_atomic_proto::{
    baselines::{BaselinePolicy, ImportBaselineRequest},
    closures::{ClosureScope, ExportBaselineClosureRequest},
    composition::{
        CaptureCompositionTargetRequest, ExactCompositionChange, PrivateCompositionInput,
        PrivateCompositionOutcome,
    },
    triage::TriageTaskProjection,
};

pub(crate) fn fixture() -> (tempfile::TempDir, Host, PrepareNativeTriageRequest) {
    let (directory, host, task) = crate::intents::tests::fixture();
    let projected = host.project_task_intent(&task).unwrap();
    let git = git2::Repository::init(directory.path().join("git-triage")).unwrap();
    let bytes = b"fn original() { println!(\"base\"); }\n";
    let id = git.blob(bytes).unwrap();
    let mut index = git2::Index::new().unwrap();
    index
        .add(&git2::IndexEntry {
            ctime: git2::IndexTime::new(0, 0),
            mtime: git2::IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: 0o100_644,
            uid: 0,
            gid: 0,
            file_size: u32::try_from(bytes.len()).unwrap(),
            id,
            flags: 0,
            flags_extended: 0,
            path: b"source.rs".to_vec(),
        })
        .unwrap();
    let tree = git.find_tree(index.write_tree_to(&git).unwrap()).unwrap();
    let signature = git2::Signature::now("Triage fixture", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(Some("HEAD"), &signature, &signature, "source", &tree, &[])
        .unwrap()
        .to_string();
    drop(tree);
    let imported = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "triage-baseline".into(),
            binding: task.binding.clone(),
            source_path: git.workdir().unwrap().to_owned(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    let closure = host
        .export_baseline_closure(&ExportBaselineClosureRequest {
            operation_id: "triage-base-export".into(),
            scope: ClosureScope {
                workspace_id: task.task_revision.workspace_id.clone(),
                root_id: task.root_id.clone(),
                repository_id: task.binding.repository_id.clone(),
                binding_epoch: task.binding.binding_epoch,
            },
            capture_revision: 1,
            baseline: imported.baseline.clone(),
        })
        .unwrap();
    let seed = host.portable_baseline_seed(&closure).unwrap();
    let store = host.cached_store(&task.binding).unwrap();
    let mut repository =
        Repository::open_with_pristine(&task.binding.store_path, store.shared_pristine()).unwrap();
    let baseline = host.baseline_store(&imported.baseline).unwrap();
    for hash in &seed.view.changes {
        let bytes = std::fs::read(baseline.repository.change_store().change_path(hash)).unwrap();
        repository.import_change_bytes(hash, &bytes).unwrap();
    }
    repository.apply_view_manifest(&seed.view).unwrap();
    let root = repository.current_view().to_owned();
    repository.create_view_from("authored", &root).unwrap();
    repository.create_view_from("target", &root).unwrap();
    let file = repository
        .record_foreign_modified_file_on_view_excluding(
            "source.rs",
            bytes,
            b"fn original() { println!(\"candidate\"); }\n",
            false,
            "authored",
            &[],
        )
        .unwrap();
    let (change, _) = repository
        .assemble_and_hash(
            "authored",
            ChangeHeader::new("actual authored candidate"),
            &[file],
        )
        .unwrap();
    let mut encoded = Vec::new();
    let hash = change.serialize(&mut encoded).unwrap();
    let object = composition::retain_bytes(&host, &encoded, 512 * 1024 * 1024).unwrap();
    let expected = crate::recording::state(&repository, "target").unwrap();
    let capture = host
        .capture_composition_target(&CaptureCompositionTargetRequest {
            operation_id: "triage-target".into(),
            scope: closure.scope.clone(),
            binding: task.binding.clone(),
            view: "target".into(),
            expected_state: expected.clone(),
        })
        .unwrap();
    let input = PrivateCompositionInput {
        operation_id: "triage-composition".into(),
        scope: closure.scope.clone(),
        target: closure.clone(),
        inherited_baseline: closure,
        expected_target: expected,
        captured_target: Some(capture),
        target_changes: Vec::new(),
        selected_changes: vec![hash.to_base32()],
        available_changes: vec![ExactCompositionChange {
            hash: hash.to_base32(),
            bytes: object,
        }],
    };
    let PrivateCompositionOutcome::Composed { receipt } = host.compose_private(&input).unwrap()
    else {
        panic!("actual composition required");
    };
    drop(repository);
    drop(store);
    drop(baseline);
    drop(git);
    let projections = vec![TriageTaskProjection {
        native_intent_id: projected.identity.native_intent_id,
        projection: projected.projection,
    }];
    let control_snapshot = host
        .capture_native_triage_control(&intent_atomic_proto::triage::CaptureNativeControlRequest {
            operation_id: "triage-current-full-control".into(),
            binding: task.binding.clone(),
            projections: projections.clone(),
        })
        .unwrap();
    (
        directory,
        host,
        PrepareNativeTriageRequest {
            operation_id: "native-triage".into(),
            binding: task.binding,
            composition: *receipt,
            projections,
            control_snapshot,
        },
    )
}

fn produced(outcome: NativeTriagePreparation) -> Box<NativeTriageReceipt> {
    match outcome {
        NativeTriagePreparation::Produced { receipt } => receipt,
        unexpected => panic!("actual native triage did not produce a report: {unexpected:?}"),
    }
}

#[test]
fn actual_native_triage_pins_full_report_control_and_original_candidate_without_code_mutation() {
    let (_directory, host, request) = fixture();
    let code = std::fs::read(request.composition.candidate_path.join("source.rs")).unwrap();
    let original = host
        .original_private_composition(&request.composition)
        .unwrap();
    let native_root = request
        .composition
        .candidate_path
        .parent()
        .unwrap()
        .join("native");
    let project_before = Repository::open_readonly_without_migration(&native_root)
        .unwrap()
        .project_identity()
        .unwrap()
        .unwrap()
        .hash;
    let receipt = produced(host.prepare_native_triage(&request).unwrap());
    assert_eq!(receipt.authority, NativeEvidenceAuthority::EvidenceOnly);
    assert_eq!(
        receipt.reviewer_execution,
        ReviewerExecutionAvailability::Unavailable
    );
    let bytes = composition::read_spool(&host, &receipt.report, MAX_REPORT).unwrap();
    let report: atomic_repository::triage::TriageReport = serde_json::from_slice(&bytes).unwrap();
    assert!(!report.changes.is_empty());
    assert_eq!(report.reference, receipt.native_reference);
    assert_eq!(report.inputs.candidate_changes, original.selected_changes);
    let signed = signing::verify(&host, &receipt.evidence).unwrap();
    assert_eq!(signed["reportSha256"], receipt.report.sha256);
    let revision: NativeTriageReadRevision = serde_json::from_slice(
        &composition::read_spool(&host, &receipt.read_revision, MAX_REPORT).unwrap(),
    )
    .unwrap();
    assert_eq!(revision.auxiliaries.len(), 4);
    let paths: BTreeSet<_> = revision
        .auxiliaries
        .iter()
        .map(|pin| pin.path.as_str())
        .collect();
    assert_eq!(
        paths,
        BTreeSet::from([
            "prompts/system_prompt.md",
            "skills/atomic-vault.md",
            "skills/code-intelligence.md",
            "memory/MEMORY.md"
        ])
    );
    assert!(revision.auxiliaries.iter().all(|pin| matches!(
        pin.canonical,
        intent_atomic_proto::triage::NativeCanonicalObservation::NotApplicable { .. }
    )));
    assert_eq!(
        revision.controls[0].projection,
        request.projections[0].projection
    );
    assert_eq!(
        revision.candidate_state,
        request.composition.candidate_state
    );
    assert_eq!(
        revision.original_target_state,
        request.composition.target_state
    );
    assert_eq!(
        code,
        std::fs::read(request.composition.candidate_path.join("source.rs")).unwrap()
    );
    host.original_private_composition(&request.composition)
        .unwrap();
    assert_eq!(
        Repository::open_readonly_without_migration(&native_root)
            .unwrap()
            .project_identity()
            .unwrap()
            .unwrap()
            .hash,
        project_before
    );
    assert_eq!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Produced { receipt }
    );
}

#[test]
fn absent_or_incomplete_control_never_becomes_an_empty_clean_native_report() {
    let (_directory, host, mut request) = fixture();
    let selected = request.projections.clone();
    request.projections.clear();
    assert!(matches!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Unavailable { .. }
    ));
    request.operation_id = "malformed-composition".into();
    request.composition.receipt_digest = "0".repeat(64);
    request.projections = selected;
    assert!(host.prepare_native_triage(&request).is_err());
}

#[test]
fn verified_newer_task_projection_makes_old_report_stale_without_rewriting_it() {
    let (_directory, host, request) = fixture();
    let receipt = produced(host.prepare_native_triage(&request).unwrap());
    let original = {
        let _writer = host.writer.lock().unwrap();
        host.export_current_intent_control(
            &request.binding,
            &request.projections[0].projection,
            &request.projections[0].native_intent_id,
        )
        .unwrap()
        .receipt()
        .clone()
    };
    let source = crate::intents::tests::task_source(1, "A newer governing task source.");
    let update = intent_atomic_proto::intents::ProjectTaskIntentRequest {
        operation_id: "newer-triage-source".into(),
        binding: request.binding.clone(),
        root_id: request.composition.scope.root_id.clone(),
        identity: original.identity,
        projection_revision: original.projection.projection_revision + 1,
        previous: Some(original.projection),
        task_revision: source.reference.clone(),
        source: crate::intents::tests::retain_source(&host, "newer-triage-task.payload", &source),
    };
    host.project_task_intent(&update).unwrap();
    assert!(matches!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Stale { .. }
    ));
    let bytes = composition::read_spool(&host, &receipt.report, MAX_REPORT).unwrap();
    assert_eq!(digest(&bytes), receipt.report.sha256);
}

#[test]
fn auxiliary_physical_tamper_extra_row_and_forged_descriptor_never_produce_triage() {
    let (_directory, host, mut request) = fixture();
    let root = host
        .binding_path(&request.binding)
        .unwrap()
        .join("intent-control/.vault");
    let path = root.join("memory/MEMORY.md");
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"tampered physical source").unwrap();
    assert!(matches!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Unavailable { .. }
    ));
    std::fs::write(&path, original).unwrap();
    let valid = request.control_snapshot.clone();
    request.control_snapshot.snapshot_digest = "0".repeat(64);
    assert!(matches!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Unavailable { .. }
    ));
    request.control_snapshot = valid;
    let store = host.cached_store(&request.binding).unwrap();
    {
        let mut transaction = store.repository().pristine().write_txn().unwrap();
        let entry = atomic_core::pristine::VaultEntry::new(
            atomic_core::pristine::VaultEntryType::Scratch,
            b"unqualified context".to_vec(),
            "{}".into(),
            "2026-11-13T00:00:00Z".into(),
        );
        transaction
            .put_vault_entry("scratch/unpinned.md", &entry)
            .unwrap();
        transaction.commit().unwrap();
    }
    assert!(matches!(
        host.prepare_native_triage(&request).unwrap(),
        NativeTriagePreparation::Unavailable { .. }
    ));
}
