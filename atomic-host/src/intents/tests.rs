use super::*;
use crate::{HostConfig, Session};
use intent_atomic_proto::intents::{AssignedIntentIdentity, SourceCriterion, TaskRevisionRef};
use intent_atomic_proto::{Command, StoreBinding};

const UID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

#[test]
#[ignore = "isolated environment fixture invoked by the ambient-provider refusal test"]
fn ambient_embedding_refusal_worker() {
    let (_directory, host, request) = fixture();
    let store = host.cached_store(&request.binding).unwrap();
    let before = store.state().unwrap();
    let vault_before = store.repository().has_vault().unwrap();
    let parent = host.binding_path(&request.binding).unwrap();
    // These inputs are deliberately invalid before any vault writer. If the
    // guard regresses, the fixture fails without reaching an embedding call.
    let mut invalid_source = request.clone();
    invalid_source.source.name = "missing-source-for-provider-refusal.payload".into();
    assert!(matches!(
        host.project_task_intent(&invalid_source),
        Err(HostError::Unsupported(_))
    ));
    let mut invalid_scope = request.clone();
    invalid_scope.root_id.clear();
    assert!(matches!(
        host.project_intent_observed(&invalid_scope, |_| panic!(
            "no journal phase may run before provider refusal"
        )),
        Err(HostError::Unsupported(_))
    ));
    assert!(!parent.join("intent-control.json").exists());
    assert!(!host
        .config
        .config_dir
        .join("intent-operations")
        .join(format!("{}.json", digest(request.operation_id.as_bytes())))
        .exists());
    assert_eq!(store.repository().has_vault().unwrap(), vault_before);
    assert_eq!(store.state().unwrap(), before);
}

#[test]
fn every_ambient_provider_refuses_both_native_projection_entrypoints_before_effects() {
    for key in ["VOYAGE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
        let mut process = std::process::Command::new(std::env::current_exe().unwrap());
        process.args([
            "--exact",
            "intents::tests::ambient_embedding_refusal_worker",
            "--ignored",
            "--nocapture",
        ]);
        for name in ["VOYAGE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
            process.env_remove(name);
        }
        process.env(key, "intent-invalid-provider-refusal-fixture");
        let result = process.output().unwrap();
        assert!(
            result.status.success(),
            "isolated provider-refusal fixture failed; no key or process output is emitted"
        );
    }
}
pub(crate) fn task_source(rev: i64, text: &str) -> NativeTaskSource {
    let criterion = "Preserve the requested invariant";
    let mut source = NativeTaskSource {
        reference: TaskRevisionRef {
            workspace_id: "workspace".into(),
            note_id: "task".into(),
            rev,
            digest: String::new(),
            projection_schema_version: 1,
        },
        title: "Original task".into(),
        content: text.into(),
        task_json: json!({"status":"review_required","acceptanceCriteria":[criterion]}).to_string(),
        criteria: vec![],
        created_at: "2026-11-13T12:00:00Z".into(),
    };
    repin(&mut source);
    source
}
fn repin(source: &mut NativeTaskSource) {
    source.reference.digest = digest(
        &serde_json::to_vec(&(
            source.reference.projection_schema_version,
            &source.reference.workspace_id,
            &source.reference.note_id,
            source.reference.rev,
            &source.title,
            &source.content,
            &source.task_json,
        ))
        .unwrap(),
    );
    let task: Value = serde_json::from_str(&source.task_json).unwrap();
    source.criteria = task["acceptanceCriteria"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let text = text.as_str().unwrap().to_owned();
            let text_digest = digest(text.as_bytes());
            let index = u32::try_from(index).unwrap();
            SourceCriterion {
                criterion_id: digest(
                    &serde_json::to_vec(&(&source.reference.digest, index, &text_digest)).unwrap(),
                ),
                index,
                text,
                text_digest,
                origin: "explicit-task-content".into(),
                required_kinds: vec![],
            }
        })
        .collect();
}
pub(crate) fn retain_source(host: &Host, name: &str, source: &NativeTaskSource) -> SpoolRef {
    let bytes = serde_json::to_vec(source).unwrap();
    exact_bytes(&host.config.spool_dir.join(name), &bytes).unwrap();
    SpoolRef {
        name: name.into(),
        length: u64::try_from(bytes.len()).unwrap(),
        sha256: digest(&bytes),
    }
}
pub(crate) fn fixture() -> (tempfile::TempDir, Host, ProjectTaskIntentRequest) {
    let directory = tempfile::tempdir().unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).unwrap();
    let config = HostConfig {
        stores_dir: directory_path.join("stores"),
        config_dir: directory_path.join("config"),
        spool_dir: directory_path.join("spool"),
    };
    let host = Host::new(config).unwrap();
    assert!(host.reconcile().unwrap().ready);
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: host.config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    host.initialize_store(&binding, "initialize").unwrap();
    let mut session = Session::default();
    host.handle(
        &mut session,
        Command::Handshake {
            identity: HostIdentity::default(),
        },
    )
    .unwrap();
    host.handle(&mut session, Command::Reconcile).unwrap();
    host.handle(
        &mut session,
        Command::OpenStore {
            binding: binding.clone(),
        },
    )
    .unwrap();
    let project = host.native_project_identity(&binding).unwrap();
    let source = task_source(
        0,
        "Preserve source: punctuation and literal ::file-ref{path=not-an-edge}.\nA second line.",
    );
    let request = ProjectTaskIntentRequest {
        operation_id: "project-task".into(),
        binding,
        root_id: "primary".into(),
        identity: AssignedIntentIdentity {
            native_intent_id: UID.into(),
            display_key: format!("INTENT::{}::1", UID.to_ascii_lowercase()),
            project_id: project.project_id,
            project_identity_hash: project.project_identity_hash,
            canonical_resource: format!("urn:atomic:intent:{UID}"),
        },
        projection_revision: 1,
        previous: None,
        task_revision: source.reference.clone(),
        source: retain_source(&host, "task-input.payload", &source),
    };
    (directory, host, request)
}

#[test]
fn preexisting_shared_vault_tables_do_not_substitute_for_control_working_copy_directories() {
    let (_directory, host, request) = fixture();
    let store = host.cached_store(&request.binding).unwrap();
    {
        // Reproduce upstream's internal post-table-commit/pre-directory gap.
        let mut txn = store.repository().pristine().write_txn().unwrap();
        txn.init_vault().unwrap();
        txn.commit().unwrap();
    }
    assert!(store.repository().has_vault().unwrap());
    assert!(!store.repository().vault_dir().exists());
    let receipt = host.project_task_intent(&request).unwrap();
    let control = host.control_repository(&request.binding).unwrap();
    assert!(control.vault_dir().join(&receipt.vault_path).is_file());
    assert_eq!(host.project_task_intent(&request).unwrap(), receipt);
}

#[test]
fn deterministic_native_uid_has_actual_distinct_pins_and_no_code_membership() {
    let (_directory, host, request) = fixture();
    let code = host
        .cached_store(&request.binding)
        .unwrap()
        .state()
        .unwrap();
    let receipt = host.project_task_intent(&request).unwrap();
    assert_eq!(receipt.identity, request.identity);
    assert_eq!(receipt.projection.task_revision, request.task_revision);
    assert!(hash_valid(&receipt.projection.pins.source_sha256));
    assert!(receipt
        .projection
        .pins
        .parsed_source_hash
        .starts_with("blake3:"));
    assert!(receipt
        .projection
        .pins
        .canonical_content_hash
        .starts_with("blake3:"));
    assert!(receipt
        .projection
        .pins
        .substance_hash
        .starts_with("blake3:"));
    assert_ne!(
        receipt.projection.pins.parsed_source_hash,
        receipt.projection.pins.canonical_content_hash
    );
    assert_eq!(
        host.cached_store(&request.binding)
            .unwrap()
            .state()
            .unwrap(),
        code,
        "control artifacts never join the code candidate view"
    );
    assert!(!request
        .binding
        .store_path
        .join(".vault")
        .join(&receipt.vault_path)
        .exists());
    assert_ne!(
        receipt.control_working_copy_id,
        host.cached_store(&request.binding)
            .unwrap()
            .repository()
            .require_working_copy_id()
            .unwrap()
            .to_string()
    );
    std::fs::remove_file(host.config.spool_dir.join(&request.source.name)).unwrap();
    assert_eq!(
        host.project_task_intent(&request).unwrap(),
        receipt,
        "terminal replay uses the retained original source"
    );
    let source = task_source(
        0,
        "Preserve source: punctuation and literal ::file-ref{path=not-an-edge}.\nA second line.",
    );
    let mut relocated = request.clone();
    relocated.source = retain_source(&host, "same-bytes-new-locator.payload", &source);
    assert_eq!(
        host.project_task_intent(&relocated).unwrap(),
        receipt,
        "spool filenames do not mint a second native intent"
    );
    let mut conflict = request.clone();
    let changed = task_source(0, "Different governing source");
    conflict.task_revision = changed.reference.clone();
    conflict.source = retain_source(&host, "changed.payload", &changed);
    assert!(host.project_task_intent(&conflict).is_err());
}

#[test]
fn exact_partial_creation_repairs_entry_manifest_and_materialization_after_reopen() {
    for interrupted in [
        Phase::Prepared,
        Phase::EntryStored,
        Phase::ManifestStored,
        Phase::Projected,
    ] {
        let (_directory, host, request) = fixture();
        let failure = host.project_intent_observed(&request, |phase| {
            if phase == interrupted {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "injected intent boundary",
                )
                .into())
            } else {
                Ok(())
            }
        });
        assert!(failure.is_err());
        let original: Journal =
            durable::read_json(&host.intent_journal_path(&request.operation_id).unwrap()).unwrap();
        std::fs::remove_file(host.config.spool_dir.join(&request.source.name)).unwrap();
        let config = host.config.clone();
        drop(host);
        let reopened = Host::new(config).unwrap();
        let recovery = reopened.reconcile().unwrap();
        assert!(
            recovery.ready,
            "{interrupted:?}: {:?}",
            recovery.unresolved_operation_ids
        );
        let result = reopened.project_task_intent(&request).unwrap();
        assert_eq!(result.identity.native_intent_id, UID);
        if let Some(prior) = original.receipt {
            assert_eq!(result, prior, "known projection is not recreated");
        }
        let repository = reopened.control_repository(&request.binding).unwrap();
        let manifest = repository.vault_manifest().unwrap();
        assert_eq!(
            manifest
                .intents
                .values()
                .filter(|entry| entry.uid == UID)
                .count(),
            1
        );
        assert_eq!(
            manifest.intents[&request.identity.display_key].vault_path,
            result.vault_path
        );
    }
}

#[test]
fn next_revision_keeps_uid_but_changes_actual_substance_and_detects_source_drift() {
    let (_directory, host, request) = fixture();
    let first = host.project_task_intent(&request).unwrap();
    let mut source = task_source(1, "A changed explicit task definition");
    source.title = "New title".into();
    repin(&mut source);
    let mut next = request.clone();
    next.operation_id = "project-task-revision-1".into();
    next.projection_revision = 2;
    next.previous = Some(first.projection.clone());
    next.task_revision = source.reference.clone();
    next.source = retain_source(&host, "task-next.payload", &source);
    let second = host.project_task_intent(&next).unwrap();
    assert_eq!(second.identity, first.identity);
    assert_ne!(
        second.projection.pins.substance_hash,
        first.projection.pins.substance_hash
    );
    let repository = host.control_repository(&request.binding).unwrap();
    let manifest = repository.vault_manifest().unwrap();
    assert_eq!(
        manifest.intents[&request.identity.display_key].title,
        "New title"
    );
    assert_eq!(
        host.project_task_intent(&request).unwrap(),
        first,
        "old exact operation remains historical, never reprojects over newer source"
    );
    let mut stale = next.clone();
    stale.operation_id = "stale-predecessor".into();
    stale.previous = Some(first.projection);
    stale.projection_revision = 2;
    assert!(host.project_task_intent(&stale).is_err());
}

#[test]
fn actual_next_turn_declaration_is_never_a_frozen_authoring_ack() {
    let (_directory, host, request) = fixture();
    let projection = host.project_task_intent(&request).unwrap();
    let store = host.cached_store(&request.binding).unwrap();
    let sessions = store.repository().dot_dir().join("sessions");
    durable::private_dir(&sessions).unwrap();
    let sessions = atomic_agent::turn::SessionStore::new(sessions).unwrap();
    let mut session = atomic_agent::turn::AgentSession::new("session-exact", "fixture", "Fixture");
    session.begin_turn();
    session.phase = atomic_agent::turn::phase::Phase::Active;
    sessions.save(&session).unwrap();
    let declare = DeclareNativeTurnRequest {
        operation_id: "declare-exact-turn".into(),
        binding: request.binding.clone(),
        projection: projection.projection,
        native_intent_id: UID.into(),
        session_id: session.session_id,
        expected_turn: 1,
    };
    let receipt = host.declare_native_turn_intent(&declare).unwrap();
    assert_eq!(receipt.stage, NativeTurnBindingStage::DeclaredOnly);
    assert_eq!(receipt.turn, 1);
    assert_eq!(
        sessions
            .turn_intent_binding("session-exact", 1)
            .unwrap()
            .unwrap()
            .intent_uid,
        UID
    );
    assert!(!store
        .repository()
        .dot_dir()
        .join("sessions/session-exact/intent-1.frozen")
        .exists());
    assert_eq!(host.declare_native_turn_intent(&declare).unwrap(), receipt);
    let mut stale = declare;
    stale.operation_id = "stale-turn".into();
    stale.expected_turn = 2;
    assert!(host.declare_native_turn_intent(&stale).is_err());
}

/// Actual pinned native setup for grant-owner fixtures. This helper creates a
/// real task projection and `SessionStore` declaration, then invokes the actual
/// host marker effect; callers never fabricate a freeze witness.
pub(crate) fn frozen_turn_fixture() -> (
    tempfile::TempDir,
    Host,
    ProjectTaskIntentRequest,
    IntentProjectionReceipt,
    intent_atomic_proto::intents::NativeTurnFreezeReceipt,
) {
    let (directory, host, request, projection, freeze) = declared_turn_fixture();
    let receipt = host.freeze_native_turn_for_record(&freeze).unwrap();
    (directory, host, request, projection, receipt)
}

pub(crate) fn declared_turn_fixture() -> (
    tempfile::TempDir,
    Host,
    ProjectTaskIntentRequest,
    IntentProjectionReceipt,
    intent_atomic_proto::intents::FreezeNativeTurnRequest,
) {
    let (directory, host, request) = fixture();
    let projection = host.project_task_intent(&request).unwrap();
    let store = host.cached_store(&request.binding).unwrap();
    let path = store.repository().dot_dir().join("sessions");
    durable::private_dir(&path).unwrap();
    let sessions = atomic_agent::turn::SessionStore::new(path).unwrap();
    let mut session = atomic_agent::turn::AgentSession::new("session-frozen", "fixture", "Fixture");
    session.begin_turn();
    session.phase = atomic_agent::turn::phase::Phase::Active;
    sessions.save(&session).unwrap();
    host.declare_native_turn_intent(&DeclareNativeTurnRequest {
        operation_id: "declare-frozen-turn".into(),
        binding: request.binding.clone(),
        projection: projection.projection.clone(),
        native_intent_id: UID.into(),
        session_id: session.session_id.clone(),
        expected_turn: 1,
    })
    .unwrap();
    let freeze = intent_atomic_proto::intents::FreezeNativeTurnRequest {
        operation_id: "record-frozen-turn".into(),
        work_binding_id: "exact-work-binding".into(),
        binding: request.binding.clone(),
        projection: projection.projection.clone(),
        native_intent_id: UID.into(),
        session_id: session.session_id,
        expected_turn: 1,
    };
    (directory, host, request, projection, freeze)
}

#[test]
fn explicit_required_kinds_and_planned_scopes_come_only_from_exact_task_source() {
    let (_directory, host, mut request) = fixture();
    let mut source = task_source(0, "A structured task");
    let mut task: Value = serde_json::from_str(&source.task_json).unwrap();
    let text = source.criteria[0].text_digest.clone();
    task["workDefinition"] = json!({"purpose":"source","criteria":[{"index":0,"textDigest":text,"requiredKinds":["unit","round-trip"]}],"files":[{"rootId":"primary","path":"src/exact.rs","role":"in-scope"},{"rootId":"primary","path":"src/keep.rs","role":"out-of-scope"},{"rootId":"primary","path":"README.md","role":"reference"}]});
    source.task_json = task.to_string();
    repin(&mut source);
    source.criteria[0].required_kinds = vec!["unit".into(), "round-trip".into()];
    request.task_revision = source.reference.clone();
    request.source = retain_source(&host, "structured.payload", &source);
    let receipt = host.project_task_intent(&request).unwrap();
    let repository = host.control_repository(&request.binding).unwrap();
    let inputs = intent_bridge::read_intent(&repository, UID).unwrap();
    let node = intent_bridge::lift(&inputs).unwrap();
    assert_eq!(
        node.has_acceptance_criterion[0].required_kinds,
        vec!["unit", "round-trip"]
    );
    assert_eq!(node.has_task[0].touches_file, vec!["src/exact.rs"]);
    assert_eq!(node.has_scope_out[0].files, vec!["src/keep.rs"]);
    assert!(node.has_acceptance_criterion[0].verifications.is_empty());
    assert_eq!(receipt.projection.task_revision, source.reference);
    let mut forged = source;
    forged.criteria[0].required_kinds.clear();
    let forged = serde_json::to_vec(&forged).unwrap();
    assert!(validate_source(&request, &forged).is_err());
}
