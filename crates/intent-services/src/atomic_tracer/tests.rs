//! These are association/orchestration tests, not real-provider qualification.

use intent_atomic_proto::{
    knowledge::{CodeFact, DerivedReceipt, DerivedRef},
    StateToken,
};
use intent_core::{
    knowledge::{KnowledgeProvenance, QueryCoverage, QueryReadBasis},
    vcs::{
        AtomicStateHash, ContentDigest, GitCommitId, GitTreeId, NativeStateRef, OperationId,
        RepositoryId, RootBinding, VcsKind,
    },
    work_evidence::{NativeBindingState, TaskRevisionRef, WorkBinding, WorkBindingAdmission},
    AgentId, NoteId, WorkspaceId,
};

use super::{
    associate,
    association::{digest, log_digest},
    fixture::{execute_test, FIXED_TEST, INITIAL_SOURCE, PACKAGE},
    ConfirmedTaskSource, Fixture, GitSourceIdentity, ProviderExecution, QueryObservation,
    RecordedRun, TaskQueryAssociation, TestObservation, TracerOutcome, TracerReport,
    FIXED_TEST_PATH, SOURCE_PATH,
};

type Mutation = Box<dyn Fn(&mut TaskQueryAssociation)>;

fn association() -> TaskQueryAssociation {
    let repository_id = RepositoryId::from_string("repository");
    let workspace_id = WorkspaceId::from_string("workspace");
    let note_id = NoteId::from_string("note");
    let root = RootBinding {
        workspace_id: workspace_id.clone(),
        root_id: "root".into(),
        repository_id: repository_id.clone(),
        kind: VcsKind::Git,
        locator: "/disposable/fixture".into(),
        epoch: 4,
    };
    let source = GitSourceIdentity {
        root: root.clone(),
        commit: GitCommitId::from_string("a".repeat(40)),
        tree: GitTreeId::from_string("b".repeat(40)),
    };
    let reference = TaskRevisionRef {
        workspace_id: workspace_id.clone(),
        note_id: note_id.clone(),
        rev: 3,
        digest: digest(b"retained task"),
        projection_schema_version: 1,
    };
    let baseline = NativeStateRef::Git {
        repository_id: repository_id.clone(),
        commit: Some(GitCommitId::from_string("c".repeat(40))),
        tree: GitTreeId::from_string("d".repeat(40)),
    };
    let binding = WorkBinding {
        admission: WorkBindingAdmission {
            binding_id: OperationId::from_string("original-binding"),
            workspace_id,
            note_id,
            expected_task_rev: 3,
            root: Some(root),
            baseline: Some(baseline),
            agent_id: AgentId::from_string("original-agent"),
            session_id: "original-session".into(),
            turn_attempt: "original-turn".into(),
            native_intent: None,
            delegation_parent: None,
            delegation_group: None,
        },
        command_digest: digest(b"actual admission"),
        task_revision: reference.clone(),
        native_state: NativeBindingState::NotRequired,
        declaration_receipt: None,
        active: false,
        created_at: "2026-11-18T12:00:00Z".into(),
    };
    let expected_task = super::TaskSpec::default();
    let run = RecordedRun {
        task: ConfirmedTaskSource {
            reference,
            title: expected_task.title,
            content: expected_task.content,
            criteria: expected_task.criteria,
            allowed_paths: vec![SOURCE_PATH.into()],
        },
        binding,
        contribution_operation_id: OperationId::from_string("actual-contribution"),
        contribution_receipt: digest(b"retained contribution"),
        source: source.clone(),
        changed_paths: vec![SOURCE_PATH.into()],
        provider: ProviderExecution {
            adapter_id: "configured-provider".into(),
            model_id: None,
            real_configured_provider: true,
        },
    };
    let preparation = DerivedReceipt {
        index: DerivedRef {
            repository_id: repository_id.as_str().into(),
            root_id: "root".into(),
            root_epoch: 4,
            generation: "durable-generation".into(),
        },
        index_epoch: 17,
        commit: source.commit.as_str().into(),
        tree: source.tree.as_str().into(),
        native_state: StateToken {
            view: "derived-view".into(),
            effective_state: "effective-state".into(),
            own_merkle: "own-merkle".into(),
        },
        manifest_digest: "manifest".into(),
        visibility_digest: "visibility".into(),
        ignore_policy_digest: "ignore".into(),
        indexed_files: 3,
        skipped_files: 0,
    };
    let read_basis = QueryReadBasis {
        repository_id: repository_id.clone(),
        root_id: "root".into(),
        root_epoch: 4,
        source_state: source.state(),
        derived_state: Some(NativeStateRef::Atomic {
            repository_id,
            view: "derived-view".into(),
            effective_state: AtomicStateHash::from_string("effective-state"),
            own_merkle: AtomicStateHash::from_string("own-merkle"),
            manifest: ContentDigest::from_string("manifest"),
        }),
        provenance: KnowledgeProvenance::ImportedGitSnapshot,
        index_epoch: 17,
        task_revision: None,
        source_event_watermark: None,
        projector_watermark: None,
        query_version: 1,
        ontology_version: "recorded-code-v1".into(),
        visibility_digest: "visibility".into(),
        ignore_policy_digest: "ignore".into(),
        stale: false,
        coverage: QueryCoverage {
            candidate_files: 1,
            read_files: 1,
            complete: true,
            ..QueryCoverage::default()
        },
        truncation: vec![],
    };
    let corrected = QueryObservation {
        facts: vec![CodeFact {
            path: SOURCE_PATH.into(),
            kind: "text".into(),
            name: None,
            line: Some(1),
            end_line: Some(1),
            preview: "return Math.round(amountCents * basisPoints / 10_000);".into(),
        }],
        read_basis,
    };
    let test = TestObservation {
        command: vec!["node".into(), "--test".into(), FIXED_TEST_PATH.into()],
        exit_code: 0,
        stdout: "actual captured stdout".into(),
        stderr: String::new(),
        log_digest: log_digest("actual captured stdout", "").unwrap(),
        source,
        fixed_test_digest: digest(FIXED_TEST.as_bytes()),
        package_digest: digest(PACKAGE.as_bytes()),
    };
    associate(run, test, preparation, corrected).unwrap()
}

#[test]
fn association_retains_original_lineage_without_inventing_native_task_linkage() {
    let association = association();
    let bytes = association.retained_bytes().unwrap();
    let reopened: TaskQueryAssociation = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reopened, association);
    reopened.validate().unwrap();
    assert_eq!(reopened.corrected_query.read_basis.task_revision, None);
    assert_eq!(
        reopened.corrected_query.read_basis.provenance,
        KnowledgeProvenance::ImportedGitSnapshot
    );
    assert_eq!(reopened.authority, "intent-composed-evidence");
}

#[test]
fn association_refuses_mismatched_source_commit_tree_root_repository_and_epoch() {
    let good = association();
    let mutations: Vec<Mutation> = vec![
        Box::new(|a| a.preparation.commit = "e".repeat(40)),
        Box::new(|a| a.preparation.tree = "f".repeat(40)),
        Box::new(|a| a.preparation.index.repository_id = "other".into()),
        Box::new(|a| a.preparation.index.root_id = "other".into()),
        Box::new(|a| a.preparation.index.root_epoch += 1),
        Box::new(|a| a.corrected_query.read_basis.index_epoch += 1),
        Box::new(|a| a.corrected_query.read_basis.root_epoch += 1),
        Box::new(|a| {
            a.corrected_query.read_basis.source_state = NativeStateRef::Git {
                repository_id: a.run.source.root.repository_id.clone(),
                commit: Some(GitCommitId::from_string("e".repeat(40))),
                tree: a.run.source.tree.clone(),
            }
        }),
        Box::new(|a| a.corrected_query.read_basis.derived_state = None),
        Box::new(|a| a.corrected_query.read_basis.visibility_digest = "other".into()),
    ];
    for mutate in mutations {
        let mut value = good.clone();
        mutate(&mut value);
        assert!(value.validate().is_err());
    }
}

#[test]
fn association_refuses_current_task_retargeting_fake_provider_or_extra_changed_files() {
    let good = association();
    let mutations: Vec<Mutation> = vec![
        Box::new(|a| a.run.task.reference.rev += 1),
        Box::new(|a| {
            a.run.task.criteria.pop();
        }),
        Box::new(|a| a.run.binding.admission.turn_attempt.clear()),
        Box::new(|a| a.run.binding.admission.expected_task_rev += 1),
        Box::new(|a| a.run.binding.admission.root.as_mut().unwrap().epoch += 1),
        Box::new(|a| a.run.binding.admission.baseline = None),
        Box::new(|a| a.run.changed_paths.push(FIXED_TEST_PATH.into())),
        Box::new(|a| a.run.changed_paths = vec![]),
        Box::new(|a| a.run.provider.real_configured_provider = false),
        Box::new(|a| a.run.contribution_receipt = ContentDigest::from_string("")),
    ];
    for mutate in mutations {
        let mut value = good.clone();
        mutate(&mut value);
        assert!(value.validate().is_err());
    }
}

#[test]
fn association_refuses_unobserved_test_success_and_modified_test_inputs() {
    let good = association();
    let mutations: Vec<Mutation> = vec![
        Box::new(|a| a.test_observation.exit_code = 1),
        Box::new(|a| a.test_observation.command = vec!["model said it passed".into()]),
        Box::new(|a| a.test_observation.stdout.push_str("edited after capture")),
        Box::new(|a| a.test_observation.fixed_test_digest = digest(b"weakened test")),
        Box::new(|a| a.test_observation.package_digest = digest(b"changed package")),
        Box::new(|a| a.test_observation.source.commit = GitCommitId::from_string("f".repeat(40))),
    ];
    for mutate in mutations {
        let mut value = good.clone();
        mutate(&mut value);
        assert!(value.validate().is_err());
    }
}

#[test]
fn association_requires_positive_complete_query_and_honest_provenance() {
    let good = association();
    let mutations: Vec<Mutation> = vec![
        Box::new(|a| a.corrected_query.facts.clear()),
        Box::new(|a| a.corrected_query.facts[0].path = "other.js".into()),
        Box::new(|a| a.corrected_query.facts[0].preview = "return Math.floor(value);".into()),
        Box::new(|a| {
            a.corrected_query.read_basis.task_revision = Some(a.run.task.reference.clone());
        }),
        Box::new(|a| a.corrected_query.read_basis.stale = true),
        Box::new(|a| a.corrected_query.read_basis.coverage.complete = false),
        Box::new(|a| a.corrected_query.read_basis.query_version = 0),
    ];
    for mutate in mutations {
        let mut value = good.clone();
        mutate(&mut value);
        assert!(value.validate().is_err());
    }
}

#[test]
fn fixture_creation_and_fixed_input_validation_never_reuse_or_weaken_a_test() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::create(&dir.path().join("fixture")).unwrap();
    assert!(Fixture::create(&fixture.directory).is_err());
    Fixture::validate_fixed_inputs(&fixture.directory).unwrap();
    std::fs::write(
        fixture.directory.join(FIXED_TEST_PATH),
        "// removed the failing assertion",
    )
    .unwrap();
    assert!(Fixture::validate_fixed_inputs(&fixture.directory).is_err());
}

#[tokio::test]
async fn actual_node_fixture_test_fails_before_and_passes_after_the_rounding_fix() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::create(&dir.path().join("fixture")).unwrap();
    let mut source = association().run.source;
    source.root.locator = fixture.directory.clone();
    let baseline = execute_test(
        &fixture.directory,
        &source,
        std::path::Path::new("node"),
        intentd_test_support::test_timeout(std::time::Duration::from_secs(15)),
    )
    .await
    .unwrap();
    assert_ne!(baseline.exit_code, 0);
    std::fs::write(
        fixture.directory.join(SOURCE_PATH),
        INITIAL_SOURCE.replace("Math.floor", "Math.round"),
    )
    .unwrap();
    let fixed = execute_test(
        &fixture.directory,
        &source,
        std::path::Path::new("node"),
        intentd_test_support::test_timeout(std::time::Duration::from_secs(15)),
    )
    .await
    .unwrap();
    assert_eq!(fixed.exit_code, 0);
    fixed.validate(&source).unwrap();
}

#[test]
fn default_report_cannot_be_confused_with_a_qualified_success() {
    let mut report = TracerReport::default();
    assert_eq!(report.outcome, TracerOutcome::Failed);
    assert!(!report.durable_reopen_verified);
    assert!(!report.sentinel_excluded);
    let markdown = report.markdown().unwrap();
    assert!(markdown.contains("FAIL"));
    assert!(markdown.contains("not a qualified independent check receipt"));
    assert!(markdown.contains("not source-adoption approval"));
    assert!(markdown.contains("Observed phases and available setup results"));
    assert!(!markdown.contains("task association blob"));
    assert!(!markdown.contains("Full typed evidence is retained"));

    report.association = Some(association());
    let unretained = report.markdown().unwrap();
    assert!(unretained.contains("task association retention was not confirmed"));
    assert!(!unretained.contains("task association blob"));

    let bytes = report
        .association
        .as_ref()
        .unwrap()
        .retained_bytes()
        .unwrap();
    report.retained_association = Some(super::RetainedAssociation {
        digest: digest(&bytes),
        length: u64::try_from(bytes.len()).unwrap(),
    });
    let retained = report.markdown().unwrap();
    assert!(retained.contains("report.json and the task association blob"));
    assert!(retained.contains("FAIL"));
    assert_eq!(report.outcome, TracerOutcome::Failed);
}

#[cfg(unix)]
#[test]
fn exclusive_output_creation_refuses_existing_directories_and_symlinks() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let occupied = temp.path().join("occupied");
    std::fs::create_dir(&occupied).unwrap();
    std::fs::write(occupied.join("keep"), b"untouched").unwrap();
    assert!(super::DirectoryGuard::create(&occupied).is_err());
    let alias = temp.path().join("alias");
    symlink(&occupied, &alias).unwrap();
    assert!(super::DirectoryGuard::create(&alias).is_err());
    assert_eq!(std::fs::read(occupied.join("keep")).unwrap(), b"untouched");
}

#[cfg(unix)]
#[test]
fn pinned_daemon_and_database_owners_refuse_replacement_before_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let output = super::DirectoryGuard::create(&temp.path().join("output")).unwrap();
    let daemon = output.create_child("daemon").unwrap();
    daemon
        .write_new("intentd.db", b"owned database fixture")
        .unwrap();
    let database = super::FileGuard::open(&daemon.path().join("intentd.db")).unwrap();
    database.validate().unwrap();
    std::fs::rename(daemon.path(), output.path().join("original-daemon")).unwrap();
    std::fs::create_dir(daemon.path()).unwrap();
    std::fs::write(daemon.path().join("intentd.db"), b"unrelated replacement").unwrap();
    assert!(daemon.validate().is_err());
    assert!(database.validate().is_err());
    assert!(daemon.write_new("must-not-appear", b"no").is_err());
    assert!(!daemon.path().join("must-not-appear").exists());
    assert_eq!(
        std::fs::read(daemon.path().join("intentd.db")).unwrap(),
        b"unrelated replacement"
    );
}
