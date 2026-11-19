use super::*;
use atomic_core::change::ChangeHeader;
use atomic_core::output::memory::Memory;
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use intent_atomic_proto::baselines::{BaselinePolicy, ImportBaselineRequest};
use intent_atomic_proto::closures::{BaselineClosure, ClosureScope, ExportBaselineClosureRequest};
use intent_atomic_proto::composition::CaptureCompositionTargetRequest;
use intent_atomic_proto::StoreBinding;

struct Fixture {
    _directory: tempfile::TempDir,
    host: Host,
    binding: StoreBinding,
    git: git2::Repository,
    closure: BaselineClosure,
    source: Repository,
    available: Vec<ExactCompositionChange>,
}

fn commit(git: &git2::Repository, files: &[(&str, u32, &[u8])]) -> String {
    let mut index = git2::Index::new().unwrap();
    for (path, mode, bytes) in files {
        let id = git.blob(bytes).unwrap();
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: *mode,
                uid: 0,
                gid: 0,
                file_size: u32::try_from(bytes.len()).unwrap(),
                id,
                flags: 0,
                flags_extended: 0,
                path: path.as_bytes().to_vec(),
            })
            .unwrap();
    }
    let tree = git.find_tree(index.write_tree_to(git).unwrap()).unwrap();
    let signature = git2::Signature::new(
        "Composition fixture",
        "fixture@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    let parent = git.head().ok().and_then(|head| head.peel_to_commit().ok());
    git.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "exact fixture",
        &tree,
        &parent.iter().collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string()
}

fn capture(
    host: &Host,
    binding: &StoreBinding,
    git: &git2::Repository,
    files: &[(&str, u32, &[u8])],
    operation: &str,
) -> BaselineClosure {
    let receipt = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: operation.into(),
            binding: binding.clone(),
            source_path: git.workdir().unwrap().to_owned(),
            commit: commit(git, files),
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    host.export_baseline_closure(&ExportBaselineClosureRequest {
        operation_id: format!("export-{operation}"),
        capture_revision: 1,
        scope: ClosureScope {
            workspace_id: "persisted-workspace".into(),
            root_id: "primary".into(),
            repository_id: binding.repository_id.clone(),
            binding_epoch: binding.binding_epoch,
        },
        baseline: receipt.baseline,
    })
    .unwrap()
}

fn fixture(files: &[(&str, u32, &[u8])]) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("host");
    durable::private_dir(&root).unwrap();
    let host = Host::new(crate::HostConfig {
        stores_dir: root.join("stores"),
        config_dir: root.join("config"),
        spool_dir: root.join("spool"),
    })
    .unwrap();
    host.reconcile().unwrap();
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: host.config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    host.initialize_store(&binding, "compose-initialize")
        .unwrap();
    let git = git2::Repository::init(directory.path().join("git")).unwrap();
    let closure = capture(&host, &binding, &git, files, "compose-baseline");
    let seed = host.portable_baseline_seed(&closure).unwrap();
    host.open_store(&binding).unwrap();
    let store = host.cached_store(&binding).unwrap();
    let mut source =
        Repository::open_with_pristine(&binding.store_path, store.shared_pristine()).unwrap();
    let baseline = host.baseline_store(&closure.baseline.baseline).unwrap();
    for hash in &seed.view.changes {
        let bytes = std::fs::read(baseline.repository.change_store().change_path(hash)).unwrap();
        source.import_change_bytes(hash, &bytes).unwrap();
    }
    source.apply_view_manifest(&seed.view).unwrap();
    let parent = source.current_view().to_owned();
    for name in ["left", "right", "target"] {
        source.create_view_from(name, &parent).unwrap();
    }
    Fixture {
        _directory: directory,
        host,
        binding,
        git,
        closure,
        source,
        available: Vec::new(),
    }
}

impl Fixture {
    fn publish(
        &mut self,
        view: &str,
        file: atomic_core::record::workflow::RecordedFile,
        message: &str,
    ) -> String {
        let (change, _) = self
            .source
            .assemble_and_hash(view, ChangeHeader::new(message), &[file])
            .unwrap();
        let mut bytes = Vec::new();
        let hash = change.serialize(&mut bytes).unwrap();
        self.source.import_change_bytes(&hash, &bytes).unwrap();
        self.source
            .insert_change(&hash, InsertOptions::default().view(view))
            .unwrap();
        let reference = retain(&self.host, &bytes).unwrap();
        self.available.push(ExactCompositionChange {
            hash: hash.to_base32(),
            bytes: reference,
        });
        hash.to_base32()
    }

    fn edit(&mut self, view: &str, path: &str, old: &[u8], new: &[u8]) -> String {
        let file = self
            .source
            .record_foreign_modified_file_on_view_excluding(path, old, new, false, view, &[])
            .unwrap();
        self.publish(view, file, &format!("edit {view} {path}"))
    }

    fn add(&mut self, view: &str, path: &str, content: &[u8]) -> String {
        let memory = Memory::new();
        memory.add_file(path, content);
        let mut file = record_added_file(
            &memory,
            &DetectedFile::added(path),
            &RecordingOptions::new(),
        )
        .unwrap();
        file.set_attr(InodeAttr::Kind(InodeKind::Regular));
        file.set_attr(InodeAttr::Mode(0o644));
        self.publish(view, file, &format!("add {view} {path}"))
    }

    fn input(
        &self,
        selected: Vec<String>,
        target: &[String],
        operation: &str,
    ) -> PrivateCompositionInput {
        for hash in target {
            self.source
                .insert_change(
                    &parse_hash(hash).unwrap(),
                    InsertOptions::default().view("target"),
                )
                .unwrap();
        }
        PrivateCompositionInput {
            operation_id: operation.into(),
            scope: self.closure.scope.clone(),
            target: self.closure.clone(),
            inherited_baseline: self.closure.clone(),
            expected_target: crate::recording::state(&self.source, "target").unwrap(),
            captured_target: Some(
                self.host
                    .capture_composition_target(&CaptureCompositionTargetRequest {
                        operation_id: format!("capture-{operation}"),
                        scope: self.closure.scope.clone(),
                        binding: self.binding.clone(),
                        view: "target".into(),
                        expected_state: crate::recording::state(&self.source, "target").unwrap(),
                    })
                    .unwrap(),
            ),
            target_changes: Vec::new(),
            selected_changes: selected,
            available_changes: self.available.clone(),
        }
    }
}

fn composed(host: &Host, input: &PrivateCompositionInput) -> PrivateCompositionReceipt {
    let PrivateCompositionOutcome::Composed { receipt } = host.compose_private(input).unwrap()
    else {
        panic!("native candidate expected");
    };
    *receipt
}

fn inventory(host: &Host, receipt: &PrivateCompositionReceipt) -> CompositionInventory {
    serde_json::from_slice(&read_spool(host, &receipt.inventory, MAX_METADATA_BYTES).unwrap())
        .unwrap()
}

#[test]
fn independent_edits_to_the_same_file_merge_using_native_graph_and_leave_sources_unchanged() {
    let base = b"one\ntwo\nthree\nfour\nfive\nsix\n";
    let mut f = fixture(&[("shared", 0o100_644, base)]);
    let left = f.edit(
        "left",
        "shared",
        base,
        b"LEFT\ntwo\nthree\nfour\nfive\nsix\n",
    );
    let right = f.edit(
        "right",
        "shared",
        base,
        b"one\ntwo\nthree\nfour\nfive\nRIGHT\n",
    );
    let input = f.input(
        vec![left.clone()],
        std::slice::from_ref(&right),
        "compose-independent",
    );
    let source_before = crate::recording::state(&f.source, "left").unwrap();
    let target_before = crate::recording::state(&f.source, "target").unwrap();
    let git_before = f.git.head().unwrap().target().unwrap();
    let receipt = composed(&f.host, &input);
    assert_eq!(
        std::fs::read(receipt.candidate_path.join("shared")).unwrap(),
        b"LEFT\ntwo\nthree\nfour\nfive\nRIGHT\n"
    );
    assert!(receipt.conflict_manifest.is_none());
    let membership = inventory(&f.host, &receipt);
    assert_eq!(membership.selected_changes, vec![left.clone()]);
    assert!(membership.full_closed_changes.contains(&left));
    assert!(membership.full_closed_changes.contains(&right));
    assert!(membership.target_context_changes.contains(&right));
    assert_eq!(
        membership.inherited_baseline_changes,
        f.host
            .portable_baseline_seed(&f.closure)
            .unwrap()
            .view
            .changes
            .iter()
            .copied()
            .map(|hash| hash.to_base32())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        crate::recording::state(&f.source, "left").unwrap(),
        source_before
    );
    assert_eq!(
        crate::recording::state(&f.source, "target").unwrap(),
        target_before
    );
    assert_eq!(f.git.head().unwrap().target().unwrap(), git_before);
    assert!(!f.source.root().join("shared").exists());
    assert_eq!(composed(&f.host, &input), receipt);
}

#[test]
fn independently_added_same_path_retains_native_conflict_object_and_both_sides() {
    let mut f = fixture(&[("seed", 0o100_644, b"seed\n")]);
    let left = f.add("left", "same", b"left side\n");
    let right = f.add("right", "same", b"right side\n");
    let input = f.input(
        vec![left.clone()],
        std::slice::from_ref(&right),
        "compose-real-conflict",
    );
    let receipt = composed(&f.host, &input);
    let bytes = std::fs::read_to_string(receipt.candidate_path.join("same")).unwrap();
    assert!(
        bytes.contains("left side") && bytes.contains("right side") && bytes.contains(">>>>>>>"),
        "{bytes}"
    );
    let conflict = read_spool(
        &f.host,
        receipt
            .conflict_manifest
            .as_ref()
            .expect("native conflict evidence"),
        MAX_METADATA_BYTES,
    )
    .unwrap();
    let native = atomic_repository::ConflictSetObject::decode(&conflict).unwrap();
    assert_eq!(native.canonical_bytes().unwrap(), conflict);
    let sides = native.side_changes();
    assert!(
        sides.contains(&parse_hash(&left).unwrap()) && sides.contains(&parse_hash(&right).unwrap())
    );
    assert_eq!(
        Some(native.hash().unwrap().to_base32()),
        receipt.native_conflict_hash
    );
    assert!(native.files.iter().any(|file| file.path == b"same"));
    let typed: Vec<intent_atomic_proto::composition::CompositionConflict> = serde_json::from_slice(
        &read_spool(&f.host, &receipt.conflicts, MAX_METADATA_BYTES).unwrap(),
    )
    .unwrap();
    assert!(typed.iter().any(|conflict| {
        conflict.path == "same"
            && conflict.kind == "name"
            && conflict.sides.iter().all(|side| side.mode == 0o644)
            && conflict
                .claimants
                .iter()
                .any(|claimant| claimant.change == left)
    }));
    assert!(
        serde_json::to_vec(&PrivateCompositionOutcome::Composed {
            receipt: Box::new(receipt.clone())
        })
        .unwrap()
        .len()
            < intent_atomic_proto::MAX_FRAME_BYTES
    );
    assert_eq!(composed(&f.host, &input), receipt);
}

#[test]
fn selected_tip_expands_real_dependency_closure_and_missing_bytes_refuse() {
    let mut f = fixture(&[("seed", 0o100_644, b"seed\n")]);
    let dependency = f.add("left", "dependency", b"dependency\n");
    let tip = f.edit("left", "dependency", b"dependency\n", b"selected\n");
    let exact = read_spool(
        &f.host,
        &f.available.last().unwrap().bytes,
        MAX_OBJECT_BYTES,
    )
    .unwrap();
    let (actual_tip, _) = Change::deserialize(&mut std::io::Cursor::new(exact)).unwrap();
    assert!(
        actual_tip
            .dependencies()
            .contains(&parse_hash(&dependency).unwrap()),
        "fixture must contain an actual native causal edge"
    );
    let input = f.input(vec![tip.clone()], &[], "compose-dependencies");
    let receipt = composed(&f.host, &input);
    let membership = inventory(&f.host, &receipt);
    assert_eq!(membership.selected_changes, vec![tip]);
    assert!(membership.dependency_only_changes.contains(&dependency));
    assert!(!membership.selected_changes.contains(&dependency));
    assert_eq!(
        std::fs::read(receipt.candidate_path.join("dependency")).unwrap(),
        b"selected\n"
    );
    let mut missing = input;
    missing.operation_id = "compose-missing-dependency".into();
    missing
        .available_changes
        .retain(|change| change.hash != dependency);
    assert!(matches!(
        f.host.compose_private(&missing),
        Err(HostError::Invalid(
            "composition dependency bytes are unavailable"
        ))
    ));
}

#[test]
fn child_inherited_baseline_is_required_by_native_identity() {
    let f = fixture(&[("base", 0o100_644, b"base\n")]);
    let child = capture(
        &f.host,
        &f.binding,
        &f.git,
        &[
            ("base", 0o100_644, b"base\n"),
            ("sibling", 0o100_644, b"sibling changes\n"),
        ],
        "child-baseline",
    );
    let mut input = f.input(Vec::new(), &[], "compose-inherited-required");
    input.inherited_baseline = child;
    let outcome = f.host.compose_private(&input).unwrap();
    let PrivateCompositionOutcome::InheritedBaselineRequired {
        missing_changes,
        missing_count,
        ..
    } = outcome
    else {
        panic!("must preserve inherited baseline requirement");
    };
    let missing: Vec<String> =
        serde_json::from_slice(&read_spool(&f.host, &missing_changes, MAX_METADATA_BYTES).unwrap())
            .unwrap();
    assert!(!missing.is_empty());
    assert_eq!(missing_count, u64::try_from(missing.len()).unwrap());
}

#[test]
fn raw_materialization_keeps_filters_crlf_modes_symlinks_and_replay_fences() {
    let f = fixture(&[
        (".gitattributes", 0o100_644, b"* eol=crlf filter=tripwire\n"),
        ("nested/.gitattributes", 0o100_644, b"* eol=lf\n"),
        ("nested/code", 0o100_755, b"#!/bin/sh\r\necho exact\r\n"),
        ("binary", 0o100_644, &[0, 255, 1]),
        ("empty", 0o100_644, b""),
        ("link", 0o120_000, b"nested/code"),
    ]);
    let input = f.input(Vec::new(), &[], "compose-raw-fidelity");
    let receipt = composed(&f.host, &input);
    assert_eq!(
        std::fs::read(receipt.candidate_path.join("nested/code")).unwrap(),
        b"#!/bin/sh\r\necho exact\r\n"
    );
    assert_eq!(
        std::fs::metadata(receipt.candidate_path.join("nested/code"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read(receipt.candidate_path.join("binary")).unwrap(),
        [0, 255, 1]
    );
    assert_eq!(
        std::fs::read(receipt.candidate_path.join("empty")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read_link(receipt.candidate_path.join("link")).unwrap(),
        Path::new("nested/code")
    );
    assert_ne!(
        receipt.target_state.effective_state,
        receipt.private_target_state.effective_state
    );
    assert_eq!(
        receipt.target_state.own_merkle,
        receipt.private_target_state.own_merkle
    );
    assert_eq!(composed(&f.host, &input), receipt);
    let mut changed = input.clone();
    changed.selected_changes.push("not-a-native-hash".into());
    assert!(matches!(
        f.host.compose_private(&changed),
        Err(HostError::Invalid("conflicting private composition replay"))
    ));
    std::fs::write(receipt.candidate_path.join("binary"), b"changed").unwrap();
    assert!(f.host.compose_private(&input).is_err());
    assert_eq!(
        crate::recording::state(&f.source, "target").unwrap(),
        input.expected_target
    );
    assert!(f.binding.store_path.join(".atomic").is_dir());
}

#[test]
fn target_capture_is_owner_verified_historical_and_cannot_be_fabricated() {
    let mut f = fixture(&[("base", 0o100_644, b"base\n")]);
    let input = f.input(Vec::new(), &[], "capture-historical");
    let capture = input.captured_target.as_ref().unwrap().clone();
    let original = capture.state.clone();
    let late = f.add("right", "late", b"new target context\n");
    f.source
        .insert_change(
            &parse_hash(&late).unwrap(),
            InsertOptions::default().view("target"),
        )
        .unwrap();
    assert_ne!(
        crate::recording::state(&f.source, "target").unwrap(),
        original
    );
    let preview = composed(&f.host, &input);
    assert_eq!(preview.target_state, original);
    assert!(!preview.candidate_path.join("late").exists());
    assert!(!inventory(&f.host, &preview)
        .full_closed_changes
        .contains(&late));
    let mut forged = input.clone();
    forged.operation_id = "forged-capture".into();
    forged.captured_target.as_mut().unwrap().capture_digest = "0".repeat(64);
    assert!(matches!(
        f.host.compose_private(&forged),
        Err(HostError::Invalid(
            "target capture is not an original host receipt"
        ))
    ));
    let mut stale = CaptureCompositionTargetRequest {
        operation_id: "stale-capture".into(),
        scope: f.closure.scope.clone(),
        binding: f.binding.clone(),
        view: "target".into(),
        expected_state: original,
    };
    assert!(matches!(
        f.host.capture_composition_target(&stale),
        Err(HostError::StaleBinding)
    ));
    stale.operation_id = "current-capture".into();
    stale.expected_state = crate::recording::state(&f.source, "target").unwrap();
    assert_eq!(
        f.host.capture_composition_target(&stale).unwrap(),
        f.host.capture_composition_target(&stale).unwrap()
    );
}

#[test]
fn target_membership_race_during_export_never_issues_a_capture_receipt() {
    let mut f = fixture(&[("base", 0o100_644, b"base\n")]);
    let late = f.add("right", "late", b"late\n");
    let request = CaptureCompositionTargetRequest {
        operation_id: "raced-export".into(),
        scope: f.closure.scope.clone(),
        binding: f.binding.clone(),
        view: "target".into(),
        expected_state: crate::recording::state(&f.source, "target").unwrap(),
    };
    let result = f.host.capture_composition_target_observed(&request, || {
        f.source
            .insert_change(
                &parse_hash(&late).unwrap(),
                InsertOptions::default().view("target"),
            )
            .unwrap();
    });
    assert!(matches!(result, Err(HostError::StaleBinding)));
    assert!(matches!(
        f.host.capture_composition_target(&request),
        Err(HostError::StaleBinding)
    ));
}

#[test]
fn sentinel_change_is_refused_without_indexing_missing_objects() {
    let f = fixture(&[("base", 0o100_644, b"base\n")]);
    let input = f.input(vec![Hash::NONE.to_base32()], &[], "sentinel-selection");
    assert!(matches!(
        f.host.compose_private(&input),
        Err(HostError::Invalid("noncanonical composition change hash"))
    ));
}

#[test]
fn empty_recorded_baseline_composes_without_fabricating_authored_changes() {
    let f = fixture(&[]);
    let input = f.input(Vec::new(), &[], "empty-composition");
    let receipt = composed(&f.host, &input);
    let membership = inventory(&f.host, &receipt);
    assert!(membership.selected_changes.is_empty());
    assert!(membership.dependency_only_changes.is_empty());
    assert!(membership.full_closed_changes.is_empty());
    assert!(std::fs::read_dir(&receipt.candidate_path)
        .unwrap()
        .next()
        .is_none());
    assert!(receipt.conflict_manifest.is_none());
    assert_eq!(composed(&f.host, &input), receipt);
}
