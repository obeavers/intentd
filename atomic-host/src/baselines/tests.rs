use super::*;
use atomic_core::change::{ChangeHeader, InodeAttr, InodeKind};
use atomic_core::output::memory::Memory;
use atomic_core::record::workflow::{record_added_file, DetectedFile, RecordingOptions};
use atomic_repository::InsertOptions;
use intent_atomic_proto::baselines::BaselinePolicy;
use intent_atomic_proto::StoreBinding;

struct Fixture {
    directory: tempfile::TempDir,
    host: Host,
    binding: StoreBinding,
    git: git2::Repository,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::HostConfig {
        stores_dir: directory.path().join("stores"),
        config_dir: directory.path().join("config"),
        spool_dir: directory.path().join("spool"),
    };
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: config.stores_dir.join(&repository_id).join("native"),
        repository_id,
        binding_epoch: 1,
    };
    let host = Host::new(config).unwrap();
    host.reconcile().unwrap();
    host.initialize_store(&binding, "initialize-baseline-fixture")
        .unwrap();
    let git = git2::Repository::init(directory.path().join("source")).unwrap();
    Fixture {
        directory,
        host,
        binding,
        git,
    }
}

fn commit(git: &git2::Repository, files: &[(&str, u32, &[u8])]) -> String {
    let mut index = git2::Index::new().unwrap();
    for (path, mode, bytes) in files {
        let oid = git.blob(bytes).unwrap();
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
                id: oid,
                flags: 0,
                flags_extended: 0,
                path: path.as_bytes().to_vec(),
            })
            .unwrap();
    }
    let tree = git.find_tree(index.write_tree_to(git).unwrap()).unwrap();
    let parent = git.head().ok().and_then(|head| head.peel_to_commit().ok());
    let parents: Vec<_> = parent.iter().collect();
    let signature = git2::Signature::new(
        "Git source",
        "fixture@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    git.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "immutable source",
        &tree,
        &parents,
    )
    .unwrap()
    .to_string()
}

fn request(f: &Fixture, commit: String, operation: &str) -> ImportBaselineRequest {
    ImportBaselineRequest {
        operation_id: operation.into(),
        binding: f.binding.clone(),
        source_path: f.git.workdir().unwrap().to_owned(),
        commit,
        previous: None,
        policy: BaselinePolicy::default(),
    }
}

fn insert_fixture_change(repository: &Repository, view: &str, path: &str) {
    let memory = Memory::new();
    memory.add_file(path, b"sibling only\n");
    let mut file = record_added_file(
        &memory,
        &DetectedFile::added(path),
        &RecordingOptions::new(),
    )
    .unwrap();
    file.set_attr(InodeAttr::Kind(InodeKind::Regular));
    file.set_attr(InodeAttr::Mode(0o644));
    let (change, _) = repository
        .assemble_and_hash(view, ChangeHeader::new("sibling"), &[file])
        .unwrap();
    let mut bytes = Vec::new();
    let hash = change.serialize(&mut bytes).unwrap();
    repository.import_change_bytes(&hash, &bytes).unwrap();
    repository
        .insert_change(&hash, InsertOptions::default().view(view))
        .unwrap();
}

#[test]
fn exact_baseline_preserves_binary_crlf_modes_symlinks_filters_and_ignored_tracked_files() {
    let f = fixture();
    f.git
        .config()
        .unwrap()
        .set_str("filter.tripwire.clean", "false")
        .unwrap();
    f.git
        .config()
        .unwrap()
        .set_str("filter.tripwire.smudge", "false")
        .unwrap();
    f.git
        .config()
        .unwrap()
        .set_bool("filter.tripwire.required", true)
        .unwrap();
    let oid = commit(
        &f.git,
        &[
            (
                ".gitattributes",
                0o100_644,
                b"* text eol=crlf filter=tripwire\n",
            ),
            (".gitignore", 0o100_644, b"ignored.dat\n"),
            ("ignored.dat", 0o100_644, b"tracked despite ignore\n"),
            (
                "nested/executable",
                0o100_755,
                b"#!/bin/sh\r\necho exact\r\n",
            ),
            ("binary", 0o100_644, &[0, 255, 1, 0, 128]),
            ("crlf", 0o100_644, b"line one\r\nline two\r\n"),
            ("empty", 0o100_644, b""),
            ("dangling", 0o120_000, b"missing-target"),
        ],
    );
    let original_head = f.git.head().unwrap().target().unwrap();
    let input = request(&f, oid, "import-fidelity");
    let receipt = f.host.import_baseline(&input).unwrap();
    assert_eq!(receipt.storage, BaselineStorage::FullReimport);
    assert_eq!(receipt.file_count, 8);
    let materialized = f
        .host
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "materialize-fidelity".into(),
            baseline: receipt.baseline.clone(),
        })
        .unwrap();
    assert_eq!(
        std::fs::read(materialized.path.join("crlf")).unwrap(),
        b"line one\r\nline two\r\n"
    );
    assert_eq!(
        std::fs::read(materialized.path.join("binary")).unwrap(),
        vec![0, 255, 1, 0, 128]
    );
    assert_eq!(
        std::fs::read(materialized.path.join("ignored.dat")).unwrap(),
        b"tracked despite ignore\n"
    );
    assert_eq!(
        std::fs::symlink_metadata(materialized.path.join("nested/executable"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read_link(materialized.path.join("dangling")).unwrap(),
        Path::new("missing-target")
    );
    assert_eq!(f.git.head().unwrap().target().unwrap(), original_head);
    assert!(!f.git.workdir().unwrap().join(".atomic").exists());
    assert_eq!(f.host.import_baseline(&input).unwrap(), receipt);
}

#[test]
fn frozen_full_import_ignores_later_source_parent_and_native_sibling_activity() {
    let f = fixture();
    let first = commit(&f.git, &[("source", 0o100_644, b"baseline\n")]);
    let receipt = f
        .host
        .import_baseline(&request(&f, first, "frozen-root"))
        .unwrap();
    commit(&f.git, &[("source", 0o100_644, b"parent advanced\n")]);
    // The immutable root has no live parent edge. Sibling membership in its
    // native store also cannot widen that root's own exact closure.
    f.host.baselines.lock().unwrap().clear();
    let root = f
        .host
        .baseline_root(&receipt.baseline)
        .unwrap()
        .join("native");
    let mut repository = Repository::open(&root).unwrap();
    let parent = repository.current_view().to_owned();
    repository.create_view_from("sibling", &parent).unwrap();
    insert_fixture_change(&repository, "sibling", "sibling-only");
    drop(repository);
    assert_eq!(f.host.read_baseline(&receipt.baseline).unwrap(), receipt);
    let output = f
        .host
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "frozen-output".into(),
            baseline: receipt.baseline.clone(),
        })
        .unwrap();
    assert_eq!(
        std::fs::read(output.path.join("source")).unwrap(),
        b"baseline\n"
    );
    assert!(!output.path.join("sibling-only").exists());
    std::fs::write(output.path.join("source"), b"private consumer changed\n").unwrap();
    assert_eq!(f.host.read_baseline(&receipt.baseline).unwrap(), receipt);
    assert!(f
        .host
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "frozen-output".into(),
            baseline: receipt.baseline
        })
        .is_err());
}

#[test]
fn five_full_reimport_baselines_retain_exact_previous_pins_and_rename_deletions() {
    let f = fixture();
    let mut previous = None;
    let mut receipts = Vec::new();
    for index in 0..5 {
        let path = format!("renamed-{index}");
        let bytes = format!("baseline {index}\r\n");
        let oid = commit(&f.git, &[(&path, 0o100_644, bytes.as_bytes())]);
        let mut input = request(&f, oid, &format!("chain-{index}"));
        input.previous = previous.clone();
        let receipt = f.host.import_baseline(&input).unwrap();
        assert_eq!(receipt.previous, previous);
        let output = f
            .host
            .materialize_baseline(&MaterializeBaselineRequest {
                operation_id: format!("chain-output-{index}"),
                baseline: receipt.baseline.clone(),
            })
            .unwrap();
        assert_eq!(
            std::fs::read(output.path.join(&path)).unwrap(),
            bytes.as_bytes()
        );
        assert_eq!(std::fs::read_dir(&output.path).unwrap().count(), 1);
        previous = Some(receipt.baseline.clone());
        receipts.push(receipt);
    }
    for receipt in receipts {
        assert_eq!(f.host.read_baseline(&receipt.baseline).unwrap(), receipt);
    }
}

#[test]
fn tracked_exclusions_reserved_paths_and_case_collisions_fail_preflight() {
    let f = fixture();
    for (index, files) in [
        vec![(".atomic/source", 0o100_644, b"reserved".as_slice())],
        vec![(".env", 0o100_644, b"secret".as_slice())],
        vec![
            ("Dir/one", 0o100_644, b"one".as_slice()),
            ("dir/two", 0o100_644, b"two".as_slice()),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let oid = commit(&f.git, &files);
        let input = request(&f, oid, &format!("refuse-{index}"));
        assert!(f.host.import_baseline(&input).is_err());
    }
    assert!(!f
        .host
        .config
        .config_dir
        .join("baseline-operations")
        .read_dir()
        .unwrap()
        .any(|entry| entry.unwrap().path().extension() == Some(std::ffi::OsStr::new("json"))));
}

#[test]
fn materialization_replay_refuses_extra_files_and_replaced_spool_root() {
    let f = fixture();
    let oid = commit(&f.git, &[("source", 0o100_644, b"baseline")]);
    let baseline = f
        .host
        .import_baseline(&request(&f, oid, "replay-baseline"))
        .unwrap()
        .baseline;
    let input = MaterializeBaselineRequest {
        operation_id: "replay-materialization".into(),
        baseline,
    };
    let output = f.host.materialize_baseline(&input).unwrap();
    std::fs::write(output.path.join("unexpected"), b"not in baseline").unwrap();
    assert!(f.host.materialize_baseline(&input).is_err());
    let retired = f.directory.path().join("retired-spool");
    std::fs::rename(&f.host.config.spool_dir, &retired).unwrap();
    durable::private_dir(&f.host.config.spool_dir).unwrap();
    assert!(matches!(
        f.host.materialize_baseline(&input),
        Err(HostError::StaleBinding)
    ));
}

#[test]
#[ignore = "nightly native qualification: records and materializes a deterministic 20,000-file corpus"]
fn qualification_twenty_thousand_file_baseline_import_and_materialization() {
    let f = fixture();
    let mut index = git2::Index::new().unwrap();
    let bytes = b"export const value = 1;\n";
    let id = f.git.blob(bytes).unwrap();
    for number in 0..20_000 {
        let path = format!("corpus/file-{number:05}.ts");
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
                path: path.into_bytes(),
            })
            .unwrap();
    }
    let tree = f
        .git
        .find_tree(index.write_tree_to(&f.git).unwrap())
        .unwrap();
    let signature = git2::Signature::new(
        "Qualification fixture",
        "fixture@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    let commit = f
        .git
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "20,000-file reference corpus",
            &tree,
            &[],
        )
        .unwrap()
        .to_string();
    let started = std::time::Instant::now();
    let receipt = f
        .host
        .import_baseline(&request(&f, commit, "qualification-20k"))
        .unwrap();
    let import_elapsed = started.elapsed();
    assert_eq!(receipt.file_count, 20_000);
    eprintln!(
        "native 20k qualification: baseline import complete in {import_elapsed:?}; beginning private materialization"
    );
    let materialize_started = std::time::Instant::now();
    let materialized = f
        .host
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "qualification-20k-output".into(),
            baseline: receipt.baseline,
        })
        .unwrap();
    assert_eq!(materialized.file_count, 20_000);
    assert_eq!(
        std::fs::read_dir(materialized.path.join("corpus"))
            .unwrap()
            .count(),
        20_000
    );
    eprintln!(
        "native 20k qualification: import={import_elapsed:?}, materialize={:?}, files={}, bytes={}",
        materialize_started.elapsed(),
        materialized.file_count,
        materialized.total_bytes
    );
}
