use super::*;
use intent_atomic_proto::baselines::{
    BaselinePolicy, ImportBaselineRequest, MaterializeBaselineRequest,
};
use intent_atomic_proto::StoreBinding;
use std::os::unix::fs::PermissionsExt;

fn fresh_host(root: &std::path::Path) -> Host {
    durable::private_dir(root).unwrap();
    let host = Host::new(crate::HostConfig {
        stores_dir: root.join("stores"),
        config_dir: root.join("config"),
        spool_dir: root.join("spool"),
    })
    .unwrap();
    host.reconcile().unwrap();
    host
}

fn captured() -> (tempfile::TempDir, Host, BaselineClosure) {
    let directory = tempfile::tempdir().unwrap();
    let host = fresh_host(&directory.path().join("host"));
    let repository_id = uuid::Uuid::new_v4().to_string();
    let binding = StoreBinding {
        store_path: host.config.stores_dir.join(&repository_id).join("native"),
        repository_id: repository_id.clone(),
        binding_epoch: 1,
    };
    host.initialize_store(&binding, "portable-seed").unwrap();
    let git = git2::Repository::init(directory.path().join("git")).unwrap();
    let mut index = git2::Index::new().unwrap();
    for (path, mode, bytes) in [
        (
            ".gitattributes",
            0o100_644,
            b"* eol=crlf filter=unknown\n".as_slice(),
        ),
        ("nested/executable", 0o100_755, b"script\r\n".as_slice()),
        ("binary", 0o100_644, [0, 255, 1].as_slice()),
        ("empty", 0o100_644, b"".as_slice()),
        ("link", 0o120_000, b"nested/executable".as_slice()),
    ] {
        let id = git.blob(bytes).unwrap();
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode,
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
    let tree = git.find_tree(index.write_tree_to(&git).unwrap()).unwrap();
    let signature = git2::Signature::now("Portable fixture", "fixture@example.invalid").unwrap();
    let commit = git
        .commit(Some("HEAD"), &signature, &signature, "source", &tree, &[])
        .unwrap()
        .to_string();
    drop(tree);
    let baseline = host
        .import_baseline(&ImportBaselineRequest {
            operation_id: "portable-baseline".into(),
            binding,
            source_path: git.workdir().unwrap().to_owned(),
            commit,
            previous: None,
            policy: BaselinePolicy::default(),
        })
        .unwrap();
    let closure = host
        .export_baseline_closure(&ExportBaselineClosureRequest {
            operation_id: "portable-export".into(),
            scope: ClosureScope {
                workspace_id: "workspace-from-store".into(),
                root_id: "primary".into(),
                repository_id,
                binding_epoch: 1,
            },
            capture_revision: 7,
            baseline: baseline.baseline,
        })
        .unwrap();
    (directory, host, closure)
}

fn copy_payload(source: &Host, target: &Host, closure: &BaselineClosure) {
    let bytes = read_payload(source, &closure.payload).unwrap();
    let path = target.config.spool_dir.join(&closure.payload.name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn portable_closure_restores_after_git_and_all_old_native_stores_are_deleted() {
    let (directory, source, closure) = captured();
    assert_eq!(closure.format, 2);
    assert_eq!(closure.object_count, 1);
    let target_directory = tempfile::tempdir().unwrap();
    let target = fresh_host(&target_directory.path().join("host"));
    copy_payload(&source, &target, &closure);
    let old_stores = source.config.stores_dir.clone();
    drop(source);
    std::fs::remove_dir_all(directory.path().join("git")).unwrap();
    std::fs::remove_dir_all(&old_stores).unwrap();
    assert!(!old_stores.exists());
    let request = RestoreBaselineClosureRequest {
        operation_id: "restore-independent".into(),
        expected_scope: closure.scope.clone(),
        closure: closure.clone(),
    };
    let receipt = target.restore_baseline_closure(&request).unwrap();
    assert_eq!(receipt, closure.baseline);
    assert_eq!(target.restore_baseline_closure(&request).unwrap(), receipt);
    let materialized = target
        .materialize_baseline(&MaterializeBaselineRequest {
            operation_id: "restored-files".into(),
            baseline: receipt.baseline.clone(),
        })
        .unwrap();
    assert_eq!(
        materialized.materialization_id,
        closure.baseline.materialization_id
    );
    assert_eq!(
        std::fs::read(materialized.path.join("binary")).unwrap(),
        vec![0, 255, 1]
    );
    assert_eq!(
        std::fs::read(materialized.path.join("nested/executable")).unwrap(),
        b"script\r\n"
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
        std::fs::read(materialized.path.join("empty")).unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        std::fs::read_link(materialized.path.join("link")).unwrap(),
        std::path::Path::new("nested/executable")
    );
    assert_eq!(
        target
            .read_baseline(&receipt.baseline)
            .unwrap()
            .native_state,
        closure.baseline.native_state
    );
}

#[test]
fn corrupted_object_and_stale_epoch_refuse_before_any_native_destination() {
    let (_directory, source, mut closure) = captured();
    let target_directory = tempfile::tempdir().unwrap();
    let target = fresh_host(&target_directory.path().join("host"));
    copy_payload(&source, &target, &closure);
    let mut stale = closure.scope.clone();
    stale.binding_epoch += 1;
    assert!(matches!(
        target.restore_baseline_closure(&RestoreBaselineClosureRequest {
            operation_id: "stale-restore".into(),
            expected_scope: stale,
            closure: closure.clone()
        }),
        Err(HostError::StaleBinding)
    ));
    let mut bytes = read_payload(&target, &closure.payload).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    closure.payload.sha256 = digest(&bytes);
    closure.payload.name = "closure-corrupt.bin".into();
    let path = target.config.spool_dir.join(&closure.payload.name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(target
        .restore_baseline_closure(&RestoreBaselineClosureRequest {
            operation_id: "corrupt-restore".into(),
            expected_scope: closure.scope.clone(),
            closure: closure.clone()
        })
        .is_err());
    assert!(!target
        .config
        .stores_dir
        .join(&closure.scope.repository_id)
        .exists());
}

#[test]
fn repeated_export_reuses_exact_artifact_and_changed_command_refuses() {
    let (_directory, host, closure) = captured();
    let mut request = ExportBaselineClosureRequest {
        operation_id: "portable-export".into(),
        scope: closure.scope.clone(),
        capture_revision: 7,
        baseline: closure.baseline.baseline.clone(),
    };
    assert_eq!(host.export_baseline_closure(&request).unwrap(), closure);
    request.capture_revision = 8;
    assert!(host.export_baseline_closure(&request).is_err());
    let bytes = read_payload(&host, &closure.payload).unwrap();
    let (mut header, _, objects) = decode(&bytes, &closure).unwrap();
    header.objects.clear();
    let malformed = encode(&header, &objects).unwrap();
    assert!(
        decode(&malformed, &closure).is_err(),
        "missing object membership cannot become an empty successful restore"
    );
}
