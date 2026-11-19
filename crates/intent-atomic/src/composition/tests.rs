use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn exact_materialization_validation_rejects_extra_paths_mode_changes_and_symlink_ancestors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("candidate");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/file"), b"exact\r\n").unwrap();
    let entry = FileEntry {
        path: "nested/file".into(),
        kind: FileKind::Regular,
        mode: 0o100_644,
        length: 7,
        sha256: digest(b"exact\r\n"),
    };
    let manifest = FileManifest {
        policy_version: BASELINE_POLICY_VERSION,
        materializer_version: MATERIALIZER_VERSION,
        entries: vec![entry],
    };
    verify_files(&root, &manifest).unwrap();
    std::fs::write(root.join("extra"), b"unretained").unwrap();
    assert!(verify_files(&root, &manifest).is_err());
    std::fs::remove_file(root.join("extra")).unwrap();
    std::fs::set_permissions(
        root.join("nested/file"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(verify_files(&root, &manifest).is_err());
    std::fs::set_permissions(
        root.join("nested/file"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::rename(root.join("nested"), directory.path().join("outside")).unwrap();
    std::os::unix::fs::symlink(directory.path().join("outside"), root.join("nested")).unwrap();
    assert!(verify_files(&root, &manifest).is_err());
}

#[test]
fn inventory_hashes_are_bounded_unique_and_canonical() {
    let one = format!("{}A", "C".repeat(51));
    let other = format!("{}Q", "B".repeat(51));
    assert!(keys(&[one.clone(), other]).is_ok());
    assert!(keys(&[one.clone(), one]).is_err());
    assert!(keys(&["A".repeat(51)]).is_err());
    assert!(keys(&["B".repeat(52)]).is_err());
    assert!(keys(&["A".repeat(52)]).is_err());
    assert!(keys(&vec!["A".repeat(52); MAX_OBJECTS + 1]).is_err());
}
