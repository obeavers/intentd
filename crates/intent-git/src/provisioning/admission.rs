//! Mechanics for already admitted source/checkout observations. These helpers
//! carry no service authority, token registry, lock or response-disclosure rule.

use std::path::Path;

use intent_core::vcs::{GitCommitId, GitCommitRelation};
use intent_core::{Error, Result};
use sha2::{Digest, Sha256};

pub(super) fn index_fingerprint(path: &Path) -> Result<[u8; 32]> {
    let repo = git2::Repository::open(path).map_err(crate::map_git_err)?;
    let mut index = repo.index().map_err(crate::map_git_err)?;
    index.read(true).map_err(crate::map_git_err)?;
    let mut hash = Sha256::new();
    for entry in index.iter() {
        hash.update(entry.mode.to_le_bytes());
        hash.update(entry.flags.to_le_bytes());
        hash.update(entry.flags_extended.to_le_bytes());
        hash.update(entry.id.as_bytes());
        hash.update(entry.path.len().to_le_bytes());
        hash.update(&entry.path);
    }
    Ok(hash.finalize().into())
}

pub(super) fn commit_relation(
    path: &Path,
    left: &GitCommitId,
    right: &GitCommitId,
) -> Result<GitCommitRelation> {
    let a = git2::Oid::from_str(left.as_str()).map_err(crate::map_git_err)?;
    let b = git2::Oid::from_str(right.as_str()).map_err(crate::map_git_err)?;
    if a == b {
        return Ok(GitCommitRelation::Equal);
    }
    let Ok(repo) = git2::Repository::open(path) else {
        return Ok(GitCommitRelation::Unavailable);
    };
    if repo.find_commit(a).is_err() || repo.find_commit(b).is_err() {
        return Ok(GitCommitRelation::Unavailable);
    }
    Ok(
        match (
            repo.graph_descendant_of(a, b),
            repo.graph_descendant_of(b, a),
        ) {
            (Ok(true), Ok(false)) => GitCommitRelation::LeftDescendsRight,
            (Ok(false), Ok(true)) => GitCommitRelation::RightDescendsLeft,
            (Ok(false), Ok(false)) => GitCommitRelation::Diverged,
            _ => GitCommitRelation::Unavailable,
        },
    )
}

pub(super) fn attach_native_checkout(
    path: &Path,
    branch: &str,
    expected: &GitCommitId,
    original_source: &str,
) -> Result<()> {
    let unavailable = || Error::Internal("Qualified native HTTPS checkout unavailable".into());
    let repo = git2::Repository::open(path).map_err(crate::map_git_err)?;
    let oid = git2::Oid::from_str(expected.as_str()).map_err(crate::map_git_err)?;
    if repo.head().map_err(crate::map_git_err)?.target() != Some(oid) {
        return Err(unavailable());
    }
    let commit = repo.find_commit(oid).map_err(crate::map_git_err)?;
    if let Ok(existing) = repo.find_branch(branch, git2::BranchType::Local) {
        if existing.get().target() != Some(oid) {
            return Err(unavailable());
        }
    } else {
        repo.branch(branch, &commit, false)
            .map_err(crate::map_git_err)?;
    }
    repo.set_head(&format!("refs/heads/{branch}"))
        .map_err(crate::map_git_err)?;
    repo.config()
        .map_err(crate::map_git_err)?
        .set_str("intent.nativeCheckoutSource", original_source)
        .map_err(crate::map_git_err)?;
    if repo.head().map_err(crate::map_git_err)?.target() != Some(oid) {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::GitWorkspaceProvisioner;
    use crate::testutil::{commit_file, init_repo};
    use intent_core::vcs::WorkspaceProvisioner;

    #[test]
    fn index_fingerprint_preserves_legacy_entry_encoding_and_executable_mode() {
        use std::fmt::Write as _;

        let source = init_repo("source-fingerprint");
        let repo = git2::Repository::open(source.path()).unwrap();
        let blob = repo.blob(b"same\n").unwrap();
        assert_eq!(blob.to_string(), "1275430f1765c63e539cb0452565563bd6aef6a6");
        let mut index = repo.index().unwrap();
        index.clear().unwrap();
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o100_644,
                uid: 0,
                gid: 0,
                file_size: 5,
                id: blob,
                flags: 7,
                flags_extended: 0,
                path: b"fixture".to_vec(),
            })
            .unwrap();
        index.write().unwrap();
        let actual = index_fingerprint(source.path()).unwrap();
        let mut hex = String::with_capacity(actual.len() * 2);
        for byte in &actual {
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            hex,
            "dfd3858b6a69f3b2afd4d1b0141f148e76ad5b910142f2462fd40dbed6f4e2ef"
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            hex,
            "f27cd4089162c5088fd9a87904a5910874689cad0c68a5c0a55064e2b58b47cf"
        );
        let mut executable = index.get_path(Path::new("fixture"), 0).unwrap();
        executable.mode = 0o100_755;
        index.add(&executable).unwrap();
        index.write().unwrap();
        assert_ne!(actual, index_fingerprint(source.path()).unwrap());
    }

    #[test]
    fn source_commit_observes_real_primitive_and_preserves_staged_index_semantics() {
        let source = init_repo("source-observed-commit");
        commit_file(source.path(), "base", "base\n");
        std::fs::write(source.path().join("pre-staged"), "other actor\n").unwrap();
        crate::stage::stage(source.path(), &["pre-staged".into()]).unwrap();
        std::fs::write(source.path().join("selected"), "selected\n").unwrap();
        let mut observed = None;
        let outcome = GitWorkspaceProvisioner
            .git_stage_commit_observed(
                source.path(),
                &["selected".into()],
                "native review",
                &mut |commit| observed = Some(commit.clone()),
            )
            .unwrap();
        assert_eq!(observed, Some(outcome.commit.clone()));
        assert_eq!(
            GitWorkspaceProvisioner
                .source_ref(source.path(), "HEAD")
                .unwrap()
                .as_str(),
            outcome.commit.as_str()
        );
        let files: std::collections::BTreeSet<_> = outcome.files.into_iter().collect();
        assert_eq!(
            files,
            std::collections::BTreeSet::from(["pre-staged".to_owned(), "selected".to_owned()])
        );
        let before = observed;
        assert!(GitWorkspaceProvisioner
            .git_stage_commit_observed(source.path(), &[], "nothing new", &mut |_| panic!(
                "clean commit must not emit a primitive receipt"
            ))
            .is_err());
        assert_eq!(before, Some(outcome.commit));
    }

    #[test]
    fn native_attachment_refuses_existing_branch_rewind_and_sets_only_exact_marker() {
        let source = init_repo("source-native-attach");
        commit_file(source.path(), "base", "base\n");
        let repo = git2::Repository::open(source.path()).unwrap();
        let base = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("selected", &base, false).unwrap();
        let original = base.id();
        drop(base);
        commit_file(source.path(), "base", "advanced\n");
        let expected = GitCommitId::from_string(repo.head().unwrap().target().unwrap().to_string());
        let provider = GitWorkspaceProvisioner;
        let url = "https://gitlab.example.test/team/project.git";
        assert!(provider
            .git_attach_native_checkout(source.path(), "selected", &expected, url)
            .is_err());
        assert_eq!(
            repo.find_branch("selected", git2::BranchType::Local)
                .unwrap()
                .get()
                .target(),
            Some(original)
        );
        assert!(provider
            .git_native_source(source.path())
            .unwrap()
            .native_source
            .is_none());
        provider
            .git_attach_native_checkout(source.path(), "created", &expected, url)
            .unwrap();
        assert_eq!(
            provider
                .git_native_source(source.path())
                .unwrap()
                .native_source
                .as_deref(),
            Some(url)
        );
        assert_eq!(repo.head().unwrap().name().unwrap(), "refs/heads/created");
    }
}
