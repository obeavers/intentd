//! Disposable Git fixture bootstrap for developer scenarios.
//!
//! The caller owns a freshly allocated directory and writes the fixture before
//! calling this seam. This does not register a workspace or authorize an agent.

use std::path::{Path, PathBuf};

use git2::{Repository, RepositoryInitOptions, Signature};
use intent_core::{Error, Result};

const MAX_FIXTURE_FILES: usize = 64;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;

fn invalid(reason: &str) -> Error {
    Error::InvalidParams(format!("disposable Git fixture: {reason}"))
}

fn filesystem(error: impl std::fmt::Display) -> Error {
    Error::Internal(format!("disposable Git fixture filesystem: {error}"))
}

fn files_in(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    bytes: &mut u64,
) -> Result<()> {
    for entry in std::fs::read_dir(directory).map_err(filesystem)? {
        let entry = entry.map_err(filesystem)?;
        let path = entry.path();
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
        {
            return Err(invalid(
                "an existing repository or Git metadata is not allowed",
            ));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(filesystem)?;
        if metadata.is_dir() {
            files_in(root, &path, files, bytes)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(invalid("hard-linked fixture files are not allowed"));
                }
            }
            *bytes = bytes.saturating_add(metadata.len());
            if files.len() >= MAX_FIXTURE_FILES || *bytes > MAX_FIXTURE_BYTES {
                return Err(invalid("fixture exceeds its file or byte budget"));
            }
            files.push(
                path.strip_prefix(root)
                    .map_err(|_| invalid("path escaped fixture root"))?
                    .to_path_buf(),
            );
        } else {
            return Err(invalid(
                "only directories and regular fixture files are allowed",
            ));
        }
    }
    Ok(())
}

/// Initialize and commit an explicitly disposable, caller-owned fixture.
///
/// Existing Git metadata, symbolic links, hard links and special files refuse
/// before repository initialization. Only the validated fixture paths enter the
/// initial commit. The returned commit and tree name that immutable baseline.
/// The caller must retain ownership of the directory during bootstrap.
///
/// # Errors
/// Returns an invalid-input error for an unsuitable fixture, or the underlying
/// filesystem/Git error. On a Git failure after initialization, the caller keeps
/// the disposable directory for diagnosis rather than retrying over it.
pub fn initialize_disposable_repository(
    path: &Path,
    author_name: &str,
    author_email: &str,
    message: &str,
) -> Result<(String, String)> {
    if !std::fs::symlink_metadata(path)
        .map_err(filesystem)?
        .is_dir()
    {
        return Err(invalid("root must be a real directory"));
    }
    let mut files = Vec::new();
    let mut bytes = 0;
    files_in(path, path, &mut files, &mut bytes)?;
    if files.is_empty() {
        return Err(invalid("fixture contains no files"));
    }
    files.sort();
    let signature = Signature::now(author_name, author_email).map_err(crate::map_git_err)?;
    let mut options = RepositoryInitOptions::new();
    options.no_reinit(true).initial_head("main");
    let repository = Repository::init_opts(path, &options).map_err(crate::map_git_err)?;
    let mut config = repository.config().map_err(crate::map_git_err)?;
    config
        .set_str("user.name", author_name)
        .map_err(crate::map_git_err)?;
    config
        .set_str("user.email", author_email)
        .map_err(crate::map_git_err)?;
    let mut index = repository.index().map_err(crate::map_git_err)?;
    for file in files {
        index.add_path(&file).map_err(crate::map_git_err)?;
    }
    index.write().map_err(crate::map_git_err)?;
    let tree_id = index.write_tree().map_err(crate::map_git_err)?;
    let tree = repository.find_tree(tree_id).map_err(crate::map_git_err)?;
    let commit = repository
        .commit(Some("HEAD"), &signature, &signature, message, &tree, &[])
        .map_err(crate::map_git_err)?;
    Ok((commit.to_string(), tree_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::create_dir(root.path().join("test")).unwrap();
        std::fs::write(
            root.path().join("src/fees.js"),
            "export const feeCents = Math.floor;\n",
        )
        .unwrap();
        std::fs::write(root.path().join("test/fees.test.mjs"), "// fixed test\n").unwrap();
        std::fs::write(root.path().join("package.json"), "{\"type\":\"module\"}\n").unwrap();
        root
    }

    #[test]
    fn baseline_names_the_actual_three_file_commit_and_refuses_reinitialization() {
        let root = fixture();
        let (commit, tree) = initialize_disposable_repository(
            root.path(),
            "Intent tracer",
            "tracer@example.invalid",
            "Fixture baseline",
        )
        .unwrap();
        let repository = Repository::open(root.path()).unwrap();
        let actual = repository.head().unwrap().peel_to_commit().unwrap();
        assert_eq!(actual.id().to_string(), commit);
        assert_eq!(actual.tree_id().to_string(), tree);
        assert_eq!(actual.parent_count(), 0);
        assert_eq!(repository.head().unwrap().shorthand().unwrap(), "main");
        assert_eq!(repository.index().unwrap().len(), 3);
        assert!(initialize_disposable_repository(
            root.path(),
            "Intent tracer",
            "tracer@example.invalid",
            "Retry"
        )
        .is_err());
        assert_eq!(repository.head().unwrap().target(), Some(actual.id()));
    }

    #[cfg(unix)]
    #[test]
    fn external_links_refuse_before_creating_git_metadata() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), root.path().join("linked")).unwrap();
        assert!(initialize_disposable_repository(
            root.path(),
            "Intent tracer",
            "tracer@example.invalid",
            "Baseline"
        )
        .is_err());
        assert!(!root.path().join(".git").exists());
        std::fs::remove_file(root.path().join("linked")).unwrap();
        std::fs::hard_link(outside.path(), root.path().join("linked")).unwrap();
        assert!(initialize_disposable_repository(
            root.path(),
            "Intent tracer",
            "tracer@example.invalid",
            "Baseline"
        )
        .is_err());
        assert!(!root.path().join(".git").exists());
    }
}
