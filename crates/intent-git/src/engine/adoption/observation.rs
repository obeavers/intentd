//! A live working-tree observer that never delegates source pathname reads to
//! libgit2. Only descriptor-relative no-follow reads produce blob payloads.
//! Ignore evaluation sees a private code-free mirror of frozen rule files.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use git2::{Index, IndexEntry, IndexTime, Oid, Repository};

use super::{
    content_digest, fs, git_ids, invalid, io, json_bytes, read, state, storage, tree_files, vcs,
    write, Policy, MAX_FILES,
};

const MAX_CAPTURE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    head: Option<Oid>,
    index_bytes: Option<Vec<u8>>,
    index_tree: Oid,
    files: BTreeMap<String, fs::Payload>,
    untracked: Vec<String>,
    ignores: BTreeMap<String, vcs::ContentDigest>,
}
pub(super) struct Observation {
    pub head: Option<String>,
    pub index_bytes: Option<Vec<u8>>,
    pub index_tree: String,
    pub working_tree: String,
    pub untracked: Vec<String>,
    pub ignore_digest: vcs::ContentDigest,
}

struct Mirror {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
}
impl Mirror {
    fn new(source: &Repository, policy: &Policy) -> vcs::VcsResult<Self> {
        let directory = tempfile::Builder::new()
            .prefix("intent-ignore-policy-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|error| io(&error))?;
        let root = directory.path().join("rules");
        let repo = storage::initialize(&root)?;
        let config_path = repo.path().join("config");
        let mut config = git2::Config::open(&config_path).map_err(crate::map_git_err)?;
        config
            .set_bool(
                "core.ignorecase",
                source
                    .config()
                    .map_err(crate::map_git_err)?
                    .get_bool("core.ignorecase")
                    .unwrap_or(false),
            )
            .map_err(crate::map_git_err)?;
        let local = source.commondir().join("info/exclude");
        let local_bytes = if policy.local_excludes.is_some() {
            let bytes = read(&local)?;
            if Some(content_digest(&bytes)) != policy.local_excludes {
                return Err(invalid("local ignore policy changed during safe capture"));
            }
            bytes
        } else {
            Vec::new()
        };
        std::fs::create_dir_all(repo.path().join("info")).map_err(|error| io(&error))?;
        std::fs::write(repo.path().join("info/exclude"), local_bytes)
            .map_err(|error| io(&error))?;
        let global = match policy
            .config
            .get("core.excludesfile")
            .and_then(Option::as_deref)
        {
            Some(path) if !path.is_empty() => {
                let bytes = match Path::new(path).symlink_metadata() {
                    Ok(_) => read(Path::new(path))?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Err(error) => return Err(io(&error)),
                };
                if policy.global_excludes.is_some()
                    && Some(content_digest(&bytes)) != policy.global_excludes
                {
                    return Err(invalid("global ignore policy changed during safe capture"));
                }
                bytes
            }
            _ => Vec::new(),
        };
        let global_path = repo.path().join("frozen-global-ignore");
        std::fs::write(&global_path, global).map_err(|error| io(&error))?;
        config
            .set_str(
                "core.excludesfile",
                global_path
                    .to_str()
                    .ok_or_else(|| invalid("private ignore path requires UTF-8"))?,
            )
            .map_err(crate::map_git_err)?;
        drop(config);
        drop(repo);
        Ok(Self {
            _directory: directory,
            root,
            config: config_path,
        })
    }
    fn matcher(&self) -> vcs::VcsResult<Repository> {
        let repo = Repository::open(&self.root).map_err(crate::map_git_err)?;
        // An on-disk-only private config prevents implicit global includes or
        // global ignore lookup from escaping this code-free mirror.
        repo.set_config(&git2::Config::open(&self.config).map_err(crate::map_git_err)?)
            .map_err(crate::map_git_err)?;
        Ok(repo)
    }
}

fn snapshot(
    repo: &Repository,
    root: &vcs::RootBinding,
    policy: &Policy,
    before_directory_open: &mut impl FnMut(&str),
) -> vcs::VcsResult<Snapshot> {
    let head = match repo.head() {
        Ok(head) => Some(head.peel_to_commit().map_err(crate::map_git_err)?.id()),
        Err(error) if error.code() == git2::ErrorCode::UnbornBranch => None,
        Err(error) => return Err(crate::map_git_err(error).into()),
    };
    let native = state(root, repo, head)?;
    let (_, head_tree) = git_ids(&native)?;
    let mut tracked: BTreeSet<String> = tree_files(repo, head_tree)?.into_keys().collect();
    let index = repo.index().map_err(crate::map_git_err)?;
    let index_path = index.path().ok_or_else(|| invalid("index has no path"))?;
    let index_bytes = match index_path.symlink_metadata() {
        Ok(_) => Some(read(index_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io(&error)),
    };
    drop(index);
    let mirror = Mirror::new(repo, policy)?;
    let frozen_index = mirror.root.join(".git/frozen-index");
    if let Some(bytes) = &index_bytes {
        write(&frozen_index, bytes)?;
    }
    let mut index = Index::open(&frozen_index).map_err(crate::map_git_err)?;
    if index.has_conflicts() {
        return Err(invalid("unresolved index conflicts block safe capture"));
    }
    for entry in index.iter() {
        if entry.flags_extended & (0x2000 | 0x4000) != 0 {
            return Err(invalid("intent-to-add/sparse index is unqualified"));
        }
        let path =
            std::str::from_utf8(&entry.path).map_err(|_| invalid("index paths require UTF-8"))?;
        if !crate::checkpoint::safe_relative_path(path)
            || crate::checkpoint::excluded(
                Path::new(path),
                &crate::checkpoint::CaptureOptions::default(),
            )
        {
            return Err(invalid("unsafe or runtime-owned path is tracked"));
        }
        tracked.insert(path.to_string());
    }
    let index_tree = index.write_tree_to(repo).map_err(crate::map_git_err)?;
    let _ = tree_files(repo, index_tree)?;
    let opened = fs::directory(&root.locator)?;
    let mut pending = vec![(String::new(), opened)];
    let mut files = BTreeMap::new();
    let mut untracked = Vec::new();
    let mut ignores = BTreeMap::new();
    let mut bytes_read = 0_usize;
    let mut entries_seen = 0_usize;
    while let Some((prefix, directory)) = pending.pop() {
        if !prefix.is_empty() {
            std::fs::create_dir_all(mirror.root.join(&prefix)).map_err(|error| io(&error))?;
        }
        // Git never follows a symlink .gitignore. Rule bytes are read from the
        // already pinned directory descriptor, never by source pathname.
        if let Some(rule) = fs::payload_at(&directory, &fs::name(".gitignore")?)? {
            if rule.mode != 0o120_000 {
                bytes_read = bytes_read.saturating_add(rule.bytes.len());
                if bytes_read > MAX_CAPTURE_BYTES {
                    return Err(invalid("safe capture exceeds its aggregate byte budget"));
                }
                std::fs::write(mirror.root.join(&prefix).join(".gitignore"), &rule.bytes)
                    .map_err(|error| io(&error))?;
                ignores.insert(format!("{prefix}/.gitignore"), content_digest(&rule.bytes));
            }
        }
        let matcher = mirror.matcher()?;
        for entry in fs::entries(&directory)? {
            if prefix.is_empty() && entry.name == ".git" {
                continue;
            }
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            if crate::checkpoint::excluded(
                Path::new(&path),
                &crate::checkpoint::CaptureOptions::default(),
            ) {
                continue;
            }
            if !crate::checkpoint::safe_relative_path(&path) {
                return Err(invalid("unsafe working path blocks safe capture"));
            }
            entries_seen += 1;
            if entries_seen > MAX_FILES {
                return Err(invalid("safe capture exceeds its entry budget"));
            }
            let descendant = tracked
                .iter()
                .any(|tracked| tracked.starts_with(&format!("{path}/")));
            let exact = tracked.contains(&path);
            if entry.kind == fs::Kind::Directory {
                if exact {
                    return Err(invalid("tracked file was replaced by a directory"));
                }
                if descendant
                    || !matcher
                        .status_should_ignore(Path::new(&format!("{path}/")))
                        .map_err(crate::map_git_err)?
                {
                    before_directory_open(&path);
                    pending.push((path, fs::child(&directory, &entry.name, false)?));
                }
            } else {
                if descendant {
                    return Err(invalid("tracked parent was replaced by a symlink or file"));
                }
                if !exact
                    && matcher
                        .status_should_ignore(Path::new(&path))
                        .map_err(crate::map_git_err)?
                {
                    continue;
                }
                let payload = fs::payload_at(&directory, &fs::name(&entry.name)?)?
                    .ok_or_else(|| invalid("working file disappeared during safe capture"))?;
                bytes_read = bytes_read.saturating_add(payload.bytes.len());
                if bytes_read > MAX_CAPTURE_BYTES {
                    return Err(invalid("safe capture exceeds its aggregate byte budget"));
                }
                if !exact {
                    untracked.push(path.clone());
                }
                files.insert(path, payload);
            }
        }
    }
    untracked.sort();
    Ok(Snapshot {
        head,
        index_bytes,
        index_tree,
        files,
        untracked,
        ignores,
    })
}

pub(super) fn read_target(
    repo: &Repository,
    root: &vcs::RootBinding,
    policy: &Policy,
) -> vcs::VcsResult<Observation> {
    read_target_checked(repo, root, policy, |_| {})
}

pub(super) fn read_target_checked(
    repo: &Repository,
    root: &vcs::RootBinding,
    policy: &Policy,
    mut before_directory_open: impl FnMut(&str),
) -> vcs::VcsResult<Observation> {
    let first = snapshot(repo, root, policy, &mut before_directory_open)?;
    let second = snapshot(repo, root, policy, &mut before_directory_open)?;
    if first != second {
        return Err(super::stale(
            "target changed during descriptor-safe capture",
        ));
    }
    drop(second);
    // Blob writes happen only after the complete bounded safe snapshots agree.
    // No CE_VALID/assume-unchanged flag can suppress a raw descriptor read.
    let mut working = Index::new().map_err(crate::map_git_err)?;
    for (path, payload) in first.files {
        let object = repo.blob(&payload.bytes).map_err(crate::map_git_err)?;
        working
            .add(&IndexEntry {
                ctime: IndexTime::new(0, 0),
                mtime: IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: payload.mode,
                uid: 0,
                gid: 0,
                file_size: u32::try_from(payload.bytes.len())
                    .map_err(|_| invalid("file size overflow"))?,
                id: object,
                flags: 0,
                flags_extended: 0,
                path: path.into_bytes(),
            })
            .map_err(crate::map_git_err)?;
    }
    let working_tree = working.write_tree_to(repo).map_err(crate::map_git_err)?;
    Ok(Observation {
        head: first.head.map(|id| id.to_string()),
        index_bytes: first.index_bytes,
        index_tree: first.index_tree.to_string(),
        working_tree: working_tree.to_string(),
        untracked: first.untracked,
        ignore_digest: content_digest(&json_bytes(&first.ignores)?),
    })
}
