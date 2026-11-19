//! Descriptor-relative traversal: no working symlink is followed while hashing.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::baselines::{SnapshotEntry, SnapshotKind};
use crate::{HostError, Result};

const MAX_ENTRIES: usize = 250_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Kind {
    Directory,
    File,
    Symlink,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Entry {
    pub path: String,
    pub kind: Kind,
    pub mode: u32,
    pub length: u64,
    pub sha256: String,
}

fn invalid(message: &'static str) -> HostError {
    HostError::Invalid(message)
}
#[cfg(target_os = "macos")]
fn mode(value: nix::libc::mode_t) -> u32 {
    u32::from(value)
}
#[cfg(not(target_os = "macos"))]
fn mode(value: nix::libc::mode_t) -> u32 {
    value
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn digest(entries: &[Entry]) -> Result<String> {
    let mut bytes = b"intent-working-manifest-v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(entries)?);
    Ok(hash(&bytes))
}
pub(super) fn excluded(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').map(str::to_ascii_lowercase).collect();
    parts.iter().any(|part| {
        matches!(
            part.as_str(),
            ".git"
                | ".atomic"
                | ".atomic-sandbox"
                | ".atomic-sandbox.d"
                | ".intent"
                | ".vault"
                | ".ssh"
                | ".aws"
                | "tool-outputs"
                | ".npmrc"
                | ".pypirc"
                | "credentials.json"
                | "id_rsa"
                | "id_ed25519"
        ) || part == ".env"
            || part.starts_with(".env.")
    }) || parts.windows(2).any(|pair| {
        matches!(
            (pair[0].as_str(), pair[1].as_str()),
            (".codex", "auth.json")
                | (".claude", ".credentials.json")
                | (".gemini", "oauth_creds.json")
        )
    }) || Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "pem" | "key" | "p12"))
}
pub(super) fn open_root(root: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(root)?)
}
pub(super) fn open_beneath(root: &File, path: &str, directory: bool) -> Result<File> {
    if !crate::baselines::source::safe_path(path) {
        return Err(invalid("capture path is invalid"));
    }
    let mut current = root.try_clone()?;
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let name = CString::new(*part).map_err(|_| invalid("capture name contains NUL"))?;
        let directory = directory || index + 1 < parts.len();
        let flags = nix::libc::O_RDONLY
            | nix::libc::O_NOFOLLOW
            | nix::libc::O_CLOEXEC
            | nix::libc::O_NONBLOCK
            | if directory { nix::libc::O_DIRECTORY } else { 0 };
        // SAFETY: current owns an open directory and name is NUL-terminated.
        let raw = unsafe { nix::libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a newly owned descriptor.
        current = unsafe { File::from_raw_fd(raw) };
    }
    Ok(current)
}
struct Directory(*mut nix::libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the successful fdopendir result.
        unsafe { nix::libc::closedir(self.0) };
    }
}
fn names(directory: &File) -> Result<Vec<String>> {
    let raw = directory.try_clone()?.into_raw_fd();
    // SAFETY: fdopendir takes ownership of this duplicated directory descriptor.
    let stream = unsafe { nix::libc::fdopendir(raw) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and therefore did not consume the descriptor.
        drop(unsafe { File::from_raw_fd(raw) });
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = Directory(stream);
    let mut result = Vec::new();
    loop {
        nix::errno::Errno::clear();
        // SAFETY: stream remains open and each returned name is consumed before
        // the next readdir call can invalidate its directory-owned buffer.
        let entry = unsafe { nix::libc::readdir(stream.0) };
        if entry.is_null() {
            if nix::errno::Errno::last_raw() != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            break;
        }
        // SAFETY: a successful readdir guarantees a terminated d_name array.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| invalid("warm copy contains non-UTF8 paths"))?;
        if name != "." && name != ".." {
            result.push(name.to_owned());
        }
        if result.len() > MAX_ENTRIES {
            return Err(invalid("warm capture entry budget exceeded"));
        }
    }
    result.sort();
    Ok(result)
}
fn walk(
    root: &File,
    directory: &File,
    prefix: &str,
    entries: &mut Vec<Entry>,
    total: &mut u64,
) -> Result<()> {
    for name in names(directory)? {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if !crate::baselines::source::safe_path(&path) {
            return Err(invalid("warm capture path is invalid"));
        }
        if excluded(&path) {
            continue;
        }
        if !path.is_ascii() {
            return Err(HostError::Unsupported(
                "non-ASCII warm capture case policy is unqualified",
            ));
        }
        let c_name = CString::new(name).map_err(|_| invalid("capture name contains NUL"))?;
        let mut metadata = std::mem::MaybeUninit::<nix::libc::stat>::uninit();
        // SAFETY: metadata points to valid writable storage; the directory and
        // name are owned. AT_SYMLINK_NOFOLLOW does not inspect a link target.
        let status = unsafe {
            nix::libc::fstatat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                metadata.as_mut_ptr(),
                nix::libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: successful fstatat initialized the complete stat value.
        let metadata = unsafe { metadata.assume_init() };
        let permissions = mode(metadata.st_mode) & 0o777;
        let file_type = mode(metadata.st_mode) & mode(nix::libc::S_IFMT);
        let (kind, length, sha256) = if file_type == mode(nix::libc::S_IFDIR) {
            let child = open_beneath(root, &path, true)?;
            walk(root, &child, &path, entries, total)?;
            (Kind::Directory, 0, String::new())
        } else if file_type == mode(nix::libc::S_IFREG) {
            let mut file = open_beneath(root, &path, false)?;
            let before = file.metadata()?;
            if !before.is_file() {
                return Err(invalid("warm capture file changed kind"));
            }
            let mut hash = Sha256::new();
            let mut buffer = vec![0u8; 64 * 1024];
            let mut length = 0u64;
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
                length = length
                    .checked_add(
                        u64::try_from(count).map_err(|_| invalid("capture length overflow"))?,
                    )
                    .ok_or_else(|| invalid("capture length overflow"))?;
                if length > MAX_BYTES {
                    return Err(invalid("warm capture byte budget exceeded"));
                }
            }
            let after = file.metadata()?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != length
                || after.len() != length
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(HostError::Uncertain(
                    "working file changed while hashing".into(),
                ));
            }
            (Kind::File, length, format!("{:x}", hash.finalize()))
        } else if file_type == mode(nix::libc::S_IFLNK) {
            let mut target = [0u8; 4097];
            // SAFETY: readlinkat writes at most the provided buffer length and
            // does not follow the link; directory/name remain owned.
            let length = unsafe {
                nix::libc::readlinkat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if length < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let length = usize::try_from(length).map_err(|_| invalid("invalid symlink length"))?;
            if length == target.len() {
                return Err(invalid("warm symlink target exceeds limit"));
            }
            (
                Kind::Symlink,
                u64::try_from(length).map_err(|_| invalid("symlink length overflow"))?,
                hash(&target[..length]),
            )
        } else {
            return Err(HostError::Unsupported(
                "warm copy contains sockets, devices or unsupported file kinds",
            ));
        };
        *total = total
            .checked_add(length)
            .ok_or_else(|| invalid("capture byte count overflow"))?;
        if *total > MAX_BYTES || entries.len() >= MAX_ENTRIES {
            return Err(invalid("warm capture exceeds budget"));
        }
        entries.push(Entry {
            path,
            kind,
            mode: permissions,
            length,
            sha256,
        });
    }
    Ok(())
}
pub(super) fn scan(root: &Path) -> Result<Vec<Entry>> {
    let root = open_root(root)?;
    let mut entries = Vec::new();
    let mut total = 0;
    walk(&root, &root, "", &mut entries, &mut total)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut folded = BTreeMap::new();
    for entry in &entries {
        if folded
            .insert(entry.path.to_ascii_lowercase(), &entry.path)
            .is_some()
        {
            return Err(invalid("warm capture contains case-colliding paths"));
        }
    }
    Ok(entries)
}
pub(super) fn sync_tree(root: &Path, entries: &[Entry]) -> Result<()> {
    let root = open_root(root)?;
    for entry in entries.iter().filter(|entry| entry.kind == Kind::File) {
        open_beneath(&root, &entry.path, false)?.sync_all()?;
    }
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| entry.kind == Kind::Directory)
    {
        open_beneath(&root, &entry.path, true)?.sync_all()?;
    }
    // Symlinks are directory entries; no link target is opened or chmodded.
    root.sync_all()?;
    Ok(())
}
pub(super) fn verify_parent(
    root: &Path,
    entries: &[Entry],
    tracked: &[SnapshotEntry],
) -> Result<()> {
    // Ignore loaders can follow control-file symlinks even when the directory
    // walker does not follow links. Check our descriptor-safe inventory first.
    for entry in entries {
        let name = entry.path.rsplit('/').next().unwrap_or(entry.path.as_str());
        if [".gitignore", ".ignore", ".atomicignore"]
            .iter()
            .any(|control| name.eq_ignore_ascii_case(control))
            && entry.kind != Kind::File
        {
            return Err(HostError::Unsupported(
                "warm-copy ignore controls must be ordinary files",
            ));
        }
    }
    let recorded: BTreeSet<_> = tracked.iter().map(|entry| entry.path.as_str()).collect();
    let files: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    for expected in tracked {
        let actual = files
            .get(expected.path.as_str())
            .ok_or_else(|| invalid("inherited-baseline-required: tracked file is missing"))?;
        let kind = match expected.kind {
            SnapshotKind::Regular | SnapshotKind::Executable => Kind::File,
            SnapshotKind::Symlink => Kind::Symlink,
        };
        if actual.kind != kind
            || actual.length != expected.length
            || actual.sha256 != expected.sha256
            || (actual.kind == Kind::File && actual.mode & 0o111 != expected.mode & 0o111)
        {
            return Err(invalid(
                "inherited-baseline-required: tracked parent differs from recorded baseline",
            ));
        }
    }
    let mut walker = ignore::WalkBuilder::new(root);
    let filter_root = root.to_owned();
    walker
        .hidden(false)
        .parents(false)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            // ignore::Walk applies this filter before loading a directory's own
            // ignore files. Prune excluded metadata/credential trees at that point.
            entry.depth() == 0
                || entry
                    .path()
                    .strip_prefix(&filter_root)
                    .ok()
                    .and_then(Path::to_str)
                    .is_none_or(|relative| !excluded(relative))
        });
    for entry in walker.build() {
        let entry = entry
            .map_err(|error| HostError::Native(format!("working ignore traversal: {error}")))?;
        if let Some(error) = entry.error() {
            return Err(HostError::Native(format!("working ignore policy: {error}")));
        }
        if entry.depth() == 0 || entry.file_type().is_some_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| invalid("working path escaped root"))?
            .to_str()
            .ok_or_else(|| invalid("working path is not UTF8"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !excluded(&path) && !recorded.contains(path.as_str()) {
            return Err(invalid(
                "inherited-baseline-required: relevant untracked parent file",
            ));
        }
    }
    Ok(())
}
