//! Descriptor-relative raw snapshot and private reconstruction. Symlink bytes
//! are retained, but a symlink is never traversed for either reads or writes.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    digest, invalid, safe_path, AggregateManifest, FileEntry, FileKind, MAX_ARCHIVE, MAX_ENTRIES,
    MAX_FILE,
};
use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) entries: Vec<FileEntry>,
    pub(super) contents: BTreeMap<String, Vec<u8>>,
}

fn name(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| invalid("checkpoint filesystem name contains NUL"))
}

#[cfg(target_os = "macos")]
fn mode(value: libc::mode_t) -> u32 {
    u32::from(value)
}
#[cfg(not(target_os = "macos"))]
fn mode(value: libc::mode_t) -> u32 {
    value
}
fn set_mode(file: &File, value: u32) -> Result<()> {
    #[cfg(target_os = "macos")]
    let value: libc::mode_t = value
        .try_into()
        .map_err(|_| invalid("invalid checkpoint mode"))?;
    // SAFETY: the file is an owned descriptor created by this restore owner.
    if unsafe { libc::fchmod(file.as_raw_fd(), value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn open_at(directory: &File, value: &str, flags: i32, mode: libc::mode_t) -> Result<File> {
    let value = name(value)?;
    // C variadic arguments require integer promotion for Darwin's u16 mode_t.
    #[cfg(target_os = "macos")]
    let mode = libc::c_uint::from(mode);
    // SAFETY: the retained directory and terminated name are valid. A successful
    // openat returns a new descriptor transferred exactly once to File.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            value.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn open_absolute(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(invalid("absolute checkpoint directory is required"));
    }
    let mut current = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or(invalid("checkpoint directory is not UTF-8"))?;
                current = open_at(&current, value, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            }
            _ => return Err(invalid("checkpoint directory contains traversal")),
        }
    }
    Ok(current)
}

fn stat_at(directory: &File, value: &str) -> Result<libc::stat> {
    let value = name(value)?;
    let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory/name and writable stat storage are valid. The value is
    // initialized only after fstatat reports success.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            value.as_ptr(),
            result.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { result.assume_init() })
}

fn same_open_file(file: &File, expected: &libc::stat) -> Result<()> {
    let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file is live and result is initialized only on success.
    if unsafe { libc::fstat(file.as_raw_fd(), result.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let actual = unsafe { result.assume_init() };
    if actual.st_dev != expected.st_dev
        || actual.st_ino != expected.st_ino
        || actual.st_mode != expected.st_mode
    {
        return Err(invalid("checkpoint path changed between lookup and open"));
    }
    Ok(())
}

fn version(metadata: &std::fs::Metadata) -> (u64, u64, u32, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: this guard owns the successful fdopendir result exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: libc returns this thread's errno storage.
    unsafe { libc::__errno_location() }
}
#[cfg(not(target_os = "linux"))]
fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: supported non-Linux host is Darwin; libc returns thread errno.
    unsafe { libc::__error() }
}

fn names(directory: &File) -> Result<Vec<String>> {
    let raw = directory.try_clone()?.into_raw_fd();
    // SAFETY: fdopendir consumes the new descriptor only on success.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        drop(unsafe { File::from_raw_fd(raw) });
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = Directory(stream);
    let mut result = Vec::new();
    loop {
        // SAFETY: errno is thread-local writable storage; readdir's successful
        // name is read before another call can reuse its directory buffer.
        unsafe {
            *errno_pointer() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *errno_pointer() } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            break;
        }
        let value = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| invalid("checkpoint contains non-UTF8 paths"))?;
        if value != "." && value != ".." {
            result.push(value.to_owned());
        }
        if result.len() > MAX_ENTRIES {
            return Err(invalid("checkpoint directory entry budget exceeded"));
        }
    }
    result.sort();
    Ok(result)
}

fn control_name(value: &str) -> bool {
    matches!(value, ".git" | ".atomic" | ".atomic-sandbox")
}

fn walk(directory: &File, prefix: &str, snapshot: &mut Snapshot, total: &mut u64) -> Result<()> {
    let before = version(&directory.metadata()?);
    for value in names(directory)? {
        if control_name(&value) {
            return Err(invalid("checkpoint contains unowned engine-control metadata; refusing rather than dropping bytes"));
        }
        let path = if prefix.is_empty() {
            value.clone()
        } else {
            format!("{prefix}/{value}")
        };
        if !safe_path(&path) || snapshot.entries.len() >= MAX_ENTRIES {
            return Err(invalid("invalid checkpoint path or file budget"));
        }
        let metadata = stat_at(directory, &value)?;
        if mode(metadata.st_mode) & 0o7000 != 0 {
            return Err(invalid(
                "checkpoint special permission bits are unsupported",
            ));
        }
        let mode = mode(metadata.st_mode) & 0o777;
        let file_type = metadata.st_mode & libc::S_IFMT;
        let (kind, bytes) = if file_type == libc::S_IFDIR {
            let child = open_at(directory, &value, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            same_open_file(&child, &metadata)?;
            snapshot.entries.push(FileEntry {
                path: path.clone(),
                kind: FileKind::Directory,
                mode,
                length: 0,
                sha256: digest(&[]),
            });
            walk(&child, &path, snapshot, total)?;
            continue;
        } else if file_type == libc::S_IFREG {
            let mut file = open_at(directory, &value, libc::O_RDONLY, 0)?;
            same_open_file(&file, &metadata)?;
            let before = version(&file.metadata()?);
            if before.3 > MAX_FILE {
                return Err(invalid("checkpoint file exceeds byte budget"));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(MAX_FILE + 1)
                .read_to_end(&mut bytes)?;
            if version(&file.metadata()?) != before || bytes.len() as u64 != before.3 {
                return Err(invalid("checkpoint source file changed during read"));
            }
            (
                if mode & 0o111 == 0 {
                    FileKind::Regular
                } else {
                    FileKind::Executable
                },
                bytes,
            )
        } else if file_type == libc::S_IFLNK {
            let value = name(&value)?;
            let mut bytes = vec![0; 4097];
            // SAFETY: directory/name and the writable bounded buffer are valid;
            // readlinkat returns target bytes without traversing the link.
            let count = unsafe {
                libc::readlinkat(
                    directory.as_raw_fd(),
                    value.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            let count = usize::try_from(count).map_err(|_| std::io::Error::last_os_error())?;
            if count == 0 || count > 4096 {
                return Err(invalid("checkpoint symlink target exceeds budget"));
            }
            bytes.truncate(count);
            let after = stat_at(
                directory,
                value.to_str().map_err(|_| invalid("invalid link name"))?,
            )?;
            if after.st_dev != metadata.st_dev
                || after.st_ino != metadata.st_ino
                || after.st_mode != metadata.st_mode
                || after.st_size != metadata.st_size
            {
                return Err(invalid("checkpoint symlink changed during read"));
            }
            (FileKind::Symlink, bytes)
        } else {
            return Err(invalid("checkpoint contains an unsupported special file"));
        };
        *total = total
            .checked_add(bytes.len() as u64)
            .ok_or(invalid("checkpoint byte count overflow"))?;
        if *total > MAX_ARCHIVE {
            return Err(invalid("checkpoint working bytes exceed budget"));
        }
        let entry = FileEntry {
            path: path.clone(),
            kind,
            mode,
            length: bytes.len() as u64,
            sha256: digest(&bytes),
        };
        snapshot.entries.push(entry);
        snapshot.contents.insert(path, bytes);
    }
    if before != version(&directory.metadata()?) {
        return Err(invalid("checkpoint source directory changed during read"));
    }
    Ok(())
}

pub(super) fn snapshot(path: &Path) -> Result<Snapshot> {
    let root = open_absolute(path)?;
    let before = version(&root.metadata()?);
    let mut snapshot = Snapshot {
        entries: Vec::new(),
        contents: BTreeMap::new(),
    };
    walk(&root, "", &mut snapshot, &mut 0)?;
    if before != version(&open_absolute(path)?.metadata()?) {
        return Err(invalid("checkpoint source root changed during capture"));
    }
    snapshot
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    super::validate_entries(&snapshot.entries, true)?;
    Ok(snapshot)
}

fn mkdir(directory: &File, value: &str) -> Result<File> {
    let value = name(value)?;
    // SAFETY: directory/name are valid; a new owner-private child is requested.
    if unsafe { libc::mkdirat(directory.as_raw_fd(), value.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    open_at(
        directory,
        value
            .to_str()
            .map_err(|_| invalid("invalid directory name"))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
}

fn parent(root: &File, path: &str) -> Result<(File, String)> {
    if !safe_path(path) {
        return Err(invalid("invalid checkpoint destination path"));
    }
    let mut parts: Vec<_> = path.split('/').collect();
    let leaf = parts
        .pop()
        .ok_or(invalid("missing checkpoint filename"))?
        .to_owned();
    let mut directory = root.try_clone()?;
    for part in parts {
        directory = open_at(&directory, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    }
    Ok((directory, leaf))
}

fn write_new(directory: &File, value: &str, bytes: &[u8]) -> Result<()> {
    let mut file = open_at(
        directory,
        value,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn read_regular(directory: &File, value: &str, maximum: u64) -> Result<Vec<u8>> {
    let mut file = open_at(directory, value, libc::O_RDONLY, 0)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum {
        return Err(invalid("invalid private checkpoint sidecar"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("private checkpoint sidecar grew beyond budget"));
    }
    Ok(bytes)
}

fn verify_exact_file(directory: &File, value: &str, expected: &[u8]) -> Result<()> {
    let mut file = open_at(directory, value, libc::O_RDONLY, 0)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments and does not access Rust memory.
    if !metadata.is_file()
        || metadata.len() != expected.len() as u64
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "private checkpoint object ownership or length differs",
        ));
    }
    let mut buffer = [0; 16_384];
    let mut offset = 0;
    while offset < expected.len() {
        let count = buffer.len().min(expected.len() - offset);
        file.read_exact(&mut buffer[..count])?;
        if buffer[..count] != expected[offset..offset + count] {
            return Err(invalid("private checkpoint object content differs"));
        }
        offset += count;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(invalid(
            "private checkpoint object grew during verification",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOwner {
    command_digest: String,
    working_manifest_digest: String,
}

pub(super) fn install_private(
    root: &Path,
    operation_id: &str,
    command_digest: &str,
    snapshot: &Snapshot,
    manifest: &AggregateManifest,
    archive: &[u8],
    objects: &BTreeMap<String, Vec<u8>>,
) -> Result<PathBuf> {
    let restore_parent = open_absolute(
        root.parent()
            .ok_or(invalid("checkpoint restore root has no parent"))?,
    )?;
    let root_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(invalid("invalid checkpoint restore root"))?;
    let directory = match mkdir(&restore_parent, root_name) {
        Ok(directory) => directory,
        Err(crate::HostError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_at(
                &restore_parent,
                root_name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?
        }
        Err(error) => return Err(error),
    };
    // SAFETY: geteuid has no arguments or Rust memory access.
    if directory.metadata()?.uid() != unsafe { libc::geteuid() }
        || directory.metadata()?.mode() & 0o077 != 0
    {
        return Err(invalid("checkpoint restore root is not owner-private"));
    }
    let leaf = format!("restore-{}", digest(operation_id.as_bytes()));
    let owner = PrivateOwner {
        command_digest: command_digest.to_owned(),
        working_manifest_digest: super::file_digest(&snapshot.entries)?,
    };
    let selection = serde_json::to_vec(&manifest.selection)?;
    let evidence = serde_json::to_vec(&manifest.evidence)?;
    let path = root.join(&leaf).join("files");
    let operation = match mkdir(&directory, &leaf) {
        Ok(operation) => {
            write_new(&operation, "owner.json", &serde_json::to_vec(&owner)?)?;
            let files = mkdir(&operation, "files")?;
            for entry in &snapshot.entries {
                let (parent, leaf) = parent(&files, &entry.path)?;
                match entry.kind {
                    FileKind::Directory => {
                        mkdir(&parent, &leaf)?;
                    }
                    FileKind::Regular | FileKind::Executable => {
                        let bytes = snapshot
                            .contents
                            .get(&entry.path)
                            .ok_or(invalid("checkpoint file payload missing"))?;
                        let mut file = open_at(
                            &parent,
                            &leaf,
                            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                            0o600,
                        )?;
                        file.write_all(bytes)?;
                        set_mode(&file, entry.mode)?;
                        file.sync_all()?;
                    }
                    FileKind::Symlink => {
                        let bytes = snapshot
                            .contents
                            .get(&entry.path)
                            .ok_or(invalid("checkpoint link payload missing"))?;
                        let target = CString::new(bytes.as_slice())
                            .map_err(|_| invalid("checkpoint link target contains NUL"))?;
                        let leaf = name(&leaf)?;
                        // SAFETY: both byte strings and parent descriptor are
                        // valid; symlinkat creates a link without traversing it.
                        if unsafe {
                            libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), leaf.as_ptr())
                        } != 0
                        {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        let actual = stat_at(
                            &parent,
                            leaf.to_str()
                                .map_err(|_| invalid("invalid symlink filename"))?,
                        )?;
                        if mode(actual.st_mode) & 0o777 != entry.mode {
                            #[cfg(target_os = "macos")]
                            let requested: libc::mode_t = entry
                                .mode
                                .try_into()
                                .map_err(|_| invalid("invalid checkpoint symlink mode"))?;
                            #[cfg(not(target_os = "macos"))]
                            let requested = entry.mode;
                            // SAFETY: changes only the freshly created link
                            // itself; AT_SYMLINK_NOFOLLOW prohibits target IO.
                            if unsafe {
                                libc::fchmodat(
                                    parent.as_raw_fd(),
                                    leaf.as_ptr(),
                                    requested,
                                    libc::AT_SYMLINK_NOFOLLOW,
                                )
                            } != 0
                            {
                                return Err(std::io::Error::last_os_error().into());
                            }
                        }
                    }
                }
                parent.sync_all()?;
            }
            for entry in snapshot
                .entries
                .iter()
                .rev()
                .filter(|entry| entry.kind == FileKind::Directory)
            {
                let (parent, leaf) = parent(&files, &entry.path)?;
                let child = open_at(&parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                set_mode(&child, entry.mode)?;
                child.sync_all()?;
            }
            files.sync_all()?;
            let selected = mkdir(&operation, "selection-objects")?;
            if let super::CheckpointSelection::Known { files, .. } = &manifest.selection {
                let mut retained = std::collections::BTreeSet::new();
                for file in files.iter().filter(|file| {
                    file.kind != intent_atomic_proto::recording::SelectedFileKind::Deletion
                }) {
                    if retained.insert(file.sha256.as_str()) {
                        write_new(&selected, &file.sha256, &objects[&file.sha256])?;
                    }
                }
            }
            selected.sync_all()?;
            write_new(&operation, "checkpoint.payload", archive)?;
            write_new(&operation, "selection.json", &selection)?;
            write_new(&operation, "work-evidence.json", &evidence)?;
            operation.sync_all()?;
            operation
        }
        Err(crate::HostError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let operation = open_at(&directory, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let prior: PrivateOwner =
                serde_json::from_slice(&read_regular(&operation, "owner.json", 4096)?)?;
            if prior.command_digest != owner.command_digest
                || prior.working_manifest_digest != owner.working_manifest_digest
            {
                return Err(invalid("conflicting aggregate restore operation replay"));
            }
            operation
        }
        Err(error) => return Err(error),
    };
    let current_root = open_absolute(root)?.metadata()?;
    let original_root = directory.metadata()?;
    let current_operation =
        open_at(&directory, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?.metadata()?;
    let original_operation = operation.metadata()?;
    if current_root.dev() != original_root.dev()
        || current_root.ino() != original_root.ino()
        || current_operation.dev() != original_operation.dev()
        || current_operation.ino() != original_operation.ino()
    {
        return Err(invalid("private checkpoint restore owner was replaced"));
    }
    verify_exact_file(&operation, "checkpoint.payload", archive)?;
    let selected = open_at(
        &operation,
        "selection-objects",
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    let expected_selected: std::collections::BTreeSet<_> = match &manifest.selection {
        super::CheckpointSelection::Unknown => std::collections::BTreeSet::new(),
        super::CheckpointSelection::Known { files, .. } => files
            .iter()
            .filter(|file| file.kind != intent_atomic_proto::recording::SelectedFileKind::Deletion)
            .map(|file| file.sha256.clone())
            .collect(),
    };
    if names(&selected)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        != expected_selected
    {
        return Err(invalid("private frozen selection object inventory differs"));
    }
    for sha256 in expected_selected {
        verify_exact_file(&selected, &sha256, &objects[&sha256])?;
    }
    if read_regular(&operation, "selection.json", super::MAX_HEADER as u64)? != selection
        || read_regular(&operation, "work-evidence.json", super::MAX_HEADER as u64)? != evidence
        || self::snapshot(&path)? != *snapshot
    {
        return Err(invalid(
            "private checkpoint restore is incomplete or changed; not exposed",
        ));
    }
    directory.sync_all()?;
    Ok(path)
}
