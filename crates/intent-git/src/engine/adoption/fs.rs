//! Descriptor-relative file effects. Existing entries are exchanged/moved into
//! retained storage, so a racing writer's old inode is never silently discarded.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::{invalid, io, Image, MAX_BLOB};
use crate::engine::{content_digest, storage, vcs};

fn c(value: &std::ffi::OsStr) -> vcs::VcsResult<CString> {
    CString::new(value.as_bytes()).map_err(|_| invalid("filesystem name contains NUL"))
}

pub(super) fn directory(path: &Path) -> vcs::VcsResult<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io(&error))
}

pub(super) fn child(parent: &File, name: &str, create: bool) -> vcs::VcsResult<File> {
    let name = CString::new(name).map_err(|_| invalid("invalid path component"))?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // Every component is checked relative to the already pinned parent.
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 && create && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(io(&std::io::Error::last_os_error()));
        }
        parent.sync_all().map_err(|error| io(&error))?;
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(io(&std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn parent(root: &File, path: &str, create: bool) -> vcs::VcsResult<(File, CString)> {
    if !crate::checkpoint::safe_relative_path(path) {
        return Err(invalid("unsafe adoption path"));
    }
    let mut components = path.split('/').collect::<Vec<_>>();
    let name = CString::new(
        components
            .pop()
            .ok_or_else(|| invalid("empty adoption path"))?,
    )
    .map_err(|_| invalid("invalid filename"))?;
    let mut parent = root.try_clone().map_err(|error| io(&error))?;
    for component in components {
        parent = child(&parent, component, create)?;
    }
    Ok((parent, name))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Payload {
    pub mode: u32,
    pub bytes: Vec<u8>,
}
impl Payload {
    pub fn image(&self) -> Image {
        Image {
            mode: self.mode,
            digest: content_digest(&self.bytes),
            length: self.bytes.len() as u64,
        }
    }
}

pub(super) fn payload_at(parent: &File, name: &CString) -> vcs::VcsResult<Option<Payload>> {
    payload_at_checked(parent, name, || {})
}

pub(super) fn payload_at_checked(
    parent: &File,
    name: &CString,
    before_regular_open: impl FnOnce(),
) -> vcs::VcsResult<Option<Payload>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(io(&error));
    }
    let stat = unsafe { stat.assume_init() };
    let mode = stat.st_mode & libc::S_IFMT;
    let (mode, bytes) = if mode == libc::S_IFLNK {
        let mut bytes = vec![0; MAX_BLOB.min(1024 * 1024) + 1];
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(io(&std::io::Error::last_os_error()));
        }
        let length = usize::try_from(length).map_err(|_| invalid("invalid symlink size"))?;
        if length >= bytes.len() {
            return Err(invalid("symlink target exceeds its byte budget"));
        }
        bytes.truncate(length);
        (0o120_000, bytes)
    } else if mode == libc::S_IFREG {
        before_regular_open();
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io(&std::io::Error::last_os_error()));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|error| io(&error))?;
        #[cfg(target_os = "macos")]
        let expected_device = u64::try_from(stat.st_dev)
            .map_err(|_| invalid("invalid filesystem device identity"))?;
        #[cfg(target_os = "linux")]
        let expected_device = stat.st_dev;
        if !metadata.is_file()
            || metadata.dev() != expected_device
            || metadata.ino() != stat.st_ino
            || metadata.len() > MAX_BLOB as u64
        {
            return Err(invalid(
                "adoption path changed identity or exceeds its byte budget",
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_BLOB as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io(&error))?;
        if bytes.len() > MAX_BLOB {
            return Err(invalid("adoption path exceeds its byte budget"));
        }
        (
            if metadata.permissions().mode() & 0o111 == 0 {
                0o100_644
            } else {
                0o100_755
            },
            bytes,
        )
    } else {
        return Err(invalid("adoption path is a directory or unsupported node"));
    };
    Ok(Some(Payload { mode, bytes }))
}

pub(super) fn image_at(parent: &File, name: &CString) -> vcs::VcsResult<Option<Image>> {
    Ok(payload_at(parent, name)?.map(|payload| payload.image()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Directory,
    Regular,
    Symlink,
}
pub(super) struct Entry {
    pub name: String,
    pub kind: Kind,
}
struct Listing(*mut libc::DIR);
impl Drop for Listing {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

pub(super) fn entries(parent: &File) -> vcs::VcsResult<Vec<Entry>> {
    let descriptor = parent
        .try_clone()
        .map_err(|error| io(&error))?
        .into_raw_fd();
    let directory = unsafe { libc::fdopendir(descriptor) };
    if directory.is_null() {
        unsafe {
            libc::close(descriptor);
        };
        return Err(io(&std::io::Error::last_os_error()));
    }
    let directory = Listing(directory);
    let mut entries = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(io(&error));
            }
            break;
        }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(raw, b"." | b"..") {
            continue;
        }
        let name = std::str::from_utf8(raw)
            .map_err(|_| invalid("target observation requires UTF-8 names"))?
            .to_string();
        let native = CString::new(raw).map_err(|_| invalid("invalid directory name"))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                native.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io(&std::io::Error::last_os_error()));
        }
        let kind = match unsafe { stat.assume_init() }.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Kind::Directory,
            libc::S_IFREG => Kind::Regular,
            libc::S_IFLNK => Kind::Symlink,
            _ => {
                return Err(invalid(
                    "target contains an unqualified special filesystem node",
                ))
            }
        };
        entries.push(Entry { name, kind });
        if entries.len() > super::MAX_FILES {
            return Err(invalid("target directory exceeds its entry budget"));
        }
    }
    entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    Ok(entries)
}

pub(super) fn image(root: &File, path: &str) -> vcs::VcsResult<Option<Image>> {
    if !crate::checkpoint::safe_relative_path(path) {
        return Err(invalid("unsafe adoption path"));
    }
    let mut components = path.split('/').collect::<Vec<_>>();
    let name = name(
        components
            .pop()
            .ok_or_else(|| invalid("empty adoption path"))?,
    )?;
    let mut parent = root.try_clone().map_err(|error| io(&error))?;
    for component in components {
        let component = self::name(component)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(io(&error));
        }
        parent = unsafe { File::from_raw_fd(fd) };
    }
    image_at(&parent, &name)
}

pub(super) fn stage(path: &Path, mode: u32, bytes: &[u8]) -> vcs::VcsResult<()> {
    if mode == 0o120_000 {
        std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(bytes), path)
            .map_err(|error| io(&error))?;
    } else {
        let mut file = storage::create_file(path)?;
        file.write_all(bytes).map_err(|error| io(&error))?;
        file.set_permissions(std::fs::Permissions::from_mode(if mode == 0o100_755 {
            0o700
        } else {
            0o600
        }))
        .map_err(|error| io(&error))?;
        file.sync_all().map_err(|error| io(&error))?;
    }
    storage::sync_directory(
        path.parent()
            .ok_or_else(|| invalid("staged file has no parent"))?,
    )
}

pub(super) fn exchange(
    from: &File,
    from_name: &CString,
    to: &File,
    to_name: &CString,
) -> vcs::VcsResult<()> {
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            from_name.as_ptr(),
            to.as_raw_fd(),
            to_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            from.as_raw_fd(),
            from_name.as_ptr(),
            to.as_raw_fd(),
            to_name.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(invalid(
        "atomic entry exchange is unqualified on this platform",
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if result != 0 {
        return Err(io(&std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(super) fn publish_new(
    from: &File,
    from_name: &CString,
    to: &File,
    to_name: &CString,
) -> vcs::VcsResult<()> {
    // linkat does not follow the source symlink, and never overwrites a racing
    // newly created target. Unlink only our owned staging alias afterwards.
    if unsafe {
        libc::linkat(
            from.as_raw_fd(),
            from_name.as_ptr(),
            to.as_raw_fd(),
            to_name.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(io(&std::io::Error::last_os_error()));
    }
    to.sync_all().map_err(|error| io(&error))?;
    if unsafe { libc::unlinkat(from.as_raw_fd(), from_name.as_ptr(), 0) } != 0 {
        return Err(io(&std::io::Error::last_os_error()));
    }
    from.sync_all().map_err(|error| io(&error))
}

pub(super) fn move_preimage(
    from: &File,
    name: &CString,
    to: &File,
    saved: &CString,
) -> vcs::VcsResult<()> {
    // Saved names are unique under the held operation lock and must not exist.
    if image_at(to, saved)?.is_some() {
        return Err(invalid("retained preimage slot already exists"));
    }
    if unsafe {
        libc::renameat(
            from.as_raw_fd(),
            name.as_ptr(),
            to.as_raw_fd(),
            saved.as_ptr(),
        )
    } != 0
    {
        return Err(io(&std::io::Error::last_os_error()));
    }
    from.sync_all().map_err(|error| io(&error))?;
    to.sync_all().map_err(|error| io(&error))
}

pub(super) fn name(value: &str) -> vcs::VcsResult<CString> {
    c(std::ffi::OsStr::new(value))
}
