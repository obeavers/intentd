//! Real copy-on-write primitives only. Unsupported filesystems refuse; no
//! ordinary copy or live shared-directory fallback is called a warm clone.

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[cfg(target_os = "linux")]
use super::manifest::Kind;
use super::manifest::{self, Entry};
use crate::{HostError, Result};

fn private_root(path: &Path) -> Result<()> {
    if !std::fs::symlink_metadata(path)?.is_dir() {
        return Err(HostError::Invalid(
            "warm clone root is not a real directory",
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn directory_clone(source: &Path, destination: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| HostError::Invalid("clone source contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| HostError::Invalid("clone destination contains NUL"))?;
    // CLONE_NOFOLLOW | CLONE_NOOWNERCOPY from pinned Darwin clonefile.h. The
    // destination is fresh inside the0700 spool, never an existing user tree.
    // SAFETY: both C strings are valid and remain live for the call.
    if unsafe { nix::libc::clonefile(source.as_ptr(), destination.as_ptr(), 0x0001 | 0x0002) } != 0
    {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(nix::libc::EXDEV | nix::libc::ENOTSUP | nix::libc::ENOSYS)
        ) {
            return Err(HostError::Unsupported(
                "APFS directory copy-on-write is unavailable; standby clone preparation is unqualified",
            ));
        }
        return Err(error.into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn prune(root: &Path) -> Result<()> {
    fn visit(root: &Path, directory: &Path) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| HostError::Invalid("clone exclusion escaped private root"))?
                .to_str()
                .ok_or(HostError::Invalid("warm clone path is not UTF8"))?;
            let metadata = std::fs::symlink_metadata(&path)?;
            if manifest::excluded(relative) {
                if metadata.is_dir() {
                    std::fs::remove_dir_all(path)?;
                } else {
                    std::fs::remove_file(path)?;
                }
            } else if metadata.is_dir() {
                visit(root, &path)?;
            }
        }
        Ok(())
    }
    visit(root, root)
}

#[cfg(target_os = "linux")]
fn reflink_file(source: &File, destination: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let metadata = source.metadata()?;
    let target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(destination)?;
    // SAFETY: both descriptors refer to owned regular files. FICLONE only
    // clones blocks into the fresh target and cannot alter the source.
    if unsafe { nix::libc::ioctl(target.as_raw_fd(), nix::libc::FICLONE, source.as_raw_fd()) } != 0
    {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(nix::libc::EXDEV | nix::libc::ENOTSUP | nix::libc::ENOSYS | nix::libc::EINVAL)
        ) {
            return Err(HostError::Unsupported(
                "filesystem reflink is unavailable; standby clone preparation is unqualified",
            ));
        }
        return Err(error.into());
    }
    target.set_permissions(metadata.permissions())?;
    target.set_times(
        std::fs::FileTimes::new()
            .set_accessed(metadata.accessed()?)
            .set_modified(metadata.modified()?),
    )?;
    target.sync_all()?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn parallel_reflinks(source: &Path, destination: &Path, entries: &[Entry]) -> Result<()> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    crate::durable::private_dir(destination)?;
    for entry in entries.iter().filter(|entry| entry.kind == Kind::Directory) {
        std::fs::create_dir(destination.join(&entry.path))?;
    }
    let source_root = manifest::open_root(source)?;
    let files: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == Kind::File)
        .collect();
    let next = AtomicUsize::new(0);
    let failure = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while failure.lock().is_ok_and(|failure| failure.is_none()) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = files.get(index) else {
                        break;
                    };
                    let result = manifest::open_beneath(&source_root, &entry.path, false)
                        .and_then(|file| reflink_file(&file, &destination.join(&entry.path)));
                    if let Err(error) = result {
                        if let Ok(mut failure) = failure.lock() {
                            *failure = Some(error);
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(error) = failure.into_inner().map_err(|_| HostError::Poisoned)? {
        return Err(error);
    }
    for entry in entries.iter().filter(|entry| entry.kind == Kind::Symlink) {
        let path = Path::new(&entry.path);
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let directory = if let Some(parent) = parent {
            manifest::open_beneath(
                &source_root,
                parent
                    .to_str()
                    .ok_or(HostError::Invalid("symlink parent is not UTF8"))?,
                true,
            )?
        } else {
            source_root.try_clone()?
        };
        let name = std::ffi::CString::new(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or(HostError::Invalid("symlink name is invalid"))?,
        )
        .map_err(|_| HostError::Invalid("symlink contains NUL"))?;
        let mut bytes = [0u8; 4097];
        use std::os::fd::AsRawFd;
        // SAFETY: directory/name are pinned and the buffer is writable; the
        // link itself is read without following its target.
        let length = unsafe {
            nix::libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let length =
            usize::try_from(length).map_err(|_| HostError::Invalid("invalid symlink length"))?;
        if length == bytes.len() {
            return Err(HostError::Invalid("symlink target exceeds capture bound"));
        }
        use std::os::unix::ffi::OsStrExt;
        std::os::unix::fs::symlink(
            std::ffi::OsStr::from_bytes(&bytes[..length]),
            destination.join(&entry.path),
        )?;
    }
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| entry.kind == Kind::Directory)
    {
        std::fs::set_permissions(
            destination.join(&entry.path),
            std::fs::Permissions::from_mode(entry.mode),
        )?;
    }
    Ok(())
}

pub(super) fn clone_warm(
    source: &Path,
    destination: &Path,
    entries: &[Entry],
) -> Result<&'static str> {
    if destination.symlink_metadata().is_ok() {
        return Err(HostError::Invalid("warm clone destination must be fresh"));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = entries;
        directory_clone(source, destination)?;
        private_root(destination)?;
        prune(destination)?;
        Ok("apfs-directory-clone")
    }
    #[cfg(target_os = "linux")]
    {
        parallel_reflinks(source, destination, entries)?;
        private_root(destination)?;
        Ok("parallel-reflink")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (source, destination, entries);
        Err(HostError::Unsupported(
            "warm copy-on-write is unqualified on this platform",
        ))
    }
}
