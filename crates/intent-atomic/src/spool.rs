//! Owner-private spool files, resolved relative to a retained directory handle.

use std::{
    ffi::CString,
    fs::{DirBuilder, File},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use intent_atomic_proto::SpoolRef;
use sha2::{Digest, Sha256};

use crate::{HostError, Result};

pub struct Spool {
    directory: File,
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and does not access Rust memory.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(HostError::InvalidSpool(
            "directory must be owner-private and not a symlink",
        ));
    }
    Ok(())
}

impl Spool {
    /// Open one owner-private directory. Parent directories must already exist.
    /// # Errors
    /// Refuses symlinks, foreign ownership, public permissions and I/O failures.
    pub fn open(path: &Path) -> Result<Self> {
        ensure_private_directory(path)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no arguments and does not access Rust memory.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(HostError::InvalidSpool(
                "directory ownership changed during open",
            ));
        }
        Ok(Self { directory })
    }

    /// Retain immutable payload bytes until their owning operation is terminal.
    /// No request cancellation or client drop removes a spool file.
    /// # Errors
    /// Returns creation, write or durability failures.
    pub fn retain(&self, bytes: &[u8]) -> Result<SpoolRef> {
        let name = format!("{}.payload", uuid::Uuid::now_v7());
        let mut file = self.open_file(&name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(SpoolRef {
            name,
            length: bytes.len() as u64,
            sha256: digest(bytes),
        })
    }

    /// Stage a portable native closure under its exact content-addressed name.
    /// Existing bytes are verified and never overwritten; all access remains
    /// relative to this retained owner-private directory descriptor.
    /// # Errors
    /// Refuses a conflicting/unsafe existing file or any write/durability failure.
    pub fn retain_closure(&self, bytes: &[u8]) -> Result<SpoolRef> {
        let sha256 = digest(bytes);
        self.retain_named(&format!("closure-{sha256}.bin"), bytes)
    }

    /// A single immutable operation result, never an overwritable pathname alias.
    pub(crate) fn retain_named(&self, name: &str, bytes: &[u8]) -> Result<SpoolRef> {
        let reference = SpoolRef {
            name: name.to_owned(),
            length: bytes.len() as u64,
            sha256: digest(bytes),
        };
        match self.open_file(
            &reference.name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                self.directory.sync_all()?;
            }
            Err(HostError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.open_verified(&reference, reference.length)?;
            }
            Err(error) => return Err(error),
        }
        Ok(reference)
    }

    /// Verify an owner-private regular file and return its handle at offset zero.
    /// The caller sets a content budget before any bytes are read.
    /// # Errors
    /// Refuses traversal, symlinks, foreign/public files, size or digest mismatch.
    pub fn open_verified(&self, reference: &SpoolRef, max_bytes: u64) -> Result<File> {
        if reference.length > max_bytes
            || reference.sha256.len() != 64
            || !reference
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(HostError::InvalidSpool("invalid content budget or digest"));
        }
        let mut file = self.open_file(&reference.name, libc::O_RDONLY)?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no arguments and does not access Rust memory.
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() != reference.length
        {
            return Err(HostError::InvalidSpool(
                "file ownership, mode or length mismatch",
            ));
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16_384];
        let mut remaining = reference.length;
        while remaining > 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| HostError::InvalidSpool("invalid file length"))?;
            let read = file.read(&mut buffer[..count])?;
            if read == 0 {
                return Err(HostError::InvalidSpool(
                    "file shortened during verification",
                ));
            }
            hasher.update(&buffer[..read]);
            remaining -= read as u64;
        }
        if file.read(&mut buffer[..1])? != 0 || hex(&hasher.finalize()) != reference.sha256 {
            return Err(HostError::InvalidSpool("file content digest mismatch"));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    /// Remove retained bytes only after the caller proves terminal ownership.
    /// # Errors
    /// Refuses invalid names and returns unlink or durability failures.
    pub fn release_after_terminal(&self, reference: &SpoolRef) -> Result<()> {
        let name = safe_name(&reference.name)?;
        // SAFETY: both the retained directory FD and NUL-terminated name are valid.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.directory.sync_all()?;
        Ok(())
    }

    fn open_file(&self, name: &str, flags: i32) -> Result<File> {
        let name = safe_name(name)?;
        // SAFETY: openat uses a live directory FD and valid NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new owned descriptor, transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn safe_name(name: &str) -> Result<CString> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(HostError::InvalidSpool(
            "expected a single relative spool filename",
        ));
    }
    CString::new(name).map_err(|_| HostError::InvalidSpool("NUL in spool name"))
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn retained_payload_survives_client_lifetime_and_detects_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path).unwrap();
        let reference = spool.retain(b"immutable change bytes").unwrap();
        drop(spool);
        let spool = Spool::open(&path).unwrap();
        assert!(spool.open_verified(&reference, 100).is_ok());
        assert!(spool.open_verified(&reference, 1).is_err());
        std::fs::write(path.join(&reference.name), b"different payload here").unwrap();
        assert!(spool.open_verified(&reference, 100).is_err());
    }

    #[test]
    fn traversal_symlink_and_public_permissions_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path).unwrap();
        let mut reference = spool.retain(b"bytes").unwrap();
        std::fs::set_permissions(
            path.join(&reference.name),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(spool.open_verified(&reference, 100).is_err());
        symlink(path.join(&reference.name), path.join("link")).unwrap();
        reference.name = "link".to_owned();
        assert!(spool.open_verified(&reference, 100).is_err());
        reference.name = "../escape".to_owned();
        assert!(spool.open_verified(&reference, 100).is_err());
        symlink(&path, temp.path().join("redirect")).unwrap();
        assert!(Spool::open(&temp.path().join("redirect")).is_err());
    }

    #[test]
    fn a_hard_link_cannot_make_an_external_file_a_spool_payload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool");
        let spool = Spool::open(&path).unwrap();
        let reference = spool.retain(b"private payload").unwrap();
        std::fs::hard_link(path.join(&reference.name), temp.path().join("outside")).unwrap();
        assert!(spool.open_verified(&reference, 100).is_err());
    }
}
