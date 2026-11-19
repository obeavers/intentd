//! Pinned identities for the developer-owned output, daemon and database paths.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

use intent_core::Result;

use super::association::invalid;

#[derive(Debug)]
pub(crate) struct DirectoryGuard {
    path: PathBuf,
    file: File,
    identity: Identity,
}

#[derive(Debug)]
pub(crate) struct FileGuard {
    path: PathBuf,
    file: File,
    identity: Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn identity(metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn identity(_metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: 0,
        inode: 0,
    }
}

fn fs_error(error: impl std::fmt::Display) -> intent_core::Error {
    intent_core::Error::Internal(format!("Atomic tracer owned path: {error}"))
}

impl DirectoryGuard {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        // Exclusive creation refuses existing directories and symlinks alike.
        std::fs::create_dir(path).map_err(fs_error)?;
        Self::open(path)
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(invalid("pinned tracer directories require Unix"));
        }
        #[cfg(unix)]
        {
            use nix::{
                fcntl::{open, OFlag},
                sys::stat::Mode,
            };
            let fd = open(
                path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(fs_error)?;
            let file = File::from(fd);
            let expected = identity(&file.metadata().map_err(fs_error)?);
            let guard = Self {
                path: path.to_path_buf(),
                file,
                identity: expected,
            };
            guard.validate()?;
            Ok(guard)
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let held = self.file.metadata().map_err(fs_error)?;
        let current = std::fs::symlink_metadata(&self.path).map_err(fs_error)?;
        if !held.is_dir()
            || !current.file_type().is_dir()
            || identity(&held) != self.identity
            || identity(&current) != self.identity
        {
            return Err(invalid(
                "owned tracer directory was replaced or became a symlink",
            ));
        }
        Ok(())
    }

    pub(crate) fn create_child(&self, name: &str) -> Result<Self> {
        self.validate()?;
        if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(invalid("invalid owned child name"));
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            return Err(invalid("pinned tracer directories require Unix"));
        }
        #[cfg(unix)]
        {
            use nix::{
                fcntl::{openat, OFlag},
                sys::stat::{mkdirat, Mode},
            };
            mkdirat(&self.file, name, Mode::from_bits_truncate(0o700)).map_err(fs_error)?;
            let fd = openat(
                &self.file,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(fs_error)?;
            let file = File::from(fd);
            let expected = identity(&file.metadata().map_err(fs_error)?);
            let child = Self {
                path: self.path.join(name),
                file,
                identity: expected,
            };
            self.validate()?;
            child.validate()?;
            Ok(child)
        }
    }

    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(invalid("invalid retained filename"));
        }
        #[cfg(not(unix))]
        {
            let _ = (name, bytes);
            return Err(invalid("pinned tracer writes require Unix"));
        }
        #[cfg(unix)]
        {
            use nix::{
                fcntl::{openat, OFlag},
                sys::stat::Mode,
            };
            use std::io::Write as _;
            let fd = openat(
                &self.file,
                name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(fs_error)?;
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(fs_error)?;
            file.sync_all().map_err(fs_error)?;
            self.file.sync_all().map_err(fs_error)?;
            self.validate()
        }
    }
}

impl FileGuard {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(invalid("pinned tracer files require Unix"));
        }
        #[cfg(unix)]
        {
            use nix::{
                fcntl::{open, OFlag},
                sys::stat::Mode,
            };
            let fd = open(
                path,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(fs_error)?;
            let file = File::from(fd);
            let metadata = file.metadata().map_err(fs_error)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(invalid("tracer database must be a private regular file"));
            }
            let expected = identity(&metadata);
            let guard = Self {
                path: path.to_path_buf(),
                file,
                identity: expected,
            };
            guard.validate()?;
            Ok(guard)
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let held = self.file.metadata().map_err(fs_error)?;
        let current = std::fs::symlink_metadata(&self.path).map_err(fs_error)?;
        if !held.is_file()
            || !current.file_type().is_file()
            || identity(&held) != self.identity
            || identity(&current) != self.identity
        {
            return Err(invalid(
                "owned tracer database was replaced or became a symlink",
            ));
        }
        #[cfg(unix)]
        {
            if held.nlink() != 1 || current.nlink() != 1 {
                return Err(invalid("owned tracer database acquired another link"));
            }
        }
        Ok(())
    }
}
