//! Owner-private filesystem metadata. Never interprets an untrusted locator as authority.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::fcntl::OFlag;
use serde::{de::DeserializeOwned, Serialize};

use crate::{HostError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(crate) fn private_dir(path: &Path) -> Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => sync_parent(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(HostError::Invalid(
            "host directories must be private real directories",
        ));
    }
    Ok(())
}

pub(crate) fn identity(path: &Path, directory: bool) -> Result<FileIdentity> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(HostError::Invalid("native locator has the wrong file kind"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65_536 {
        return Err(HostError::Invalid(
            "host metadata must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(HostError::Invalid("host metadata exceeded its bound"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 65_536 {
        return Err(HostError::Invalid("host metadata exceeds frame bound"));
    }
    let parent = path
        .parent()
        .ok_or(HostError::Invalid("metadata needs a parent"))?;
    let temporary = parent.join(format!(".pending-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        if replace {
            // Callers have checked the immutable command before replacing its
            // own journal entry. Refuse symlink substitution even in this private directory.
            identity(path, false)?;
            std::fs::rename(&temporary, path)?;
        } else {
            std::fs::hard_link(&temporary, path)?;
            std::fs::remove_file(&temporary)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(HostError::Invalid("directory needs a parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Initialization creates no source files. Flush every initialized native file
/// and directory before persisting the primitive's identity receipt.
pub(crate) fn sync_tree(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(HostError::Invalid("symlink in native initialization"));
    }
    if metadata.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for child in std::fs::read_dir(path)? {
            sync_tree(&child?.path())?;
        }
        File::open(path)?.sync_all()?;
    } else if metadata.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
            .open(path)?
            .sync_all()?;
    } else {
        return Err(HostError::Invalid("special file in native initialization"));
    }
    Ok(())
}
