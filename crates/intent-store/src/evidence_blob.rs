//! Durable content-addressed evidence bytes, separate from workspace lifetime.
//!
//! The daemon owns the parent directory. Blob names are lowercase SHA-256
//! digests. Unix operations use one pinned directory descriptor and never follow
//! a blob or store-root symlink. Installation cannot overwrite an existing name;
//! a replay verifies the existing bytes before acknowledging their durability.

use std::path::{Path, PathBuf};

use intent_core::vcs::ContentDigest;
use intent_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// A retained object's expected bytes, independent of its filesystem locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceBlob {
    pub digest: ContentDigest,
    pub length: u64,
}

/// Blocking filesystem storage. Callers schedule it outside the async runtime.
#[derive(Debug)]
pub struct EvidenceBlobStore {
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    directory: std::fs::File,
}

impl EvidenceBlobStore {
    /// Open or create a private store beneath an existing daemon-owned parent.
    ///
    /// # Errors
    /// Refuses a symlink/non-directory root, unavailable durability primitives,
    /// or any filesystem failure. Non-Unix durability remains unsupported.
    pub fn open(root: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            unix::open(root)
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(unsupported())
        }
    }

    /// Store bytes, or verify an identical previously installed object.
    ///
    /// # Errors
    /// A corrupt existing object is never overwritten. Write, verification or
    /// synchronization failures return an error, even if installation occurred;
    /// retrying the same bytes verifies and durably acknowledges that object.
    pub fn put(&self, bytes: &[u8]) -> Result<EvidenceBlob> {
        #[cfg(unix)]
        {
            unix::put(self, bytes, |_| Ok(()))
        }
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(unsupported())
        }
    }

    /// Read the exact referenced bytes, verifying length and digest each time.
    ///
    /// # Errors
    /// Refuses malformed references, missing or changed roots, non-regular
    /// objects (including symlinks), corruption, and filesystem failures.
    pub fn read(&self, reference: &EvidenceBlob) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            unix::read(self, reference, true)
        }
        #[cfg(not(unix))]
        {
            let _ = reference;
            Err(unsupported())
        }
    }

    /// Resolve a verified object for a daemon-owned consumer. The returned path
    /// is a locator, not authority; use `read` when consuming bytes directly.
    ///
    /// # Errors
    /// Applies the same reference, root, file-kind and byte checks as `read`.
    pub fn path_for(&self, reference: &EvidenceBlob) -> Result<PathBuf> {
        #[cfg(unix)]
        {
            unix::read(self, reference, false)?;
            Ok(self.root.join(reference.digest.as_str()))
        }
        #[cfg(not(unix))]
        {
            let _ = reference;
            Err(unsupported())
        }
    }
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Internal(format!("evidence blob: {message}"))
}

#[cfg(not(unix))]
fn unsupported() -> Error {
    invalid("durable blob storage is not qualified on this platform")
}

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    use nix::errno::Errno;
    use nix::fcntl::{open as open_file, openat, AtFlags, OFlag};
    use nix::sys::stat::Mode;
    use nix::unistd::{linkat, unlinkat, UnlinkatFlags};
    use sha2::{Digest, Sha256};

    use super::{invalid, ContentDigest, Error, EvidenceBlob, EvidenceBlobStore, Path, Result};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum PutPhase {
        TemporarySynced,
        Installed,
    }

    pub(super) fn open(root: &Path) -> Result<EvidenceBlobStore> {
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir().map_err(invalid)?.join(root)
        };
        let parent = root
            .parent()
            .filter(|_| root.file_name().is_some())
            .ok_or_else(|| {
                invalid("store needs its own directory beneath a daemon-owned parent")
            })?;
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {
                // The directory entry itself must survive a crash too.
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(invalid)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(invalid(error)),
        }
        let directory: File = open_file(
            &root,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(invalid)?
        .into();
        if directory.metadata().map_err(invalid)?.mode() & 0o077 != 0 {
            return Err(invalid("store directory must be private to its owner"));
        }
        directory.sync_all().map_err(invalid)?;
        Ok(EvidenceBlobStore { root, directory })
    }

    fn check_root(store: &EvidenceBlobStore) -> Result<()> {
        let current = std::fs::symlink_metadata(&store.root).map_err(invalid)?;
        let pinned = store.directory.metadata().map_err(invalid)?;
        if !current.is_dir() || current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            return Err(invalid("store root changed after it was opened"));
        }
        Ok(())
    }

    fn validate(reference: &EvidenceBlob) -> Result<&str> {
        let digest = reference.digest.as_str();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidParams(
                "evidence blob digest must be 64 lowercase SHA-256 hex digits".into(),
            ));
        }
        Ok(digest)
    }

    fn object(store: &EvidenceBlobStore, name: &str) -> Result<File> {
        let file: File = openat(
            &store.directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(invalid)?
        .into();
        if !file.metadata().map_err(invalid)?.is_file() {
            return Err(invalid("object is not a regular file"));
        }
        Ok(file)
    }

    fn verify(file: &mut File, reference: &EvidenceBlob, retain: bool) -> Result<Vec<u8>> {
        if !file.metadata().map_err(invalid)?.is_file()
            || file.metadata().map_err(invalid)?.len() != reference.length
        {
            return Err(invalid(
                "object length or file kind differs from its reference",
            ));
        }
        file.seek(SeekFrom::Start(0)).map_err(invalid)?;
        let mut digest = Sha256::new();
        let mut output = Vec::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 8_192];
        loop {
            let count = file.read(&mut buffer).map_err(invalid)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(u64::try_from(count).map_err(invalid)?)
                .ok_or_else(|| invalid("object length overflow"))?;
            if length > reference.length {
                return Err(invalid("object grew during verification"));
            }
            digest.update(&buffer[..count]);
            if retain {
                output.extend_from_slice(&buffer[..count]);
            }
        }
        if length != reference.length
            || format!("{:x}", digest.finalize()) != reference.digest.as_str()
        {
            return Err(invalid("object bytes differ from their reference"));
        }
        Ok(output)
    }

    struct Pending<'a> {
        store: &'a EvidenceBlobStore,
        name: String,
    }

    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            let _ = unlinkat(
                &self.store.directory,
                self.name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
    }

    pub(super) fn put(
        store: &EvidenceBlobStore,
        bytes: &[u8],
        mut observed: impl FnMut(PutPhase) -> Result<()>,
    ) -> Result<EvidenceBlob> {
        check_root(store)?;
        let reference = EvidenceBlob {
            digest: ContentDigest::from_string(format!("{:x}", Sha256::digest(bytes))),
            length: u64::try_from(bytes.len()).map_err(invalid)?,
        };
        let name = validate(&reference)?;
        let temporary_name = format!(".pending-{}", uuid::Uuid::new_v4());
        let mut file: File = openat(
            &store.directory,
            temporary_name.as_str(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(invalid)?
        .into();
        let pending = Pending {
            store,
            name: temporary_name,
        };
        file.write_all(bytes).map_err(invalid)?;
        file.sync_all().map_err(invalid)?;
        verify(&mut file, &reference, false)?;
        observed(PutPhase::TemporarySynced)?;
        match linkat(
            &store.directory,
            pending.name.as_str(),
            &store.directory,
            name,
            AtFlags::empty(),
        ) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(invalid(error)),
        }
        verify(&mut object(store, name)?, &reference, false)?;
        observed(PutPhase::Installed)?;
        // A concurrent creator may not have synced the name yet. Every replay
        // must complete the same durability barrier before returning success.
        drop(pending);
        store.directory.sync_all().map_err(invalid)?;
        Ok(reference)
    }

    pub(super) fn read(
        store: &EvidenceBlobStore,
        reference: &EvidenceBlob,
        retain: bool,
    ) -> Result<Vec<u8>> {
        let name = validate(reference)?;
        check_root(store)?;
        verify(&mut object(store, name)?, reference, retain)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::Arc;

    fn store() -> (tempfile::TempDir, EvidenceBlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceBlobStore::open(&dir.path().join("evidence")).unwrap();
        (dir, store)
    }

    #[test]
    fn replay_verifies_one_installed_object_and_reopen_reads_exact_bytes() {
        let (dir, store) = store();
        let reference = store.put(b"retained evidence\0\xff").unwrap();
        let path = store.path_for(&reference).unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(store.put(b"retained evidence\0\xff").unwrap(), reference);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        drop(store);
        let reopened = EvidenceBlobStore::open(&dir.path().join("evidence")).unwrap();
        assert_eq!(
            reopened.read(&reference).unwrap(),
            b"retained evidence\0\xff"
        );
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let empty = reopened.put(&[]).unwrap();
        assert_eq!(reopened.read(&empty).unwrap(), b"");
    }

    #[test]
    fn concurrent_identical_creates_converge_without_overwrite() {
        let (_dir, store) = store();
        let store = Arc::new(store);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || store.put(b"same bytes").unwrap())
            })
            .collect();
        let references: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(references
            .iter()
            .all(|reference| reference == &references[0]));
        assert_eq!(store.read(&references[0]).unwrap(), b"same bytes");
        assert_eq!(std::fs::read_dir(&store.root).unwrap().count(), 1);
    }

    #[test]
    fn tampered_existing_object_is_never_repaired_by_overwriting_it() {
        let (_dir, store) = store();
        let reference = store.put(b"expected").unwrap();
        let path = store.path_for(&reference).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        assert!(store.read(&reference).is_err());
        assert!(store.path_for(&reference).is_err());
        assert!(store.put(b"expected").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"tampered");
    }

    #[test]
    fn malformed_or_wrong_length_references_are_refused() {
        let (_dir, store) = store();
        let reference = store.put(b"bytes").unwrap();
        for digest in [
            "../outside",
            "/outside",
            "",
            &"A".repeat(64),
            &"a".repeat(63),
        ] {
            let invalid = EvidenceBlob {
                digest: ContentDigest::from_string(digest),
                length: 5,
            };
            assert!(matches!(store.read(&invalid), Err(Error::InvalidParams(_))));
            assert!(store.path_for(&invalid).is_err());
        }
        let wrong_length = EvidenceBlob {
            length: 4,
            ..reference
        };
        assert!(store.read(&wrong_length).is_err());
    }

    #[test]
    fn symlink_objects_and_roots_never_follow_the_target() {
        let (dir, store) = store();
        let reference = store.put(b"retained").unwrap();
        let object = store.path_for(&reference).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"retained").unwrap();
        std::fs::remove_file(&object).unwrap();
        symlink(&outside, &object).unwrap();
        assert!(store.read(&reference).is_err());
        assert!(store.put(b"retained").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"retained");
        let alias = dir.path().join("alias");
        symlink(&store.root, &alias).unwrap();
        assert!(EvidenceBlobStore::open(&alias).is_err());
    }

    #[test]
    fn replaced_store_root_is_refused_without_touching_replacement() {
        let (dir, store) = store();
        let reference = store.put(b"retained").unwrap();
        let old = dir.path().join("old");
        std::fs::rename(&store.root, &old).unwrap();
        std::fs::create_dir(&store.root).unwrap();
        assert!(store.read(&reference).is_err());
        assert!(store.put(b"replacement").is_err());
        assert_eq!(std::fs::read_dir(&store.root).unwrap().count(), 0);
    }

    #[test]
    fn interrupted_installation_can_be_retried_without_duplicate_objects() {
        for failed_phase in [unix::PutPhase::TemporarySynced, unix::PutPhase::Installed] {
            let (_dir, store) = store();
            let result = unix::put(&store, b"recoverable", |phase| {
                if phase == failed_phase {
                    Err(invalid("injected interruption"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            let reference = store.put(b"recoverable").unwrap();
            assert_eq!(store.read(&reference).unwrap(), b"recoverable");
            assert_eq!(std::fs::read_dir(&store.root).unwrap().count(), 1);
        }
    }

    #[test]
    fn orphaned_temporary_bytes_are_not_read_as_evidence() {
        let (_dir, store) = store();
        std::fs::write(store.root.join(".pending-orphan"), b"half written").unwrap();
        let reference = store.put(b"complete").unwrap();
        assert_eq!(store.read(&reference).unwrap(), b"complete");
        assert_eq!(
            std::fs::read(store.root.join(".pending-orphan")).unwrap(),
            b"half written"
        );
    }

    #[test]
    fn refuses_a_nonprivate_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(EvidenceBlobStore::open(&path).is_err());
    }
}
