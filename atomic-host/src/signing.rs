//! Daemon-owned native Ed25519 evidence signing. No default/user Atomic identity
//! store is opened, and a signature never maps its key to a reviewer principal.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use atomic_identity::{
    keypair::{KeyPair, SecretKey},
    signing::Signer,
};
use intent_atomic_proto::{
    triage::{LocalNativeSigner, NativeEvidenceAuthority, SignedNativeEvidence},
    HostIdentity,
};
use serde_json::Value;

use crate::{composition, durable, Host, HostError, Result};

const MAX_DOCUMENT: u64 = 1024 * 1024;
fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}

fn owner(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid takes no arguments and does not access Rust memory.
    if metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir() || metadata.mode() & 0o077 != 0
        } else {
            !metadata.is_file()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != 32
        }
    {
        return Err(HostError::Invalid(
            "native evidence key requires private owned real files",
        ));
    }
    Ok(())
}

fn key(host: &Host, create: bool) -> Result<KeyPair> {
    let directory = host.config.config_dir.join("evidence-keys");
    if !create && !directory.try_exists()? {
        return Err(HostError::Invalid("native evidence key is unavailable"));
    }
    durable::private_dir(&directory)?;
    owner(&directory, true)?;
    let path = directory.join("ed25519.key");
    if !path.try_exists()? {
        if !create {
            return Err(HostError::Invalid("native evidence key is unavailable"));
        }
        let key = KeyPair::generate();
        let temporary = directory.join(format!(".pending-{}", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&temporary)?;
        file.write_all(key.secret.as_bytes())?;
        file.sync_all()?;
        let publication = std::fs::hard_link(&temporary, &path);
        std::fs::remove_file(&temporary)?;
        match publication {
            Ok(()) => File::open(&directory)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    owner(&path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(&path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and does not access Rust memory.
    if !metadata.is_file()
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.len() != 32
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(HostError::Invalid(
            "native evidence key changed while opening",
        ));
    }
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(HostError::Invalid("native evidence key length changed"));
    }
    let pair = KeyPair::from_secret_key(SecretKey::from_bytes(&bytes));
    bytes.fill(0);
    let signer = LocalNativeSigner {
        did: atomic_canonical::did::did_for_public_key(&pair.public),
        public_key_base32: pair.public.to_base32(),
    };
    let identity = directory.join("identity.json");
    if identity.try_exists()? {
        let original: LocalNativeSigner = durable::read_json(&identity)?;
        if original != signer {
            return Err(HostError::Invalid(
                "configured native evidence key identity changed",
            ));
        }
    } else {
        if !create {
            return Err(HostError::Invalid(
                "native evidence signer identity is unavailable",
            ));
        }
        durable::write_json(&identity, &signer, false)?;
    }
    Ok(pair)
}

/// Caller holds the host writer lane so signer/control evidence revisions cannot
/// interleave. This helper only writes its own key and immutable spool artifacts.
pub(crate) fn attest(host: &Host, mut value: Value) -> Result<SignedNativeEvidence> {
    let key = key(host, true)?;
    let object = value.as_object_mut().ok_or(HostError::Invalid(
        "native signed evidence must be an object",
    ))?;
    if object.contains_key("proof") {
        return Err(HostError::Invalid(
            "native evidence cannot replace an existing proof",
        ));
    }
    let did = atomic_canonical::did::did_for_public_key(&key.public);
    if object.get("attributedTo").is_some_and(|author| {
        author
            .as_str()
            .is_none_or(|author| !author.is_empty() && author != did)
    }) {
        return Err(HostError::Invalid(
            "native evidence attributedTo differs from configured signing key",
        ));
    }
    object.insert("attributedTo".into(), Value::String(did.clone()));
    let prepared = atomic_canonical::proof::prepare_attestation(value, &key.public);
    let signature = Signer::new(&key).sign(&prepared.signing_bytes);
    let signed = atomic_canonical::proof::attach_proof(prepared.value, &key.public, &signature);
    atomic_canonical::proof::verify_value(&signed, &key.public).map_err(native)?;
    let bytes = atomic_canonical::jcs::canonicalize(&signed).into_bytes();
    if u64::try_from(bytes.len()).map_err(native)? > MAX_DOCUMENT {
        return Err(HostError::Invalid(
            "native signed evidence exceeds byte budget",
        ));
    }
    let document = composition::retain_bytes(host, &bytes, MAX_DOCUMENT)?;
    Ok(SignedNativeEvidence {
        host: HostIdentity::default(),
        authority: NativeEvidenceAuthority::EvidenceOnly,
        signer: LocalNativeSigner {
            did,
            public_key_base32: key.public.to_base32(),
        },
        cryptosuite: atomic_canonical::proof::CRYPTOSUITE.into(),
        canonical_content_hash: signed
            .get("contentHash")
            .and_then(Value::as_str)
            .ok_or(HostError::Invalid(
                "native signer omitted canonical content hash",
            ))?
            .into(),
        document,
    })
}

pub(crate) fn verify(host: &Host, evidence: &SignedNativeEvidence) -> Result<Value> {
    let key = key(host, false)?;
    if evidence.host != HostIdentity::default()
        || evidence.authority != NativeEvidenceAuthority::EvidenceOnly
        || evidence.cryptosuite != atomic_canonical::proof::CRYPTOSUITE
        || evidence.signer.public_key_base32 != key.public.to_base32()
        || evidence.signer.did != atomic_canonical::did::did_for_public_key(&key.public)
    {
        return Err(HostError::Invalid(
            "native evidence signer differs from configured identity",
        ));
    }
    let bytes = composition::read_spool(host, &evidence.document, MAX_DOCUMENT)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if atomic_canonical::jcs::canonicalize(&value).as_bytes() != bytes
        || value.get("attributedTo").and_then(Value::as_str) != Some(evidence.signer.did.as_str())
        || value.get("contentHash").and_then(Value::as_str)
            != Some(evidence.canonical_content_hash.as_str())
    {
        return Err(HostError::Invalid(
            "native evidence content or attributedTo changed",
        ));
    }
    atomic_canonical::proof::verify_value(&value, &key.public).map_err(native)?;
    Ok(value)
}

impl Host {
    /// Qualify canonical signing only; this does not create a native review,
    /// bind a reviewer principal, or change an Intent task/candidate state.
    /// # Errors
    /// Refuses signer substitution, malformed values and unsafe key storage.
    pub fn sign_local_native_evidence(&self, value: Value) -> Result<SignedNativeEvidence> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        attest(self, value)
    }

    /// Verify actual native proof plus the explicit configured attributedTo.
    /// # Errors
    /// Refuses tampered content/proofs, changed key identity and unsafe bytes.
    pub fn verify_local_native_evidence(&self, evidence: &SignedNativeEvidence) -> Result<Value> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        verify(self, evidence)
    }
}

#[cfg(test)]
mod tests;
