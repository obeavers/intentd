//! Mechanical host-private reconstruction. OS/callback/SQL selection custody
//! remains with the daemon's opaque original-turn producer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use intent_atomic_proto::recording::SelectedFileKind;
use intent_atomic_proto::sealed_record_source::{
    RecordSourcePayload, SealRecordSourceRequest, SealedRecordSource, MAX_RECORD_SOURCE_BYTES,
    MAX_RECORD_SOURCE_FILES, MAX_RECORD_SOURCE_FILE_BYTES, RECORD_SOURCE_PAYLOAD_VERSION,
};
use intent_atomic_proto::{Command, Reply, SpoolRef};

use crate::native_work::{digest, invalid, sha_valid, AtomicNativeWorkClient};
use crate::spool::Spool;
use crate::Result;

const MAX_PAYLOAD: u64 = 512 * 1024 * 1024;

pub struct OwnedRecordSourceSeal {
    request: SealRecordSourceRequest,
    envelope: SpoolRef,
}

impl OwnedRecordSourceSeal {
    #[must_use]
    pub fn request(&self) -> &SealRecordSourceRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub struct RetainedSealedRecordSource {
    pub source: SealedRecordSource,
    pub envelope: SpoolRef,
}

fn safe(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.is_ascii()
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path.split('/').count() <= 64
        && path.split('/').all(|part| {
            !matches!(part, "" | "." | "..")
                && !matches!(
                    part.to_ascii_lowercase().as_str(),
                    ".atomic" | ".atomic-sandbox" | ".atomic-sandbox.d" | ".git"
                )
        })
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || value.len() as u64 > MAX_RECORD_SOURCE_FILE_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "sealed record source contains noncanonical or oversized bytes",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn validate_payload(payload: &RecordSourcePayload) -> Result<()> {
    if payload.version != RECORD_SOURCE_PAYLOAD_VERSION
        || payload.files.len() > MAX_RECORD_SOURCE_FILES
    {
        return Err(invalid(
            "sealed record source payload version or file budget differs",
        ));
    }
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    let mut components = BTreeMap::new();
    let selected_names = payload
        .files
        .iter()
        .map(|entry| entry.file.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut total = 0u64;
    for entry in &payload.files {
        let file = &entry.file;
        if !safe(&file.path)
            || !sha_valid(&file.sha256)
            || previous.is_some_and(|path| path >= file.path.as_str())
            || !folded.insert(file.path.to_ascii_lowercase())
            || file.length > MAX_RECORD_SOURCE_FILE_BYTES
        {
            return Err(invalid(
                "sealed source selected paths are malformed, colliding or unbounded",
            ));
        }
        let mut prefix = String::new();
        for part in file.path.split('/') {
            if !prefix.is_empty() {
                if selected_names.contains(prefix.as_str()) {
                    return Err(invalid(
                        "selected source path has a selected non-directory ancestor",
                    ));
                }
                prefix.push('/');
            }
            prefix.push_str(part);
            if components
                .insert(prefix.to_ascii_lowercase(), prefix.clone())
                .is_some_and(|original| original != prefix)
            {
                return Err(invalid("selected source parent components collide by case"));
            }
        }
        let bytes = decode_hex(&entry.content_hex)?;
        if bytes.len() as u64 != file.length
            || digest(&bytes) != file.sha256
            || (file.kind == SelectedFileKind::Deletion && !bytes.is_empty())
            || (file.kind == SelectedFileKind::Symlink
                && (bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0)))
        {
            return Err(invalid(
                "sealed source bytes differ from their exact selected descriptor",
            ));
        }
        total = total
            .checked_add(file.length)
            .ok_or_else(|| invalid("sealed source length overflow"))?;
        if total > MAX_RECORD_SOURCE_BYTES {
            return Err(invalid("sealed source byte budget exceeded"));
        }
        previous = Some(&file.path);
    }
    Ok(())
}

fn validate_request(request: &SealRecordSourceRequest) -> Result<()> {
    if request.operation_id.is_empty()
        || request.operation_id.len() > 256
        || request.operation_id.chars().any(char::is_control)
        || !sha_valid(&request.selection_digest)
        || request.binding.repository_id != request.capture.repository_id
        || request.scope.repository_id != request.binding.repository_id
        || request.scope.binding_epoch != request.binding.binding_epoch
        || request.scope.workspace_id.is_empty()
        || request.scope.root_id.is_empty()
        || request.binding.binding_epoch != request.capture.binding_epoch
        || request.capture.baseline.repository_id != request.binding.repository_id
        || request.capture.baseline.binding_epoch != request.binding.binding_epoch
        || !sha_valid(&request.capture.baseline_manifest_digest)
        || request.payload.length > MAX_PAYLOAD
        || !sha_valid(&request.payload.sha256)
    {
        return Err(invalid(
            "sealed source request differs from its exact original binding/capture",
        ));
    }
    Ok(())
}

fn private_source(path: &Path, spool: &Path) -> bool {
    path.is_absolute()
        && path != spool
        && path.starts_with(spool)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

impl AtomicNativeWorkClient {
    /// Retain exact bounded selected bytes before constructing an immutable host
    /// request. This performs no native mutation or provider qualification.
    /// # Errors
    /// Refuses malformed selected bytes or unavailable private spool retention.
    pub async fn retain_record_source_payload(
        &self,
        payload: RecordSourcePayload,
    ) -> Result<SpoolRef> {
        validate_payload(&payload)?;
        let bytes = serde_json::to_vec(&payload)?;
        if bytes.len() as u64 > MAX_PAYLOAD {
            return Err(invalid("sealed source serialized payload exceeds budget"));
        }
        let root = self.host.spool_path();
        tokio::task::spawn_blocking(move || Spool::open(&root)?.retain(&bytes))
            .await
            .map_err(|_| invalid("sealed source payload retention worker failed"))?
    }

    /// # Errors
    /// Refuses a foreign binding, changed original payload or invalid request.
    pub async fn retain_record_source_seal(
        &self,
        request: SealRecordSourceRequest,
    ) -> Result<OwnedRecordSourceSeal> {
        validate_request(&request)?;
        let bytes = self.read_retained(&request.payload, MAX_PAYLOAD).await?;
        let payload: RecordSourcePayload = serde_json::from_slice(&bytes)?;
        validate_payload(&payload)?;
        if payload
            .files
            .iter()
            .map(|entry| &entry.file)
            .ne(request.files.iter())
        {
            return Err(invalid(
                "sealed source request relabels its retained selected bytes",
            ));
        }
        self.open_store(&request.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedRecordSourceSeal { request, envelope })
    }

    /// Seal only the original retained command. The host independently validates
    /// its capture journal and immutable baseline, preserving original native IDs.
    /// # Errors
    /// Returns host refusal/uncertainty, changed receipt or unavailable retention.
    pub async fn seal_record_source(
        &self,
        pending: &OwnedRecordSourceSeal,
    ) -> Result<RetainedSealedRecordSource> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        let bytes = self
            .read_retained(&pending.request.payload, MAX_PAYLOAD)
            .await?;
        let payload: RecordSourcePayload = serde_json::from_slice(&bytes)?;
        validate_payload(&payload)?;
        if payload
            .files
            .iter()
            .map(|entry| &entry.file)
            .ne(pending.request.files.iter())
        {
            return Err(invalid("sealed source payload changed before exchange"));
        }
        self.open_store(&pending.request.binding).await?;
        let Reply::RecordSourceSealed { source } = self
            .host
            .request(Command::SealRecordSource {
                request: Box::new(pending.request.clone()),
            })
            .await?
        else {
            return Err(invalid("expected actual private sealed source receipt"));
        };
        if !source.matches_request(&pending.request)
            || source.sealed_state.view != source.expected_state.view
            || source.sealed_state.own_merkle != source.expected_state.own_merkle
            || source.command_digest != digest(&serde_json::to_vec(&pending.request)?)
            || !private_source(&source.sealed_source, &self.host.spool_path())
        {
            return Err(invalid(
                "private sealed source receipt differs from original command",
            ));
        }
        let envelope = self.retain_command(&source).await?;
        Ok(RetainedSealedRecordSource {
            source: *source,
            envelope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_atomic_proto::recording::SelectedFile;
    use intent_atomic_proto::sealed_record_source::RecordSourceFile;

    fn payload(path: &str, bytes: &[u8]) -> RecordSourcePayload {
        RecordSourcePayload {
            version: 1,
            files: vec![RecordSourceFile {
                file: SelectedFile {
                    path: path.into(),
                    kind: SelectedFileKind::Regular,
                    length: bytes.len() as u64,
                    sha256: digest(bytes),
                },
                content_hex: crate::spool::hex(bytes),
            }],
        }
    }

    #[test]
    fn exact_binary_and_crlf_bytes_are_bound_before_host_exchange() {
        let mut source = payload("src/input.bin", b"a\r\n\0\xff");
        assert!(validate_payload(&source).is_ok());
        source.files[0].content_hex.replace_range(0..2, "62");
        assert!(validate_payload(&source).is_err());
    }

    #[test]
    fn traversal_and_casefolded_native_metadata_refuse() {
        for path in [
            "../outside",
            "a/../outside",
            ".ATOMIC/atomic.redb",
            "a/.Git/config",
        ] {
            assert!(validate_payload(&payload(path, b"x")).is_err());
        }
        let mut colliding = payload("A/x", b"x");
        colliding.files.extend(payload("a/y", b"y").files);
        assert!(validate_payload(&colliding).is_err());
        let mut ancestor = payload("a", b"x");
        ancestor.files.extend(payload("a/child", b"y").files);
        assert!(validate_payload(&ancestor).is_err());
    }

    #[test]
    fn deletion_and_symlink_never_reinterpret_regular_bytes() {
        let mut source = payload("selected", b"data");
        source.files[0].file.kind = SelectedFileKind::Deletion;
        assert!(validate_payload(&source).is_err());
        source.files[0].file.kind = SelectedFileKind::Symlink;
        assert!(validate_payload(&source).is_ok());
        source.files[0] = payload("selected", b"bad\0target").files.remove(0);
        source.files[0].file.kind = SelectedFileKind::Symlink;
        assert!(validate_payload(&source).is_err());
    }
}
