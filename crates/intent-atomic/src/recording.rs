//! Exact native record requests remain owned across cancellation and recovery.
//! A returned record fact is separate from task/source authorization and from
//! any subsequent reconciliation, which must never erase that fact.

use std::{collections::BTreeSet, path::Component};

use intent_atomic_proto::{
    recording::{
        NativeRecordReceipt, PrepareRecordRequest, PreparedNativeRecord, RecordPreparation,
        SelectedFileKind, RECORD_POLICY_VERSION,
    },
    Command, HostIdentity, Reply, SpoolRef,
};

use crate::{
    intents::RetainedNativeTurnFreeze,
    native_work::{
        digest, invalid, native_hash, sha_valid, AtomicNativeWorkClient, MAX_RECORD_BYTES,
    },
    Result,
};

#[derive(Clone)]
pub struct OwnedRecordPreparation {
    request: PrepareRecordRequest,
    envelope: SpoolRef,
    freeze: Option<RetainedFreeze>,
}

#[derive(Clone)]
struct RetainedFreeze {
    receipt: intent_atomic_proto::intents::NativeTurnFreezeReceipt,
    envelope: SpoolRef,
}

impl OwnedRecordPreparation {
    #[must_use]
    pub fn request(&self) -> &PrepareRecordRequest {
        &self.request
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedPreparedRecord {
    original: OwnedRecordPreparation,
    prepared: PreparedNativeRecord,
    envelope: SpoolRef,
}

impl OwnedPreparedRecord {
    #[must_use]
    pub fn prepared(&self) -> &PreparedNativeRecord {
        &self.prepared
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub enum OwnedPreparedRecordOutcome {
    Prepared(Box<OwnedPreparedRecord>),
    NoChanges {
        original: Box<OwnedRecordPreparation>,
        envelope: SpoolRef,
    },
}

pub struct RetainedNativeRecordAdmission {
    pub receipt: NativeRecordReceipt,
    /// Missing spool retention cannot erase the already validated native fact.
    pub envelope: Option<SpoolRef>,
    pub post_effect_retention_error: Option<String>,
}

impl AtomicNativeWorkClient {
    /// Restore only the exact retained preparation after daemon restart. This
    /// reads local immutable evidence without normal store admission, so an
    /// unresolved original operation can reach the narrow native recovery lane.
    /// The host still verifies its own durable journal before any admission.
    /// # Errors
    /// Refuses changed request/encoding bytes, foreign private paths or outcomes.
    pub async fn restore_record_preparation(
        &self,
        request_envelope: &SpoolRef,
        prepared_envelope: &SpoolRef,
    ) -> Result<OwnedPreparedRecordOutcome> {
        let request: PrepareRecordRequest =
            serde_json::from_slice(&self.read_retained(request_envelope, 48_000).await?)?;
        self.verify_command(request_envelope, &request).await?;
        validate_request(&request, &self.host.spool_path())?;
        let outcome: RecordPreparation = serde_json::from_slice(
            &self
                .read_retained(prepared_envelope, crate::native_work::MAX_METADATA)
                .await?,
        )?;
        self.verify_command(prepared_envelope, &outcome).await?;
        validate_preparation(&request, &outcome)?;
        let original = OwnedRecordPreparation {
            request,
            envelope: request_envelope.clone(),
            freeze: None,
        };
        match outcome {
            RecordPreparation::Prepared { record } => {
                self.read_retained(&record.bytes, MAX_RECORD_BYTES).await?;
                Ok(OwnedPreparedRecordOutcome::Prepared(Box::new(
                    OwnedPreparedRecord {
                        original,
                        prepared: *record,
                        envelope: prepared_envelope.clone(),
                    },
                )))
            }
            RecordPreparation::NoChanges { .. } => Ok(OwnedPreparedRecordOutcome::NoChanges {
                original: Box::new(original),
                envelope: prepared_envelope.clone(),
            }),
        }
    }

    /// Prepare a mechanical unbound record exchange for explicit local owners.
    /// Source-authoring lifecycle callers must use `retain_bound_record`.
    /// # Errors
    /// Refuses unbounded inputs, foreign private sources or unavailable stores.
    pub async fn retain_record(
        &self,
        request: PrepareRecordRequest,
    ) -> Result<OwnedRecordPreparation> {
        validate_request(&request, &self.host.spool_path())?;
        self.open_store(&request.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedRecordPreparation {
            request,
            envelope,
            freeze: None,
        })
    }

    /// # Errors
    /// Refuses a different record operation/binding or changed frozen envelope.
    pub async fn retain_bound_record(
        &self,
        request: PrepareRecordRequest,
        frozen: &RetainedNativeTurnFreeze,
    ) -> Result<OwnedRecordPreparation> {
        if frozen.receipt.host != HostIdentity::default()
            || frozen.receipt.operation_id != request.operation_id
            || frozen.receipt.binding != request.binding
        {
            return Err(invalid(
                "record source differs from its original native freeze",
            ));
        }
        self.verify_command(&frozen.envelope, &frozen.receipt)
            .await?;
        let mut owned = self.retain_record(request).await?;
        owned.freeze = Some(RetainedFreeze {
            receipt: frozen.receipt.clone(),
            envelope: frozen.envelope.clone(),
        });
        Ok(owned)
    }

    /// Send only the retained immutable selection and metadata. Native object
    /// encoding/hashing is performed by the isolated host, never reconstructed.
    /// # Errors
    /// Returns host/transport uncertainty or changed selection/encoding receipts.
    pub async fn prepare_record(
        &self,
        pending: &OwnedRecordPreparation,
    ) -> Result<OwnedPreparedRecordOutcome> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let command = if let Some(frozen) = &pending.freeze {
            self.verify_command(&frozen.envelope, &frozen.receipt)
                .await?;
            Command::PrepareBoundExactRecord {
                request: Box::new(pending.request.clone()),
                freeze: Box::new(frozen.receipt.clone()),
            }
        } else {
            Command::PrepareExactRecord {
                request: Box::new(pending.request.clone()),
            }
        };
        let Reply::ExactRecordPrepared { outcome } = self.host.request(command).await? else {
            return Err(invalid("expected exact native record preparation"));
        };
        validate_preparation(&pending.request, &outcome)?;
        let envelope = self.retain_command(&outcome).await?;
        match *outcome {
            RecordPreparation::Prepared { record } => {
                self.read_retained(&record.bytes, MAX_RECORD_BYTES).await?;
                Ok(OwnedPreparedRecordOutcome::Prepared(Box::new(
                    OwnedPreparedRecord {
                        original: pending.clone(),
                        prepared: *record,
                        envelope,
                    },
                )))
            }
            RecordPreparation::NoChanges { .. } => Ok(OwnedPreparedRecordOutcome::NoChanges {
                original: Box::new(pending.clone()),
                envelope,
            }),
        }
    }

    /// Finish only this exact prepared operation. This is the narrow same-journal
    /// recovery call; it does not admit unrelated mutations on a blocked host.
    /// Persist the returned receipt before attempting `reconcile` separately.
    /// # Errors
    /// Returns uncertain/native refusal or a mismatched exact membership receipt.
    pub async fn admit_record(
        &self,
        pending: &OwnedPreparedRecord,
    ) -> Result<RetainedNativeRecordAdmission> {
        self.verify_command(&pending.original.envelope, &pending.original.request)
            .await?;
        let outcome = RecordPreparation::Prepared {
            record: Box::new(pending.prepared.clone()),
        };
        self.verify_command(&pending.envelope, &outcome).await?;
        self.read_retained(&pending.prepared.bytes, MAX_RECORD_BYTES)
            .await?;
        if self.host.recovery_ready().await {
            self.open_store(&pending.prepared.binding).await?;
        } else {
            let recovery = self.reconcile().await?;
            if recovery.ready {
                self.open_store(&pending.prepared.binding).await?;
            } else if recovery.unresolved_operation_ids != [pending.prepared.operation_id.clone()] {
                return Err(crate::HostError::RecoveryRequired);
            }
        }
        let Reply::ExactRecordAdmitted { receipt } = self
            .host
            .request(Command::AdmitExactRecord {
                prepared: Box::new(pending.prepared.clone()),
            })
            .await?
        else {
            return Err(invalid("expected exact native record membership receipt"));
        };
        validate_admission(&pending.prepared, &receipt)?;
        let retention = self.retain_command(&receipt).await;
        Ok(admission_fact(receipt, retention))
    }
}

fn admission_fact(
    receipt: NativeRecordReceipt,
    retained: Result<SpoolRef>,
) -> RetainedNativeRecordAdmission {
    let (envelope, post_effect_retention_error) = match retained {
        Ok(envelope) => (Some(envelope), None),
        Err(error) => (None, Some(error.to_string())),
    };
    RetainedNativeRecordAdmission {
        receipt,
        envelope,
        post_effect_retention_error,
    }
}

fn validate_request(request: &PrepareRecordRequest, spool: &std::path::Path) -> Result<()> {
    if request.operation_id.is_empty()
        || request.operation_id.len() > 256
        || request.files.is_empty()
        || request.files.len() > 1024
        || request.message.is_empty()
        || request.author_name.is_empty()
        || !request.sealed_source.is_absolute()
        || request.sealed_source == spool
        || !request.sealed_source.starts_with(spool)
        || request
            .sealed_source
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || serde_json::to_vec(request)?.len() > 48_000
        || request.expected_state.view.is_empty()
        || request.expected_state.effective_state.is_empty()
        || request.expected_state.own_merkle.is_empty()
    {
        return Err(invalid(
            "native record request exceeds its exact private-source scope",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut bytes = 0_u64;
    for file in &request.files {
        bytes = bytes
            .checked_add(file.length)
            .ok_or_else(|| invalid("native record byte budget overflow"))?;
        if !safe_path(&file.path)
            || !seen.insert(&file.path)
            || !sha_valid(&file.sha256)
            || bytes > 128 * 1024 * 1024
        {
            return Err(invalid(
                "native record selection is invalid or exceeds its byte budget",
            ));
        }
    }
    let _: serde_json::Value = serde_json::from_str(&request.context_json)?;
    Ok(())
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.is_ascii()
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.eq_ignore_ascii_case(".git")
                && !part.eq_ignore_ascii_case(".atomic")
        })
}

fn validate_preparation(request: &PrepareRecordRequest, outcome: &RecordPreparation) -> Result<()> {
    let command = digest(&serde_json::to_vec(request)?);
    let selection = digest(&serde_json::to_vec(&request.files)?);
    match outcome {
        RecordPreparation::NoChanges {
            operation_id,
            command_digest,
            expected_state,
            selection_digest,
        } if operation_id == &request.operation_id
            && command_digest == &command
            && expected_state == &request.expected_state
            && selection_digest == &selection =>
        {
            Ok(())
        }
        RecordPreparation::Prepared { record } => {
            let metadata = native_metadata_digest(request, &selection)?;
            let paths: BTreeSet<_> = record.recorded_paths.iter().collect();
            let deleted: BTreeSet<_> = record.deleted_paths.iter().collect();
            if record.host != HostIdentity::default()
                || record.operation_id != request.operation_id
                || record.binding != request.binding
                || record.expected_state != request.expected_state
                || record.command_digest != command
                || record.selection_digest != selection
                || record.metadata_digest != metadata
                || !native_hash(&record.change_hash)
                || record.bytes.length == 0
                || record.bytes.length > 128 * 1024 * 1024
                || !sha_valid(&record.bytes.sha256)
                || paths.len() != record.recorded_paths.len()
                || deleted.len() != record.deleted_paths.len()
                || !paths.is_disjoint(&deleted)
                || paths.is_empty() && deleted.is_empty()
                || record.recorded_paths.iter().any(|path| {
                    !request
                        .files
                        .iter()
                        .any(|file| file.path == *path && file.kind != SelectedFileKind::Deletion)
                })
                || record.deleted_paths.iter().any(|path| {
                    !request
                        .files
                        .iter()
                        .any(|file| file.path == *path && file.kind == SelectedFileKind::Deletion)
                })
            {
                return Err(invalid(
                    "native record preparation differs from original selection and metadata",
                ));
            }
            Ok(())
        }
        RecordPreparation::NoChanges { .. } => Err(invalid(
            "native no-change outcome differs from original exact request",
        )),
    }
}

fn native_metadata_digest(request: &PrepareRecordRequest, selection: &str) -> Result<String> {
    // The independent host uses serde_json's default sorted-object encoding.
    // Intent enables preserve_order workspace-wide; do not let that feature
    // change the hash of the same native metadata/context across the boundary.
    fn sorted(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(values) => {
                let ordered: std::collections::BTreeMap<_, _> = values
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect();
                serde_json::Value::Object(ordered.into_iter().collect())
            }
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sorted).collect())
            }
            other => other,
        }
    }
    let context: serde_json::Value = serde_json::from_str(&request.context_json)?;
    Ok(digest(&serde_json::to_vec(&sorted(serde_json::json!({
        "policyVersion": RECORD_POLICY_VERSION, "operationId":request.operation_id,
        "repositoryId":request.binding.repository_id,"bindingEpoch":request.binding.binding_epoch,
        "selectionDigest":selection,"context":context
    })))?))
}

fn validate_admission(
    prepared: &PreparedNativeRecord,
    receipt: &NativeRecordReceipt,
) -> Result<()> {
    if receipt.operation_id != prepared.operation_id
        || receipt.change_hash != prepared.change_hash
        || receipt.encoding_sha256 != prepared.bytes.sha256
        || receipt.encoding_length != prepared.bytes.length
        || receipt.before != prepared.expected_state
        || receipt.after.view != prepared.expected_state.view
        || receipt.after.effective_state.is_empty()
        || receipt.after.own_merkle.is_empty()
    {
        return Err(invalid(
            "native record admission differs from its original exact encoding",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
