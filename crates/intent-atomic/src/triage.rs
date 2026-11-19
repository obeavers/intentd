//! Native triage evidence bound to the original candidate/control read cut.
//! Native verdicts and locally signed documents confer no reviewer authority.

use std::collections::{BTreeMap, BTreeSet};

use intent_atomic_proto::{
    triage::{
        CaptureNativeControlRequest, NativeControlSnapshotRef, NativeEvidenceAuthority,
        NativeTriagePreparation, NativeTriageReadRevision, PrepareNativeTriageRequest,
        ReviewerExecutionAvailability,
    },
    Command, HostIdentity, Reply, SpoolRef,
};
use serde_json::Value;

use crate::{
    native_work::{invalid, sha_valid, AtomicNativeWorkClient},
    Result,
};

const MAX_REPORT: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct OwnedNativeControlSnapshot {
    request: CaptureNativeControlRequest,
    snapshot: NativeControlSnapshotRef,
    envelope: SpoolRef,
}

impl OwnedNativeControlSnapshot {
    #[must_use]
    pub fn snapshot(&self) -> &NativeControlSnapshotRef {
        &self.snapshot
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedNativeTriage {
    request: PrepareNativeTriageRequest,
    envelope: SpoolRef,
}

impl OwnedNativeTriage {
    #[must_use]
    pub fn request(&self) -> &PrepareNativeTriageRequest {
        &self.request
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub struct RetainedNativeTriage {
    pub outcome: NativeTriagePreparation,
    pub envelope: SpoolRef,
}

impl AtomicNativeWorkClient {
    /// Capture the full actual native control cut, including qualified auxiliary
    /// rows. A caller-provided descriptor alone is never control authority.
    /// # Errors
    /// Refuses a different binding/projection inventory or invalid descriptor.
    pub async fn capture_control(
        &self,
        request: CaptureNativeControlRequest,
    ) -> Result<OwnedNativeControlSnapshot> {
        validate_control_request(&request)?;
        self.open_store(&request.binding).await?;
        let command = self.retain_command(&request).await?;
        let Reply::NativeControlCaptured { snapshot } = self
            .host
            .request(Command::CaptureNativeControl {
                request: request.clone(),
            })
            .await?
        else {
            return Err(invalid("expected actual native control snapshot"));
        };
        self.verify_command(&command, &request).await?;
        if snapshot.host != HostIdentity::default()
            || snapshot.operation_id != request.operation_id
            || snapshot.binding != request.binding
            || !sha_valid(&snapshot.snapshot_digest)
            || snapshot.snapshot_digest != snapshot.descriptor.sha256
            || snapshot.manifest_merkle.is_empty()
        {
            return Err(invalid(
                "native control snapshot differs from original capture request",
            ));
        }
        let descriptor: Value =
            serde_json::from_slice(&self.read_retained(&snapshot.descriptor, MAX_REPORT).await?)?;
        if descriptor.get("request") != Some(&serde_json::to_value(&request)?)
            || descriptor.get("manifestMerkle").and_then(Value::as_str)
                != Some(snapshot.manifest_merkle.as_str())
            || descriptor.get("policyVersion").and_then(Value::as_u64) != Some(1)
        {
            return Err(invalid(
                "native control descriptor contains another source cut",
            ));
        }
        let envelope = self.retain_command(&snapshot).await?;
        Ok(OwnedNativeControlSnapshot {
            request,
            snapshot,
            envelope,
        })
    }

    /// # Errors
    /// Refuses a triage request not using this exact owned full-control snapshot.
    pub async fn retain_triage(
        &self,
        request: PrepareNativeTriageRequest,
        control: &OwnedNativeControlSnapshot,
    ) -> Result<OwnedNativeTriage> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || request.control_snapshot != control.snapshot
            || request.binding != control.request.binding
            || request.projections != control.request.projections
            || request.binding.repository_id != request.composition.scope.repository_id
            || request.binding.binding_epoch != request.composition.scope.binding_epoch
            || request.composition.host != HostIdentity::default()
        {
            return Err(invalid(
                "native triage request differs from its original composition/control cut",
            ));
        }
        self.verify_command(&control.envelope, &control.snapshot)
            .await?;
        self.open_store(&request.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedNativeTriage { request, envelope })
    }

    /// Retain exact native findings and read revision. Signature verification is
    /// performed by the isolated host; this daemon check binds the received
    /// envelope and bytes to the original request. It creates no portable signer
    /// trust, reviewer identity, independence or source acceptance authority.
    /// # Errors
    /// Refuses foreign replies, changed evidence/read cuts or malformed results.
    pub async fn triage(&self, pending: &OwnedNativeTriage) -> Result<RetainedNativeTriage> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let Reply::NativeTriagePrepared { outcome } = self
            .host
            .request(Command::PrepareNativeTriage {
                request: Box::new(pending.request.clone()),
            })
            .await?
        else {
            return Err(invalid("expected exact native triage preparation"));
        };
        if let NativeTriagePreparation::Produced { receipt } = outcome.as_ref() {
            let request = &pending.request;
            if receipt.host != HostIdentity::default()
                || receipt.operation_id != request.operation_id
                || receipt.scope != request.composition.scope
                || receipt.authority != NativeEvidenceAuthority::EvidenceOnly
                || receipt.reviewer_execution != ReviewerExecutionAvailability::Unavailable
                || receipt.report_schema != "atomic.triage.report.v1"
                || receipt.native_reference.is_empty()
                || receipt.native_reference.len() > 256
                || receipt.evidence.host != HostIdentity::default()
                || receipt.evidence.authority != NativeEvidenceAuthority::EvidenceOnly
                || receipt.evidence.signer.did.is_empty()
                || receipt.evidence.signer.public_key_base32.is_empty()
                || receipt.evidence.cryptosuite.is_empty()
                || receipt.evidence.canonical_content_hash.is_empty()
            {
                return Err(invalid(
                    "native triage evidence differs from its original request",
                ));
            }
            let report_bytes = self.read_retained(&receipt.report, MAX_REPORT).await?;
            let report: Value = serde_json::from_slice(&report_bytes)?;
            let revision_bytes = self
                .read_retained(&receipt.read_revision, MAX_REPORT)
                .await?;
            let revision: NativeTriageReadRevision = serde_json::from_slice(&revision_bytes)?;
            validate_revision(request, &revision)?;
            let evidence_bytes = self
                .read_retained(&receipt.evidence.document, MAX_REPORT)
                .await?;
            let evidence: Value = serde_json::from_slice(&evidence_bytes)?;
            if report.get("reference").and_then(Value::as_str)
                != Some(receipt.native_reference.as_str())
                || report.get("verdict") != Some(&serde_json::to_value(receipt.native_verdict)?)
                || evidence.get("@type").and_then(Value::as_str)
                    != Some("IntentNativeTriageEvidence")
                || evidence.get("schema").and_then(Value::as_str)
                    != Some("intent.native-triage-evidence.v1")
                || evidence.get("authority").and_then(Value::as_str) != Some("evidenceOnly")
                || evidence.get("operationId").and_then(Value::as_str)
                    != Some(request.operation_id.as_str())
                || evidence.get("scope") != Some(&serde_json::to_value(&request.composition.scope)?)
                || evidence.get("reportSha256").and_then(Value::as_str)
                    != Some(receipt.report.sha256.as_str())
                || evidence.get("reportLength").and_then(Value::as_u64)
                    != Some(receipt.report.length)
                || evidence.get("readRevisionSha256").and_then(Value::as_str)
                    != Some(receipt.read_revision.sha256.as_str())
                || evidence.get("readRevision") != Some(&serde_json::to_value(&revision)?)
                || evidence.get("nativeReference").and_then(Value::as_str)
                    != Some(receipt.native_reference.as_str())
                || evidence.get("attributedTo").and_then(Value::as_str)
                    != Some(receipt.evidence.signer.did.as_str())
                || evidence.get("contentHash").and_then(Value::as_str)
                    != Some(receipt.evidence.canonical_content_hash.as_str())
                || evidence.get("reviewerExecution").and_then(Value::as_str) != Some("unavailable")
                || !evidence.get("proof").is_some_and(Value::is_object)
            {
                return Err(invalid(
                    "native triage retained documents contain another report/read revision",
                ));
            }
        } else {
            let reason = match outcome.as_ref() {
                NativeTriagePreparation::Stale { reason }
                | NativeTriagePreparation::Unavailable { reason }
                | NativeTriagePreparation::Malformed { reason } => reason,
                NativeTriagePreparation::Produced { .. } => unreachable!(),
            };
            if reason.is_empty() || reason.len() > 16_384 {
                return Err(invalid("native triage refusal has no bounded reason"));
            }
        }
        let envelope = self.retain_command(outcome.as_ref()).await?;
        Ok(RetainedNativeTriage {
            outcome: *outcome,
            envelope,
        })
    }
}

fn validate_control_request(request: &CaptureNativeControlRequest) -> Result<()> {
    let keys: BTreeSet<_> = request
        .projections
        .iter()
        .map(|item| &item.native_intent_id)
        .collect();
    if request.operation_id.is_empty()
        || request.operation_id.len() > 256
        || request.projections.is_empty()
        || request.projections.len() > 64
        || keys.len() != request.projections.len()
    {
        return Err(invalid(
            "native control capture requires bounded unique projections",
        ));
    }
    Ok(())
}

fn validate_revision(
    request: &PrepareNativeTriageRequest,
    revision: &NativeTriageReadRevision,
) -> Result<()> {
    let selected: BTreeMap<_, _> = request
        .projections
        .iter()
        .map(|item| (&item.native_intent_id, &item.projection))
        .collect();
    let actual: BTreeMap<_, _> = revision
        .controls
        .iter()
        .map(|item| (&item.native_intent_id, &item.projection))
        .collect();
    if revision.composition_receipt_digest != request.composition.receipt_digest
        || revision.candidate_state != request.composition.candidate_state
        || revision.original_target_state != request.composition.target_state
        || revision.materialization_id != request.composition.materialization_id
        || revision.control_snapshot != request.control_snapshot
        || revision.control_manifest_merkle != request.control_snapshot.manifest_merkle
        || !sha_valid(&revision.control_manifest_sha256)
        || revision.project_identity_hash.is_empty()
        || actual != selected
        || actual.len() != revision.controls.len()
        || revision.controls.iter().any(|pin| {
            pin.source_sha256 != pin.projection.pins.source_sha256
                || pin.canonical_hash != pin.projection.pins.canonical_content_hash
                || pin.substance_hash != pin.projection.pins.substance_hash
                || pin.vault_path != format!("intents/{}/intent.md", pin.native_intent_id)
                || !sha_valid(&pin.native_entry_sha256)
        })
    {
        return Err(invalid(
            "native triage read revision differs from exact original inputs",
        ));
    }
    Ok(())
}
