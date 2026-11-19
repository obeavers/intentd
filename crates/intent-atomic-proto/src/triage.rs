//! Native triage/signing evidence. These values never establish a reviewer
//! principal, independent execution, task readiness or source mutation authority.

use crate::{HostIdentity, SpoolRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeEvidenceAuthority {
    EvidenceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalNativeSigner {
    /// Native DID derived from the real Ed25519 public key, never an agent label.
    pub did: String,
    pub public_key_base32: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedNativeEvidence {
    pub host: HostIdentity,
    pub authority: NativeEvidenceAuthority,
    pub signer: LocalNativeSigner,
    pub cryptosuite: String,
    pub canonical_content_hash: String,
    /// Exact JCS document with native proof; no secret key or native configuration.
    pub document: SpoolRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageTaskProjection {
    pub native_intent_id: String,
    pub projection: crate::intents::IntentProjectionRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareNativeTriageRequest {
    pub operation_id: String,
    pub binding: crate::StoreBinding,
    pub composition: crate::composition::PrivateCompositionReceipt,
    pub control_snapshot: NativeControlSnapshotRef,
    /// Every current Intent/task entry must have an exact selected projection;
    /// qualified auxiliary entries are pinned separately by `control_snapshot`.
    pub projections: Vec<TriageTaskProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeControlReadPin {
    pub native_intent_id: String,
    pub projection: crate::intents::IntentProjectionRef,
    pub vault_path: String,
    pub source_sha256: String,
    pub native_entry_sha256: String,
    pub canonical_hash: String,
    pub substance_hash: String,
    pub proof_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTriageReadRevision {
    pub composition_receipt_digest: String,
    pub candidate_state: crate::StateToken,
    pub original_target_state: crate::StateToken,
    pub materialization_id: String,
    pub control_manifest_merkle: String,
    pub control_manifest_sha256: String,
    pub project_identity_hash: String,
    pub controls: Vec<NativeControlReadPin>,
    pub control_snapshot: NativeControlSnapshotRef,
    pub auxiliaries: Vec<AuxiliaryControlReadPin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeTriageVerdict {
    Ready,
    Blocked,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReviewerExecutionAvailability {
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTriageReceipt {
    pub operation_id: String,
    pub host: HostIdentity,
    pub scope: crate::closures::ClosureScope,
    pub authority: NativeEvidenceAuthority,
    pub reviewer_execution: ReviewerExecutionAvailability,
    pub report_schema: String,
    pub report: SpoolRef,
    pub native_reference: String,
    pub native_verdict: NativeTriageVerdict,
    pub read_revision: SpoolRef,
    /// Full signed envelope covers original fences, exact report bytes and read revisions.
    pub evidence: SignedNativeEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase", deny_unknown_fields)]
pub enum NativeTriagePreparation {
    Produced { receipt: Box<NativeTriageReceipt> },
    Stale { reason: String },
    Unavailable { reason: String },
    Malformed { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureNativeControlRequest {
    pub operation_id: String,
    pub binding: crate::StoreBinding,
    pub projections: Vec<TriageTaskProjection>,
}

/// Host-observed exact read cut, not a grant or caller-created authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeControlSnapshotRef {
    pub operation_id: String,
    pub host: HostIdentity,
    pub binding: crate::StoreBinding,
    pub descriptor: SpoolRef,
    pub manifest_merkle: String,
    pub snapshot_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum NativeCanonicalObservation {
    Canonical {
        content_hash: String,
        proof_sha256: Option<String>,
    },
    NotApplicable {
        reason: String,
        raw_proof_sha256: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuxiliaryControlReadPin {
    pub path: String,
    pub kind: String,
    pub native_entry_sha256: String,
    pub native_body_hash: String,
    pub source_sha256: String,
    pub canonical: NativeCanonicalObservation,
    pub substance: NativeSubstanceObservation,
    pub proof: NativeProofObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum NativeSubstanceObservation {
    NotApplicable { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeProofObservation {
    Absent,
}
