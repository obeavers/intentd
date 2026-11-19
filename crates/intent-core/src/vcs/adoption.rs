//! Exact target capture and adoption. Serialized descriptions do not authorize
//! effects: a live service barrier, an accepted Store decision and an inspecting
//! backend observation are separate, opaque carriers.

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};

use super::{ContentDigest, MaterializationId, NativeStateRef, OperationId, RootBinding};
use crate::{Error, Result};

/// Lifetime attestation held by the actual service write-barrier owner. This is
/// neither wire data nor a substitute for closing/draining real turn admission.
/// The owner permanently clears `live` before releasing its barrier.
pub struct WriteBarrierPermit {
    root: RootBinding,
    operation_id: OperationId,
    live: Arc<AtomicBool>,
}

impl WriteBarrierPermit {
    /// Constructor sites are restricted to the actual service barrier owner.
    /// # Errors
    /// Refuses an unnamed operation or an already closed owner.
    #[doc(hidden)]
    pub fn from_admitted_write_barrier(
        root: RootBinding,
        operation_id: OperationId,
        live: Arc<AtomicBool>,
    ) -> Result<Self> {
        if operation_id.as_str().is_empty() || !live.load(Ordering::Acquire) {
            return Err(invalid("write barrier is unavailable"));
        }
        Ok(Self {
            root,
            operation_id,
            live,
        })
    }
    #[must_use]
    pub fn root(&self) -> &RootBinding {
        &self.root
    }
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetCaptureReceipt {
    pub format_version: u32,
    pub operation_id: OperationId,
    pub root: RootBinding,
    pub state: NativeStateRef,
    pub reference: Option<String>,
    pub selection_digest: ContentDigest,
    pub working_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub capture_digest: ContentDigest,
    pub clean: bool,
}

/// Backend-inspected retained target bytes. There is no Deserialize impl.
#[derive(Clone, Debug)]
pub struct PreparedTargetCapture {
    receipt: TargetCaptureReceipt,
    manifest_path: PathBuf,
}
impl PreparedTargetCapture {
    /// Restricted to inspecting backend adapters by a source constructor lint.
    /// # Errors
    /// Refuses mixed scope or malformed immutable digest identities.
    #[doc(hidden)]
    pub fn from_captured_target(
        receipt: TargetCaptureReceipt,
        manifest_path: PathBuf,
    ) -> Result<Self> {
        if receipt.format_version != 1
            || receipt.operation_id.as_str().is_empty()
            || receipt.state.kind() != receipt.root.kind
            || receipt.state.repository_id() != &receipt.root.repository_id
            || !manifest_path.is_absolute()
            || [
                &receipt.selection_digest,
                &receipt.working_digest,
                &receipt.policy_digest,
                &receipt.capture_digest,
            ]
            .into_iter()
            .any(|value| !sha256(value))
        {
            return Err(invalid("invalid inspected target capture"));
        }
        Ok(Self {
            receipt,
            manifest_path,
        })
    }
    #[must_use]
    pub fn receipt(&self) -> &TargetCaptureReceipt {
        &self.receipt
    }
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionPreparationReceipt {
    pub format_version: u32,
    pub operation_id: OperationId,
    pub root: RootBinding,
    pub before: NativeStateRef,
    pub after: NativeStateRef,
    pub capture_digest: ContentDigest,
    pub composition_receipt_digest: ContentDigest,
    pub materialization_id: MaterializationId,
    pub selection_revision: ContentDigest,
    pub composition_revision: ContentDigest,
    pub closure_digest: ContentDigest,
    pub write_manifest_digest: ContentDigest,
    pub prepared_digest: ContentDigest,
}

/// Exact immutable adoption command retained by the backend, never decoded from
/// a caller. Its manifest includes the complete expected pre/post path states.
#[derive(Clone, Debug)]
pub struct PreparedAdoption {
    receipt: AdoptionPreparationReceipt,
    manifest_path: PathBuf,
}
impl PreparedAdoption {
    /// Restricted to inspecting backend adapters by a source constructor lint.
    /// # Errors
    /// Refuses mixed state/root or malformed immutable identities.
    #[doc(hidden)]
    pub fn from_prepared_adoption(
        receipt: AdoptionPreparationReceipt,
        manifest_path: PathBuf,
    ) -> Result<Self> {
        validate_preparation(&receipt)?;
        if !manifest_path.is_absolute() {
            return Err(invalid("adoption manifest must be absolute"));
        }
        Ok(Self {
            receipt,
            manifest_path,
        })
    }
    #[must_use]
    pub fn receipt(&self) -> &AdoptionPreparationReceipt {
        &self.receipt
    }
    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionAuthorizationReceipt {
    pub decision_operation_id: OperationId,
    pub decision_receipt_digest: ContentDigest,
    pub offer_id: String,
    pub offer_digest: ContentDigest,
    pub candidate_id: String,
    pub preparation: AdoptionPreparationReceipt,
}

/// Minted only by the Store writer after accepting/replaying the exact original
/// human decision and reserving this effect. No Deserialize implementation.
#[derive(Clone, Debug)]
pub struct AdoptionAuthorization {
    receipt: AdoptionAuthorizationReceipt,
    allows_apply: bool,
}
impl AdoptionAuthorization {
    /// Constructor sites are restricted to the accepted-decision Store owner.
    /// # Errors
    /// Refuses incomplete decision/offer/candidate/preparation identities.
    #[doc(hidden)]
    pub fn from_accepted_store_decision(receipt: AdoptionAuthorizationReceipt) -> Result<Self> {
        validate_preparation(&receipt.preparation)?;
        if receipt.decision_operation_id.as_str().is_empty()
            || receipt.offer_id.is_empty()
            || receipt.candidate_id.is_empty()
            || receipt.candidate_id.len() > 256
            || !sha256(&receipt.decision_receipt_digest)
            || !sha256(&receipt.offer_digest)
        {
            return Err(invalid("invalid accepted adoption authorization"));
        }
        Ok(Self {
            receipt,
            allows_apply: true,
        })
    }
    #[must_use]
    pub fn receipt(&self) -> &AdoptionAuthorizationReceipt {
        &self.receipt
    }
    /// Permanently downgrade this carrier to historical inspection only. The
    /// original serialized accepted-decision receipt remains byte-identical.
    #[must_use]
    pub fn into_reconciliation_only(mut self) -> Self {
        self.allows_apply = false;
        self
    }
    #[must_use]
    pub fn allows_apply(&self) -> bool {
        self.allows_apply
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservedAdoptionReceipt {
    pub format_version: u32,
    pub authorization: AdoptionAuthorizationReceipt,
    pub target_reference: Option<String>,
    pub preimages_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    /// A completed native effect is retained even if a later durability or
    /// projection step reports a problem. This never authorizes a second apply.
    pub post_effect_errors: Vec<String>,
}

/// A known recorded-state effect is distinct from a qualified complete adoption.
/// Neither observation permits task completion or another native apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdoptionProgressObservation {
    CasReturnedSuccess,
    ObservedAfterFailedCas,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionProgressReceipt {
    pub format_version: u32,
    pub authorization: AdoptionAuthorizationReceipt,
    pub target_reference: Option<String>,
    pub observation: AdoptionProgressObservation,
    pub effect_digest: ContentDigest,
}

/// Actual native CAS progress, never an assertion that the working copy is
/// complete/durable. Its original fact can be retained after later root drift.
#[derive(Clone, Debug)]
pub struct VerifiedAdoptionProgress {
    receipt: AdoptionProgressReceipt,
    receipt_path: PathBuf,
}
impl VerifiedAdoptionProgress {
    /// Restricted to inspecting backend adapters by the constructor-site lint.
    /// # Errors
    /// Refuses incomplete authorization or malformed retained effect identities.
    #[doc(hidden)]
    pub fn from_observed_adoption_progress(
        receipt: AdoptionProgressReceipt,
        receipt_path: PathBuf,
    ) -> Result<Self> {
        AdoptionAuthorization::from_accepted_store_decision(receipt.authorization.clone())?;
        if receipt.format_version != 1
            || !sha256(&receipt.effect_digest)
            || !receipt_path.is_absolute()
        {
            return Err(invalid("invalid observed adoption progress"));
        }
        Ok(Self {
            receipt,
            receipt_path,
        })
    }
    #[must_use]
    pub fn receipt(&self) -> &AdoptionProgressReceipt {
        &self.receipt
    }
    #[must_use]
    pub fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }
}

/// Proof of an actual inspected terminal native effect. Replay status lives
/// outside the immutable original receipt bytes and never rewrites history.
#[derive(Clone, Debug)]
pub struct VerifiedAdoptionReceipt {
    receipt: ObservedAdoptionReceipt,
    receipt_path: PathBuf,
    replayed: bool,
}
impl VerifiedAdoptionReceipt {
    /// Constructor sites are restricted to inspecting actual backend adapters.
    /// # Errors
    /// Refuses incomplete state/command or malformed retained receipt pins.
    #[doc(hidden)]
    pub fn from_observed_adoption(
        receipt: ObservedAdoptionReceipt,
        receipt_path: PathBuf,
        replayed: bool,
    ) -> Result<Self> {
        AdoptionAuthorization::from_accepted_store_decision(receipt.authorization.clone())?;
        if receipt.format_version != 1
            || !receipt_path.is_absolute()
            || !sha256(&receipt.preimages_digest)
            || !sha256(&receipt.receipt_digest)
        {
            return Err(invalid("invalid observed adoption effect"));
        }
        Ok(Self {
            receipt,
            receipt_path,
            replayed,
        })
    }
    #[must_use]
    pub fn receipt(&self) -> &ObservedAdoptionReceipt {
        &self.receipt
    }
    #[must_use]
    pub fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }
    #[must_use]
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidParams(reason.into())
}
fn sha256(value: &ContentDigest) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_preparation(receipt: &AdoptionPreparationReceipt) -> Result<()> {
    if receipt.format_version != 1
        || receipt.operation_id.as_str().is_empty()
        || [&receipt.before, &receipt.after].into_iter().any(|state| {
            state.kind() != receipt.root.kind
                || state.repository_id() != &receipt.root.repository_id
        })
        || !sha256(&ContentDigest::from_string(
            receipt.materialization_id.as_str(),
        ))
        || [
            &receipt.capture_digest,
            &receipt.composition_receipt_digest,
            &receipt.selection_revision,
            &receipt.composition_revision,
            &receipt.closure_digest,
            &receipt.write_manifest_digest,
            &receipt.prepared_digest,
        ]
        .into_iter()
        .any(|value| !sha256(value))
    {
        return Err(invalid("invalid immutable adoption preparation"));
    }
    Ok(())
}
