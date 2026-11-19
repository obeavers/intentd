//! Native-owner composition evidence. Serialized receipt data is not a caller
//! credential; only the opaque verified carrier admits contribution inventory.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::vcs::{
    ContentDigest, MaterializationId, NativeChangeRef, NativeStateRef, OperationId, RootBinding,
};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCompositionReceipt {
    pub operation_id: OperationId,
    pub root: RootBinding,
    pub base_state: NativeStateRef,
    pub target_state: NativeStateRef,
    pub candidate_state: NativeStateRef,
    pub materialization_id: MaterializationId,
    pub selected_changes: Vec<NativeChangeRef>,
    pub dependency_only_changes: Vec<NativeChangeRef>,
    pub full_closed_changes: Vec<NativeChangeRef>,
    pub inherited_baseline_changes: Vec<NativeChangeRef>,
    /// Actual original target closure; may overlap the baseline or selected changes.
    pub target_context_changes: Vec<NativeChangeRef>,
    /// Backend-derived preview anchors; these are never authored contributions.
    pub composition_only_changes: Vec<NativeChangeRef>,
    pub selection_revision: ContentDigest,
    pub composition_revision: ContentDigest,
    pub conflict_manifest: Option<ContentDigest>,
    pub receipt_digest: ContentDigest,
}

/// No Deserialize implementation: RPC data cannot mint native-owner proof.
#[derive(Clone, Debug)]
pub struct VerifiedCompositionReceipt(NativeCompositionReceipt);

impl VerifiedCompositionReceipt {
    /// Backend verification entry point. Constructor sites are restricted by a
    /// source lint to actual native owner adapters, after native state, private
    /// materialization and complete membership have been inspected. Structural
    /// validation here supplements that inspection; it does not replace it.
    /// # Errors
    /// Refuses mixed repositories, duplicated or inconsistent membership pins.
    #[doc(hidden)]
    pub fn from_verified_backend(receipt: NativeCompositionReceipt) -> Result<Self> {
        let invalid = || Error::InvalidParams("invalid verified native composition receipt".into());
        if receipt.operation_id.as_str().is_empty()
            || [
                &receipt.base_state,
                &receipt.target_state,
                &receipt.candidate_state,
            ]
            .iter()
            .any(|state| {
                state.repository_id() != &receipt.root.repository_id
                    || state.kind() != receipt.root.kind
            })
            || [
                receipt.materialization_id.as_str(),
                receipt.selection_revision.as_str(),
                receipt.composition_revision.as_str(),
                receipt.receipt_digest.as_str(),
            ]
            .iter()
            .any(|digest| !sha256(digest))
            || receipt
                .conflict_manifest
                .as_ref()
                .is_some_and(|digest| !sha256(digest.as_str()))
        {
            return Err(invalid());
        }
        let keys = |changes: &[NativeChangeRef]| -> Result<BTreeSet<String>> {
            let mut values = BTreeSet::new();
            for change in changes {
                if change.repository_id() != &receipt.root.repository_id
                    || change.kind() != receipt.root.kind
                    || !values.insert(serde_json::to_string(change).map_err(|_| invalid())?)
                {
                    return Err(invalid());
                }
            }
            Ok(values)
        };
        let full = keys(&receipt.full_closed_changes)?;
        let selected = keys(&receipt.selected_changes)?;
        let dependencies = keys(&receipt.dependency_only_changes)?;
        let inherited = keys(&receipt.inherited_baseline_changes)?;
        let target_context = keys(&receipt.target_context_changes)?;
        let composition_only = keys(&receipt.composition_only_changes)?;
        if !selected.is_subset(&full)
            || !dependencies.is_subset(&full)
            || !inherited.is_subset(&full)
            || !selected.is_disjoint(&dependencies)
            || !target_context.is_subset(&full)
            || !composition_only.is_subset(&full)
            || !composition_only.is_disjoint(&selected)
            || !composition_only.is_disjoint(&dependencies)
            || !composition_only.is_disjoint(&inherited)
            || !composition_only.is_disjoint(&target_context)
            || selected
                .iter()
                .chain(&dependencies)
                .chain(&inherited)
                .chain(&target_context)
                .chain(&composition_only)
                .cloned()
                .collect::<BTreeSet<_>>()
                != full
        {
            return Err(invalid());
        }
        Ok(Self(receipt))
    }

    #[must_use]
    pub fn receipt(&self) -> &NativeCompositionReceipt {
        &self.0
    }
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
