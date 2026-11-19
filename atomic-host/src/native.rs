//! Exactly one shared native database handle for an admitted canonical store.

use std::sync::Arc;

use atomic_core::{
    kg::project_id::MintReason,
    pristine::{GraphTxnT, Pristine, ViewState, ViewTxnT},
    Base32, Hash,
};
use atomic_repository::{manifest::ViewManifest, Repository};
use intent_atomic_proto::{HostIdentity, StateToken, StoreBinding};
use serde::{Deserialize, Serialize};

use crate::{durable, HostError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoreProof {
    host: HostIdentity,
    repository_id: String,
    binding_epoch: u64,
    native_directory: durable::FileIdentity,
    native_database: durable::FileIdentity,
    project_id: String,
    project_identity_hash: String,
}

impl StoreProof {
    pub(crate) fn validate(&self, binding: &StoreBinding) -> Result<()> {
        if self.host != HostIdentity::default()
            || self.repository_id != binding.repository_id
            || self.binding_epoch != binding.binding_epoch
            || self.native_directory != durable::identity(&binding.store_path, true)?
        {
            return Err(HostError::StaleBinding);
        }
        durable::identity(&binding.store_path.join(".atomic"), true)?;
        if self.native_database
            != durable::identity(&binding.store_path.join(".atomic/atomic.redb"), false)?
        {
            return Err(HostError::StaleBinding);
        }
        Ok(())
    }

    fn check_repository(&self, repository: &Repository) -> Result<()> {
        let identity = repository
            .project_identity()
            .map_err(native)?
            .ok_or(HostError::Invalid(
                "native store has no retained project identity",
            ))?;
        if identity.project_id().map_err(native)?.to_base32() != self.project_id
            || identity.hash.to_base32() != self.project_identity_hash
        {
            return Err(HostError::StaleBinding);
        }
        Ok(())
    }
}

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}

/// Lift of the pinned upstream private `effective_state` encoding. All view
/// rows, including ancestors and own Merkle, come from one native read snapshot.
/// Parity tests guard the exact upstream fencing identity across scope changes.
pub(crate) fn snapshot_state(repository: &Repository, name: &str) -> Result<StateToken> {
    snapshot_state_with(repository, name, || {})
}

#[cfg(test)]
pub(crate) fn snapshot_state_observed(
    repository: &Repository,
    name: &str,
    observed: impl FnOnce(),
) -> Result<StateToken> {
    snapshot_state_with(repository, name, observed)
}

fn snapshot_state_with(
    repository: &Repository,
    name: &str,
    observed: impl FnOnce(),
) -> Result<StateToken> {
    let txn = repository.pristine().read_txn().map_err(native)?;
    let view = txn
        .get_view(name)
        .map_err(native)?
        .ok_or_else(|| HostError::Native(format!("native view '{name}' is unavailable")))?;
    observed();
    let chain = txn.resolve_full_view_chain(&view).map_err(native)?;
    Ok(state_from_rows(&view, &chain))
}

fn state_from_rows(view: &ViewState, chain: &[ViewState]) -> StateToken {
    let mut encoded = b"atomic.sandbox.effective-view.v1".to_vec();
    for row in std::iter::once(view).chain(chain.iter().filter(|row| row.id != view.id)) {
        encoded.extend_from_slice(&row.id.to_le_bytes());
        encoded.push(row.kind as u8);
        encoded.extend_from_slice(row.state.as_bytes());
        encoded.extend_from_slice(&row.change_count.to_le_bytes());
    }
    StateToken {
        view: view.name.clone(),
        effective_state: Hash::of(&encoded).to_base32(),
        own_merkle: view.state.to_base32(),
    }
}

/// Capture the original numeric state fence, complete ordered view hierarchy
/// and dependency-closed membership together. Reconstructed private views may
/// receive different numeric IDs and cannot replace this original fence.
pub(crate) fn snapshot_views(
    repository: &Repository,
    name: &str,
) -> Result<(StateToken, Vec<ViewManifest>, Vec<Hash>)> {
    let txn = repository.pristine().read_txn().map_err(native)?;
    let view = txn
        .get_view(name)
        .map_err(native)?
        .ok_or_else(|| HostError::Native(format!("native view '{name}' is unavailable")))?;
    let chain = txn.resolve_full_view_chain(&view).map_err(native)?;
    let state = state_from_rows(&view, &chain);
    let mut manifests = Vec::with_capacity(chain.len());
    for row in &chain {
        let mut changes = Vec::new();
        for entry in txn.iter_changes(row, 0).map_err(native)? {
            let (_, id, _) = entry.map_err(native)?;
            changes.push(
                txn.get_external(id)
                    .map_err(native)?
                    .ok_or(HostError::Invalid(
                        "native membership has no external identity",
                    ))?,
            );
        }
        let parent = row
            .parent
            .map(|id| {
                chain
                    .iter()
                    .find(|parent| parent.id == id)
                    .map(|parent| parent.name.clone())
                    .ok_or(HostError::Invalid("native view hierarchy is incomplete"))
            })
            .transpose()?;
        let manifest = ViewManifest {
            name: row.name.clone(),
            scope: row.kind,
            parent,
            changes,
            state: row.state,
        };
        manifest.verify().map_err(native)?;
        manifests.push(manifest);
    }
    let visible = atomic_repository::graph_visibility_closure(&txn, &view).map_err(native)?;
    let mut closure = Vec::new();
    for id in visible.iter_dependency_first().copied() {
        closure.push(
            txn.get_external(id)
                .map_err(native)?
                .ok_or(HostError::Invalid(
                    "native graph visibility has no external identity",
                ))?,
        );
    }
    Ok((state, manifests, closure))
}

pub(crate) fn initialize(binding: &StoreBinding) -> Result<StoreProof> {
    durable::private_dir(&binding.store_path)?;
    let repository = Repository::init(&binding.store_path).map_err(native)?;
    // Upgrade minting never loads a default signing identity or global config.
    // Source-authoring identities belong to the later, separately qualified gate.
    let identity = repository
        .ensure_project_identity(MintReason::Upgrade)
        .map_err(native)?;
    let proof = StoreProof {
        host: HostIdentity::default(),
        repository_id: binding.repository_id.clone(),
        binding_epoch: binding.binding_epoch,
        native_directory: durable::identity(&binding.store_path, true)?,
        native_database: durable::identity(&repository.database_path(), false)?,
        project_id: identity.project_id().map_err(native)?.to_base32(),
        project_identity_hash: identity.hash.to_base32(),
    };
    durable::sync_tree(&binding.store_path)?;
    durable::sync_parent(&binding.store_path)?;
    Ok(proof)
}

pub(crate) struct NativeStore {
    binding: StoreBinding,
    proof: StoreProof,
    // The repository and any later worker-created repository views share this
    // one Pristine. Readers use redb read transactions, not the writer lane.
    pristine: Arc<Pristine>,
    repository: Repository,
}

impl NativeStore {
    pub(crate) fn repository(&self) -> &Repository {
        &self.repository
    }

    pub(crate) fn shared_pristine(&self) -> Arc<Pristine> {
        self.pristine.clone()
    }

    pub(crate) fn open(binding: &StoreBinding, proof: &StoreProof) -> Result<Self> {
        proof.validate(binding)?;
        // This refuses pending native recovery and old formats before the
        // writable shared-handle constructor can perform any implicit repair.
        let preflight =
            Repository::open_readonly_without_migration(&binding.store_path).map_err(native)?;
        proof.check_repository(&preflight)?;
        drop(preflight);
        Self::open_validated(binding, proof)
    }

    /// The caller has verified an exact owned record journal and its original
    /// spool bytes. This permits redb transaction repair for that pinned file;
    /// it never enrolls, upgrades or repairs an unowned user repository.
    pub(crate) fn open_owned_recovery(binding: &StoreBinding, proof: &StoreProof) -> Result<Self> {
        proof.validate(binding)?;
        Self::open_validated(binding, proof)
    }

    fn open_validated(binding: &StoreBinding, proof: &StoreProof) -> Result<Self> {
        let pristine = Arc::new(
            Pristine::open_existing(binding.store_path.join(".atomic/atomic.redb"))
                .map_err(native)?,
        );
        let repository = Repository::open_with_pristine(&binding.store_path, pristine.clone())
            .map_err(native)?;
        proof.validate(binding)?;
        proof.check_repository(&repository)?;
        Ok(Self {
            binding: binding.clone(),
            proof: proof.clone(),
            pristine,
            repository,
        })
    }

    pub(crate) fn validate(&self, binding: &StoreBinding, proof: &StoreProof) -> Result<()> {
        if binding.repository_id != self.binding.repository_id
            || binding.binding_epoch != self.binding.binding_epoch
            || proof != &self.proof
        {
            return Err(HostError::StaleBinding);
        }
        proof.validate(binding)?;
        proof.check_repository(&self.repository)
    }

    pub(crate) fn state(&self) -> Result<StateToken> {
        self.proof.validate(&self.binding)?;
        self.proof.check_repository(&self.repository)?;
        // Keep the owned shared handle in use; this never reopens a database.
        self.pristine
            .ensure_supported_repository_capabilities()
            .map_err(native)?;
        snapshot_state(&self.repository, self.repository.current_view())
    }
}
