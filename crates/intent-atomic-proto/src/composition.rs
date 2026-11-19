//! Private composition qualification, never a target write/adoption grant.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    closures::{BaselineClosure, ClosureScope},
    HostIdentity, SpoolRef, StateToken, StoreBinding,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCompositionChange {
    pub hash: String,
    pub bytes: SpoolRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateCompositionInput {
    pub operation_id: String,
    pub scope: ClosureScope,
    pub target: BaselineClosure,
    pub inherited_baseline: BaselineClosure,
    pub expected_target: StateToken,
    /// Host-issued immutable source capture; absence supports frozen baseline roots only.
    pub captured_target: Option<CapturedCompositionTarget>,
    pub target_changes: Vec<String>,
    pub selected_changes: Vec<String>,
    pub available_changes: Vec<ExactCompositionChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionInventory {
    pub selected_changes: Vec<String>,
    pub dependency_only_changes: Vec<String>,
    pub full_closed_changes: Vec<String>,
    pub inherited_baseline_changes: Vec<String>,
    pub target_context_changes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateCompositionReceipt {
    pub operation_id: String,
    pub host: HostIdentity,
    pub scope: ClosureScope,
    pub command_digest: String,
    pub target_state: StateToken,
    /// Derived private identity. Numeric view IDs may differ from the original source.
    pub private_target_state: StateToken,
    pub target_capture_digest: Option<String>,
    pub candidate_state: StateToken,
    pub state_manifest: SpoolRef,
    pub materialization_id: String,
    pub materialization_manifest: SpoolRef,
    pub inventory: SpoolRef,
    pub conflict_manifest: Option<SpoolRef>,
    /// Neutral typed side inventory from the actual native conflict object.
    pub conflicts: SpoolRef,
    pub native_conflict_hash: Option<String>,
    pub candidate_path: PathBuf,
    pub selection_revision: String,
    pub composition_revision: String,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase", deny_unknown_fields)]
pub enum PrivateCompositionOutcome {
    InheritedBaselineRequired {
        operation_id: String,
        host: HostIdentity,
        scope: Box<ClosureScope>,
        command_digest: String,
        missing_changes: SpoolRef,
        missing_count: u64,
    },
    Composed {
        receipt: Box<PrivateCompositionReceipt>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureCompositionTargetRequest {
    pub operation_id: String,
    pub scope: ClosureScope,
    pub binding: StoreBinding,
    pub view: String,
    pub expected_state: StateToken,
}

/// A handle to an actual host-owned immutable capture. Supplying this DTO alone
/// is not proof: the owner checks its immutable capture journal before use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedCompositionTarget {
    pub operation_id: String,
    pub host: HostIdentity,
    pub scope: ClosureScope,
    pub binding: StoreBinding,
    pub state: StateToken,
    pub manifest: SpoolRef,
    pub capture_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionStateManifest {
    pub native_state: StateToken,
    pub view_manifests: Vec<String>,
    pub exact_objects: Vec<ExactCompositionChange>,
    pub files: SpoolRef,
    pub inventory: SpoolRef,
    pub full_closed_changes: Vec<String>,
    pub materialization_id: String,
    pub conflict_manifest: Option<String>,
    pub conflicts: SpoolRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionConflict {
    pub path: String,
    pub kind: String,
    pub line: Option<u32>,
    pub base: Option<CompositionConflictSide>,
    pub sides: Vec<CompositionConflictSide>,
    pub claimants: Vec<CompositionConflictClaimant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionConflictSide {
    pub change: String,
    pub start: u64,
    pub end: u64,
    pub content: String,
    pub mode: u32,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionConflictClaimant {
    pub change: String,
    pub inode: u64,
    pub path: Vec<u8>,
    pub directory: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Command, Reply, MAX_FRAME_BYTES};

    fn reference() -> SpoolRef {
        SpoolRef {
            name: "immutable.payload".into(),
            length: 16_777_216,
            sha256: "a".repeat(64),
        }
    }
    fn scope() -> ClosureScope {
        ClosureScope {
            workspace_id: "workspace".into(),
            root_id: "primary".into(),
            repository_id: "repository".into(),
            binding_epoch: 7,
        }
    }
    fn state() -> StateToken {
        StateToken {
            view: "target".into(),
            effective_state: "A".repeat(52),
            own_merkle: "A".repeat(52),
        }
    }
    fn capture() -> CapturedCompositionTarget {
        CapturedCompositionTarget {
            operation_id: "capture".into(),
            host: HostIdentity::default(),
            scope: scope(),
            binding: StoreBinding {
                repository_id: "repository".into(),
                binding_epoch: 7,
                store_path: "/private/stores/repository/native".into(),
            },
            state: state(),
            manifest: reference(),
            capture_digest: "b".repeat(64),
        }
    }
    fn receipt() -> PrivateCompositionReceipt {
        PrivateCompositionReceipt {
            operation_id: "compose".into(),
            host: HostIdentity::default(),
            scope: scope(),
            command_digest: reference().sha256,
            target_state: state(),
            private_target_state: state(),
            target_capture_digest: Some("b".repeat(64)),
            candidate_state: state(),
            state_manifest: reference(),
            materialization_id: "c".repeat(64),
            materialization_manifest: reference(),
            inventory: reference(),
            conflict_manifest: Some(reference()),
            conflicts: reference(),
            native_conflict_hash: Some("A".repeat(52)),
            candidate_path: "/private/spool/compositions/command/files".into(),
            selection_revision: "d".repeat(64),
            composition_revision: "e".repeat(64),
            receipt_digest: "f".repeat(64),
        }
    }

    #[test]
    fn capture_reply_rejects_foreign_scope_state_binding_host_and_reply_kind() {
        let original = capture();
        let command = Command::CaptureCompositionTarget {
            request: CaptureCompositionTargetRequest {
                operation_id: original.operation_id.clone(),
                scope: original.scope.clone(),
                binding: original.binding.clone(),
                view: original.state.view.clone(),
                expected_state: original.state.clone(),
            },
        };
        assert!(Reply::CompositionTargetCaptured {
            capture: original.clone()
        }
        .matches_command(&command));
        for field in 0..5 {
            let mut changed = original.clone();
            match field {
                0 => changed.scope.root_id = "other".into(),
                1 => changed.state.own_merkle = "Q".repeat(52),
                2 => changed.binding.binding_epoch += 1,
                3 => changed.host.atomic_revision = "other".into(),
                _ => changed.operation_id = "other".into(),
            }
            assert!(
                !Reply::CompositionTargetCaptured { capture: changed }.matches_command(&command)
            );
        }
        assert!(!Reply::Pong.matches_command(&command));
        assert!(!command.is_read_only());
        assert!(command.requires_recovery());
    }

    #[test]
    fn composition_replies_are_command_pinned_and_large_inventories_stay_spooled() {
        let command = Command::ComposePrivate { input: reference() };
        let original = receipt();
        let reply = Reply::PrivateComposed {
            outcome: Box::new(PrivateCompositionOutcome::Composed {
                receipt: Box::new(original.clone()),
            }),
        };
        assert!(reply.matches_command(&command));
        assert!(serde_json::to_vec(&reply).unwrap().len() < MAX_FRAME_BYTES);
        let mut changed = original.clone();
        changed.command_digest = "0".repeat(64);
        assert!(!Reply::PrivateComposed {
            outcome: Box::new(PrivateCompositionOutcome::Composed {
                receipt: Box::new(changed)
            })
        }
        .matches_command(&command));
        let mut changed = original;
        changed.host.store_format += 1;
        assert!(!Reply::PrivateComposed {
            outcome: Box::new(PrivateCompositionOutcome::Composed {
                receipt: Box::new(changed)
            })
        }
        .matches_command(&command));
        let missing = |count, sha| Reply::PrivateComposed {
            outcome: Box::new(PrivateCompositionOutcome::InheritedBaselineRequired {
                operation_id: "compose".into(),
                host: HostIdentity::default(),
                scope: Box::new(scope()),
                command_digest: sha,
                missing_changes: reference(),
                missing_count: count,
            }),
        };
        let missing_reply = missing(4096, reference().sha256);
        let wire = serde_json::to_value(&missing_reply).unwrap();
        assert_eq!(
            wire["outcome"]["scope"],
            serde_json::to_value(scope()).unwrap()
        );
        assert_eq!(
            serde_json::from_value::<Reply>(wire).unwrap(),
            missing_reply
        );
        assert!(missing(4096, reference().sha256).matches_command(&command));
        assert!(
            serde_json::to_vec(&missing(4096, reference().sha256))
                .unwrap()
                .len()
                < MAX_FRAME_BYTES
        );
        for count in [0, 4097] {
            assert!(!missing(count, reference().sha256).matches_command(&command));
        }
        assert!(!missing(1, "0".repeat(64)).matches_command(&command));
        assert!(!Reply::Pong.matches_command(&command));
        assert!(!command.is_read_only());
        assert!(command.requires_recovery());
    }
}
