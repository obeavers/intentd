//! Portable format-2 frozen-baseline component. This does not claim a captured
//! live working overlay, selection, or separately versioned work-evidence closure.

use serde::{Deserialize, Serialize};

use crate::{
    baselines::{BaselineReceipt, BaselineRef},
    HostIdentity, SpoolRef,
};

pub const CLOSURE_FORMAT: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClosureScope {
    pub workspace_id: String,
    pub root_id: String,
    pub repository_id: String,
    pub binding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportBaselineClosureRequest {
    pub operation_id: String,
    pub scope: ClosureScope,
    /// Allocated durably by the owning service before capture; never minted by
    /// the host or inferred from timestamps, filenames or current UI state.
    pub capture_revision: u64,
    pub baseline: BaselineRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClosureProfile {
    FrozenBaseline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaselineClosure {
    pub format: u32,
    pub profile: ClosureProfile,
    pub host: HostIdentity,
    pub scope: ClosureScope,
    pub capture_revision: u64,
    pub baseline: BaselineReceipt,
    /// Exact native object closure +view manifest+file manifest. No database.
    pub payload: SpoolRef,
    pub object_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreBaselineClosureRequest {
    pub operation_id: String,
    pub expected_scope: ClosureScope,
    pub closure: BaselineClosure,
}

#[cfg(test)]
mod tests {
    use crate::{Command, HostIdentity, Reply};

    #[test]
    fn restore_command_preserves_the_inline_request_wire_shape() {
        let scope = serde_json::json!({
            "workspaceId": "workspace",
            "rootId": "primary",
            "repositoryId": "repository",
            "bindingEpoch": 7
        });
        let wire = serde_json::json!({
            "command": "restoreBaselineClosure",
            "request": {
                "operationId": "restore",
                "expectedScope": scope,
                "closure": {
                    "format": super::CLOSURE_FORMAT,
                    "profile": "frozenBaseline",
                    "host": HostIdentity::default(),
                    "scope": scope,
                    "captureRevision": 3,
                    "baseline": {
                        "baseline": {
                            "repositoryId": "repository",
                            "bindingEpoch": 7,
                            "baselineId": "baseline"
                        },
                        "host": HostIdentity::default(),
                        "sourceCommit": "c".repeat(40),
                        "sourceTree": "d".repeat(40),
                        "previous": null,
                        "storage": "fullReimport",
                        "nativeState": {
                            "view": "baseline",
                            "effectiveState": "A".repeat(52),
                            "ownMerkle": "A".repeat(52)
                        },
                        "manifestDigest": "e".repeat(64),
                        "materializationId": "f".repeat(64),
                        "fileCount": 1,
                        "totalBytes": 5,
                        "policy": {
                            "version": 1,
                            "caseSensitive": false,
                            "excludedPaths": []
                        }
                    },
                    "payload": {
                        "name": "baseline.payload",
                        "length": 512,
                        "sha256": "a".repeat(64)
                    },
                    "objectCount": 1
                }
            }
        });
        let command: Command = serde_json::from_value(wire.clone()).unwrap();
        let Command::RestoreBaselineClosure { request } = &command else {
            panic!("expected restore command");
        };
        assert!(Reply::BaselineClosureRestored {
            receipt: request.closure.baseline.clone()
        }
        .matches_command(&command));
        assert_eq!(serde_json::to_value(&command).unwrap(), wire);
        assert!(!command.is_read_only());
        assert!(command.requires_recovery());
    }
}
