//! Serialization and refusal contracts for the repository engine boundary.

use intent_core::vcs::{
    NativeChangeRef, NativeObjectRef, NativeStateRef, RecordOutcome, RecordSkipReason,
    VcsCapabilities, VcsError, VcsKind, WorkspaceEngine,
};
use intent_core::Error;
use serde_json::json;
use std::path::Path;

#[test]
fn git_state_retains_commit_tree_and_repository_scope() {
    let fixture = include_str!("goldens/vcs_git_state.json");
    let state: NativeStateRef = serde_json::from_str(fixture).unwrap();
    assert_eq!(state.kind(), VcsKind::Git);
    assert_eq!(
        state.repository_id().as_str(),
        "dc07d23a-bb24-4221-a90b-78112dd7e831"
    );
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        serde_json::from_str::<serde_json::Value>(fixture).unwrap()
    );
}

#[test]
fn atomic_state_retains_exact_membership_manifest_and_state_tokens() {
    let fixture = include_str!("goldens/vcs_atomic_state.json");
    let state: NativeStateRef = serde_json::from_str(fixture).unwrap();
    assert_eq!(state.kind(), VcsKind::Atomic);
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        serde_json::from_str::<serde_json::Value>(fixture).unwrap()
    );
    let mut incomplete = serde_json::to_value(state).unwrap();
    incomplete.as_object_mut().unwrap().remove("manifest");
    assert!(serde_json::from_value::<NativeStateRef>(incomplete).is_err());
}

#[test]
fn native_hash_namespaces_cannot_be_reinterpreted_during_decode() {
    let wrong_commit = json!({
        "kind": "git",
        "repositoryId": "repo",
        "change": "atomic-change"
    });
    assert!(serde_json::from_value::<NativeChangeRef>(wrong_commit).is_err());
    let mixed = json!({
        "kind": "atomic",
        "repositoryId": "repo",
        "change": "native-change",
        "commit": "not-a-native-change"
    });
    assert!(serde_json::from_value::<NativeChangeRef>(mixed).is_err());
    let blob = json!({"kind": "git", "object": "blob-id"});
    assert!(serde_json::from_value::<NativeObjectRef>(blob.clone()).is_ok());
    assert!(serde_json::from_value::<NativeChangeRef>(blob).is_err());
}

#[test]
fn unknown_backend_is_refused_before_it_can_look_empty() {
    let unknown = json!({"kind": "future-engine", "repositoryId": "repo"});
    assert!(serde_json::from_value::<NativeStateRef>(unknown).is_err());
}

struct UnqualifiedEngine;

impl WorkspaceEngine for UnqualifiedEngine {
    fn kind(&self) -> VcsKind {
        VcsKind::Atomic
    }

    fn capabilities(&self) -> VcsCapabilities {
        VcsCapabilities::default()
    }
}

#[test]
fn trait_is_object_safe_and_unimplemented_reads_never_claim_clean() {
    let engine: &dyn WorkspaceEngine = &UnqualifiedEngine;
    assert_eq!(engine.capabilities(), VcsCapabilities::default());
    assert!(matches!(
        engine.is_ignored(Path::new("working-copy"), "source.rs"),
        Err(VcsError::Unsupported {
            operation: "isIgnored",
            kind: VcsKind::Atomic
        })
    ));
    assert!(matches!(
        engine.classify_paths(Path::new("working-copy"), &["source.rs".to_owned()]),
        Err(VcsError::Unsupported { .. })
    ));
    assert!(matches!(
        engine.lockable_paths(Path::new("working-copy"), &[], &[]),
        Err(VcsError::Unsupported { .. })
    ));
}

#[test]
fn legacy_backend_error_preserves_category_and_exact_display() {
    let error = Error::GitAuthorization("permission denied".to_owned());
    let display = error.to_string();
    let code = error.code();
    let converted = VcsError::from(error);
    assert_eq!(converted.to_string(), display);
    let VcsError::Backend(error) = converted else {
        panic!("legacy backend error category was lost")
    };
    assert!(matches!(error, Error::GitAuthorization(_)));
    assert_eq!(error.code(), code);
}

#[test]
fn recorded_and_skipped_have_distinct_serialized_outcomes() {
    let skipped = RecordOutcome::Skipped(RecordSkipReason::MissingAttribution);
    assert_eq!(
        serde_json::to_value(&skipped).unwrap(),
        json!({"outcome": "skipped", "result": "missingAttribution"})
    );
    assert!(serde_json::from_value::<RecordOutcome>(json!({
        "outcome": "recorded",
        "result": "missingAttribution"
    }))
    .is_err());
}
