//! Negative compatibility qualification against the actual pinned native
//! policy/registry. No listener or Host entry is created; these facts do not
//! qualify a CLI, counted read, canonical write or provider process.

use std::sync::Arc;

use libatomic::daemon::sandbox_grants::{
    grant_capabilities, is_sandbox_scoped, GrantRequest, InMemorySandboxGrants, SandboxGrants,
    SANDBOX_METHODS, SANDBOX_TOKEN_METADATA,
};
use libatomic::daemon::state::DaemonState;

fn route(service: &str, method: &str) -> String {
    format!("/atomic.{service}/{method}")
}

#[test]
fn skill_vault_knowledge_and_attestation_allowlist_is_not_a_scoped_handler_proof() {
    for (service, method) in [
        ("VaultService", "GetVaultEntry"),
        ("VaultService", "ListVaultEntries"),
        ("VaultService", "CreateVaultEntity"),
        ("VaultService", "UpdateVaultEntity"),
        ("VaultService", "ValidateVaultEntity"),
        ("KnowledgeService", "QueryGraph"),
        ("AttestationService", "PrepareAttestation"),
        ("AttestationService", "RecordAttestation"),
        ("AttestationService", "VerifyAttestation"),
    ] {
        assert!(SANDBOX_METHODS.contains(&(service, method)));
        assert!(!is_sandbox_scoped(&route(service, method)));
    }
}

#[test]
fn cross_view_triage_and_canonical_repository_queries_are_not_native_sandbox_routes() {
    for (service, method) in [
        ("TriageService", "ListTriageCandidates"),
        ("TriageService", "GenerateTriageReview"),
        ("RepositoryQueryService", "Status"),
        ("RepositoryQueryService", "Log"),
        ("RepositoryQueryService", "GetChange"),
        ("RepositoryQueryService", "DiffWorkingCopy"),
        ("MaintenanceService", "ReindexWorkspace"),
    ] {
        assert!(!is_sandbox_scoped(&route(service, method)));
    }
    assert!(is_sandbox_scoped("/atomic.SandboxService/GetFileStates"));
    assert!(is_sandbox_scoped("/atomic.SandboxService/GetChanges"));
}

#[test]
fn native_read_registry_capability_does_not_grant_skill_writes_or_knowledge() {
    let registry = InMemorySandboxGrants::new();
    let (token, grant) = registry
        .open(GrantRequest {
            repository_id: b"policy-only-no-native-store".to_vec(),
            view: "policy-view".into(),
            view_id: Some(1),
            acting_as: None,
            capabilities: grant_capabilities(&["sandbox.read".into()]).unwrap(),
            ttl_secs: 60,
        })
        .unwrap();
    let resolved = registry.resolve(&token).unwrap();
    assert!(resolved.allows("sandbox.read"));
    for capability in [
        "sandbox.submit",
        "vault.read",
        "vault.write",
        "knowledge.read",
    ] {
        assert!(!resolved.allows(capability));
    }
    registry.close(&grant.repository_id, &grant.view).unwrap();
    assert!(registry.resolve(&token).is_err());
}

#[test]
fn missing_token_is_a_native_local_caller_and_requires_a_mandatory_host_ingress_gate() {
    let state = DaemonState::new();
    let request = tonic::Request::new(());
    assert!(state.sandbox_caller(&request).unwrap().is_none());
    assert!(state.local_only(&request, "OpenSandbox").is_ok());
    // A raw service cannot be exposed to provider traffic merely by setting a
    // default repository or attaching an optional token interceptor.
    assert!(!is_sandbox_scoped("/atomic.SandboxService/OpenSandbox"));
}

#[test]
fn copied_native_extension_does_not_prove_live_registry_or_host_counted_custody() {
    let registry = Arc::new(InMemorySandboxGrants::new());
    let (token, grant) = registry
        .open(GrantRequest {
            repository_id: b"policy-only-no-native-store".to_vec(),
            view: "policy-view".into(),
            view_id: Some(1),
            acting_as: None,
            capabilities: grant_capabilities(&["sandbox.read".into()]).unwrap(),
            ttl_secs: 60,
        })
        .unwrap();
    let state = DaemonState::new().with_sandbox_grants(registry.clone());
    registry.close(&grant.repository_id, &grant.view).unwrap();
    let mut token_request = tonic::Request::new(());
    token_request.metadata_mut().insert_bin(
        SANDBOX_TOKEN_METADATA,
        tonic::metadata::MetadataValue::from_bytes(&token),
    );
    assert!(state.sandbox_caller(&token_request).is_err());
    let mut copied = tonic::Request::new(());
    copied.extensions_mut().insert(grant);
    let caller = state.sandbox_caller(&copied).unwrap().unwrap();
    assert!(caller.revalidate(&state).is_ok());
    // This is a trusted-native-extension path, not permission to reconstruct a
    // Host grant Entry/ReadGuard from serialized claims or bypass its drain.
}
