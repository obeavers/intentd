use super::*;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> (tempfile::TempDir, Host) {
    let directory = tempfile::tempdir().unwrap();
    let host = Host::new(crate::HostConfig {
        stores_dir: directory.path().join("stores"),
        config_dir: directory.path().join("config"),
        spool_dir: directory.path().join("spool"),
    })
    .unwrap();
    (directory, host)
}

#[test]
fn actual_canonical_gate_signature_and_configured_attribution_round_trip() {
    let (_directory, host) = fixture();
    let fm = serde_json::json!({"id":"INTENT-1","uid":"signing-fixture","title":"canonical qualification","status":"todo","created_at":"2026-11-13T00:00:00Z"});
    let node = atomic_canonical::lift::lift_intent(
        fm.as_object().unwrap(),
        ":::why\nA qualification reason.\n:::",
    )
    .unwrap();
    let signed = host.sign_local_native_evidence(node.to_value()).unwrap();
    let actual = host.verify_local_native_evidence(&signed).unwrap();
    let node: atomic_canonical::CanonicalNode = serde_json::from_value(actual.clone()).unwrap();
    let gate = atomic_canonical::validate_intent(&node);
    assert!(gate.conforms, "{:?}", gate.results);
    assert_eq!(actual["attributedTo"], signed.signer.did);
    let public = atomic_identity::PublicKey::from_base32(&signed.signer.public_key_base32).unwrap();
    atomic_canonical::verify(&node, &public).unwrap();
    let again = host
        .sign_local_native_evidence(serde_json::json!({"report":"same daemon evidence identity"}))
        .unwrap();
    assert_eq!(signed.signer, again.signer);
    let key_path = host.config.config_dir.join("evidence-keys/ed25519.key");
    let metadata = std::fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.len(), 32);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(!host.config.config_dir.join("identities").exists());
}

#[test]
fn proof_body_signature_and_attributed_to_tampering_never_verify() {
    let (_directory, host) = fixture();
    let signed=host.sign_local_native_evidence(serde_json::json!({"report":"exact report bytes","target":"original target","closure":["one","two"]})).unwrap();
    let original = host.verify_local_native_evidence(&signed).unwrap();
    for field in ["report", "target", "attributedTo"] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!("tampered");
        let bytes = atomic_canonical::jcs::canonicalize(&changed).into_bytes();
        let mut evidence = signed.clone();
        evidence.document = composition::retain_bytes(&host, &bytes, MAX_DOCUMENT).unwrap();
        assert!(host.verify_local_native_evidence(&evidence).is_err());
    }
    let mut wrong = signed.clone();
    wrong.signer.did = "did:atomic:not-the-configured-key".into();
    assert!(host.verify_local_native_evidence(&wrong).is_err());
    let bad=host.sign_local_native_evidence(serde_json::json!({"attributedTo":"another-agent-label","report":"not a principal binding"}));
    assert!(bad.is_err());
}

#[test]
fn unsafe_or_replaced_key_storage_is_refused_and_missing_verification_never_mints() {
    let (_directory, host) = fixture();
    let signed = host
        .sign_local_native_evidence(serde_json::json!({"report":"retained"}))
        .unwrap();
    let path = host.config.config_dir.join("evidence-keys/ed25519.key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(host.verify_local_native_evidence(&signed).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(host.verify_local_native_evidence(&signed).is_err());
    assert!(!path.exists());
    std::os::unix::fs::symlink(host.config.config_dir.join("elsewhere"), &path).unwrap();
    assert!(host
        .sign_local_native_evidence(serde_json::json!({"report":"unsafe"}))
        .is_err());
}
