use super::*;

#[tokio::test]
async fn missing_production_composition_refuses_before_any_runtime_io() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("must-remain-absent");
    let mut driver = ServicesTracerDriver::new(ServicesTracerConfig {
        directory: path.clone(),
        host_binary: temporary.path().join("never-executed-host"),
        provider: "codex".into(),
        model: None,
        timeout: Duration::from_secs(1),
    })
    .unwrap();
    let error = driver.open_runtime(false).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("production application composer"));
    assert!(!path.exists());
    assert!(driver.runtime.is_none());
}

#[test]
fn contribution_arrival_never_substitutes_for_observed_original_turn_retirement() {
    assert!(!original_turn_settled(
        true,
        false,
        AgentStatus::RuntimeIdle
    ));
    assert!(!original_turn_settled(
        false,
        true,
        AgentStatus::RuntimeIdle
    ));
    assert!(!original_turn_settled(false, false, AgentStatus::Active));
    assert!(original_turn_settled(
        false,
        false,
        AgentStatus::RuntimeIdle
    ));
}

#[tokio::test]
async fn replaced_daemon_is_rejected_before_any_runtime_reopen() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("new-run");
    let output = Arc::new(crate::atomic_tracer::DirectoryGuard::create(&path).unwrap());
    let daemon = Arc::new(output.create_child("daemon").unwrap());
    daemon
        .write_new("intentd.db", b"owned fixture, not opened as a database")
        .unwrap();
    let database =
        crate::atomic_tracer::FileGuard::open(&daemon.path().join("intentd.db")).unwrap();
    let mut driver = ServicesTracerDriver::new(ServicesTracerConfig {
        directory: path,
        host_binary: temporary.path().join("never-executed-host"),
        provider: "codex".into(),
        model: None,
        timeout: Duration::from_secs(1),
    })
    .unwrap()
    .with_composer(|services| services);
    driver.output = Some(output.clone());
    driver.daemon = Some(daemon.clone());
    driver.database = Some(database);
    driver.validate_owned_paths(true).unwrap();
    std::fs::rename(daemon.path(), output.path().join("original-daemon")).unwrap();
    std::fs::create_dir(daemon.path()).unwrap();
    std::fs::write(daemon.path().join("intentd.db"), b"unrelated replacement").unwrap();
    let error = driver.open_runtime(true).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("owned tracer directory was replaced"));
    assert!(driver.runtime.is_none());
    assert_eq!(
        std::fs::read(daemon.path().join("intentd.db")).unwrap(),
        b"unrelated replacement"
    );
}
