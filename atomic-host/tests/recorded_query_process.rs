//! Actual host process and transport coverage for the Git-authoritative query lane.
//! This test requires Unix IPC. An unavailable listener is a failed prerequisite,
//! never a successful mocked query or restart result.
#![cfg(unix)]

use std::{path::Path, sync::Arc};

use intent_atomic::{knowledge::AtomicCodeClient, HostLaunchConfig, HostSupervisor};
use intent_atomic_proto::knowledge::{
    CodeQuery, CodeQueryRequest, DerivedReceipt, ImportDerivedRequest, QueryBudget, SourceScope,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn recorded_fee(source: &Path) -> TestResult<(String, String)> {
    std::fs::create_dir_all(source.join("src"))?;
    std::fs::write(
        source.join("src/fees.js"),
        "exports.feeCents = (amountCents, basisPoints) => Math.round(amountCents * basisPoints / 10000);\n",
    )?;
    let repository = git2::Repository::init(source)?;
    let mut index = repository.index()?;
    index.add_path(Path::new("src/fees.js"))?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repository.find_tree(tree_id)?;
    let signature = git2::Signature::now("Recorded query fixture", "fixture@example.invalid")?;
    let commit = repository.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "round the fee to the nearest cent",
        &tree,
        &[],
    )?;
    Ok((commit.to_string(), tree_id.to_string()))
}

async fn prepare_and_query(
    config: HostLaunchConfig,
    request: ImportDerivedRequest,
    expected_tree: &str,
) -> TestResult<DerivedReceipt> {
    let host = Arc::new(HostSupervisor::new(config)?);
    let task_host = Arc::clone(&host);
    let expected_tree = expected_tree.to_owned();
    let result = tokio::spawn(async move {
        let client = AtomicCodeClient::new(task_host);
        assert!(client
            .prepared_index(&request.scope, &request.commit)
            .await?
            .is_none());
        let receipt = client.import(&request).await?;
        assert_eq!(receipt.commit, request.commit);
        assert_eq!(receipt.tree, expected_tree);
        assert_eq!(receipt.index.repository_id, request.scope.repository_id);
        assert_eq!(receipt.index.root_id, request.scope.root_id);
        assert_eq!(receipt.index.root_epoch, request.scope.root_epoch);
        assert_eq!(
            client
                .prepared_index(&request.scope, &request.commit)
                .await?,
            Some(receipt.clone())
        );
        let mut query = CodeQueryRequest {
            index: receipt.index.clone(),
            allowed_paths: request.scope.allowed_paths.clone(),
            expected_commit: request.commit.clone(),
            query: CodeQuery::Search {
                pattern: "Math.round".into(),
                literal: true,
            },
            budget: QueryBudget::default(),
        };
        let found = client.query(&query).await?;
        assert_eq!(found.basis.commit, receipt.commit);
        assert_eq!(found.basis.tree, receipt.tree);
        assert_eq!(found.basis.index, receipt.index);
        assert_eq!(found.basis.index_epoch, receipt.index_epoch);
        assert_eq!(found.basis.native_state, receipt.native_state);
        assert!(!found.basis.stale);
        assert!(found
            .facts
            .iter()
            .any(|fact| { fact.path == "src/fees.js" && fact.preview.contains("Math.round") }));
        query.query = CodeQuery::Search {
            pattern: "UncommittedFeeSentinel".into(),
            literal: true,
        };
        assert!(client.query(&query).await?.facts.is_empty());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(receipt)
    })
    .await;
    // Reap the owned process even when the exercise returns an error or panics.
    let shutdown = host.shutdown().await;
    shutdown?;
    result?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_process_import_query_and_reprepare_preserve_recorded_generation() -> TestResult<()>
{
    // Keep the Unix socket path under platform limits, including on macOS.
    let directory = tempfile::Builder::new()
        .prefix("atomic-query-")
        .tempdir_in("/tmp")?;
    let probe = directory.path().join("probe.sock");
    let listener = std::os::unix::net::UnixListener::bind(&probe).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("recorded-query process test requires permitted Unix IPC: {error}"),
        )
    })?;
    drop(listener);
    std::fs::remove_file(probe)?;

    let source = directory.path().join("source");
    let (commit, tree) = recorded_fee(&source)?;
    std::fs::write(
        source.join("src/fees.js"),
        "// UncommittedFeeSentinel\nexports.feeCents = () => -1;\n",
    )?;
    let request = ImportDerivedRequest {
        operation_id: "recorded-query-fixture-import".into(),
        scope: SourceScope {
            repository_id: uuid::Uuid::new_v4().to_string(),
            root_id: "fee-root".into(),
            root_epoch: 1,
            source_path: source.clone(),
            allowed_paths: vec!["src/fees.js".into()],
            excluded_paths: vec![],
        },
        commit,
    };
    let config = HostLaunchConfig::new(
        Path::new(env!("CARGO_BIN_EXE_intent-atomic-host")).to_path_buf(),
        directory.path().join("daemon"),
        directory.path().join("stores"),
    );
    let first = prepare_and_query(config.clone(), request.clone(), &tree).await?;
    // A fresh supervisor starts a fresh child and a client with no prepared-index
    // authority. Explicit reprepare must reopen the durable original generation.
    let reopened = prepare_and_query(config, request, &tree).await?;
    assert_eq!(reopened, first);
    assert_eq!(
        std::fs::read_to_string(source.join("src/fees.js"))?,
        "// UncommittedFeeSentinel\nexports.feeCents = () => -1;\n"
    );
    Ok(())
}
