use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use intent_atomic_proto::knowledge::DerivedReceipt;
use intent_core::{BoxFuture, Error, Result};

use super::{
    associate,
    association::{invalid, validate_preparation, validate_query},
    digest,
    fixture::{execute_test, io_error},
    ExecutionCounts, Fixture, GitSourceIdentity, QueryObservation, RecordedRun,
    RetainedAssociation, TaskQueryAssociation, TaskSpec, TracerOutcome, TracerReport, SOURCE_PATH,
};

/// Services-owned ports for the executable scenario. Implementations must use
/// ordinary task confirmation, admission, configured provider execution and
/// retained Git contributions. No command may create a synthetic run receipt.
pub trait TracerDriver: Send {
    fn prepare_fixture<'a>(
        &'a mut self,
        fixture: &'a Fixture,
    ) -> BoxFuture<'a, Result<GitSourceIdentity>>;
    fn confirm_and_run<'a>(
        &'a mut self,
        fixture: &'a Fixture,
        task: &'a TaskSpec,
    ) -> BoxFuture<'a, Result<RecordedRun>>;
    /// Materialize precisely the recorded commit through the rooted Git adapter.
    fn materialize<'a>(
        &'a mut self,
        run: &'a RecordedRun,
        destination: &'a Path,
    ) -> BoxFuture<'a, Result<GitSourceIdentity>>;
    fn prepare_recorded_code<'a>(
        &'a mut self,
        run: &'a RecordedRun,
    ) -> BoxFuture<'a, Result<DerivedReceipt>>;
    /// Literal query restricted to src/fees.js through actual Services/host transport.
    fn query_recorded_code<'a>(
        &'a mut self,
        run: &'a RecordedRun,
        pattern: &'a str,
    ) -> BoxFuture<'a, Result<QueryObservation>>;
    /// Store exact bytes in the existing immutable evidence store before reopening.
    fn retain_association<'a>(
        &'a mut self,
        association: &'a TaskQueryAssociation,
    ) -> BoxFuture<'a, Result<RetainedAssociation>>;
    /// Stop and recreate both Services and host, keeping their fixture data.
    fn restart(&mut self) -> BoxFuture<'_, Result<()>>;
    fn retained_run<'a>(
        &'a mut self,
        original: &'a RecordedRun,
    ) -> BoxFuture<'a, Result<RecordedRun>>;
    fn read_association<'a>(
        &'a mut self,
        retained: &'a RetainedAssociation,
    ) -> BoxFuture<'a, Result<TaskQueryAssociation>>;
    /// Count actual agent-run admissions and Git contribution receipts in this scenario.
    fn execution_counts(&mut self) -> BoxFuture<'_, Result<ExecutionCounts>>;
    /// Settle providers, Services writers and the host on every final outcome.
    fn shutdown(&mut self) -> BoxFuture<'_, Result<()>>;
}

#[derive(Clone, Debug)]
pub struct TracerOptions {
    /// Dedicated developer output/data directory. Existing project directories
    /// are never reset; an existing fixture or report refuses a new scenario.
    pub directory: PathBuf,
    pub node_binary: PathBuf,
    pub test_timeout: Duration,
}

impl TracerOptions {
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            node_binary: "node".into(),
            test_timeout: Duration::from_secs(30),
        }
    }
}

/// Execute one real scenario and save honest success/failure evidence.
///
/// A scenario failure is returned as a Failed report so the developer still
/// gets report.json/report.md. Callers must exit nonzero for Failed outcomes.
/// # Errors
/// Refuses unsafe output reuse or an inability to retain the report itself.
pub async fn run_and_write_report(
    driver: &mut impl TracerDriver,
    options: &TracerOptions,
) -> Result<TracerReport> {
    let output = Arc::new(super::DirectoryGuard::create(&options.directory)?);
    let mut report = TracerReport::default();
    match execute(driver, options, &output, &mut report).await {
        Ok(()) => report.outcome = TracerOutcome::Passed,
        Err(error) => report.error = Some(error.to_string()),
    }
    if let Err(error) = driver.shutdown().await {
        report.outcome = TracerOutcome::Failed;
        report.error = Some(match report.error {
            Some(previous) => format!("{previous}; shutdown also failed: {error}"),
            None => format!("Tracer shutdown failed: {error}"),
        });
    }
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| Error::Internal(format!("encode tracer report: {error}")))?;
    output.write_new("report.json", &bytes)?;
    output.write_new("report.md", report.markdown()?.as_bytes())?;
    Ok(report)
}

async fn execute(
    driver: &mut impl TracerDriver,
    options: &TracerOptions,
    output: &Arc<super::DirectoryGuard>,
    report: &mut TracerReport,
) -> Result<()> {
    let fixture = Fixture::create_owned(&options.directory.join("fixture"), Arc::clone(output))?;
    let initial = driver.prepare_fixture(&fixture).await?;
    initial.validate()?;
    report.baseline = Some(initial.clone());
    report.observed(
        "fixture",
        "Created a disposable committed Git fixture with an unchanged fixed test.",
    );

    let initial_test = execute_test(
        &fixture.directory,
        &initial,
        &options.node_binary,
        options.test_timeout,
    )
    .await?;
    report.baseline_test = Some(initial_test.clone());
    if initial_test.exit_code == 0 {
        return Err(invalid(
            "the initial floor-based fixture unexpectedly passed the fixed test",
        ));
    }
    report.observed(
        "baseline test",
        "The actual fixed test fails against the initial recorded floor implementation.",
    );

    let run = driver
        .confirm_and_run(&fixture, &TaskSpec::default())
        .await?;
    run.validate_baseline(&initial)?;
    let counts = driver.execution_counts().await?;
    if counts
        != (ExecutionCounts {
            agent_runs: 1,
            contributions: 1,
        })
    {
        return Err(invalid(
            "the scenario did not retain exactly one agent run and one contribution",
        ));
    }
    report.observed("task and contribution", "One real configured provider ran from the confirmed original task; exactly src/fees.js changed.");

    let recorded = options.directory.join("recorded");
    if driver.materialize(&run, &recorded).await? != run.source {
        return Err(invalid(
            "test materialization source differs from the retained contribution",
        ));
    }
    Fixture::validate_fixed_inputs(&recorded)?;
    let recorded_source =
        std::fs::read_to_string(recorded.join(SOURCE_PATH)).map_err(|error| io_error(&error))?;
    if !recorded_source.contains("Math.round") || !recorded_source.contains("feeCents") {
        return Err(invalid(
            "recorded source does not contain the corrected feeCents implementation",
        ));
    }
    let observed_test = execute_test(
        &recorded,
        &run.source,
        &options.node_binary,
        options.test_timeout,
    )
    .await?;
    observed_test.validate(&run.source)?;
    report.observed(
        "recorded test",
        "The actual unchanged Node test passed against a materialization of the recorded commit.",
    );

    let prepared = driver.prepare_recorded_code(&run).await?;
    validate_preparation(&run.source, &prepared)?;
    let symbol = driver.query_recorded_code(&run, "feeCents").await?;
    validate_query(&run.source, &prepared, &symbol)?;
    if !symbol
        .facts
        .iter()
        .any(|fact| fact.path == SOURCE_PATH && fact.preview.contains("feeCents"))
    {
        return Err(invalid(
            "the real recorded-code query returned no positive feeCents hit",
        ));
    }
    let corrected = driver.query_recorded_code(&run, "Math.round").await?;
    let association = associate(run.clone(), observed_test, prepared.clone(), corrected)?;
    let bytes = association.retained_bytes()?;
    let retained = driver.retain_association(&association).await?;
    if retained.digest != digest(&bytes) || retained.length != bytes.len() as u64 {
        return Err(invalid(
            "retained task/query association differs from its exact observed bytes",
        ));
    }
    report.association = Some(association.clone());
    report.retained_association = Some(retained.clone());
    report.observed("Atomic query", "The real host returned positive symbol and corrected-content hits with matching commit, tree, root, epoch and imported provenance.");

    let sentinel = format!(
        "INTENT_ATOMIC_TRACER_UNCOMMITTED_SENTINEL_{}",
        uuid::Uuid::now_v7()
    );
    fixture.add_sentinel(&sentinel)?;
    let absent = driver.query_recorded_code(&run, &sentinel).await?;
    validate_query(&run.source, &prepared, &absent)?;
    if !absent.facts.is_empty() {
        return Err(invalid(
            "recorded-code query leaked the uncommitted working-file sentinel",
        ));
    }
    report.sentinel_excluded = true;
    report.observed(
        "uncommitted sentinel",
        "A working-file-only sentinel was absent from the exact recorded query.",
    );

    driver.restart().await?;
    if driver.execution_counts().await? != counts || driver.retained_run(&run).await? != run {
        return Err(invalid(
            "restart changed original lineage or created an agent run/contribution",
        ));
    }
    let reopened = driver.read_association(&retained).await?;
    reopened.validate()?;
    if reopened.retained_bytes()? != bytes {
        return Err(invalid(
            "reopened task/query association differs from retained original evidence",
        ));
    }
    let reprepared = driver.prepare_recorded_code(&run).await?;
    validate_preparation(&run.source, &reprepared)?;
    if reprepared != prepared {
        return Err(invalid(
            "explicit preparation did not reopen the same durable derived generation",
        ));
    }
    let requeried = driver.query_recorded_code(&run, "Math.round").await?;
    validate_query(&run.source, &reprepared, &requeried)?;
    if requeried != association.corrected_query {
        return Err(invalid(
            "reopened recorded query differs from the retained original result",
        ));
    }
    let absent = driver.query_recorded_code(&run, &sentinel).await?;
    validate_query(&run.source, &reprepared, &absent)?;
    if !absent.facts.is_empty() || driver.execution_counts().await? != counts {
        return Err(invalid(
            "restart lost recorded-source isolation or duplicated execution",
        ));
    }
    report.durable_reopen_verified = true;
    report.observed("durable reopen", "Services and host restarted; explicit reprepare reused the same derived generation and original task evidence without another agent run or contribution.");
    Ok(())
}
