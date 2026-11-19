//! Developer-only, Git-authoritative task-to-recorded-query tracer.
//!
//! The controller never replaces task or source authority with a query receipt.
//! Its driver must use the ordinary configured provider and retained admissions.
//! Test drivers verify orchestration only; they do not qualify a real T1 run.

mod association;
mod controller;
mod fixture;
mod owned_directory;
mod report;

pub(crate) use association::digest;
pub(crate) use owned_directory::{DirectoryGuard, FileGuard};

pub use association::{
    associate, ConfirmedTaskSource, ExecutionCounts, GitSourceIdentity, ProviderExecution,
    QueryObservation, RecordedRun, RetainedAssociation, TaskQueryAssociation, TestObservation,
};
pub use controller::{run_and_write_report, TracerDriver, TracerOptions};
pub use fixture::{Fixture, TaskSpec, FIXED_TEST_PATH, SOURCE_PATH};
pub use report::{PhaseObservation, TracerOutcome, TracerReport};

#[cfg(test)]
mod tests;
