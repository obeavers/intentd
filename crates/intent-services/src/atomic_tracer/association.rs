use intent_atomic_proto::knowledge::{CodeFact, DerivedReceipt};
use intent_core::{
    knowledge::{KnowledgeProvenance, QueryReadBasis},
    vcs::{
        AtomicStateHash, ContentDigest, GitCommitId, GitTreeId, NativeStateRef, OperationId,
        RootBinding, VcsKind,
    },
    work_evidence::{NativeBindingState, TaskRevisionRef, WorkBinding},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fixture::{SOURCE_PATH, TASK_INSTRUCTION};

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidParams(format!("Atomic tracer: {}", message.into()))
}

pub(crate) fn digest(bytes: &[u8]) -> ContentDigest {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    ContentDigest::from_string(hex)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitSourceIdentity {
    pub root: RootBinding,
    pub commit: GitCommitId,
    pub tree: GitTreeId,
}

impl GitSourceIdentity {
    #[must_use]
    pub fn state(&self) -> NativeStateRef {
        NativeStateRef::Git {
            repository_id: self.root.repository_id.clone(),
            commit: Some(self.commit.clone()),
            tree: self.tree.clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let full_oid =
            |value: &str| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        if self.root.kind != VcsKind::Git
            || self.root.repository_id.as_str().is_empty()
            || self.root.root_id.is_empty()
            || !full_oid(self.commit.as_str())
            || !full_oid(self.tree.as_str())
        {
            return Err(invalid(
                "a complete immutable Git source identity is required",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmedTaskSource {
    pub reference: TaskRevisionRef,
    pub title: String,
    pub content: String,
    pub criteria: Vec<String>,
    /// Read from the original confirmed task, not a current assignment.
    pub allowed_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderExecution {
    pub adapter_id: String,
    pub model_id: Option<String>,
    /// An explicit honesty marker. Scripted ACP workers must set this to false.
    pub real_configured_provider: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRun {
    pub task: ConfirmedTaskSource,
    pub binding: WorkBinding,
    pub contribution_operation_id: OperationId,
    pub contribution_receipt: ContentDigest,
    pub source: GitSourceIdentity,
    /// Actual committed changed paths, including additions and deletions.
    pub changed_paths: Vec<String>,
    pub provider: ProviderExecution,
}

impl RecordedRun {
    pub(crate) fn validate(&self) -> Result<()> {
        self.source.validate()?;
        let admission = &self.binding.admission;
        if self.task.reference != self.binding.task_revision
            || admission.expected_task_rev != self.task.reference.rev
            || admission.workspace_id != self.task.reference.workspace_id
            || admission.note_id != self.task.reference.note_id
            || admission.workspace_id != self.source.root.workspace_id
            || admission.root.as_ref() != Some(&self.source.root)
            || admission.binding_id.as_str().is_empty()
            || admission.turn_attempt.is_empty()
            || admission.session_id.is_empty()
            || self.contribution_operation_id.as_str().is_empty()
            || self.contribution_receipt.as_str().is_empty()
            || admission.native_intent.is_some()
            || self.binding.native_state != NativeBindingState::NotRequired
            || !matches!(&admission.baseline, Some(NativeStateRef::Git { repository_id, commit: Some(_), .. }) if repository_id == &self.source.root.repository_id)
        {
            return Err(invalid(
                "original task/admission/contribution identity mismatch",
            ));
        }
        let expected_task = super::TaskSpec::default();
        if self.task.title != expected_task.title
            || self.task.content != expected_task.content
            || !self.task.content.contains(TASK_INSTRUCTION)
            || self.task.criteria != expected_task.criteria
            || self.task.allowed_paths != [SOURCE_PATH]
            || self.changed_paths != [SOURCE_PATH]
        {
            return Err(invalid(
                "confirmed task or exact one-file contribution differs from the fixture",
            ));
        }
        if !self.provider.real_configured_provider || self.provider.adapter_id.trim().is_empty() {
            return Err(invalid(
                "T1 requires one real configured provider; scripted success is not accepted",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_baseline(&self, initial: &GitSourceIdentity) -> Result<()> {
        self.validate()?;
        if self.source.root != initial.root
            || self.binding.admission.baseline.as_ref() != Some(&initial.state())
            || self.source.commit == initial.commit
        {
            return Err(invalid(
                "recorded run did not retain the original fixture baseline",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestObservation {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub log_digest: ContentDigest,
    pub source: GitSourceIdentity,
    pub fixed_test_digest: ContentDigest,
    pub package_digest: ContentDigest,
}

impl TestObservation {
    pub(crate) fn validate(&self, source: &GitSourceIdentity) -> Result<()> {
        if &self.source != source
            || self.exit_code != 0
            || self.command.len() != 3
            || self.command[1] != "--test"
            || self.command[2] != super::FIXED_TEST_PATH
            || self.log_digest != log_digest(&self.stdout, &self.stderr)?
            || self.fixed_test_digest != digest(super::fixture::FIXED_TEST.as_bytes())
            || self.package_digest != digest(super::fixture::PACKAGE.as_bytes())
        {
            return Err(invalid(
                "test observation is not a successful execution of the unchanged recorded fixture",
            ));
        }
        Ok(())
    }
}

pub(crate) fn log_digest(stdout: &str, stderr: &str) -> Result<ContentDigest> {
    let bytes = serde_json::to_vec(&(stdout, stderr))
        .map_err(|error| Error::Internal(format!("encode test logs: {error}")))?;
    Ok(digest(&bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryObservation {
    pub facts: Vec<CodeFact>,
    pub read_basis: QueryReadBasis,
}

pub(crate) fn validate_preparation(
    source: &GitSourceIdentity,
    prepared: &DerivedReceipt,
) -> Result<()> {
    if prepared.index.repository_id != source.root.repository_id.as_str()
        || prepared.index.root_id != source.root.root_id
        || prepared.index.root_epoch != source.root.epoch
        || prepared.commit != source.commit.as_str()
        || prepared.tree != source.tree.as_str()
        || prepared.index.generation.is_empty()
        || prepared.manifest_digest.is_empty()
    {
        return Err(invalid(
            "contribution and imported source identities differ",
        ));
    }
    Ok(())
}

pub(crate) fn validate_query(
    source: &GitSourceIdentity,
    prepared: &DerivedReceipt,
    query: &QueryObservation,
) -> Result<()> {
    validate_preparation(source, prepared)?;
    let basis = &query.read_basis;
    let expected_derived = NativeStateRef::Atomic {
        repository_id: source.root.repository_id.clone(),
        view: prepared.native_state.view.clone(),
        effective_state: AtomicStateHash::from_string(&prepared.native_state.effective_state),
        own_merkle: AtomicStateHash::from_string(&prepared.native_state.own_merkle),
        manifest: ContentDigest::from_string(&prepared.manifest_digest),
    };
    if basis.repository_id != source.root.repository_id
        || basis.root_id != source.root.root_id
        || basis.root_epoch != source.root.epoch
        || basis.source_state != source.state()
        || basis.derived_state.as_ref() != Some(&expected_derived)
        || basis.index_epoch != prepared.index_epoch
        || basis.provenance != KnowledgeProvenance::ImportedGitSnapshot
        || basis.task_revision.is_some()
        || basis.stale
        || !basis.coverage.complete
        || !basis.truncation.is_empty()
        || basis.visibility_digest != prepared.visibility_digest
        || basis.ignore_policy_digest != prepared.ignore_policy_digest
        || basis.query_version == 0
        || basis.ontology_version.is_empty()
    {
        return Err(invalid(
            "query does not describe the exact complete imported Git snapshot",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskQueryAssociation {
    pub schema_version: u32,
    /// Intent composes this evidence; native task-intent linkage is not claimed.
    pub authority: String,
    pub run: RecordedRun,
    pub test_observation: TestObservation,
    pub preparation: DerivedReceipt,
    pub corrected_query: QueryObservation,
}

impl TaskQueryAssociation {
    /// Validate a retained association again after a durable reopen.
    /// # Errors
    /// Refuses corrupt evidence, source drift and fabricated native task linkage.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.authority != "intent-composed-evidence" {
            return Err(invalid(
                "unknown task/query association schema or authority",
            ));
        }
        self.run.validate()?;
        self.test_observation.validate(&self.run.source)?;
        validate_query(&self.run.source, &self.preparation, &self.corrected_query)?;
        if !self
            .corrected_query
            .facts
            .iter()
            .any(|fact| fact.path == SOURCE_PATH && fact.preview.contains("Math.round"))
        {
            return Err(invalid(
                "the corrected recorded content has no positive query hit",
            ));
        }
        Ok(())
    }

    /// Exact bytes for the existing immutable evidence-blob store.
    /// # Errors
    /// Refuses an invalid association or serialization failure.
    pub fn retained_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| Error::Internal(format!("encode tracer association: {error}")))
    }
}

/// Construct an association only after all actual observations agree.
/// # Errors
/// Refuses source, task, test, query or provenance mismatches.
pub fn associate(
    run: RecordedRun,
    test_observation: TestObservation,
    preparation: DerivedReceipt,
    corrected_query: QueryObservation,
) -> Result<TaskQueryAssociation> {
    let association = TaskQueryAssociation {
        schema_version: 1,
        authority: "intent-composed-evidence".into(),
        run,
        test_observation,
        preparation,
        corrected_query,
    };
    association.validate()?;
    Ok(association)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedAssociation {
    pub digest: ContentDigest,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionCounts {
    pub agent_runs: u64,
    pub contributions: u64,
}
