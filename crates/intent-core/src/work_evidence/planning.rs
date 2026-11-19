//! Explicit prospective task requirements. Declared paths describe the plan;
//! they do not grant filesystem access or prove observed edits/criterion success.

use serde::{Deserialize, Serialize};

use crate::vcs::ContentDigest;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskWorkPurpose {
    Source,
    Research,
    Review,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskCriterionRequirement {
    /// Position in the same task's exact acceptanceCriteria source.
    pub index: u32,
    /// SHA-256 of that exact criterion text, preventing index reuse after edits.
    pub text_digest: ContentDigest,
    pub required_kinds: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskFileRole {
    Reference,
    InScope,
    OutOfScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskFileReference {
    pub root_id: String,
    /// Repository-relative slash path; no host locator or implicit current root.
    pub path: String,
    pub role: TaskFileRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskWorkDefinition {
    pub purpose: TaskWorkPurpose,
    pub criteria: Vec<TaskCriterionRequirement>,
    pub files: Vec<TaskFileReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskConfigureWorkDefinitionInput {
    pub expected_note_version: i64,
    pub acceptance_criteria: Vec<String>,
    pub work_definition: Option<TaskWorkDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskConfigureWorkDefinitionResult {
    pub note: crate::Note,
    pub task_revision: super::TaskRevisionRef,
}
