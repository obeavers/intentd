//! Derived, recorded-code read contracts. Source metadata grants no task authority.

use crate::StateToken;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceScope {
    pub repository_id: String,
    pub root_id: String,
    pub root_epoch: u64,
    pub source_path: PathBuf,
    /// A nonempty union of exact paths/directory prefixes; "." means the owned root.
    pub allowed_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportDerivedRequest {
    pub operation_id: String,
    pub scope: SourceScope,
    /// Full immutable SHA-1 commit identity. Ref names and live HEAD are refused.
    pub commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivedRef {
    pub repository_id: String,
    pub root_id: String,
    pub root_epoch: u64,
    pub generation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivedReceipt {
    pub index: DerivedRef,
    pub index_epoch: u64,
    pub commit: String,
    pub tree: String,
    pub native_state: StateToken,
    pub manifest_digest: String,
    pub visibility_digest: String,
    pub ignore_policy_digest: String,
    pub indexed_files: u64,
    pub skipped_files: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CodeQuery {
    Search { pattern: String, literal: bool },
    Entities { path: String },
    Impact { target: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryBudget {
    pub max_results: u32,
    pub max_bytes: u32,
    pub max_files: u32,
    pub max_source_bytes: u64,
    pub max_millis: u32,
}

impl Default for QueryBudget {
    fn default() -> Self {
        Self {
            max_results: 20,
            max_bytes: 32_768,
            max_files: 128,
            max_source_bytes: 2_097_152,
            max_millis: 2_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeQueryRequest {
    pub index: DerivedRef,
    pub allowed_paths: Vec<String>,
    pub expected_commit: String,
    pub query: CodeQuery,
    pub budget: QueryBudget,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryCoverage {
    pub candidate_files: u64,
    pub read_files: u64,
    pub skipped_files: u64,
    pub unsupported_grammar_files: u64,
    pub source_bytes: u64,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryTruncation {
    ResultLimit,
    ByteLimit,
    SourceReadBudget,
    TimeBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryReadBasis {
    pub index: DerivedRef,
    pub index_epoch: u64,
    pub commit: String,
    pub tree: String,
    pub native_state: StateToken,
    pub manifest_digest: String,
    pub source_event_watermark: Option<u64>,
    pub projector_watermark: Option<u64>,
    pub query_version: u32,
    pub ontology_version: String,
    pub visibility_digest: String,
    pub ignore_policy_digest: String,
    pub stale: bool,
    pub coverage: QueryCoverage,
    pub truncation: Vec<QueryTruncation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeFact {
    pub path: String,
    pub kind: String,
    pub name: Option<String>,
    pub line: Option<u64>,
    pub end_line: Option<u64>,
    pub preview: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeQueryResult {
    pub basis: QueryReadBasis,
    pub facts: Vec<CodeFact>,
}
