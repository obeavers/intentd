//! Explicit evidence for recorded-code queries. It never authorizes a traversal.

use serde::{Deserialize, Serialize};

use crate::{
    vcs::{NativeStateRef, RepositoryId},
    work_evidence::TaskRevisionRef,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnowledgeProvenance {
    ImportedGitSnapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryCoverage {
    pub candidate_files: u64,
    pub read_files: u64,
    pub skipped_files: u64,
    pub unsupported_grammar_files: u64,
    /// Charged source bytes; native rereads are reserved before execution.
    pub source_bytes: u64,
    /// Input coverage within this scope, not proof that a semantic edge is absent.
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
    pub repository_id: RepositoryId,
    pub root_id: String,
    pub root_epoch: u64,
    pub source_state: NativeStateRef,
    pub derived_state: Option<NativeStateRef>,
    pub provenance: KnowledgeProvenance,
    /// Opaque generation nonce, not an ordered event/projector watermark.
    pub index_epoch: u64,
    pub task_revision: Option<TaskRevisionRef>,
    /// Unknown/unestablished watermarks stay null; zero must never stand in for them.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        vcs::{GitCommitId, GitTreeId},
        RetrieveResult,
    };

    #[test]
    fn legacy_context_json_is_unchanged_when_no_read_basis_was_established() {
        assert_eq!(
            serde_json::to_value(RetrieveResult::default()).unwrap(),
            serde_json::json!({"items": []})
        );
        let old: RetrieveResult = serde_json::from_str(r#"{"items":[]}"#).unwrap();
        assert!(old.read_basis.is_none());
    }

    #[test]
    fn query_basis_keeps_unknown_watermarks_and_imported_provenance_explicit() {
        let repository_id = RepositoryId::from_string("repository");
        let basis = QueryReadBasis {
            repository_id: repository_id.clone(),
            root_id: "root".into(),
            root_epoch: 3,
            source_state: NativeStateRef::Git {
                repository_id,
                commit: Some(GitCommitId::from_string("commit")),
                tree: GitTreeId::from_string("tree"),
            },
            derived_state: None,
            provenance: KnowledgeProvenance::ImportedGitSnapshot,
            index_epoch: 7,
            task_revision: None,
            source_event_watermark: None,
            projector_watermark: None,
            query_version: 1,
            ontology_version: "ontology".into(),
            visibility_digest: "visibility".into(),
            ignore_policy_digest: "policy".into(),
            stale: true,
            coverage: QueryCoverage::default(),
            truncation: vec![QueryTruncation::SourceReadBudget],
        };
        let encoded = serde_json::to_value(&basis).unwrap();
        assert_eq!(encoded["provenance"], "importedGitSnapshot");
        assert!(encoded["sourceEventWatermark"].is_null());
        assert!(encoded["projectorWatermark"].is_null());
        assert_eq!(
            serde_json::from_value::<QueryReadBasis>(encoded).unwrap(),
            basis
        );
    }
}
