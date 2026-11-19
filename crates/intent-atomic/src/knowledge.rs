//! Recorded-code adapters. Services supply immutable authorized bindings; paths
//! arriving in a retrieval request never create or broaden those bindings.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use intent_atomic_proto::{knowledge as wire, Command, Reply};
use intent_core::vcs::{
    AtomicStateHash, ContentDigest, GitCommitId, GitTreeId, NativeStateRef, RepositoryId,
};
use intent_core::{
    ContextEngine, ContextError, EngineAvailability, RetrieveRequest, RetrieveResult, RetrievedItem,
};

use crate::{HostError, HostSupervisor, Result};

pub struct AtomicCodeClient {
    host: Arc<HostSupervisor>,
    indexes: tokio::sync::RwLock<HashMap<String, wire::DerivedReceipt>>,
}

impl AtomicCodeClient {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self {
            host,
            indexes: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Build a derived snapshot. The service must first authorize the whole scope.
    /// # Errors
    /// Returns host admission, source-policy, import and transport failures.
    pub async fn import(
        &self,
        request: &wire::ImportDerivedRequest,
    ) -> Result<wire::DerivedReceipt> {
        match self
            .host
            .request(Command::ImportDerived {
                request: request.clone(),
            })
            .await?
        {
            Reply::DerivedImported { receipt } => {
                let key = index_key(&request.scope, &request.commit)?;
                let mut indexes = self.indexes.write().await;
                if indexes.len() >= 256 && !indexes.contains_key(&key) {
                    if let Some(old) = indexes.keys().next().cloned() {
                        indexes.remove(&old);
                    }
                }
                indexes.insert(key, receipt.clone());
                Ok(receipt)
            }
            _ => Err(HostError::Protocol("expected derived import receipt")),
        }
    }

    /// Read the service-owned mapping; an external derived reference cannot
    /// create query authority. Missing entries need explicit preparation.
    /// # Errors
    /// Returns scope serialization failure.
    pub async fn prepared_index(
        &self,
        scope: &wire::SourceScope,
        commit: &str,
    ) -> Result<Option<wire::DerivedReceipt>> {
        let key = index_key(scope, commit)?;
        Ok(self.indexes.read().await.get(&key).cloned())
    }

    /// Read only a previously authorized derived generation and path union.
    /// # Errors
    /// Refuses out-of-scope facts and returns host/query or transport failures.
    pub async fn query(&self, request: &wire::CodeQueryRequest) -> Result<wire::CodeQueryResult> {
        let reply = self
            .host
            .request(Command::QueryCode {
                request: request.clone(),
            })
            .await?;
        let Reply::CodeQuery { result } = reply else {
            return Err(HostError::Protocol("expected code query result"));
        };
        if result.facts.len() > request.budget.max_results as usize
            || serde_json::to_vec(&result)?.len() > request.budget.max_bytes as usize
            || result.basis.coverage.read_files > u64::from(request.budget.max_files)
            || result.basis.coverage.source_bytes > request.budget.max_source_bytes
            || result.facts.iter().any(|fact| {
                !safe_path(&fact.path) || !authorized(&fact.path, &request.allowed_paths)
            })
        {
            return Err(HostError::Protocol(
                "derived query returned facts outside its scope or budget",
            ));
        }
        Ok(result)
    }
}

fn index_key(scope: &wire::SourceScope, commit: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(crate::spool::hex(&Sha256::digest(serde_json::to_vec(&(
        scope, commit,
    ))?)))
}

/// Owner-supplied context grant. It is never inferred from a request's filesystem path.
#[derive(Clone, Debug)]
pub struct ContextBinding {
    pub workspace_id: intent_core::WorkspaceId,
    pub workspace_path: PathBuf,
    pub index: wire::DerivedRef,
    pub allowed_paths: Vec<String>,
    pub expected_commit: String,
}

/// A real, explicitly constructed lexical backend. It is not registered as a
/// normal app option until service authorization and transport gates are complete.
pub struct AtomicContextEngine {
    client: AtomicCodeClient,
    bindings: HashMap<intent_core::WorkspaceId, ContextBinding>,
}

impl AtomicContextEngine {
    /// Install only scopes whose repository/root epoch the owner already admitted.
    /// # Errors
    /// Refuses duplicate workspace grants, relative locators and empty path scopes.
    pub fn new(client: AtomicCodeClient, bindings: Vec<ContextBinding>) -> Result<Self> {
        let mut owned = HashMap::new();
        for binding in bindings {
            if !binding.workspace_path.is_absolute()
                || binding.allowed_paths.is_empty()
                || binding
                    .allowed_paths
                    .iter()
                    .any(|path| path != "." && !safe_path(path))
            {
                return Err(HostError::Configuration(
                    "invalid recorded-code context binding",
                ));
            }
            if owned
                .insert(binding.workspace_id.clone(), binding)
                .is_some()
            {
                return Err(HostError::Configuration(
                    "duplicate context workspace binding",
                ));
            }
        }
        Ok(Self {
            client,
            bindings: owned,
        })
    }
}

#[async_trait::async_trait]
impl ContextEngine for AtomicContextEngine {
    async fn availability(&self) -> EngineAvailability {
        if self.bindings.is_empty() {
            return EngineAvailability::Unavailable {
                reason: "No authorized recorded-code roots".into(),
            };
        }
        match self.client.host.request(Command::Ping).await {
            Ok(Reply::Pong) if self.client.host.recovery_ready().await => {
                EngineAvailability::Available {
                    name: "atomic-recorded-code".into(),
                    version: Some(intent_atomic_proto::ATOMIC_REVISION.into()),
                }
            }
            Ok(_) => EngineAvailability::Unavailable {
                reason: "Atomic recovery is incomplete".into(),
            },
            Err(error) => EngineAvailability::Unavailable {
                reason: error.to_string(),
            },
        }
    }

    async fn retrieve(
        &self,
        request: RetrieveRequest,
    ) -> std::result::Result<RetrieveResult, ContextError> {
        let binding = self
            .bindings
            .get(&request.workspace_id)
            .filter(|binding| binding.workspace_path == request.workspace_path)
            .ok_or_else(|| ContextError::Unavailable {
                reason: "No authorized recorded-code binding for this workspace root".into(),
            })?;
        let budget = wire::QueryBudget {
            max_results: u32::try_from(request.max_results.unwrap_or(20).clamp(1, 100))
                .unwrap_or(100),
            ..Default::default()
        };
        let result = self
            .client
            .query(&wire::CodeQueryRequest {
                index: binding.index.clone(),
                allowed_paths: binding.allowed_paths.clone(),
                expected_commit: binding.expected_commit.clone(),
                query: wire::CodeQuery::Search {
                    pattern: request.query,
                    literal: true,
                },
                budget,
            })
            .await
            .map_err(|error| ContextError::CommandFailed(error.to_string()))?;
        Ok(to_context_result(result))
    }
}

fn to_context_result(result: wire::CodeQueryResult) -> RetrieveResult {
    RetrieveResult {
        items: result
            .facts
            .into_iter()
            .map(|fact| RetrievedItem {
                file: fact.path,
                symbol: fact.name,
                line: fact.line,
                preview: fact.preview,
                score: None,
            })
            .collect(),
        read_basis: Some(canonical_read_basis(result.basis)),
    }
}

/// Preserve established host query evidence in the core response vocabulary.
#[must_use]
pub fn canonical_read_basis(basis: wire::QueryReadBasis) -> intent_core::QueryReadBasis {
    let repository_id = RepositoryId::from_string(&basis.index.repository_id);
    let source_state = NativeStateRef::Git {
        repository_id: repository_id.clone(),
        commit: Some(GitCommitId::from_string(basis.commit)),
        tree: GitTreeId::from_string(basis.tree),
    };
    let derived_state = NativeStateRef::Atomic {
        repository_id: repository_id.clone(),
        view: basis.native_state.view,
        effective_state: AtomicStateHash::from_string(basis.native_state.effective_state),
        own_merkle: AtomicStateHash::from_string(basis.native_state.own_merkle),
        manifest: ContentDigest::from_string(basis.manifest_digest),
    };
    intent_core::QueryReadBasis {
        repository_id,
        root_id: basis.index.root_id,
        root_epoch: basis.index.root_epoch,
        source_state,
        derived_state: Some(derived_state),
        provenance: intent_core::KnowledgeProvenance::ImportedGitSnapshot,
        index_epoch: basis.index_epoch,
        task_revision: None,
        source_event_watermark: basis.source_event_watermark,
        projector_watermark: basis.projector_watermark,
        query_version: basis.query_version,
        ontology_version: basis.ontology_version,
        visibility_digest: basis.visibility_digest,
        ignore_policy_digest: basis.ignore_policy_digest,
        stale: basis.stale,
        coverage: intent_core::QueryCoverage {
            candidate_files: basis.coverage.candidate_files,
            read_files: basis.coverage.read_files,
            skipped_files: basis.coverage.skipped_files,
            unsupported_grammar_files: basis.coverage.unsupported_grammar_files,
            source_bytes: basis.coverage.source_bytes,
            complete: basis.coverage.complete,
        },
        truncation: basis
            .truncation
            .into_iter()
            .map(|reason| match reason {
                wire::QueryTruncation::ResultLimit => intent_core::QueryTruncation::ResultLimit,
                wire::QueryTruncation::ByteLimit => intent_core::QueryTruncation::ByteLimit,
                wire::QueryTruncation::SourceReadBudget => {
                    intent_core::QueryTruncation::SourceReadBudget
                }
                wire::QueryTruncation::TimeBudget => intent_core::QueryTruncation::TimeBudget,
            })
            .collect(),
    }
}

fn authorized(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        prefix == "."
            || path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', ':', '\0'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_conversion_retains_recorded_state_scope_staleness_and_budget_evidence() {
        let result = wire::CodeQueryResult {
            basis: wire::QueryReadBasis {
                index: wire::DerivedRef {
                    repository_id: "repo".into(),
                    root_id: "root".into(),
                    root_epoch: 9,
                    generation: "generation".into(),
                },
                index_epoch: 11,
                commit: "recorded-commit".into(),
                tree: "recorded-tree".into(),
                native_state: intent_atomic_proto::StateToken {
                    view: "derived".into(),
                    effective_state: "effective".into(),
                    own_merkle: "own".into(),
                },
                manifest_digest: "manifest".into(),
                source_event_watermark: None,
                projector_watermark: None,
                query_version: 1,
                ontology_version: "ontology".into(),
                visibility_digest: "visibility".into(),
                ignore_policy_digest: "ignore".into(),
                stale: true,
                coverage: wire::QueryCoverage {
                    candidate_files: 3,
                    read_files: 1,
                    ..wire::QueryCoverage::default()
                },
                truncation: vec![wire::QueryTruncation::SourceReadBudget],
            },
            facts: vec![wire::CodeFact {
                path: "src/lib.rs".into(),
                kind: "contentMatch".into(),
                name: None,
                line: Some(3),
                end_line: None,
                preview: "recorded bytes".into(),
            }],
        };
        let converted = to_context_result(result);
        assert_eq!(converted.items[0].preview, "recorded bytes");
        let basis = converted.read_basis.unwrap();
        assert_eq!(basis.root_epoch, 9);
        assert!(basis.stale);
        assert_eq!(
            basis.provenance,
            intent_core::KnowledgeProvenance::ImportedGitSnapshot
        );
        assert_eq!(basis.source_event_watermark, None);
        assert_eq!(
            basis.truncation,
            vec![intent_core::QueryTruncation::SourceReadBudget]
        );
        assert!(
            matches!(basis.source_state, NativeStateRef::Git { commit: Some(commit), .. } if commit.as_str() == "recorded-commit")
        );
    }

    #[tokio::test]
    async fn retrieval_request_cannot_create_or_broaden_an_owner_binding() {
        let host = Arc::new(
            HostSupervisor::new(crate::HostLaunchConfig::new(
                "/unconfigured/intent-atomic-host".into(),
                "/uncreated/daemon".into(),
                "/uncreated/stores".into(),
            ))
            .unwrap(),
        );
        let workspace_id = intent_core::WorkspaceId::from_string("workspace");
        let engine = AtomicContextEngine::new(
            AtomicCodeClient::new(host),
            vec![ContextBinding {
                workspace_id: workspace_id.clone(),
                workspace_path: "/owned/repository".into(),
                index: wire::DerivedRef {
                    repository_id: "repo".into(),
                    root_id: "root".into(),
                    root_epoch: 1,
                    generation: "generation".into(),
                },
                allowed_paths: vec!["src/public".into()],
                expected_commit: "commit".into(),
            }],
        )
        .unwrap();
        let result = engine
            .retrieve(RetrieveRequest {
                workspace_id,
                workspace_path: "/other/repository".into(),
                query: "needle".into(),
                max_results: None,
            })
            .await;
        assert!(matches!(result, Err(ContextError::Unavailable { .. })));
    }
}
