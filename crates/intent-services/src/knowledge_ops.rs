//! Explicit recorded-code operations. No caller-supplied path or derived hash
//! authorizes a read; the service resolves the owned workspace/root and epoch.

use std::{path::Path, sync::Arc};

use intent_atomic::knowledge::{canonical_read_basis, AtomicCodeClient};
use intent_atomic_proto::knowledge::{
    CodeQuery, CodeQueryRequest, DerivedReceipt, ImportDerivedRequest, QueryBudget, SourceScope,
};
use intent_core::{
    vcs::{NativeStateRef, RootBinding},
    Error, Result, WorkspaceGitRootId, WorkspaceId,
};

use crate::Services;

impl Services {
    /// Install the owned host client without exposing a normal app capability.
    #[must_use]
    pub fn with_atomic_code_client(mut self, client: Arc<AtomicCodeClient>) -> Self {
        self.atomic_code_client = Some(client);
        self
    }

    async fn recorded_code_source(
        &self,
        workspace_id: &WorkspaceId,
        git_root_id: Option<&WorkspaceGitRootId>,
    ) -> Result<(RootBinding, SourceScope, String)> {
        let workspace = self.store.get_workspace(workspace_id).await?;
        let locator = match self.resolve_git_read_root(&workspace, git_root_id).await? {
            Some(path) => path,
            None => crate::git_ops::worktree_path(&workspace)
                .ok_or_else(|| Error::Unsupported("workspace has no recorded Git root".into()))?,
        };
        let binding = self
            .git_engine_binding(&workspace, git_root_id, &locator)
            .await?;
        let engine = self.git_workspace_engine();
        let root = binding.clone();
        let state = tokio::task::spawn_blocking(move || {
            engine
                .recorded_state(&root)
                .map_err(crate::vcs_ops::engine_error)
        })
        .await
        .map_err(|error| Error::Internal(format!("recorded-code state observation: {error}")))??;
        let NativeStateRef::Git {
            repository_id,
            commit: Some(commit),
            ..
        } = state
        else {
            return Err(Error::Unsupported(
                "recorded-code queries require a committed Git state".into(),
            ));
        };
        if repository_id != binding.repository_id {
            return Err(Error::InvalidParams(
                "recorded source repository identity changed".into(),
            ));
        }
        self.validate_recorded_code_binding(&binding).await?;
        let scope = SourceScope {
            repository_id: binding.repository_id.as_str().into(),
            root_id: binding.root_id.clone(),
            root_epoch: binding.epoch,
            source_path: binding.locator.clone(),
            allowed_paths: vec![".".into()],
            excluded_paths: vec![],
        };
        Ok((binding, scope, commit.0))
    }

    async fn validate_recorded_code_binding(&self, binding: &RootBinding) -> Result<()> {
        let current = self
            .store
            .vcs_root_binding(&binding.workspace_id, &binding.root_id)
            .await?;
        if current.as_ref() != Some(binding) {
            return Err(Error::InvalidParams(
                "recorded-code root binding changed".into(),
            ));
        }
        Ok(())
    }

    fn owned_code_client(&self) -> Result<Arc<AtomicCodeClient>> {
        if let Some(client) = &self.atomic_code_client {
            return Ok(Arc::clone(client));
        }
        Err(Error::Unsupported(
            "recorded-code host is not explicitly configured".into(),
        ))
    }

    /// Owner-only background preparation for the current, server-resolved commit.
    /// Source authority stays in Git; this creates only a rebuildable derived index.
    /// # Errors
    /// Returns authorization, binding, source-state or native host failures.
    pub async fn prepare_recorded_code(
        &self,
        workspace_id: WorkspaceId,
        git_root_id: Option<WorkspaceGitRootId>,
    ) -> Result<DerivedReceipt> {
        self.require_owner(&workspace_id, "prepare recorded-code index")
            .await?;
        let client = self.owned_code_client()?;
        let (binding, scope, commit) = self
            .recorded_code_source(&workspace_id, git_root_id.as_ref())
            .await?;
        let receipt = if let Some(receipt) = client
            .prepared_index(&scope, &commit)
            .await
            .map_err(host_error)?
        {
            receipt
        } else {
            client
                .import(&ImportDerivedRequest {
                    operation_id: uuid::Uuid::now_v7().to_string(),
                    scope,
                    commit,
                })
                .await
                .map_err(host_error)?
        };
        self.require_owner(&workspace_id, "prepare recorded-code index")
            .await?;
        self.validate_recorded_code_binding(&binding).await?;
        Ok(receipt)
    }

    /// Read an already-prepared recorded index. Host failure or an absent index
    /// is an error; this explicit lane never falls back to live working files.
    /// `paths` only narrows the service-authorized workspace root.
    /// # Errors
    /// Refuses missing membership, foreign/rebound roots, unsafe filters, absent
    /// preparation and native/transport failures.
    pub async fn query_recorded_code(
        &self,
        workspace_id: WorkspaceId,
        git_root_id: Option<WorkspaceGitRootId>,
        query: CodeQuery,
        paths: Vec<String>,
        budget: QueryBudget,
    ) -> Result<serde_json::Value> {
        self.require_member(&workspace_id).await?;
        let client = self.owned_code_client()?;
        if paths.is_empty()
            || paths.len() > 64
            || paths.iter().any(|path| path != "." && !safe_filter(path))
        {
            return Err(Error::InvalidParams(
                "bounded repository-relative code filters are required".into(),
            ));
        }
        let (binding, scope, commit) = self
            .recorded_code_source(&workspace_id, git_root_id.as_ref())
            .await?;
        let receipt = client
            .prepared_index(&scope, &commit)
            .await
            .map_err(host_error)?
            .ok_or_else(|| {
                Error::Unsupported(
                    "recorded-code index is not prepared for the current commit".into(),
                )
            })?;
        let request = CodeQueryRequest {
            index: receipt.index,
            allowed_paths: paths,
            expected_commit: commit,
            query,
            budget: budget.clone(),
        };
        let result = client.query(&request).await.map_err(host_error)?;
        self.require_member(&workspace_id).await?;
        self.validate_recorded_code_binding(&binding).await?;
        let mut basis = canonical_read_basis(result.basis);
        let (current_binding, _, current_commit) = self
            .recorded_code_source(&workspace_id, git_root_id.as_ref())
            .await?;
        if current_binding != binding {
            return Err(Error::InvalidParams(
                "recorded-code root changed before response admission".into(),
            ));
        }
        self.require_member(&workspace_id).await?;
        if matches!(&basis.source_state, NativeStateRef::Git { commit: Some(commit), .. } if commit.as_str() != current_commit)
        {
            basis.stale = true;
        }
        let read_basis = bounded_search_basis(Some(&basis))?
            .ok_or_else(|| Error::Internal("recorded query has no read basis".into()))?;
        let mut reply = serde_json::json!({"facts":result.facts,"readBasis":read_basis});
        while serde_json::to_vec(&reply)
            .map_err(|error| Error::Internal(error.to_string()))?
            .len()
            > budget.max_bytes as usize
        {
            let removed = reply["facts"].as_array_mut().and_then(Vec::pop);
            if removed.is_none() {
                return Err(Error::Internal(
                    "code query budget cannot retain its read basis".into(),
                ));
            }
            reply["readBasis"]["coverage"]["complete"] = serde_json::Value::Bool(false);
            let reasons = reply["readBasis"]["truncation"]
                .as_array_mut()
                .ok_or_else(|| Error::Internal("query truncation shape changed".into()))?;
            if !reasons.iter().any(|value| value == "byteLimit") {
                reasons.push(serde_json::json!("byteLimit"));
            }
        }
        Ok(reply)
    }
}

fn safe_filter(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !path.contains(['\\', ':', '\0'])
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn host_error(error: impl std::fmt::Display) -> Error {
    Error::Internal(format!("recorded-code backend: {error}"))
}

fn bounded_search_basis(
    basis: Option<&intent_core::knowledge::QueryReadBasis>,
) -> Result<Option<serde_json::Value>> {
    basis
        .map(|basis| {
            let bytes = serde_json::to_vec(basis)
                .map_err(|error| Error::Internal(format!("serialize query read basis: {error}")))?;
            if bytes.len() > 16_384 {
                return Err(Error::Internal(
                    "query read basis exceeds its 16 KiB metadata budget".into(),
                ));
            }
            serde_json::from_slice(&bytes)
                .map_err(|error| Error::Internal(format!("serialize query read basis: {error}")))
        })
        .transpose()
}
