//! Working-copy lifecycle before a durable workspace/root binding exists.
//!
//! Source locators and checkout anchors are observations, not authority or a
//! repository UUID. Services admit the source, choose the layout, retain locks,
//! verify ownership before cleanup, and persist the resulting root binding.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{GitCommitId, GitObjectId, VcsError, VcsKind, VcsResult};
use crate::CheckoutMode;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "layout",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GitCheckoutPlan {
    Linked {
        source: PathBuf,
        destination: PathBuf,
        registration_name: String,
        branch: String,
        base_ref: Option<String>,
        remote: String,
    },
    CowClone {
        source: PathBuf,
        destination: PathBuf,
        branch: String,
        base_ref: Option<String>,
        remote: String,
        /// Retarget a cache-derived clone after creation, when requested.
        origin_url: Option<String>,
    },
    DirectClone {
        source: PathBuf,
        destination: PathBuf,
        origin_url: String,
        branch: String,
        base_ref: Option<String>,
    },
    ExistingBranch {
        repository: PathBuf,
        branch: String,
    },
    InPlace {
        repository: PathBuf,
        branch: String,
        base_ref: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CheckoutPlan {
    Git {
        checkout: GitCheckoutPlan,
        /// A fetched, resolved provider head. Never fill this with a symbolic ref.
        expected_head: Option<GitCommitId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum CheckoutAnchor {
    Git { commit: GitCommitId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvisionedCheckout {
    pub destination: PathBuf,
    pub mode: CheckoutMode,
    pub anchor: CheckoutAnchor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DetachPlan {
    GitLinked {
        repository: PathBuf,
        checkout: PathBuf,
    },
    GitStandalone {
        checkout: PathBuf,
    },
}

/// Receipt for the locked detach phase. Recursive deletion happens separately,
/// after the owner releases the checkout/provisioning lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachedCheckout {
    pub trash: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CleanupPlan {
    DetachedCheckout { trash: PathBuf },
    Directory { directory: PathBuf },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CopyOnWriteSupport {
    Supported,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvisionEvent {
    SubmoduleOutput { chunk: String },
}

pub type ProvisionProgress = Arc<dyn Fn(ProvisionEvent) + Send + Sync>;

/// PR materialization distinguishes user repositories from the owned cache:
/// only cache-owned, unchanged helper branches may advance on a repeated fetch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ProvisionSource {
    Repository { path: PathBuf },
    OwnedCache { path: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequestCheckout {
    pub source: ProvisionSource,
    pub remote: String,
    pub number: u64,
    pub branch: String,
    pub expected_head: Option<GitCommitId>,
}

/// Non-durable source signals used by the legacy local-work surface and
/// lifecycle custody checks. This is not a candidate or an acceptance receipt.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub has_remote_refs: bool,
    pub unpushed_count: u64,
    pub uncommitted_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalWorkBlockerKind {
    Uncommitted,
    Unpushed,
    Stash,
    ExternalWorktree,
}

impl LocalWorkBlockerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uncommitted => "uncommitted changes",
            Self::Unpushed => "unpushed commits",
            Self::Stash => "a stash",
            Self::ExternalWorktree => "a linked worktree outside the folder",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkBlocker {
    pub kind: LocalWorkBlockerKind,
    pub repo: PathBuf,
}

/// Observed Git source metadata before a durable workspace root exists.
/// The native-source marker restricts transport routing; it is not authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitNativeSource {
    pub origin_url: Option<String>,
    pub native_source: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitCommitRelation {
    Equal,
    LeftDescendsRight,
    RightDescendsLeft,
    Diverged,
    Unavailable,
}

/// Compatibility receipt for the original native-review staged commit. The
/// observer receives the real primitive result before fallible postprocessing.
#[derive(Clone, Debug)]
pub struct GitSourceCommit {
    pub commit: GitCommitId,
    pub files: Vec<String>,
    pub index_refresh_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitSourceDiffCount {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
}

/// Blocking lifecycle primitives. Nothing here selects a fallback layout,
/// grants filesystem access, deletes a source branch by inference, or owns the
/// service's workspace metadata. Callers schedule these off the async runtime.
pub trait WorkspaceProvisioner: Send + Sync {
    fn kind(&self) -> VcsKind;

    fn unsupported(&self, operation: &'static str) -> VcsError {
        VcsError::Unsupported {
            operation,
            kind: self.kind(),
        }
    }

    /// # Errors
    /// Returns unsupported; Git checks the exact refs/heads syntax.
    fn git_branch_name_valid(&self, _branch: &str) -> VcsResult<bool> {
        Err(self.unsupported("gitBranchNameValid"))
    }

    /// # Errors
    /// Returns unsupported or unreadable Git source configuration.
    fn git_native_source(&self, _source: &Path) -> VcsResult<GitNativeSource> {
        Err(self.unsupported("gitNativeSource"))
    }

    /// # Errors
    /// Returns unsupported or an index read failure. The fingerprint preserves
    /// exact entry order, conflict stages, modes and extension flags.
    fn git_index_fingerprint(&self, _source: &Path) -> VcsResult<[u8; 32]> {
        Err(self.unsupported("gitIndexFingerprint"))
    }

    /// # Errors
    /// Returns unsupported or the original changed-path observation error.
    fn git_changed_paths(&self, _source: &Path) -> VcsResult<Vec<String>> {
        Err(self.unsupported("gitChangedPaths"))
    }

    /// # Errors
    /// Returns unsupported or the original HEAD/index/workdir comparison error.
    fn git_diff_counts(&self, _source: &Path, _staged: bool) -> VcsResult<Vec<GitSourceDiffCount>> {
        Err(self.unsupported("gitDiffCounts"))
    }

    /// # Errors
    /// Returns unsupported or the original stage/commit error. The caller owns
    /// the original lock and consuming authority for this compatibility action.
    fn git_stage_commit_observed(
        &self,
        _source: &Path,
        _files: &[String],
        _message: &str,
        _observed: &mut dyn FnMut(&GitCommitId),
    ) -> VcsResult<GitSourceCommit> {
        Err(self.unsupported("gitStageCommitObserved"))
    }

    /// # Errors
    /// Returns unsupported or invalid object IDs. Missing/unreadable graphs
    /// return Unavailable instead of inventing publication coverage.
    fn git_commit_relation(
        &self,
        _source: &Path,
        _left: &GitCommitId,
        _right: &GitCommitId,
    ) -> VcsResult<GitCommitRelation> {
        Err(self.unsupported("gitCommitRelation"))
    }

    /// # Errors
    /// Returns unsupported or a changed checkout/branch/expected HEAD. Services
    /// retain original native credential and checkout-publication lifetimes.
    fn git_attach_native_checkout(
        &self,
        _checkout: &Path,
        _branch: &str,
        _expected: &GitCommitId,
        _original_source: &str,
    ) -> VcsResult<()> {
        Err(self.unsupported("gitAttachNativeCheckout"))
    }

    /// # Errors
    /// Returns unsupported, checkout failure or a mismatching expected head.
    fn create(
        &self,
        _plan: &CheckoutPlan,
        _progress: Option<ProvisionProgress>,
    ) -> VcsResult<ProvisionedCheckout> {
        Err(self.unsupported("createCheckout"))
    }

    /// # Errors
    /// Returns unsupported or the backend's prune/rename error.
    fn detach(&self, _plan: &DetachPlan) -> VcsResult<DetachedCheckout> {
        Err(self.unsupported("detachCheckout"))
    }

    /// # Errors
    /// Returns unsupported or the backend's recursive-removal error.
    fn cleanup(&self, _plan: &CleanupPlan) -> VcsResult<()> {
        Err(self.unsupported("cleanupCheckout"))
    }

    /// # Errors
    /// Returns unsupported or a probe failure; a negative probe remains explicit.
    fn copy_support(&self, _source: &Path, _destination: &Path) -> VcsResult<CopyOnWriteSupport> {
        Err(self.unsupported("copySupport"))
    }

    /// # Errors
    /// Returns unsupported or a repository read failure.
    fn base_resolves(&self, _source: &Path, _base: &str, _remote: &str) -> VcsResult<bool> {
        Err(self.unsupported("baseResolves"))
    }

    /// # Errors
    /// Returns unsupported; Git preserves its existing fail-soft missing-repo probe.
    fn registered_checkout(&self, _source: &Path, _checkout: &Path) -> VcsResult<bool> {
        Err(self.unsupported("registeredCheckout"))
    }

    /// # Errors
    /// Returns unsupported; a missing checkout branch remains explicit.
    fn checkout_branch(&self, _checkout: &Path) -> VcsResult<Option<String>> {
        Err(self.unsupported("checkoutBranch"))
    }

    /// # Errors
    /// Returns unsupported or a branch-deletion error. The caller proves ownership.
    fn delete_source_branch(&self, _source: &Path, _branch: &str) -> VcsResult<()> {
        Err(self.unsupported("deleteSourceBranch"))
    }

    /// # Errors
    /// Returns unsupported or the backend's source ref lookup error.
    fn source_ref(&self, _source: &Path, _reference: &str) -> VcsResult<GitObjectId> {
        Err(self.unsupported("sourceRef"))
    }

    /// # Errors
    /// Returns unsupported or a boundary lookup failure, never an invented anchor.
    fn source_boundary(
        &self,
        _source: &Path,
        _base_ref: Option<&str>,
        _base_sha: Option<&str>,
        _target: &str,
    ) -> VcsResult<Option<GitCommitId>> {
        Err(self.unsupported("sourceBoundary"))
    }

    /// # Errors
    /// Returns unsupported or the backend's source default-branch lookup error.
    fn source_default_branch(&self, _source: &Path) -> VcsResult<String> {
        Err(self.unsupported("sourceDefaultBranch"))
    }

    /// # Errors
    /// Returns unsupported; Git preserves its fail-soft source branch observation.
    fn source_current_branch(&self, _source: &Path) -> VcsResult<Option<String>> {
        Err(self.unsupported("sourceCurrentBranch"))
    }

    /// # Errors
    /// Returns unsupported or an unreadable local repository, never a zeroed success.
    fn inspect_local_work(&self, _source: &Path) -> VcsResult<LocalWorkSummary> {
        Err(self.unsupported("inspectLocalWork"))
    }

    /// # Errors
    /// Returns unsupported or a source graph read failure. Invalid/missing heads do not cover.
    fn head_reached_by(&self, _source: &Path, _heads: &[GitCommitId]) -> VcsResult<bool> {
        Err(self.unsupported("headReachedBy"))
    }

    /// # Errors
    /// Returns unsupported or an incomplete custody scan; callers retain the folder on error.
    fn inspect_standalone_work(
        &self,
        _root: &Path,
        _heads: &[GitCommitId],
    ) -> VcsResult<Option<LocalWorkBlocker>> {
        Err(self.unsupported("inspectStandaloneWork"))
    }

    /// # Errors
    /// Returns unsupported or a repository lookup error.
    fn unique_branch_name(&self, _source: &Path, _desired: &str) -> VcsResult<String> {
        Err(self.unsupported("uniqueBranchName"))
    }

    /// # Errors
    /// Returns unsupported, fetch failure, a moved provider head or branch conflict.
    fn prepare_pull_request(
        &self,
        _request: &PullRequestCheckout,
        _token: Option<&str>,
    ) -> VcsResult<()> {
        Err(self.unsupported("preparePullRequest"))
    }

    /// # Errors
    /// Returns unsupported or a source-ref lookup error; absent remote base is explicit.
    fn source_refresh_branch(
        &self,
        _source: &Path,
        _base: Option<&str>,
        _remote: &str,
    ) -> VcsResult<Option<String>> {
        Err(self.unsupported("sourceRefreshBranch"))
    }

    /// # Errors
    /// Returns unsupported or the classified backend base-refresh failure.
    fn refresh_source_base(
        &self,
        _source: &Path,
        _base: Option<&str>,
        _remote: &str,
        _token: Option<&str>,
        _timeout: Option<Duration>,
    ) -> VcsResult<()> {
        Err(self.unsupported("refreshSourceBase"))
    }
}
