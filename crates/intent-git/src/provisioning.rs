//! Git working-copy lifecycle behind the pre-binding provisioning contract.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use intent_core::vcs::{
    CheckoutAnchor, CheckoutPlan, CleanupPlan, CopyOnWriteSupport, DetachPlan, DetachedCheckout,
    GitCheckoutPlan, GitCommitId, GitCommitRelation, GitNativeSource, GitObjectId, GitSourceCommit,
    ProvisionEvent, ProvisionProgress, ProvisionSource, ProvisionedCheckout, PullRequestCheckout,
    VcsKind, VcsResult, WorkspaceProvisioner,
};
use intent_core::{CheckoutMode, Error};

/// Stateless lifecycle adapter. Services choose fallbacks and retain repository
/// locks; construction or a supplied path grants no authority to delete data.
#[derive(Debug, Default)]
pub struct GitWorkspaceProvisioner;

mod admission;

impl WorkspaceProvisioner for GitWorkspaceProvisioner {
    fn kind(&self) -> VcsKind {
        VcsKind::Git
    }

    fn git_branch_name_valid(&self, branch: &str) -> VcsResult<bool> {
        Ok(git2::Reference::is_valid_name(&format!(
            "refs/heads/{branch}"
        )))
    }

    fn git_native_source(&self, source: &Path) -> VcsResult<GitNativeSource> {
        Ok(GitNativeSource {
            origin_url: crate::remote::origin_url(source)?,
            native_source: git2::Repository::open(source)
                .ok()
                .and_then(|repo| repo.config().ok())
                .and_then(|config| config.get_string("intent.nativeCheckoutSource").ok()),
        })
    }

    fn git_index_fingerprint(&self, source: &Path) -> VcsResult<[u8; 32]> {
        Ok(admission::index_fingerprint(source)?)
    }

    fn git_changed_paths(&self, source: &Path) -> VcsResult<Vec<String>> {
        Ok(crate::commit::all_changed_paths(source)?)
    }

    fn git_diff_counts(
        &self,
        source: &Path,
        staged: bool,
    ) -> VcsResult<Vec<intent_core::vcs::GitSourceDiffCount>> {
        let diffs = if staged {
            crate::diff::diff_head_to_index(source)?
        } else {
            crate::diff::diff_index_to_workdir(source)?
        };
        Ok(diffs
            .into_iter()
            .map(|diff| intent_core::vcs::GitSourceDiffCount {
                path: diff.path,
                additions: diff.additions,
                deletions: diff.deletions,
            })
            .collect())
    }

    fn git_stage_commit_observed(
        &self,
        source: &Path,
        files: &[String],
        message: &str,
        observed: &mut dyn FnMut(&GitCommitId),
    ) -> VcsResult<GitSourceCommit> {
        if !files.is_empty() {
            crate::stage::stage(source, files)?;
        }
        let outcome = crate::commit::commit_observed(source, message, |sha| {
            observed(&GitCommitId::from_string(sha));
        })?;
        Ok(GitSourceCommit {
            commit: GitCommitId::from_string(outcome.hash),
            files: outcome.files,
            index_refresh_error: outcome.index_refresh_error,
        })
    }

    fn git_commit_relation(
        &self,
        source: &Path,
        left: &GitCommitId,
        right: &GitCommitId,
    ) -> VcsResult<GitCommitRelation> {
        Ok(admission::commit_relation(source, left, right)?)
    }

    fn git_attach_native_checkout(
        &self,
        checkout: &Path,
        branch: &str,
        expected: &GitCommitId,
        original_source: &str,
    ) -> VcsResult<()> {
        Ok(admission::attach_native_checkout(
            checkout,
            branch,
            expected,
            original_source,
        )?)
    }

    fn create(
        &self,
        plan: &CheckoutPlan,
        progress: Option<ProvisionProgress>,
    ) -> VcsResult<ProvisionedCheckout> {
        let CheckoutPlan::Git {
            checkout,
            expected_head,
        } = plan;
        let (destination, mode, head) = match checkout {
            GitCheckoutPlan::Linked {
                source,
                destination,
                registration_name,
                branch,
                base_ref,
                remote,
            } => {
                let head = crate::worktree::provision_worktree(
                    source,
                    registration_name,
                    destination,
                    branch,
                    base_ref.as_deref(),
                    remote,
                )?;
                (destination.clone(), CheckoutMode::Worktree, head)
            }
            GitCheckoutPlan::CowClone {
                source,
                destination,
                branch,
                base_ref,
                remote,
                origin_url,
            } => {
                let head = crate::cow_checkout::provision_cow_checkout(
                    source,
                    destination,
                    branch,
                    base_ref.as_deref(),
                    remote,
                )?;
                if let Some(origin) = origin_url {
                    crate::remote::set_remote_url(destination, "origin", origin)?;
                }
                (destination.clone(), CheckoutMode::Cow, head)
            }
            GitCheckoutPlan::DirectClone {
                source,
                destination,
                origin_url,
                branch,
                base_ref,
            } => {
                let chunks: Option<crate::repo_cache::ProgressChunkFn> = progress.map(|progress| {
                    Arc::new(move |chunk: &str| {
                        progress(ProvisionEvent::SubmoduleOutput {
                            chunk: chunk.to_string(),
                        });
                    }) as crate::repo_cache::ProgressChunkFn
                });
                let head = crate::repo_cache::provision_direct_checkout_with_progress(
                    source,
                    destination,
                    origin_url,
                    branch,
                    base_ref.as_deref(),
                    chunks,
                )?;
                (destination.clone(), CheckoutMode::Direct, head)
            }
            GitCheckoutPlan::ExistingBranch { repository, branch } => {
                crate::branches::checkout_branch(repository, branch)?;
                let head = crate::refs::rev_parse(repository, "HEAD")?;
                (repository.clone(), CheckoutMode::Direct, head)
            }
            GitCheckoutPlan::InPlace {
                repository,
                branch,
                base_ref,
            } => {
                // Preserve the existing retry behavior: reuse the branch first;
                // if it cannot be checked out, create at the requested base.
                if crate::branches::checkout_branch(repository, branch).is_err() {
                    match base_ref.as_deref().filter(|base| !base.is_empty()) {
                        Some(base) => crate::branches::create_branch_at(repository, branch, base)?,
                        None => crate::branches::create_branch(repository, branch, true)?,
                    }
                }
                let head = crate::refs::rev_parse(repository, "HEAD")?;
                (repository.clone(), CheckoutMode::Direct, head)
            }
        };
        if expected_head
            .as_ref()
            .is_some_and(|expected| expected.as_str() != head)
        {
            return Err(Error::InvalidParams("provisioned checkout does not match the fetched PR head; workspace creation cancelled".into()).into());
        }
        Ok(ProvisionedCheckout {
            destination,
            mode,
            anchor: CheckoutAnchor::Git {
                commit: GitCommitId(head),
            },
        })
    }

    fn detach(&self, plan: &DetachPlan) -> VcsResult<DetachedCheckout> {
        let trash = match plan {
            DetachPlan::GitLinked {
                repository,
                checkout,
            } => crate::worktree::detach_worktree(repository, checkout)?,
            DetachPlan::GitStandalone { checkout } => {
                crate::worktree::detach_checkout_dir(checkout)?
            }
        };
        Ok(DetachedCheckout { trash })
    }

    fn cleanup(&self, plan: &CleanupPlan) -> VcsResult<()> {
        match plan {
            CleanupPlan::DetachedCheckout { trash } => {
                crate::worktree::remove_detached_worktree(trash)?;
            }
            CleanupPlan::Directory { directory } => {
                crate::fs_remove::remove_dir_all_parallel(directory)
                    .map_err(|error| Error::Internal(error.to_string()))?;
            }
        }
        Ok(())
    }

    fn copy_support(&self, source: &Path, destination: &Path) -> VcsResult<CopyOnWriteSupport> {
        Ok(match crate::cow_probe(source, destination)? {
            crate::CowSupport::Supported => CopyOnWriteSupport::Supported,
            crate::CowSupport::Unsupported => CopyOnWriteSupport::Unsupported,
        })
    }

    fn base_resolves(&self, source: &Path, base: &str, remote: &str) -> VcsResult<bool> {
        Ok(crate::worktree::base_ref_resolves(source, base, remote)?)
    }

    fn registered_checkout(&self, source: &Path, checkout: &Path) -> VcsResult<bool> {
        Ok(crate::worktree::is_registered_worktree(source, checkout))
    }

    fn checkout_branch(&self, checkout: &Path) -> VcsResult<Option<String>> {
        Ok(crate::worktree::worktree_branch(checkout))
    }

    fn delete_source_branch(&self, source: &Path, branch: &str) -> VcsResult<()> {
        Ok(crate::branches::delete_local_branch(source, branch)?)
    }

    fn source_ref(&self, source: &Path, reference: &str) -> VcsResult<GitObjectId> {
        Ok(GitObjectId(crate::refs::rev_parse(source, reference)?))
    }

    fn source_boundary(
        &self,
        source: &Path,
        base_ref: Option<&str>,
        base_sha: Option<&str>,
        target: &str,
    ) -> VcsResult<Option<GitCommitId>> {
        Ok(
            crate::diff::resolve_branch_boundary(source, base_ref, base_sha, target)?
                .map(GitCommitId),
        )
    }

    fn source_default_branch(&self, source: &Path) -> VcsResult<String> {
        Ok(crate::branches::repo_default_branch(source)?)
    }

    fn source_current_branch(&self, source: &Path) -> VcsResult<Option<String>> {
        Ok(crate::status::current_branch_at(source))
    }

    fn inspect_local_work(&self, source: &Path) -> VcsResult<intent_core::vcs::LocalWorkSummary> {
        let summary = crate::local_changes(source)?;
        Ok(intent_core::vcs::LocalWorkSummary {
            branch: summary.branch,
            has_remote_refs: summary.has_remote_refs,
            unpushed_count: summary.unpushed_count,
            uncommitted_count: summary.uncommitted_count,
        })
    }

    fn head_reached_by(&self, source: &Path, heads: &[GitCommitId]) -> VcsResult<bool> {
        let heads: Vec<String> = heads.iter().map(|head| head.0.clone()).collect();
        Ok(crate::head_reached_by(source, &heads)?)
    }

    fn inspect_standalone_work(
        &self,
        root: &Path,
        heads: &[GitCommitId],
    ) -> VcsResult<Option<intent_core::vcs::LocalWorkBlocker>> {
        let heads: Vec<String> = heads.iter().map(|head| head.0.clone()).collect();
        Ok(
            crate::standalone_work::standalone_work(root, &heads)?.map(|work| {
                use crate::standalone_work::StandaloneWorkKind as GitKind;
                use intent_core::vcs::{LocalWorkBlocker, LocalWorkBlockerKind};
                LocalWorkBlocker {
                    repo: work.repo,
                    kind: match work.kind {
                        GitKind::Uncommitted => LocalWorkBlockerKind::Uncommitted,
                        GitKind::Unpushed => LocalWorkBlockerKind::Unpushed,
                        GitKind::Stash => LocalWorkBlockerKind::Stash,
                        GitKind::ExternalWorktree => LocalWorkBlockerKind::ExternalWorktree,
                    },
                }
            }),
        )
    }

    fn unique_branch_name(&self, source: &Path, desired: &str) -> VcsResult<String> {
        Ok(crate::branches::ensure_unique_branch_name(source, desired)?)
    }

    fn prepare_pull_request(
        &self,
        request: &PullRequestCheckout,
        token: Option<&str>,
    ) -> VcsResult<()> {
        let expected = request.expected_head.as_ref().map(GitCommitId::as_str);
        match &request.source {
            ProvisionSource::Repository { path } => crate::fetch::prepare_pr_branch(
                path,
                &request.remote,
                request.number,
                &request.branch,
                expected,
                token,
            )?,
            ProvisionSource::OwnedCache { path } => crate::fetch::prepare_cached_pr_branch(
                path,
                &request.remote,
                request.number,
                &request.branch,
                expected,
                token,
            )?,
        }
        Ok(())
    }

    fn source_refresh_branch(
        &self,
        source: &Path,
        base: Option<&str>,
        remote: &str,
    ) -> VcsResult<Option<String>> {
        Ok(crate::fetch::workspace_base_refresh_branch(
            source, base, remote,
        )?)
    }

    fn refresh_source_base(
        &self,
        source: &Path,
        base: Option<&str>,
        remote: &str,
        token: Option<&str>,
        timeout: Option<Duration>,
    ) -> VcsResult<()> {
        Ok(crate::fetch::refresh_workspace_base_with_timeout(
            source, base, remote, token, timeout,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{commit_file, init_repo};

    #[test]
    fn linked_checkout_detach_and_cleanup_preserve_the_source() {
        let source = init_repo("provision-contract-linked");
        commit_file(source.path(), "source.txt", "source\n");
        let storage = tempfile::tempdir().unwrap();
        let destination = storage.path().join("checkout");
        let provisioner = GitWorkspaceProvisioner;
        let original = provisioner.source_ref(source.path(), "HEAD").unwrap();
        let created = provisioner
            .create(
                &CheckoutPlan::Git {
                    checkout: GitCheckoutPlan::Linked {
                        source: source.path().to_path_buf(),
                        destination: destination.clone(),
                        registration_name: "contract-checkout".into(),
                        branch: "workspace".into(),
                        base_ref: None,
                        remote: "origin".into(),
                    },
                    expected_head: Some(GitCommitId(original.0.clone())),
                },
                None,
            )
            .unwrap();
        assert_eq!(created.mode, CheckoutMode::Worktree);
        assert_eq!(
            created.anchor,
            CheckoutAnchor::Git {
                commit: GitCommitId(original.0.clone())
            }
        );
        assert!(provisioner
            .registered_checkout(source.path(), &destination)
            .unwrap());
        let detached = provisioner
            .detach(&DetachPlan::GitLinked {
                repository: source.path().to_path_buf(),
                checkout: destination.clone(),
            })
            .unwrap();
        assert!(!destination.exists());
        let trash = detached.trash.unwrap();
        assert!(trash.exists());
        let cleanup = CleanupPlan::DetachedCheckout {
            trash: trash.clone(),
        };
        provisioner.cleanup(&cleanup).unwrap();
        provisioner.cleanup(&cleanup).unwrap();
        assert!(!trash.exists());
        assert_eq!(
            provisioner.source_ref(source.path(), "HEAD").unwrap(),
            original
        );
        assert_eq!(
            std::fs::read_to_string(source.path().join("source.txt")).unwrap(),
            "source\n"
        );
    }

    #[test]
    fn retrying_an_in_place_checkout_does_not_rewind_its_existing_branch() {
        let source = init_repo("provision-contract-retry");
        commit_file(source.path(), "source.txt", "base\n");
        let provisioner = GitWorkspaceProvisioner;
        let base = provisioner.source_ref(source.path(), "HEAD").unwrap();
        let plan = CheckoutPlan::Git {
            checkout: GitCheckoutPlan::InPlace {
                repository: source.path().to_path_buf(),
                branch: "workspace".into(),
                base_ref: Some(base.0),
            },
            expected_head: None,
        };
        provisioner.create(&plan, None).unwrap();
        commit_file(source.path(), "source.txt", "authored work\n");
        let authored = provisioner.source_ref(source.path(), "HEAD").unwrap();
        let retried = provisioner.create(&plan, None).unwrap();
        assert_eq!(
            retried.anchor,
            CheckoutAnchor::Git {
                commit: GitCommitId(authored.0)
            }
        );
        assert_eq!(
            std::fs::read_to_string(source.path().join("source.txt")).unwrap(),
            "authored work\n"
        );
    }
}
