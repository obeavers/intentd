//! Git implementation of the engine boundary.
//!
//! Blocking operations deliberately delegate to the established Git mechanics.
//! Authorization, assignment scopes, capture barriers, and operation admission
//! stay with the caller. A root tagged for another engine is never opened as Git.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use intent_core::vcs::{self, GitObjectId, NativeObjectRef, VcsFileEntry, VcsKind, VcsStatus};
use intent_core::{Error, FileStatus, GitStatus};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod adoption;
mod composition;
mod recording;
mod storage;

/// Stateless Git adapter. Share it through the composition root rather than
/// selecting an implementation by probing a workspace's filesystem.
#[derive(Debug, Default)]
pub struct GitWorkspaceEngine {
    comparisons: Mutex<ComparisonCache>,
}

const MAX_COMPARISONS: usize = 64;
const MAX_COMPARISON_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIFF_BYTES: usize = 480_000;
const MIN_DIFF_BYTES: usize = 64_000;

#[derive(Debug, Default)]
struct ComparisonCache {
    entries: HashMap<String, Arc<Comparison>>,
    order: VecDeque<String>,
    bytes: usize,
}

struct ComparisonBasis {
    method: &'static str,
    source: std::path::PathBuf,
    before: vcs::NativeStateRef,
    after: vcs::NativeStateRef,
    before_capture: vcs::ContentDigest,
    after_capture: vcs::ContentDigest,
}

#[derive(Debug)]
struct Comparison {
    source: std::path::PathBuf,
    files: Vec<crate::diff::TreeDelta>,
    bytes: usize,
}

fn comparison_resident_bytes(comparison: &Comparison) -> usize {
    let strings = comparison.files.iter().fold(0usize, |bytes, file| {
        bytes
            .saturating_add(file.path.capacity())
            .saturating_add(file.old_blob.as_ref().map_or(0, String::capacity))
            .saturating_add(file.new_blob.as_ref().map_or(0, String::capacity))
    });
    std::mem::size_of::<Comparison>()
        .saturating_add(
            comparison
                .source
                .capacity()
                .saturating_mul(if cfg!(windows) { 2 } else { 1 }),
        )
        .saturating_add(
            comparison
                .files
                .capacity()
                .saturating_mul(std::mem::size_of::<crate::diff::TreeDelta>()),
        )
        .saturating_add(strings)
        // Include the map key, queue key, Arc counters and table bookkeeping.
        .saturating_add(512)
}

impl GitWorkspaceEngine {
    fn compare_basis(
        &self,
        basis: ComparisonBasis,
        query: &vcs::DiffQuery,
        page_token: Option<&str>,
        trees: impl FnOnce() -> vcs::VcsResult<(String, String)>,
    ) -> vcs::VcsResult<vcs::DiffPage> {
        let mut paths = query.paths.clone();
        paths.sort();
        paths.dedup();
        if paths
            .iter()
            .any(|path| !crate::checkpoint::safe_relative_path(path))
        {
            return Err(vcs::VcsError::InvalidInput {
                reason: "comparison paths must be canonical repository-relative paths".into(),
            });
        }
        let budget = usize::try_from(query.max_bytes)
            .unwrap_or(MAX_DIFF_BYTES)
            .clamp(MIN_DIFF_BYTES, MAX_DIFF_BYTES);
        let before_capture = basis.before_capture;
        let after_capture = basis.after_capture;
        let key = content_digest(&json_bytes(&(
            basis.method,
            &basis.source,
            &before_capture,
            &after_capture,
            &paths,
            budget,
        ))?);
        let offset = match page_token {
            Some(token) => parse_comparison_token(token, &key)?,
            None => 0,
        };
        let cached = self
            .comparisons
            .lock()
            .map_err(|_| vcs::VcsError::Unavailable {
                reason: "comparison cache poisoned".into(),
            })?
            .entries
            .get(key.as_str())
            .cloned();
        let comparison = if let Some(cached) = cached {
            cached
        } else {
            if page_token.is_some() {
                return Err(vcs::VcsError::Unavailable {
                    reason: "comparison cursor expired; restart from the first page".into(),
                });
            }
            let source = &basis.source;
            let (old_tree, new_tree) = trees()?;
            let wanted: HashSet<&str> = paths.iter().map(String::as_str).collect();
            let files: Vec<_> = crate::diff::tree_deltas(source, &old_tree, &new_tree, &paths)?
                .into_iter()
                .filter(|file| wanted.is_empty() || wanted.contains(file.path.as_str()))
                .collect();
            let mut comparison = Comparison {
                source: source.clone(),
                files,
                bytes: 0,
            };
            comparison.bytes = comparison_resident_bytes(&comparison);
            if comparison.bytes > MAX_COMPARISON_METADATA_BYTES {
                return Err(vcs::VcsError::Unavailable {
                    reason: "comparison metadata exceeds the resident byte budget".into(),
                });
            }
            let comparison = Arc::new(comparison);
            let mut cache = self
                .comparisons
                .lock()
                .map_err(|_| vcs::VcsError::Unavailable {
                    reason: "comparison cache poisoned".into(),
                })?;
            if let Some(existing) = cache.entries.get(key.as_str()).cloned() {
                existing
            } else {
                while cache.entries.len() >= MAX_COMPARISONS
                    || cache.bytes + comparison.bytes > MAX_COMPARISON_METADATA_BYTES
                {
                    let Some(old) = cache.order.pop_front() else {
                        break;
                    };
                    if let Some(removed) = cache.entries.remove(&old) {
                        cache.bytes = cache.bytes.saturating_sub(removed.bytes);
                    }
                }
                cache.bytes += comparison.bytes;
                cache.order.push_back(key.as_str().to_string());
                cache
                    .entries
                    .insert(key.as_str().to_string(), comparison.clone());
                comparison
            }
        };
        if offset > comparison.files.len() {
            return Err(vcs::VcsError::InvalidInput {
                reason: "comparison cursor lies beyond its immutable file list".into(),
            });
        }
        let mut page = vcs::DiffPage {
            before: basis.before,
            after: basis.after,
            before_capture,
            after_capture,
            files: Vec::new(),
            next_token: None,
        };
        let reserve_token = format!("git.compare.v1:{}:{}", key.as_str(), comparison.files.len());
        let mut used = json_bytes(&page)?.len() + reserve_token.len() + 32;
        for (position, file) in comparison.files.iter().enumerate().skip(offset) {
            let mut entry =
                neutral_diff(crate::diff::hydrate_tree_delta(&comparison.source, file)?);
            let mut bytes = json_bytes(&entry)?.len() + 1;
            if used + bytes > budget && !page.files.is_empty() {
                page.next_token = Some(format!("git.compare.v1:{}:{position}", key.as_str()));
                break;
            }
            if used + bytes > budget {
                entry.hunks.clear();
                entry.truncated_reason = Some(vcs::DiffOmission::FileTooLarge);
                bytes = json_bytes(&entry)?.len() + 1;
                if used + bytes > budget {
                    return Err(vcs::VcsError::InvalidInput {
                        reason: "comparison file metadata exceeds the requested page budget".into(),
                    });
                }
            }
            used += bytes;
            page.files.push(entry);
        }
        Ok(page)
    }

    /// Lift an already-computed Git scan into the neutral read model. This does
    /// no repository I/O, so cached attribution and lock reads need no new scan.
    /// Conflict metadata is unknown because the legacy status omits it; use
    /// `WorkspaceEngine::status` for an index-backed conflict result.
    #[must_use]
    pub fn status_from_git(status: GitStatus) -> VcsStatus {
        VcsStatus {
            kind: VcsKind::Git,
            branch: status.branch,
            view: None,
            ahead: status.ahead,
            behind: status.behind,
            diverged: status.diverged,
            files: status.files.into_iter().map(file_status).collect(),
            has_uncommitted_changes: status.has_uncommitted_changes,
            has_untracked_files: status.has_untracked_files,
            files_truncated: status.files_truncated,
            total_files: status.total_files,
            has_upstream: status.has_upstream,
            unpushed_count: status.unpushed_count,
            conflicts: None,
        }
    }

    /// Convert only the file rows of a cached status, preserving Git's staged
    /// and unstaged double entries and gitlink metadata without a new scan.
    /// Conflict flags remain unknown until an engine status scan provides them.
    #[must_use]
    pub fn status_files_from_git(files: &[FileStatus]) -> Vec<VcsFileEntry> {
        files.iter().cloned().map(file_status).collect()
    }
}

impl vcs::WorkspaceEngine for GitWorkspaceEngine {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn capture_target(
        &self,
        root: &vcs::RootBinding,
        barrier: &vcs::WriteBarrierPermit,
        spool: &Path,
    ) -> vcs::VcsResult<vcs::PreparedTargetCapture> {
        adoption::capture_target(root, barrier, spool)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reopen_target_capture(
        &self,
        root: &vcs::RootBinding,
        manifest: &Path,
    ) -> vcs::VcsResult<vcs::PreparedTargetCapture> {
        adoption::reopen_capture(root, manifest)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn prepare_adoption(
        &self,
        root: &vcs::RootBinding,
        capture: &vcs::PreparedTargetCapture,
        candidate: &vcs::PreparedComposition,
        operation: &vcs::OperationId,
        spool: &Path,
    ) -> vcs::VcsResult<vcs::PreparedAdoption> {
        adoption::prepare(root, capture, candidate, operation, spool)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reopen_adoption(
        &self,
        root: &vcs::RootBinding,
        manifest: &Path,
    ) -> vcs::VcsResult<vcs::PreparedAdoption> {
        adoption::reopen_preparation(root, manifest)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn apply_adoption(
        &self,
        root: &vcs::RootBinding,
        barrier: &vcs::WriteBarrierPermit,
        prepared: &vcs::PreparedAdoption,
        authorization: &vcs::AdoptionAuthorization,
    ) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
        adoption::apply(root, barrier, prepared, authorization)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn reconcile_adoption(
        &self,
        root: &vcs::RootBinding,
        barrier: &vcs::WriteBarrierPermit,
        prepared: &vcs::PreparedAdoption,
        authorization: &vcs::AdoptionAuthorization,
    ) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
        adoption::reconcile(root, barrier, prepared, authorization)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn read_adoption_receipt(
        &self,
        root: &vcs::RootBinding,
        prepared: &vcs::PreparedAdoption,
        authorization: &vcs::AdoptionAuthorization,
    ) -> vcs::VcsResult<vcs::VerifiedAdoptionReceipt> {
        adoption::read_receipt(root, prepared, authorization)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn read_adoption_progress(
        &self,
        root: &vcs::RootBinding,
        prepared: &vcs::PreparedAdoption,
        authorization: &vcs::AdoptionAuthorization,
    ) -> vcs::VcsResult<vcs::VerifiedAdoptionProgress> {
        adoption::read_progress(root, prepared, authorization)
    }
    fn reopen_composition(
        &self,
        root: &vcs::RootBinding,
        directory: &Path,
    ) -> vcs::VcsResult<vcs::PreparedComposition> {
        composition::reopen(root, directory)
    }
    fn copy_composition(
        &self,
        prepared: &vcs::PreparedComposition,
        destination: &Path,
    ) -> vcs::VcsResult<vcs::PreparedComposition> {
        composition::copy(prepared, destination)
    }
    fn kind(&self) -> VcsKind {
        VcsKind::Git
    }

    fn capabilities(&self) -> vcs::VcsCapabilities {
        vcs::VcsCapabilities {
            staging: true,
            hunk_staging: true,
            exact_record: cfg!(unix),
            composition: cfg!(unix),
            materialization: cfg!(unix),
            closure_export: cfg!(unix),
            closure_restore: cfg!(unix),
            ..vcs::VcsCapabilities::default()
        }
    }

    fn recorded_state(&self, root: &vcs::RootBinding) -> vcs::VcsResult<vcs::NativeStateRef> {
        let repo =
            git2::Repository::open(git_root(root, "recordedState")?).map_err(crate::map_git_err)?;
        let head = match repo.head() {
            Ok(head) => head,
            Err(error) if error.code() == git2::ErrorCode::UnbornBranch => {
                return Ok(vcs::NativeStateRef::Git {
                    repository_id: root.repository_id.clone(),
                    commit: None,
                    tree: vcs::GitTreeId::from_string(empty_tree_id()?.to_string()),
                })
            }
            Err(error) => return Err(crate::map_git_err(error).into()),
        };
        let commit = head.peel_to_commit().map_err(crate::map_git_err)?;
        Ok(vcs::NativeStateRef::Git {
            repository_id: root.repository_id.clone(),
            commit: Some(vcs::GitCommitId::from_string(commit.id().to_string())),
            tree: vcs::GitTreeId::from_string(commit.tree_id().to_string()),
        })
    }

    fn files_without_renames(&self, root: &vcs::RootBinding) -> vcs::VcsResult<Vec<VcsFileEntry>> {
        Ok(
            crate::status::files_without_renames(git_root(root, "filesWithoutRenames")?)?
                .into_iter()
                .map(file_status)
                .collect(),
        )
    }

    fn status(&self, root: &vcs::RootBinding) -> vcs::VcsResult<VcsStatus> {
        let path = git_root(root, "status")?;
        let mut status = Self::status_from_git(crate::status::status(path)?);
        // Legacy GitStatus has no conflict field. Read the index so the native
        // read model does not turn that missing field into a claim of no conflicts.
        let repo = git2::Repository::open(path).map_err(crate::map_git_err)?;
        let index = repo.index().map_err(crate::map_git_err)?;
        let mut conflicted = HashSet::new();
        for conflict in index.conflicts().map_err(crate::map_git_err)? {
            let conflict = conflict.map_err(crate::map_git_err)?;
            for entry in [conflict.ancestor, conflict.our, conflict.their]
                .into_iter()
                .flatten()
            {
                conflicted.insert(String::from_utf8_lossy(&entry.path).into_owned());
            }
        }
        status.conflicts = Some(u64::try_from(conflicted.len()).unwrap_or(u64::MAX));
        for file in &mut status.files {
            file.conflicted = Some(conflicted.contains(&file.path));
        }
        Ok(status)
    }

    fn diff_working(
        &self,
        root: &vcs::RootBinding,
        scope: vcs::DiffScope,
        paths: Option<&[String]>,
    ) -> vcs::VcsResult<Vec<vcs::FileDiffWithHunks>> {
        let path = git_root(root, "diffWorking")?;
        let paths = paths.filter(|paths| !paths.is_empty());
        let specs: Option<Vec<&str>> =
            paths.map(|paths| paths.iter().map(String::as_str).collect());
        let wanted = |file: &str| paths.is_none_or(|paths| paths.iter().any(|p| p == file));
        let entries = match scope {
            vcs::DiffScope::Unstaged => {
                crate::diff::diff_index_to_workdir_with_hunks(path, specs.as_deref())?
            }
            vcs::DiffScope::Staged => crate::diff::diff_head_to_index(path)?
                .into_iter()
                .filter(|file| wanted(&file.path))
                .map(|file| hydrate_diff(path, file))
                .collect::<intent_core::Result<Vec<_>>>()?,
            vcs::DiffScope::Working => {
                crate::diff::diff_head_to_workdir_with_hunks(path, specs.as_deref())?
            }
        };
        Ok(entries
            .into_iter()
            .filter(|entry| wanted(&entry.file.path))
            .map(neutral_diff)
            .collect())
    }

    fn diff_change(
        &self,
        root: &vcs::RootBinding,
        change: &vcs::NativeChangeRef,
    ) -> vcs::VcsResult<Vec<vcs::FileDiffWithHunks>> {
        let path = git_root(root, "diffChange")?;
        let commit = git_change(root, change, "diffChange")?;
        // Missing state remains an error; legacy wire policy may explicitly
        // choose its historical empty-array fallback outside the engine.
        crate::diff::diff_commit(path, commit)?
            .into_iter()
            .map(|file| {
                hydrate_diff(path, file)
                    .map(neutral_diff)
                    .map_err(Into::into)
            })
            .collect()
    }

    fn diff_summaries(
        &self,
        root: &vcs::RootBinding,
        read: &vcs::DiffRead,
    ) -> vcs::VcsResult<Vec<vcs::FileDiff>> {
        let path = git_root(root, "diffSummaries")?;
        let files = match read {
            vcs::DiffRead::Unstaged => crate::diff::diff_index_to_workdir(path)?,
            vcs::DiffRead::Staged => crate::diff::diff_head_to_index(path)?,
            vcs::DiffRead::WorkingTracked => crate::diff::diff_head_to_workdir_tracked(path)?,
            vcs::DiffRead::UnstagedTracked => crate::diff::diff_index_to_workdir_tracked(path)?,
            vcs::DiffRead::Range { base_ref } => crate::diff::diff_range(path, base_ref)?,
            vcs::DiffRead::TwoDot { from, to } => crate::diff::diff_two_dot(path, from, to)?,
            vcs::DiffRead::Commit { revision } => {
                crate::diff::diff_commit(path, &git_revision(root, revision, "diffSummaries")?)?
            }
        };
        Ok(files.into_iter().map(neutral_summary).collect())
    }

    fn hunks_between(
        &self,
        root: &vcs::RootBinding,
        old: Option<&NativeObjectRef>,
        new: Option<&NativeObjectRef>,
    ) -> vcs::VcsResult<Vec<vcs::DiffHunk>> {
        Ok(crate::diff::hunks_between(
            git_root(root, "hunksBetween")?,
            git_object_ref(old)?,
            git_object_ref(new)?,
        )?
        .into_iter()
        .map(neutral_hunk)
        .collect())
    }

    fn show_file_bytes(
        &self,
        root: &vcs::RootBinding,
        revision: &vcs::RevisionSpec,
        path: &str,
    ) -> vcs::VcsResult<Vec<u8>> {
        Ok(crate::show::show_file_bytes(
            git_root(root, "showFile")?,
            &git_revision(root, revision, "showFile")?,
            path,
        )?)
    }

    fn resolve_ref(
        &self,
        root: &vcs::RootBinding,
        reference: &str,
    ) -> vcs::VcsResult<NativeObjectRef> {
        Ok(git_object(crate::refs::rev_parse(
            git_root(root, "resolveRef")?,
            reference,
        )?))
    }

    fn current_branch(&self, root: &vcs::RootBinding) -> vcs::VcsResult<Option<String>> {
        let branch = crate::conflicts::current_branch(git_root(root, "currentBranch")?)?;
        Ok((!branch.is_empty()).then_some(branch))
    }

    fn detect_default_branch(&self, root: &vcs::RootBinding) -> vcs::VcsResult<Option<String>> {
        Ok(crate::conflicts::detect_default_branch(git_root(
            root,
            "detectDefaultBranch",
        )?)?)
    }

    fn merge_conflicts(
        &self,
        root: &vcs::RootBinding,
        from: &str,
        target: &str,
    ) -> vcs::VcsResult<vcs::MergeConflicts> {
        let result = crate::conflicts::detect_merge_conflicts(
            git_root(root, "mergeConflicts")?,
            from,
            target,
        )?;
        Ok(vcs::MergeConflicts {
            has_conflicts: result.has_conflicts,
            conflicted_files: result.conflicted_files,
            cannot_determine: result.cannot_determine,
        })
    }

    fn is_ancestor(
        &self,
        root: &vcs::RootBinding,
        ancestor: &str,
        descendant: &str,
    ) -> vcs::VcsResult<bool> {
        Ok(crate::refs::is_ancestor(
            git_root(root, "isAncestor")?,
            ancestor,
            descendant,
        )?)
    }

    fn ahead_behind(&self, root: &vcs::RootBinding, base: &str) -> vcs::VcsResult<(i64, i64)> {
        Ok(crate::remote::ahead_behind(
            git_root(root, "aheadBehind")?,
            base,
        )?)
    }

    fn resolve_branch_boundary(
        &self,
        root: &vcs::RootBinding,
        base_ref: Option<&str>,
        base_sha: Option<&str>,
        target: &str,
    ) -> vcs::VcsResult<Option<vcs::NativeChangeRef>> {
        Ok(crate::diff::resolve_branch_boundary(
            git_root(root, "resolveBranchBoundary")?,
            base_ref,
            base_sha,
            target,
        )?
        .map(|hash| change_ref(root, hash)))
    }

    fn history(
        &self,
        root: &vcs::RootBinding,
        read: &vcs::HistoryRead,
    ) -> vcs::VcsResult<Vec<vcs::HistoryEntry>> {
        let path = git_root(root, "history")?;
        let entries = match read {
            vcs::HistoryRead::Since {
                base_ref,
                limit,
                include_files,
            } => crate::history::history_since(path, base_ref.as_deref(), *limit, *include_files)?,
            vcs::HistoryRead::Bounded {
                boundary,
                limit,
                include_older,
                include_files,
            } => {
                let boundary = boundary
                    .as_ref()
                    .map(|change| git_change(root, change, "history"))
                    .transpose()?;
                crate::history::history_bounded(
                    path,
                    boundary,
                    *limit,
                    *include_older,
                    *include_files,
                )?
            }
            vcs::HistoryRead::Snapshot {
                snapshot,
                limit,
                include_older,
                include_files,
            } => {
                let oid = |change: &vcs::NativeChangeRef| {
                    git2::Oid::from_str(git_change(root, change, "history")?)
                        .map_err(crate::map_git_err)
                        .map_err(vcs::VcsError::from)
                };
                let snapshot = crate::history::HistorySnapshot {
                    head: oid(&snapshot.head)?,
                    boundary: snapshot.boundary.as_ref().map(oid).transpose()?,
                    upstream: snapshot.upstream.as_ref().map(oid).transpose()?,
                };
                crate::history::history_bounded_snapshot(
                    path,
                    &snapshot,
                    *limit,
                    *include_older,
                    *include_files,
                )?
            }
        };
        Ok(entries
            .into_iter()
            .map(|entry| vcs::HistoryEntry {
                change: change_ref(root, entry.hash),
                message: entry.message,
                author: entry.author,
                author_email: entry.author_email,
                date: entry.date,
                files: entry.files,
                files_changed: entry.files_changed,
                published: entry.is_pushed,
                agent_id: entry.agent_id,
                linked_note_id: entry.linked_note_id,
            })
            .collect())
    }

    fn hunks_for_diff(
        &self,
        root: &vcs::RootBinding,
        file: &vcs::FileDiff,
    ) -> vcs::VcsResult<Vec<vcs::DiffHunk>> {
        let path = git_root(root, "hunksForDiff")?;
        let file = crate::diff::FileDiff {
            path: file.path.clone(),
            old_mode: file.old_mode,
            new_mode: file.new_mode,
            additions: file.additions,
            deletions: file.deletions,
            is_binary: file.is_binary,
            old_blob: git_object_ref(file.old_object.as_ref())?.map(str::to_string),
            new_blob: git_object_ref(file.new_object.as_ref())?.map(str::to_string),
            old_is_gitlink: file.old_is_gitlink,
            new_is_gitlink: file.new_is_gitlink,
        };
        Ok(hydrate_diff(path, file)?
            .hunks
            .into_iter()
            .map(neutral_hunk)
            .collect())
    }

    fn change_details(
        &self,
        root: &vcs::RootBinding,
        revision: &vcs::RevisionSpec,
    ) -> vcs::VcsResult<vcs::ChangeDetails> {
        let details = crate::history::commit_details(
            git_root(root, "changeDetails")?,
            &git_revision(root, revision, "changeDetails")?,
        )?;
        Ok(vcs::ChangeDetails {
            change: change_ref(root, details.hash),
            author: details.author,
            author_email: details.author_email,
            date: details.date,
            message: details.message,
            files: details
                .files
                .into_iter()
                .map(|file| vcs::ChangeFileStat {
                    path: file.path,
                    additions: file.additions,
                    deletions: file.deletions,
                })
                .collect(),
        })
    }

    fn capture_history_refresh(
        &self,
        root: &vcs::RootBinding,
        base_ref: Option<&str>,
        base_sha: Option<&str>,
    ) -> vcs::VcsResult<Option<vcs::HistoryRefreshCapture>> {
        Ok(crate::history::capture_history_refresh(
            git_root(root, "captureHistoryRefresh")?,
            base_ref,
            base_sha,
        )
        .map(|capture| {
            let change = |oid: git2::Oid| change_ref(root, oid.to_string());
            vcs::HistoryRefreshCapture {
                inputs: vcs::HistoryRefreshInputs {
                    head: change(capture.inputs.head),
                    branch: capture.inputs.branch,
                    upstream: capture.inputs.upstream.map(change),
                    boundary_refs: capture
                        .inputs
                        .boundary_refs
                        .into_iter()
                        .map(|oid| oid.map(change))
                        .collect(),
                    fallback: capture.inputs.fallback_oid.map(change),
                },
                history: vcs::HistorySnapshot {
                    head: change(capture.history.head),
                    boundary: capture.history.boundary.map(change),
                    upstream: capture.history.upstream.map(change),
                },
            }
        }))
    }

    fn resolve_workspace_boundary(
        &self,
        root: &vcs::RootBinding,
        base_ref: Option<&str>,
        base_sha: Option<&str>,
    ) -> vcs::VcsResult<Option<vcs::NativeChangeRef>> {
        Ok(crate::history::resolve_workspace_boundary(
            git_root(root, "resolveWorkspaceBoundary")?,
            base_ref,
            base_sha,
        )?
        .map(|hash| change_ref(root, hash)))
    }

    fn compare(
        &self,
        before: &vcs::CapturedState,
        after: &vcs::CapturedState,
        query: &vcs::DiffQuery,
        page_token: Option<&str>,
    ) -> vcs::VcsResult<vcs::DiffPage> {
        if before.binding != after.binding || before.binding.kind != VcsKind::Git {
            return Err(vcs::VcsError::InvalidInput {
                reason: "comparison requires the same Git root binding and epoch".into(),
            });
        }
        let basis = ComparisonBasis {
            method: "intent-git-compare-v1",
            source: git_root(&after.binding, "compare")?.to_path_buf(),
            before: before.state.clone(),
            after: after.state.clone(),
            before_capture: content_digest(&json_bytes(before)?),
            after_capture: content_digest(&json_bytes(after)?),
        };
        self.compare_basis(basis, query, page_token, || {
            Ok((captured_work_tree(before)?, captured_work_tree(after)?))
        })
    }

    fn compose(
        &self,
        root: &vcs::RootBinding,
        request: &vcs::ComposeRequest,
        spool_directory: &Path,
    ) -> vcs::VcsResult<vcs::PreparedComposition> {
        composition::compose(root, request, spool_directory)
    }

    fn compare_composition(
        &self,
        root: &vcs::RootBinding,
        prepared: &vcs::PreparedComposition,
        query: &vcs::DiffQuery,
        page_token: Option<&str>,
    ) -> vcs::VcsResult<vcs::DiffPage> {
        let basis = composition::comparison(root, prepared)?;
        let tree = |state: &vcs::NativeStateRef| match state {
            vcs::NativeStateRef::Git { tree, .. } => Ok(tree.as_str().to_string()),
            vcs::NativeStateRef::Atomic { .. } => Err(storage::invalid(
                "Git composition comparison requires Git tree identities",
            )),
        };
        let old_tree = tree(&basis.before)?;
        let new_tree = tree(&basis.after)?;
        self.compare_basis(basis, query, page_token, || Ok((old_tree, new_tree)))
    }

    fn prepare_record(
        &self,
        selection: &vcs::FrozenSelection,
        metadata: &vcs::FixedRecordMetadata,
        spool_directory: &Path,
    ) -> vcs::VcsResult<vcs::PreparedRecord> {
        recording::prepare_record(selection, metadata, spool_directory)
    }

    fn admit_record(
        &self,
        root: &vcs::RootBinding,
        record: &vcs::PreparedRecord,
        expected_state: &vcs::NativeStateRef,
    ) -> vcs::VcsResult<vcs::NativeReceipt> {
        recording::admit_record(root, record, expected_state)
    }

    fn materialize(
        &self,
        root: &vcs::RootBinding,
        state: &vcs::NativeStateRef,
        destination: &Path,
    ) -> vcs::VcsResult<vcs::MaterializationReceipt> {
        storage::materialize(root, state, destination)
    }

    fn export_closure(
        &self,
        root: &vcs::RootBinding,
        state: &vcs::NativeStateRef,
        grant: &vcs::RetentionGrant,
        spool_directory: &Path,
    ) -> vcs::VcsResult<vcs::NativeClosureManifest> {
        storage::export_closure(root, state, grant, spool_directory)
    }

    fn verify_materialization(
        &self,
        receipt: &vcs::MaterializationReceipt,
        generated: &[String],
    ) -> vcs::VcsResult<()> {
        storage::verify_materialization(receipt, generated)
    }

    fn copy_materialization(
        &self,
        receipt: &vcs::MaterializationReceipt,
        destination: &Path,
    ) -> vcs::VcsResult<vcs::MaterializationReceipt> {
        storage::copy_materialization(receipt, destination)
    }

    fn restore_closure(
        &self,
        manifest: &vcs::NativeClosureManifest,
        destination: &Path,
    ) -> vcs::VcsResult<vcs::RestoreReceipt> {
        storage::restore_closure(manifest, destination)
    }

    fn capture(
        &self,
        root: &vcs::RootBinding,
        permit: &vcs::CapturePermit,
    ) -> vcs::VcsResult<vcs::CapturedState> {
        let path = git_root(root, "capture")?;
        if permit.binding_epoch != root.epoch {
            return Err(vcs::VcsError::Stale {
                reason: "capture permit belongs to a different root binding epoch".into(),
            });
        }
        let options = crate::checkpoint::CaptureOptions {
            excluded_paths: permit.excluded_paths.iter().map(Into::into).collect(),
        };
        let state = self.recorded_state(root)?;
        if matches!(state, vcs::NativeStateRef::Git { commit: None, .. }) {
            let (index, working) = crate::checkpoint::capture_unborn(path, &options)?;
            return Ok(vcs::CapturedState {
                binding: root.clone(),
                state,
                working_copy: vcs::CapturedWorkingCopy::GitUnborn {
                    object_format: "sha1".into(),
                    index_tree: vcs::GitTreeId::from_string(index),
                    working_tree: vcs::GitTreeId::from_string(working),
                },
            });
        }
        let snapshot = crate::checkpoint::capture(path, &options)?;
        let repo = git2::Repository::open(path).map_err(crate::map_git_err)?;
        let commit = repo
            .find_commit(git2::Oid::from_str(&snapshot.head).map_err(crate::map_git_err)?)
            .map_err(crate::map_git_err)?;
        Ok(vcs::CapturedState {
            binding: root.clone(),
            state: vcs::NativeStateRef::Git {
                repository_id: root.repository_id.clone(),
                commit: Some(vcs::GitCommitId::from_string(snapshot.head.clone())),
                tree: vcs::GitTreeId::from_string(commit.tree_id().to_string()),
            },
            working_copy: vcs::CapturedWorkingCopy::Git {
                anchors: vcs::GitCaptureAnchors {
                    object_format: snapshot.object_format,
                    head: Some(vcs::GitCommitId::from_string(snapshot.head)),
                    index: vcs::GitCommitId::from_string(snapshot.index),
                    wip: snapshot.wip.map(vcs::GitCommitId::from_string),
                    branch: snapshot.branch,
                },
            },
        })
    }

    fn observe_status(&self, root: &Path) -> vcs::VcsResult<VcsStatus> {
        Ok(Self::status_from_git(crate::status::status(root)?))
    }

    fn pull_branch(
        &self,
        root: &Path,
        branch: &str,
        token: Option<&str>,
        classify_authorization: bool,
    ) -> vcs::VcsResult<intent_core::GitPullResult> {
        Ok(if classify_authorization {
            crate::pull::pull_branch_classified(root, branch, token)?
        } else {
            crate::pull::pull_branch(root, branch, token)?
        })
    }

    fn is_ignored(&self, root: &Path, path: &str) -> vcs::VcsResult<bool> {
        Ok(crate::attribution::is_ignored_untracked(root, path))
    }

    fn classify_paths(&self, root: &Path, paths: &[String]) -> vcs::VcsResult<Vec<vcs::PathState>> {
        Ok(crate::attribution::classify_paths(root, paths)?
            .into_iter()
            .map(|state| match state {
                crate::attribution::PathState::Dirty => vcs::PathState::Dirty,
                crate::attribution::PathState::Clean => vcs::PathState::Clean,
                crate::attribution::PathState::Unknown => vcs::PathState::Unknown,
            })
            .collect())
    }

    fn lockable_paths(
        &self,
        root: &Path,
        status: &[VcsFileEntry],
        paths: &[String],
    ) -> vcs::VcsResult<Vec<String>> {
        let status = status
            .iter()
            .map(legacy_file_status)
            .collect::<vcs::VcsResult<Vec<_>>>()?;
        let lockable = crate::attribution::lockable_paths(root, &status, paths);
        // Preserve caller order and avoid exposing HashSet iteration order.
        Ok(paths
            .iter()
            .filter(|path| lockable.contains(*path))
            .cloned()
            .collect())
    }

    fn record(
        &self,
        root: &vcs::RootBinding,
        request: &vcs::RecordRequest,
    ) -> vcs::VcsResult<vcs::RecordOutcome> {
        let path = git_root(root, "record")?;
        let outcome = match &request.selection {
            vcs::RecordSelection::Unattributed => {
                return Ok(vcs::RecordOutcome::Skipped(
                    vcs::RecordSkipReason::MissingAttribution,
                ));
            }
            vcs::RecordSelection::StagedIndex => {
                if crate::commit::staged_paths(path)?.is_empty()
                    && !crate::commit::has_pending_merge(path)?
                {
                    return Ok(vcs::RecordOutcome::Skipped(
                        vcs::RecordSkipReason::NoChanges,
                    ));
                }
                crate::commit::commit_with_trailers(
                    path,
                    &request.message,
                    request.agent_id.as_deref(),
                    request.linked_note_id.as_deref(),
                )
            }
            vcs::RecordSelection::Explicit(paths) => {
                if paths.is_empty() {
                    return Ok(vcs::RecordOutcome::Skipped(
                        vcs::RecordSkipReason::NoChanges,
                    ));
                }
                crate::commit::commit_paths_with_trailers(
                    path,
                    &request.message,
                    request.agent_id.as_deref(),
                    request.linked_note_id.as_deref(),
                    paths,
                )
            }
            vcs::RecordSelection::Attributed(attributed) => {
                if request.agent_id.as_ref().is_none_or(String::is_empty) {
                    return Ok(vcs::RecordOutcome::Skipped(
                        vcs::RecordSkipReason::MissingAttribution,
                    ));
                }
                let attributed: HashSet<&str> = attributed.iter().map(String::as_str).collect();
                let context = crate::submodule::path_context(path)?;
                let paths: Vec<String> = crate::commit::all_changed_paths(path)?
                    .into_iter()
                    .filter(|path| attributed.contains(path.as_str()))
                    .filter(|path| {
                        context.as_ref().is_none_or(|context| {
                            crate::submodule::submodule_containing(
                                &context.paths,
                                path,
                                context.ignore_case,
                            )
                            .is_none()
                        })
                    })
                    .collect();
                if paths.is_empty() {
                    return Ok(vcs::RecordOutcome::Skipped(
                        vcs::RecordSkipReason::NoChanges,
                    ));
                }
                crate::commit::commit_paths_with_trailers(
                    path,
                    &request.message,
                    request.agent_id.as_deref(),
                    request.linked_note_id.as_deref(),
                    &paths,
                )
            }
        };
        match outcome {
            Ok(outcome) => Ok(vcs::RecordOutcome::Recorded(vcs::RecordedChange {
                change: vcs::NativeChangeRef::Git {
                    repository_id: root.repository_id.clone(),
                    commit: vcs::GitCommitId::from_string(outcome.hash),
                },
                files: outcome.files,
                index_refresh_error: outcome.index_refresh_error,
            })),
            Err(Error::Internal(message)) if message == crate::commit::CLEAN_TREE_ERROR => Ok(
                vcs::RecordOutcome::Skipped(vcs::RecordSkipReason::NoChanges),
            ),
            Err(Error::Internal(message))
                if message == crate::commit::PARTIAL_MERGE_COMMIT_ERROR =>
            {
                Ok(vcs::RecordOutcome::Skipped(
                    vcs::RecordSkipReason::MergeInProgress,
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn stage(&self, root: &vcs::RootBinding, paths: &[String]) -> vcs::VcsResult<()> {
        Ok(crate::stage::stage(git_root(root, "stage")?, paths)?)
    }

    fn stage_hunk(&self, root: &vcs::RootBinding, path: &str, diff: &str) -> vcs::VcsResult<()> {
        Ok(crate::stage::stage_hunk(
            git_root(root, "stageHunk")?,
            path,
            diff,
        )?)
    }

    fn unstage_hunk(&self, root: &vcs::RootBinding, path: &str, diff: &str) -> vcs::VcsResult<()> {
        Ok(crate::stage::unstage_hunk(
            git_root(root, "unstageHunk")?,
            path,
            diff,
        )?)
    }

    fn changed_paths(
        &self,
        root: &vcs::RootBinding,
        staged_only: bool,
    ) -> vcs::VcsResult<Vec<String>> {
        let path = git_root(root, "changedPaths")?;
        Ok(if staged_only {
            crate::commit::staged_paths(path)?
        } else {
            crate::commit::all_changed_paths(path)?
        })
    }

    fn has_pending_merge(&self, root: &vcs::RootBinding) -> vcs::VcsResult<bool> {
        Ok(crate::commit::has_pending_merge(git_root(
            root,
            "hasPendingMerge",
        )?)?)
    }

    fn remove_index_lock(&self, root: &vcs::RootBinding) -> vcs::VcsResult<bool> {
        Ok(crate::worktree::remove_index_lock(git_root(
            root,
            "removeIndexLock",
        )?)?)
    }

    fn unstage(&self, root: &vcs::RootBinding, paths: &[String]) -> vcs::VcsResult<()> {
        Ok(crate::stage::unstage(git_root(root, "unstage")?, paths)?)
    }

    fn discard(&self, root: &vcs::RootBinding, paths: &[String]) -> vcs::VcsResult<()> {
        Ok(crate::stage::discard(git_root(root, "discard")?, paths)?)
    }

    fn create_branch(
        &self,
        root: &vcs::RootBinding,
        name: &str,
        checkout: bool,
    ) -> vcs::VcsResult<()> {
        Ok(crate::branches::create_branch(
            git_root(root, "createBranch")?,
            name,
            checkout,
        )?)
    }

    fn checkout_branch(&self, root: &vcs::RootBinding, name: &str) -> vcs::VcsResult<()> {
        Ok(crate::branches::checkout_branch(
            git_root(root, "checkoutBranch")?,
            name,
        )?)
    }

    fn rename_branch(&self, root: &vcs::RootBinding, old: &str, new: &str) -> vcs::VcsResult<()> {
        Ok(crate::branches::rename_branch(
            git_root(root, "renameBranch")?,
            old,
            new,
        )?)
    }

    fn commit_tree(
        &self,
        root: &vcs::RootBinding,
        parent: &str,
        message: &str,
    ) -> vcs::VcsResult<vcs::NativeChangeRef> {
        Ok(change_ref(
            root,
            crate::squash::commit_tree(git_root(root, "commitTree")?, parent, message)?,
        ))
    }

    fn update_ref(
        &self,
        root: &vcs::RootBinding,
        reference: &str,
        change: &vcs::NativeChangeRef,
    ) -> vcs::VcsResult<()> {
        Ok(crate::squash::update_ref(
            git_root(root, "updateRef")?,
            reference,
            git_change(root, change, "updateRef")?,
        )?)
    }

    fn rebase(
        &self,
        root: &vcs::RootBinding,
        target: &str,
    ) -> vcs::VcsResult<vcs::IntegrateOutcome> {
        let result = crate::rebase::rebase_with_autostash(git_root(root, "rebase")?, target)?;
        Ok(vcs::IntegrateOutcome {
            success: result.success,
            aborted: result.aborted,
            error: result.error,
        })
    }

    fn reset(
        &self,
        root: &vcs::RootBinding,
        target: &vcs::NativeChangeRef,
        mode: vcs::ResetMode,
    ) -> vcs::VcsResult<()> {
        let path = git_root(root, "reset")?;
        let commit = git_change(root, target, "reset")?;
        match mode {
            vcs::ResetMode::Soft => crate::reset::reset_soft(path, commit)?,
            vcs::ResetMode::Hard => crate::reset::reset_hard(path, commit)?,
        }
        Ok(())
    }

    fn reset_revision(
        &self,
        root: &vcs::RootBinding,
        target: &vcs::RevisionSpec,
        mode: vcs::ResetMode,
    ) -> vcs::VcsResult<()> {
        let path = git_root(root, "resetRevision")?;
        let target = git_revision(root, target, "resetRevision")?;
        match mode {
            vcs::ResetMode::Soft => crate::reset::reset_soft(path, &target)?,
            vcs::ResetMode::Hard => crate::reset::reset_hard(path, &target)?,
        }
        Ok(())
    }
}

fn git_root<'a>(root: &'a vcs::RootBinding, operation: &'static str) -> vcs::VcsResult<&'a Path> {
    if root.kind != VcsKind::Git {
        return Err(vcs::VcsError::Unsupported {
            operation,
            kind: root.kind,
        });
    }
    Ok(&root.locator)
}

fn git_change<'a>(
    root: &vcs::RootBinding,
    change: &'a vcs::NativeChangeRef,
    operation: &'static str,
) -> vcs::VcsResult<&'a str> {
    let vcs::NativeChangeRef::Git {
        repository_id,
        commit,
    } = change
    else {
        return Err(vcs::VcsError::Unsupported {
            operation,
            kind: VcsKind::Atomic,
        });
    };
    if repository_id != &root.repository_id {
        return Err(vcs::VcsError::InvalidInput {
            reason: "change belongs to a different repository".into(),
        });
    }
    // A native change reference is immutable. Accepting a symbolic revspec
    // here would let the same purported identity resolve to different commits.
    if commit.as_str().len() != 40 || git2::Oid::from_str(commit.as_str()).is_err() {
        return Err(vcs::VcsError::InvalidInput {
            reason: "Git change reference requires a full commit object identifier".into(),
        });
    }
    Ok(commit.as_str())
}

fn git_revision(
    root: &vcs::RootBinding,
    revision: &vcs::RevisionSpec,
    operation: &'static str,
) -> vcs::VcsResult<String> {
    match revision {
        vcs::RevisionSpec::Head => Ok("HEAD".into()),
        vcs::RevisionSpec::Index { stage } if *stage <= 3 => Ok(format!(":{stage}")),
        vcs::RevisionSpec::Index { .. } => Err(vcs::VcsError::InvalidInput {
            reason: "index stage must be between zero and three".into(),
        }),
        vcs::RevisionSpec::Change { change } => {
            Ok(git_change(root, change, operation)?.to_string())
        }
        vcs::RevisionSpec::GitRef { reference } => Ok(reference.clone()),
    }
}

fn git_object_ref(object: Option<&NativeObjectRef>) -> vcs::VcsResult<Option<&str>> {
    match object {
        None => Ok(None),
        Some(NativeObjectRef::Git { object }) => Ok(Some(object.as_str())),
        Some(NativeObjectRef::Atomic { .. }) => Err(vcs::VcsError::InvalidInput {
            reason: "Atomic object supplied to Git content read".into(),
        }),
    }
}

fn change_ref(root: &vcs::RootBinding, hash: String) -> vcs::NativeChangeRef {
    vcs::NativeChangeRef::Git {
        repository_id: root.repository_id.clone(),
        commit: vcs::GitCommitId::from_string(hash),
    }
}

fn json_bytes<T: serde::Serialize + ?Sized>(value: &T) -> vcs::VcsResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| Error::Internal(format!("VCS serialization failed: {error}")).into())
}

fn content_digest(bytes: &[u8]) -> vcs::ContentDigest {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> vcs::ContentDigest {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    vcs::ContentDigest::from_string(encoded)
}

fn parse_comparison_token(token: &str, expected: &vcs::ContentDigest) -> vcs::VcsResult<usize> {
    let invalid = || vcs::VcsError::InvalidInput {
        reason: "comparison token does not match this snapshot, query and root binding".into(),
    };
    let rest = token.strip_prefix("git.compare.v1:").ok_or_else(invalid)?;
    let (digest, offset) = rest.split_once(':').ok_or_else(invalid)?;
    if digest != expected.as_str()
        || offset.is_empty()
        || !offset.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    offset.parse().map_err(|_| invalid())
}

fn captured_work_tree(capture: &vcs::CapturedState) -> vcs::VcsResult<String> {
    let source = git_root(&capture.binding, "compare")?;
    let vcs::NativeStateRef::Git {
        repository_id,
        commit,
        tree,
    } = &capture.state
    else {
        return Err(vcs::VcsError::InvalidInput {
            reason: "Git capture has a non-Git recorded state".into(),
        });
    };
    if let vcs::CapturedWorkingCopy::GitUnborn {
        object_format,
        index_tree,
        working_tree,
    } = &capture.working_copy
    {
        if object_format != "sha1"
            || repository_id != &capture.binding.repository_id
            || commit.is_some()
            || tree.as_str() != empty_tree_id()?.to_string()
        {
            return Err(vcs::VcsError::InvalidInput {
                reason: "invalid unborn Git capture identity".into(),
            });
        }
        let repo = git2::Repository::open(source).map_err(crate::map_git_err)?;
        for tree in [index_tree, working_tree] {
            repo.find_tree(git2::Oid::from_str(tree.as_str()).map_err(crate::map_git_err)?)
                .map_err(crate::map_git_err)?;
        }
        return Ok(working_tree.as_str().into());
    }
    let vcs::CapturedWorkingCopy::Git { anchors } = &capture.working_copy else {
        return Err(vcs::VcsError::InvalidInput {
            reason: "Git capture has a non-Git working overlay".into(),
        });
    };
    if repository_id != &capture.binding.repository_id || commit != &anchors.head {
        return Err(vcs::VcsError::InvalidInput {
            reason: "capture identities do not match their root binding".into(),
        });
    }
    let repo = git2::Repository::open(source).map_err(crate::map_git_err)?;
    let snapshot = crate::checkpoint::Snapshot {
        object_format: anchors.object_format.clone(),
        head: anchors
            .head
            .as_ref()
            .ok_or_else(|| vcs::VcsError::InvalidInput {
                reason: "capture lacks a recorded HEAD".into(),
            })?
            .as_str()
            .into(),
        index: anchors.index.as_str().into(),
        wip: anchors.wip.as_ref().map(|id| id.as_str().into()),
        branch: anchors.branch.clone(),
    };
    let (head, _, working) = crate::checkpoint::validate(&repo, &snapshot)?;
    let actual_tree = repo
        .find_commit(head)
        .map_err(crate::map_git_err)?
        .tree_id();
    if actual_tree.to_string() != tree.as_str() {
        return Err(vcs::VcsError::InvalidInput {
            reason: "capture recorded tree does not match its immutable commit".into(),
        });
    }
    Ok(working.to_string())
}

fn empty_tree_id() -> vcs::VcsResult<git2::Oid> {
    git2::Oid::hash_object(git2::ObjectType::Tree, &[])
        .map_err(crate::map_git_err)
        .map_err(Into::into)
}

fn hydrate_diff(
    path: &Path,
    file: crate::diff::FileDiff,
) -> intent_core::Result<crate::diff::FileDiffWithHunks> {
    let hunks = if file.is_gitlink() {
        crate::diff::gitlink_hunks(file.gitlink_old_sha(), file.gitlink_new_sha())
    } else if file.is_binary {
        Vec::new()
    } else {
        crate::diff::hunks_between(path, file.old_blob.as_deref(), file.new_blob.as_deref())?
    };
    Ok(crate::diff::FileDiffWithHunks { file, hunks })
}

fn neutral_diff(entry: crate::diff::FileDiffWithHunks) -> vcs::FileDiffWithHunks {
    let file = entry.file;
    let hunks = if file.is_gitlink() {
        crate::diff::gitlink_hunks(file.gitlink_old_sha(), file.gitlink_new_sha())
    } else if file.is_binary {
        Vec::new()
    } else {
        entry.hunks
    };
    vcs::FileDiffWithHunks {
        file: neutral_summary(file),
        truncated_reason: None,
        hunks: hunks.into_iter().map(neutral_hunk).collect(),
    }
}

fn neutral_summary(file: crate::diff::FileDiff) -> vcs::FileDiff {
    vcs::FileDiff {
        path: file.path,
        old_mode: file.old_mode,
        new_mode: file.new_mode,
        additions: file.additions,
        deletions: file.deletions,
        is_binary: file.is_binary,
        old_object: file.old_blob.map(git_object),
        new_object: file.new_blob.map(git_object),
        old_is_gitlink: file.old_is_gitlink,
        new_is_gitlink: file.new_is_gitlink,
    }
}

fn neutral_hunk(hunk: crate::diff::DiffHunk) -> vcs::DiffHunk {
    vcs::DiffHunk {
        old_start: hunk.old_start,
        old_lines: hunk.old_lines,
        new_start: hunk.new_start,
        new_lines: hunk.new_lines,
        lines: hunk
            .lines
            .into_iter()
            .map(|line| vcs::DiffLine {
                kind: match line.kind {
                    crate::diff::DiffLineKind::Context => vcs::DiffLineKind::Context,
                    crate::diff::DiffLineKind::Addition => vcs::DiffLineKind::Addition,
                    crate::diff::DiffLineKind::Deletion => vcs::DiffLineKind::Deletion,
                },
                content: line.content,
                old_lineno: line.old_lineno,
                new_lineno: line.new_lineno,
            })
            .collect(),
    }
}

fn legacy_file_status(file: &VcsFileEntry) -> vcs::VcsResult<FileStatus> {
    let object = |object: &Option<NativeObjectRef>| match object {
        Some(NativeObjectRef::Git { object }) => Ok(Some(object.as_str().to_string())),
        None => Ok(None),
        Some(NativeObjectRef::Atomic { .. }) => Err(vcs::VcsError::InvalidInput {
            reason: "Atomic object in Git status".into(),
        }),
    };
    Ok(FileStatus {
        path: file.path.clone(),
        status: file.status,
        staged: file.staged,
        mode: file.mode.clone(),
        old_sha: object(&file.old_object)?,
        new_sha: object(&file.new_object)?,
    })
}

fn file_status(file: FileStatus) -> VcsFileEntry {
    VcsFileEntry {
        path: file.path,
        status: file.status,
        staged: file.staged,
        conflicted: None,
        mode: file.mode,
        old_object: file.old_sha.map(git_object),
        new_object: file.new_sha.map(git_object),
    }
}

fn git_object(value: String) -> NativeObjectRef {
    NativeObjectRef::Git {
        object: GitObjectId::from_string(value),
    }
}

#[cfg(test)]
mod tests;
