//! Rebuildable recorded Git snapshots. No imported fact is source or task authority.
//!
//! The upstream history importer is CLI-private and mutates Git administrative
//! files. This uses the documented latest-tree fallback: authorized Git blobs
//! are recorded once through native repository primitives into an immutable,
//! owner-private derived generation. Git history/authorship is not synthesized.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use atomic_core::{change::ChangeHeader, Base32};
use atomic_repository::{ContentSearchOptions, RecordOptions, Repository, SyntaxIndex};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use intent_atomic_proto::knowledge::{
    CodeFact, CodeQuery, CodeQueryRequest, CodeQueryResult, DerivedReceipt, DerivedRef,
    ImportDerivedRequest, QueryCoverage, QueryReadBasis, QueryTruncation, SourceScope,
};
use intent_atomic_proto::{HostIdentity, StateToken};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{durable, Host, HostError, Result};

const POLICY_VERSION: &str = "intent-derived-git-text-v1";
const MAX_FILE: usize = 262_144;
const MAX_IMPORT_BYTES: usize = 33_554_432;
const MAX_IMPORT_FILES: usize = 8_192;
const MANIFEST_LIMIT: u64 = 8_388_608;

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    path: String,
    length: u64,
    digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    scope: SourceScope,
    files: Vec<Entry>,
    skipped: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DerivedOwner {
    generation: String,
    directory: durable::FileIdentity,
    purpose: String,
}

fn published(root: &Path) -> PathBuf {
    root.join(".atomic/intent-derived/published.json")
}
fn owner_path(root: &Path) -> PathBuf {
    root.with_extension("owner.json")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    operation_id: String,
    command_digest: String,
    request: ImportDerivedRequest,
    generation: String,
    phase: ImportPhase,
    receipt: Option<DerivedReceipt>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum ImportPhase {
    Prepared,
    Published,
    FailedKnown,
}

pub(crate) struct DerivedStore {
    receipt: DerivedReceipt,
    manifest: Manifest,
    repository: Repository,
    directory: durable::FileIdentity,
    database: durable::FileIdentity,
}

impl Host {
    fn derived_store(&self, root: &Path, index: &DerivedRef) -> Result<Arc<DerivedStore>> {
        let mut stores = self.knowledge.lock().map_err(|_| HostError::Poisoned)?;
        let store = if let Some(store) = stores.get(&index.generation) {
            Arc::clone(store)
        } else {
            let store = Arc::new(load_store(root, index)?);
            stores.insert(index.generation.clone(), Arc::clone(&store));
            store
        };
        store.validate(root, index)?;
        Ok(store)
    }
    fn derived_root(&self, index: &DerivedRef) -> Result<PathBuf> {
        if durable::identity(&self.config.stores_dir, true)? != self.stores_root_identity {
            return Err(HostError::StaleBinding);
        }
        validate_identity(&index.repository_id, &index.root_id, index.root_epoch)?;
        if index.generation.len() != 64
            || !index
                .generation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(HostError::Invalid("invalid derived generation"));
        }
        let parent = self.config.stores_dir.join(&index.repository_id);
        let derived = parent.join("derived");
        if parent.try_exists()? {
            durable::private_dir(&parent)?;
        }
        if derived.try_exists()? {
            durable::private_dir(&derived)?;
        }
        Ok(derived.join(&index.generation))
    }

    /// Import only an immutable, authorized Git tree into a derived namespace.
    /// # Errors
    /// Refuses unsafe scope, mutable ref names, missing objects and unproved replay.
    pub fn import_derived(&self, request: &ImportDerivedRequest) -> Result<DerivedReceipt> {
        validate_scope(&request.scope)?;
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || !full_oid(&request.commit)
            || serde_json::to_vec(request)?.len() > 16_384
        {
            return Err(HostError::Invalid(
                "bounded operation, scope and immutable SHA-1 commit required",
            ));
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let journal_dir = self.config.config_dir.join("derived-operations");
        durable::private_dir(&journal_dir)?;
        let command_digest = digest(&serde_json::to_vec(request)?);
        let generation = digest(&serde_json::to_vec(&(
            &request.scope,
            &request.commit,
            POLICY_VERSION,
            HostIdentity::default(),
        ))?);
        let index = DerivedRef {
            repository_id: request.scope.repository_id.clone(),
            root_id: request.scope.root_id.clone(),
            root_epoch: request.scope.root_epoch,
            generation: generation.clone(),
        };
        let final_root = self.derived_root(&index)?;
        let derived_parent = final_root
            .parent()
            .ok_or(HostError::Invalid("derived generation has no parent"))?;
        let repository_parent = derived_parent.parent().ok_or(HostError::Invalid(
            "derived namespace has no repository parent",
        ))?;
        durable::private_dir(repository_parent)?;
        durable::private_dir(derived_parent)?;
        let journal_path =
            journal_dir.join(format!("{}.json", digest(request.operation_id.as_bytes())));
        let existed = journal_path.try_exists()?;
        if existed {
            let previous: Journal = durable::read_json(&journal_path)?;
            if previous.command_digest != command_digest || previous.request != *request {
                return Err(HostError::Invalid(
                    "derived import operation was reused for another command",
                ));
            }
        }
        let mut journal = Journal {
            operation_id: request.operation_id.clone(),
            command_digest,
            request: request.clone(),
            generation,
            phase: ImportPhase::Prepared,
            receipt: None,
        };
        durable::write_json(&journal_path, &journal, existed)?;
        if published(&final_root).try_exists()? {
            let store = self.derived_store(&final_root, &index)?;
            journal.phase = ImportPhase::Published;
            let receipt = store.receipt.clone();
            journal.receipt = Some(receipt.clone());
            durable::write_json(&journal_path, &journal, true)?;
            return Ok(receipt);
        }
        let owner_exists = owner_path(&final_root).try_exists()?;
        {
            let mut stores = self.knowledge.lock().map_err(|_| HostError::Poisoned)?;
            if stores
                .get(&index.generation)
                .is_some_and(|store| Arc::strong_count(store) > 1)
            {
                return Err(HostError::Invalid(
                    "derived generation has an admitted reader",
                ));
            }
            stores.remove(&index.generation);
        }
        if final_root.try_exists()? {
            validate_owner(&final_root, &index)?;
            // Derived data has no source authority. Retain an interrupted attempt
            // under a private name; never reuse its partially initialized graph.
            let retained = derived_parent.join(format!(".failed-{}", uuid::Uuid::new_v4()));
            std::fs::rename(&final_root, retained)?;
            durable::sync_parent(&final_root)?;
        }
        durable::private_dir(&final_root)?;
        durable::write_json(
            &owner_path(&final_root),
            &DerivedOwner {
                generation: index.generation.clone(),
                directory: durable::identity(&final_root, true)?,
                purpose: "derivedOnly".into(),
            },
            owner_exists,
        )?;
        let receipt = build_snapshot(request, index, &final_root)?;
        durable::sync_tree(&final_root)?;
        let receipt_bytes = read_bounded(
            &final_root.join(".atomic/intent-derived/receipt.json"),
            65_536,
        )?;
        durable::write_json(&published(&final_root), &digest(&receipt_bytes), false)?;
        journal.phase = ImportPhase::Published;
        journal.receipt = Some(receipt.clone());
        durable::write_json(&journal_path, &journal, true)?;
        self.derived_store(&final_root, &receipt.index)?;
        Ok(receipt)
    }

    /// Inspect retained publication proof; incomplete derived work is rebuildable,
    /// never a claim that source changed or an invitation to inspect current HEAD.
    pub(crate) fn reconcile_derived(&self) -> Result<()> {
        let journal_dir = self.config.config_dir.join("derived-operations");
        if !journal_dir.try_exists()? {
            return Ok(());
        }
        durable::private_dir(&journal_dir)?;
        for file in std::fs::read_dir(journal_dir)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let mut journal: Journal = durable::read_json(&file.path())?;
            if file.file_name().to_string_lossy()
                != format!("{}.json", digest(journal.operation_id.as_bytes()))
                || journal.command_digest != digest(&serde_json::to_vec(&journal.request)?)
            {
                return Err(HostError::Invalid(
                    "derived journal immutable command mismatch",
                ));
            }
            let index = DerivedRef {
                repository_id: journal.request.scope.repository_id.clone(),
                root_id: journal.request.scope.root_id.clone(),
                root_epoch: journal.request.scope.root_epoch,
                generation: journal.generation.clone(),
            };
            let root = self.derived_root(&index)?;
            if published(&root).try_exists()? {
                let store = self.derived_store(&root, &index)?;
                journal.phase = ImportPhase::Published;
                journal.receipt = Some(store.receipt.clone());
            } else {
                journal.phase = ImportPhase::FailedKnown;
                journal.receipt = None;
            }
            durable::write_json(&file.path(), &journal, true)?;
        }
        Ok(())
    }

    /// Query recorded native bytes. Scope is applied before content reads and
    /// syntax traversal; source worktrees and ambient graph neighbours are unused.
    /// # Errors
    /// Refuses broader visibility, stale bindings, invalid budgets and corruption.
    pub fn query_code(&self, request: &CodeQueryRequest) -> Result<CodeQueryResult> {
        let started = Instant::now();
        self.read_admitted()?;
        let budget = &request.budget;
        if !(1..=100).contains(&budget.max_results)
            || !(4_096..=49_152).contains(&budget.max_bytes)
            || !(1..=512).contains(&budget.max_files)
            || budget.max_source_bytes == 0
            || budget.max_source_bytes > 8_388_608
            || !(1..=5_000).contains(&budget.max_millis)
            || !full_oid(&request.expected_commit)
        {
            return Err(HostError::Invalid("invalid bounded code query"));
        }
        validate_paths(&request.allowed_paths)?;
        match &request.query {
            CodeQuery::Search { pattern, .. } if pattern.is_empty() || pattern.len() > 2_048 => {
                return Err(HostError::Invalid("bounded search pattern required"));
            }
            CodeQuery::Entities { path }
                if !safe_path(path) || !authorized(path, &request.allowed_paths) =>
            {
                return Err(HostError::Invalid("entity path is outside query scope"));
            }
            CodeQuery::Impact { target } => {
                let (path, symbol) = target
                    .rsplit_once('#')
                    .ok_or(HostError::Invalid("impact requires an exact path#symbol"))?;
                if !safe_path(path)
                    || !authorized(path, &request.allowed_paths)
                    || symbol.is_empty()
                    || symbol.len() > 256
                {
                    return Err(HostError::Invalid("impact target is outside query scope"));
                }
            }
            _ => {}
        }
        let root = self.derived_root(&request.index)?;
        let store = self.derived_store(&root, &request.index)?;
        for path in &request.allowed_paths {
            if !authorized(path, &store.manifest.scope.allowed_paths) {
                return Err(HostError::Invalid(
                    "query traversal exceeds imported visibility",
                ));
            }
        }
        let deadline = Duration::from_millis(u64::from(budget.max_millis));
        let candidates: Vec<_> = store
            .manifest
            .files
            .iter()
            .filter(|file| {
                authorized(&file.path, &request.allowed_paths)
                    && !matches!(&request.query, CodeQuery::Entities { path } if file.path != *path)
            })
            .collect();
        let mut coverage = QueryCoverage {
            candidate_files: candidates.len() as u64,
            skipped_files: store
                .manifest
                .skipped
                .iter()
                .filter(|path| authorized(path, &request.allowed_paths))
                .count() as u64,
            ..QueryCoverage::default()
        };
        let mut truncation = Vec::new();
        let mut sources = Vec::new();
        for file in candidates {
            let charge =
                file.length
                    .saturating_mul(if matches!(request.query, CodeQuery::Search { .. }) {
                        2
                    } else {
                        1
                    });
            if sources.len() >= budget.max_files as usize
                || coverage.source_bytes.saturating_add(charge) > budget.max_source_bytes
            {
                truncation.push(QueryTruncation::SourceReadBudget);
                break;
            }
            if started.elapsed() >= deadline {
                truncation.push(QueryTruncation::TimeBudget);
                break;
            }
            let bytes = store
                .repository
                .get_file_content_on_view(&file.path, &store.receipt.native_state.view)
                .map_err(native)?
                .ok_or(HostError::Invalid("recorded source disappeared"))?;
            if bytes.len() as u64 != file.length || digest(&bytes) != file.digest {
                return Err(HostError::Invalid(
                    "recorded source differs from retained Git tree manifest",
                ));
            }
            let text = String::from_utf8(bytes).map_err(native)?;
            coverage.source_bytes += charge;
            coverage.read_files += 1;
            if !atomic_semantic::is_supported(&file.path) {
                coverage.unsupported_grammar_files += 1;
            }
            sources.push((file.path.clone(), text));
        }
        let mut facts = Vec::new();
        match &request.query {
            CodeQuery::Search { pattern, literal } => {
                if pattern.is_empty() || pattern.len() > 2_048 {
                    return Err(HostError::Invalid("bounded search pattern required"));
                }
                {
                    let mut paths: Vec<_> = sources.iter().map(|(path, _)| path.clone()).collect();
                    if paths.is_empty() {
                        paths.push(".atomic/no-authorized-query-content".into());
                    }
                    let pattern = if *literal {
                        literal_pattern(pattern)
                    } else {
                        pattern.clone()
                    };
                    let found = store
                        .repository
                        .search_content_paths_on_view(
                            &store.receipt.native_state.view,
                            &pattern,
                            ContentSearchOptions {
                                max_results: Some(budget.max_results as usize),
                                ..ContentSearchOptions::default()
                            },
                            &paths,
                        )
                        .map_err(native)?;
                    if found.total_matches > found.matches.len() {
                        truncation.push(QueryTruncation::ResultLimit);
                    }
                    for hit in found.matches {
                        if !authorized(&hit.path, &request.allowed_paths) {
                            return Err(HostError::Invalid("native query crossed its path scope"));
                        }
                        facts.push(CodeFact {
                            kind: if hit.path.ends_with(".svelte") {
                                "file"
                            } else {
                                "contentMatch"
                            }
                            .into(),
                            line: if hit.path.ends_with(".svelte") {
                                None
                            } else {
                                Some(u64::from(hit.line_number))
                            },
                            path: hit.path,
                            name: None,
                            end_line: None,
                            preview: truncate(&hit.line_content, 1_024),
                        });
                    }
                }
            }
            CodeQuery::Entities { path } => {
                if !safe_path(path) || !authorized(path, &request.allowed_paths) {
                    return Err(HostError::Invalid("entity path is outside query scope"));
                }
                let selected: Vec<_> = sources
                    .into_iter()
                    .filter(|(file, _)| file == path)
                    .collect();
                if atomic_semantic::is_supported(path) {
                    for entity in SyntaxIndex::from_sources(&selected).entities {
                        facts.push(CodeFact {
                            path: entity.file,
                            kind: entity.kind.as_str().into(),
                            name: Some(truncate(&entity.name, 256)),
                            line: Some(u64::from(entity.line)),
                            end_line: Some(u64::from(entity.end_line)),
                            preview: truncate(
                                entity.signature.as_deref().unwrap_or(&entity.name),
                                1_024,
                            ),
                        });
                    }
                } else if let Some((path, _)) = selected.first() {
                    facts.push(CodeFact {
                        path: path.clone(),
                        kind: "file".into(),
                        name: None,
                        line: None,
                        end_line: None,
                        preview: "No grammar at this Atomic pin; file-level evidence only.".into(),
                    });
                }
            }
            CodeQuery::Impact { target } => {
                let (path, name) = target
                    .rsplit_once('#')
                    .ok_or(HostError::Invalid("impact requires an exact path#symbol"))?;
                if !safe_path(path)
                    || !authorized(path, &request.allowed_paths)
                    || name.is_empty()
                    || name.len() > 256
                {
                    return Err(HostError::Invalid("impact target is outside query scope"));
                }
                for caller in SyntaxIndex::from_sources(&sources).callers(target) {
                    facts.push(CodeFact {
                        path: caller.path,
                        kind: "possibleCaller".into(),
                        name: Some(truncate(&caller.name, 256)),
                        line: Some(u64::from(caller.line)),
                        end_line: None,
                        preview: truncate(caller.summary.as_deref().unwrap_or(&caller.name), 1_024),
                    });
                }
            }
        }
        if started.elapsed() >= deadline && !truncation.contains(&QueryTruncation::TimeBudget) {
            truncation.push(QueryTruncation::TimeBudget);
        }
        if facts.len() > budget.max_results as usize {
            facts.truncate(budget.max_results as usize);
            truncation.push(QueryTruncation::ResultLimit);
        }
        coverage.complete = truncation.is_empty()
            && coverage.skipped_files == 0
            && coverage.read_files == coverage.candidate_files
            && (matches!(request.query, CodeQuery::Search { .. })
                || coverage.unsupported_grammar_files == 0);
        let receipt = &store.receipt;
        let mut result = CodeQueryResult {
            basis: QueryReadBasis {
                index: receipt.index.clone(),
                index_epoch: receipt.index_epoch,
                commit: receipt.commit.clone(),
                tree: receipt.tree.clone(),
                native_state: receipt.native_state.clone(),
                manifest_digest: receipt.manifest_digest.clone(),
                source_event_watermark: None,
                projector_watermark: None,
                query_version: 1,
                ontology_version: atomic_core::kg::ontology::VERSION_IRI.into(),
                visibility_digest: digest(&serde_json::to_vec(&(
                    &receipt.visibility_digest,
                    &request.allowed_paths,
                ))?),
                ignore_policy_digest: receipt.ignore_policy_digest.clone(),
                stale: receipt.commit != request.expected_commit,
                coverage,
                truncation,
            },
            facts,
        };
        while serde_json::to_vec(&result)?.len() > budget.max_bytes as usize {
            if result.facts.pop().is_none() {
                return Err(HostError::Invalid(
                    "query byte budget cannot hold its read basis",
                ));
            }
            result.basis.coverage.complete = false;
            if !result
                .basis
                .truncation
                .contains(&QueryTruncation::ByteLimit)
            {
                result.basis.truncation.push(QueryTruncation::ByteLimit);
            }
        }
        Ok(result)
    }
}

impl DerivedStore {
    fn validate(&self, root: &Path, index: &DerivedRef) -> Result<()> {
        if self.receipt.index != *index
            || durable::identity(root, true)? != self.directory
            || durable::identity(&root.join(".atomic/atomic.redb"), false)? != self.database
            || state(&self.repository)? != self.receipt.native_state
        {
            return Err(HostError::StaleBinding);
        }
        Ok(())
    }
}

fn load_store(root: &Path, index: &DerivedRef) -> Result<DerivedStore> {
    validate_owner(root, index)?;
    durable::identity(root, true)?;
    durable::identity(&root.join(".atomic"), true)?;
    durable::identity(&root.join(".atomic/intent-derived"), true)?;
    let receipt_bytes = read_bounded(&root.join(".atomic/intent-derived/receipt.json"), 65_536)?;
    let proof: String = durable::read_json(&published(root))?;
    if proof != digest(&receipt_bytes) {
        return Err(HostError::StaleBinding);
    }
    let receipt: DerivedReceipt = serde_json::from_slice(&receipt_bytes)?;
    let manifest_bytes = read_bounded(
        &root.join(".atomic/intent-derived/files.json"),
        MANIFEST_LIMIT,
    )?;
    if receipt.index != *index || digest(&manifest_bytes) != receipt.manifest_digest {
        return Err(HostError::StaleBinding);
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    validate_scope(&manifest.scope)?;
    if manifest.scope.repository_id != index.repository_id
        || manifest.scope.root_id != index.root_id
        || manifest.scope.root_epoch != index.root_epoch
        || !full_oid(&receipt.commit)
        || !full_oid(&receipt.tree)
    {
        return Err(HostError::StaleBinding);
    }
    let expected_generation = digest(&serde_json::to_vec(&(
        &manifest.scope,
        &receipt.commit,
        POLICY_VERSION,
        HostIdentity::default(),
    ))?);
    if expected_generation != index.generation {
        return Err(HostError::StaleBinding);
    }
    let repository = Repository::open_readonly_without_migration(root).map_err(native)?;
    if state(&repository)? != receipt.native_state {
        return Err(HostError::StaleBinding);
    }
    Ok(DerivedStore {
        directory: durable::identity(root, true)?,
        database: durable::identity(&root.join(".atomic/atomic.redb"), false)?,
        receipt,
        manifest,
        repository,
    })
}

fn validate_owner(root: &Path, index: &DerivedRef) -> Result<()> {
    let owner: DerivedOwner = durable::read_json(&owner_path(root))?;
    if owner.generation != index.generation
        || owner.purpose != "derivedOnly"
        || owner.directory != durable::identity(root, true)?
    {
        return Err(HostError::StaleBinding);
    }
    Ok(())
}

fn state(repository: &Repository) -> Result<StateToken> {
    let view = repository.current_view();
    Ok(StateToken {
        view: view.into(),
        effective_state: repository
            .sandbox_effective_state(view)
            .map_err(native)?
            .to_base32(),
        own_merkle: repository
            .get_view_info(view)
            .map_err(native)?
            .state_base32(),
    })
}

fn build_snapshot(
    request: &ImportDerivedRequest,
    index: DerivedRef,
    root: &Path,
) -> Result<DerivedReceipt> {
    let git = git2::Repository::open_ext(
        &request.scope.source_path,
        git2::RepositoryOpenFlags::NO_SEARCH,
        std::iter::empty::<&Path>(),
    )
    .map_err(native)?;
    let commit = git
        .find_commit(git2::Oid::from_str(&request.commit).map_err(native)?)
        .map_err(native)?;
    let tree = commit.tree().map_err(native)?;
    let mut entries = BTreeMap::new();
    let mut portable_names = std::collections::HashSet::new();
    let mut overflow = false;
    tree.walk(git2::TreeWalkMode::PreOrder, |parent, entry| {
        let Ok(name) = entry.name() else {
            overflow = true;
            return git2::TreeWalkResult::Abort;
        };
        let path = format!("{parent}{name}");
        if name.contains('/')
            || !safe_path(&path)
            || !portable_names.insert(path.to_ascii_lowercase())
        {
            overflow = true;
            return git2::TreeWalkResult::Abort;
        }
        if forbidden(&path) {
            return git2::TreeWalkResult::Skip;
        }
        if entry.kind() == Some(git2::ObjectType::Tree) {
            if !intersects(&path, &request.scope.allowed_paths) {
                return git2::TreeWalkResult::Skip;
            }
        } else if authorized(&path, &request.scope.allowed_paths)
            || (name == ".gitignore"
                && intersects(parent.trim_end_matches('/'), &request.scope.allowed_paths))
        {
            entries.insert(path, (entry.id(), entry.filemode()));
        }
        if entries.len() > 50_000 {
            overflow = true;
            git2::TreeWalkResult::Abort
        } else {
            git2::TreeWalkResult::Ok
        }
    })
    .map_err(native)?;
    if overflow {
        return Err(HostError::Invalid("source tree exceeds path/name budget"));
    }
    let mut ignore_matchers: Vec<Gitignore> = Vec::new();
    let mut ignore_bytes = Vec::new();
    for (path, (oid, mode)) in &entries {
        if path.rsplit('/').next() != Some(".gitignore") {
            continue;
        }
        if *mode != 0o100_644 && *mode != 0o100_755 {
            return Err(HostError::Invalid(
                "ignore policy must be a regular recorded file",
            ));
        }
        let bytes = git_blob(&git, *oid, 65_536)?
            .ok_or(HostError::Invalid("ignore policy exceeds budget"))?;
        if ignore_bytes.len() + bytes.len() > 1_048_576 || ignore_matchers.len() >= 128 {
            return Err(HostError::Invalid("ignore policy total exceeds budget"));
        }
        let text = std::str::from_utf8(&bytes).map_err(native)?;
        let target = root.join(path);
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::write(&target, &bytes)?;
        let mut builder = GitignoreBuilder::new(target.parent().unwrap());
        for line in text.lines() {
            builder
                .add_line(Some(target.clone()), line)
                .map_err(native)?;
        }
        ignore_matchers.push(builder.build().map_err(native)?);
        ignore_bytes.extend_from_slice(path.as_bytes());
        ignore_bytes.extend_from_slice(&bytes);
    }
    let mut manifest = Manifest {
        scope: request.scope.clone(),
        files: Vec::new(),
        skipped: Vec::new(),
    };
    let mut total = 0;
    for (path, (oid, mode)) in entries {
        if path.rsplit('/').next() == Some(".gitignore") {
            continue;
        }
        if !authorized(&path, &request.scope.allowed_paths) {
            continue;
        }
        let mut ignored = false;
        for rules in &ignore_matchers {
            let matched = rules.matched_path_or_any_parents(root.join(&path), false);
            if matched.is_ignore() {
                ignored = true;
            } else if matched.is_whitelist() {
                ignored = false;
            }
        }
        if ignored
            || authorized(&path, &request.scope.excluded_paths)
            || !matches!(mode, 0o100_644 | 0o100_755)
        {
            manifest.skipped.push(path);
            continue;
        }
        let Some(bytes) = git_blob(&git, oid, MAX_FILE)? else {
            manifest.skipped.push(path);
            continue;
        };
        if bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
            || manifest.files.len() >= MAX_IMPORT_FILES
            || total + bytes.len() > MAX_IMPORT_BYTES
        {
            manifest.skipped.push(path);
            continue;
        }
        total += bytes.len();
        let target = root.join(&path);
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::write(target, &bytes)?;
        manifest.files.push(Entry {
            path,
            length: bytes.len() as u64,
            digest: digest(&bytes),
        });
    }
    let repository = Repository::init(root).map_err(native)?;
    // Recorded code queries mint file IRIs from a native project identity. The
    // upgrade identity is local to this derived index, never Git authorship.
    repository
        .ensure_project_identity(atomic_core::kg::project_id::MintReason::Upgrade)
        .map_err(native)?;
    if !manifest.files.is_empty() {
        let wc = repository.require_working_copy_id().map_err(native)?;
        let paths: Vec<_> = manifest
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        repository.add_batch(wc, &paths).map_err(native)?;
        let mut header = ChangeHeader::new(format!("Derived Git snapshot {}", request.commit));
        let timestamp = commit.time().seconds();
        header.timestamp = if timestamp >= 0 {
            UNIX_EPOCH + Duration::from_secs(timestamp.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(timestamp.unsigned_abs())
        }
        .into();
        repository.record(wc, header, RecordOptions::new().paths(paths).sync_vault(false).enrich_kg(false)
            .update_file_index(false).with_skip_binary(true).with_max_file_size(MAX_IMPORT_BYTES as u64)
            .metadata_bytes(serde_json::to_vec(&serde_json::json!({"origin":"importedGitSnapshot","sourceCommit":request.commit,
                "sourceTree":tree.id().to_string(),"authority":"derivedOnly"}))?)).map_err(native)?;
        for file in &manifest.files {
            let content = repository
                .get_file_content_on_view(&file.path, repository.current_view())
                .map_err(native)?
                .ok_or(HostError::Invalid("native import lost a tracked file"))?;
            if digest(&content) != file.digest {
                return Err(HostError::Invalid(
                    "native import differs from Git blob bytes",
                ));
            }
        }
    }
    let bytes = serde_json::to_vec(&manifest)?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        return Err(HostError::Invalid("derived manifest exceeds budget"));
    }
    let metadata_dir = root.join(".atomic/intent-derived");
    durable::private_dir(&metadata_dir)?;
    write_large(&metadata_dir.join("files.json"), &bytes)?;
    let native_state = state(&repository)?;
    let epoch_hash = Sha256::digest(serde_json::to_vec(&(&index, &native_state))?);
    // A generation nonce, not an ordering watermark. Keep it lossless in JS;
    // the full generation/state digests remain the actual identity fences.
    let index_epoch =
        (u64::from_be_bytes(epoch_hash[..8].try_into().unwrap()) & ((1_u64 << 53) - 1)).max(1);
    let receipt = DerivedReceipt {
        index,
        index_epoch,
        commit: request.commit.clone(),
        tree: tree.id().to_string(),
        native_state,
        manifest_digest: digest(&bytes),
        visibility_digest: digest(&serde_json::to_vec(&request.scope.allowed_paths)?),
        ignore_policy_digest: digest(&serde_json::to_vec(&(
            POLICY_VERSION,
            &request.scope.excluded_paths,
            digest(&ignore_bytes),
        ))?),
        indexed_files: manifest.files.len() as u64,
        skipped_files: manifest.skipped.len() as u64,
    };
    durable::write_json(&metadata_dir.join("receipt.json"), &receipt, false)?;
    drop(repository);
    Ok(receipt)
}

fn git_blob(git: &git2::Repository, oid: git2::Oid, maximum: usize) -> Result<Option<Vec<u8>>> {
    let (length, kind) = git
        .odb()
        .map_err(native)?
        .read_header(oid)
        .map_err(native)?;
    if kind != git2::ObjectType::Blob || length > maximum {
        return Ok(None);
    }
    Ok(Some(git.find_blob(oid).map_err(native)?.content().to_vec()))
}

fn validate_identity(repository: &str, root: &str, epoch: u64) -> Result<()> {
    let id = uuid::Uuid::parse_str(repository).map_err(native)?;
    if id.to_string() != repository || root.is_empty() || root.len() > 256 || epoch == 0 {
        return Err(HostError::Invalid("invalid source root identity"));
    }
    Ok(())
}

fn validate_scope(scope: &SourceScope) -> Result<()> {
    validate_identity(&scope.repository_id, &scope.root_id, scope.root_epoch)?;
    if !scope.source_path.is_absolute() {
        return Err(HostError::Invalid(
            "absolute authorized source locator required",
        ));
    }
    validate_paths(&scope.allowed_paths)?;
    if scope.excluded_paths.len() > 64 || scope.excluded_paths.iter().any(|path| !safe_path(path)) {
        return Err(HostError::Invalid("invalid source excludes"));
    }
    Ok(())
}

pub(crate) fn authorized(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        prefix == "."
            || path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}
fn intersects(path: &str, prefixes: &[String]) -> bool {
    path.is_empty()
        || authorized(path, prefixes)
        || prefixes
            .iter()
            .any(|prefix| prefix.starts_with(&format!("{path}/")))
}
fn validate_paths(paths: &[String]) -> Result<()> {
    if paths.is_empty()
        || paths.len() > 64
        || paths.iter().any(|path| path != "." && !safe_path(path))
    {
        return Err(HostError::Invalid(
            "nonempty bounded path-prefix scope required",
        ));
    }
    Ok(())
}
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains(['\\', ':', '\0'])
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn full_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn forbidden(path: &str) -> bool {
    let components: Vec<_> = path.split('/').map(str::to_ascii_lowercase).collect();
    // Keep the existing checkpoint credential/runtime exclusions before any
    // source read, in addition to this lane's text-only deny policy.
    if components.windows(2).any(|pair| {
        matches!(
            (pair[0].as_str(), pair[1].as_str()),
            (".codex", "auth.json")
                | (".claude", ".credentials.json")
                | (".gemini", "oauth_creds.json")
        )
    }) {
        return true;
    }
    components.iter().any(|lower| {
        matches!(
            lower.as_str(),
            ".git"
                | ".atomic"
                | ".atomic-sandbox"
                | ".vault"
                | ".intent"
                | "tool-outputs"
                | "node_modules"
                | ".aws"
                | ".ssh"
        ) || lower == ".env"
            || lower.starts_with(".env.")
            || matches!(
                lower.as_str(),
                ".npmrc" | ".pypirc" | "credentials.json" | "id_rsa" | "id_ed25519"
            )
            || Path::new(lower).extension().is_some_and(|extension| {
                extension.eq_ignore_ascii_case("pem")
                    || extension.eq_ignore_ascii_case("key")
                    || extension.eq_ignore_ascii_case("p12")
            })
    })
}
fn truncate(value: &str, limit: usize) -> String {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].into()
}
fn literal_pattern(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if "\\.+*?()|[]{}^$".contains(character) {
            output.push('\\');
        }
        output.push(character);
    }
    output
}
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum {
        return Err(HostError::Invalid("derived metadata exceeds budget"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(HostError::Invalid("derived metadata grew beyond budget"));
    }
    Ok(bytes)
}
fn write_large(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::HostConfig;
    use intent_atomic_proto::knowledge::QueryBudget;

    pub(crate) fn fixture() -> (
        tempfile::TempDir,
        Host,
        ImportDerivedRequest,
        git2::Repository,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let git = git2::Repository::init(&source).unwrap();
        let files = [
            (
                "src/public/lib.rs",
                "// RecordedNeedle\npub fn leaf() -> u32 { 3 }\npub fn caller() -> u32 { leaf() }\n",
            ),
            (
                "src/private/hidden.rs",
                "pub fn private_caller() -> u32 { leaf() }\n",
            ),
            ("src/public/Card.svelte", "<div>RecordedNeedle</div>\n"),
            (".gitignore", "ignored.txt\n"),
            ("ignored.txt", "SecretNeedle\n"),
            (".env", "SecretNeedle\n"),
            ("node_modules/dependency.js", "SecretNeedle\n"),
            (".intent/secrets/value", "SecretNeedle\n"),
            (".intent/attachments/value", "SecretNeedle\n"),
            (".codex/auth.json", "SecretNeedle\n"),
            (".claude/.credentials.json", "SecretNeedle\n"),
            (".gemini/oauth_creds.json", "SecretNeedle\n"),
            ("tool-outputs/value", "SecretNeedle\n"),
            (".atomic-sandbox", "SecretNeedle\n"),
        ];
        let mut index = git.index().unwrap();
        for (path, bytes) in files {
            let target = source.join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
            index.add_path(Path::new(path)).unwrap();
        }
        index.write().unwrap();
        let tree = index.write_tree().unwrap();
        let signature =
            git2::Signature::now("Source author metadata", "source@example.test").unwrap();
        let commit = {
            let tree = git.find_tree(tree).unwrap();
            git.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "source commit",
                &tree,
                &[],
            )
            .unwrap()
        };
        std::fs::write(source.join("src/public/lib.rs"), "dirty physical bytes\n").unwrap();
        let host = Host::new(HostConfig {
            stores_dir: temp.path().join("stores"),
            config_dir: temp.path().join("config"),
            spool_dir: temp.path().join("spool"),
        })
        .unwrap();
        host.reconcile().unwrap();
        let request = ImportDerivedRequest {
            operation_id: "derived-import-1".into(),
            scope: SourceScope {
                repository_id: uuid::Uuid::new_v4().to_string(),
                root_id: "root".into(),
                root_epoch: 1,
                source_path: source,
                allowed_paths: vec![".".into()],
                excluded_paths: vec![],
            },
            commit: commit.to_string(),
        };
        (temp, host, request, git)
    }

    pub(crate) fn query(
        receipt: &DerivedReceipt,
        query: CodeQuery,
        paths: &[&str],
    ) -> CodeQueryRequest {
        CodeQueryRequest {
            index: receipt.index.clone(),
            allowed_paths: paths.iter().map(|path| (*path).into()).collect(),
            expected_commit: receipt.commit.clone(),
            query,
            budget: QueryBudget::default(),
        }
    }

    #[test]
    fn source_policy_blocks_casefold_reserved_runtime_and_key_names() {
        for path in [
            ".ATOMIC/config",
            ".Git/config",
            ".Atomic-Sandbox",
            ".Env",
            "private.PEM",
            ".Codex/auth.JSON",
        ] {
            assert!(forbidden(path), "reserved or credential input: {path}");
        }
    }

    #[test]
    fn git_snapshot_import_is_idempotent_recorded_and_does_not_touch_source() {
        let (_temp, host, request, git) = fixture();
        let before_head = git.head().unwrap().target();
        let before_index = std::fs::read(git.path().join("index")).unwrap();
        let receipt = host.import_derived(&request).unwrap();
        assert_eq!(receipt, host.import_derived(&request).unwrap());
        let mut other_attempt = request.clone();
        other_attempt.operation_id = "another-import-attempt".into();
        assert_eq!(receipt, host.import_derived(&other_attempt).unwrap());
        let found = host
            .query_code(&query(
                &receipt,
                CodeQuery::Search {
                    pattern: "RecordedNeedle".into(),
                    literal: true,
                },
                &["src/public"],
            ))
            .unwrap();
        assert_eq!(found.facts.len(), 2);
        assert_eq!(found.basis.commit, request.commit);
        assert_eq!(found.basis.source_event_watermark, None);
        assert!(!found.basis.stale);
        assert_eq!(git.head().unwrap().target(), before_head);
        assert_eq!(
            std::fs::read(git.path().join("index")).unwrap(),
            before_index
        );
        assert_eq!(
            std::fs::read_to_string(request.scope.source_path.join("src/public/lib.rs")).unwrap(),
            "dirty physical bytes\n"
        );
        assert!(!request.scope.source_path.join(".atomic").exists());
        let secret = host
            .query_code(&query(
                &receipt,
                CodeQuery::Search {
                    pattern: "SecretNeedle".into(),
                    literal: true,
                },
                &["."],
            ))
            .unwrap();
        assert!(secret.facts.is_empty());
    }

    #[test]
    fn entities_and_impact_use_only_scoped_recorded_native_sources() {
        let (_temp, host, request, _git) = fixture();
        let receipt = host.import_derived(&request).unwrap();
        let entities = host
            .query_code(&query(
                &receipt,
                CodeQuery::Entities {
                    path: "src/public/lib.rs".into(),
                },
                &["src/public"],
            ))
            .unwrap();
        assert!(entities
            .facts
            .iter()
            .any(|fact| fact.name.as_deref() == Some("leaf")));
        let callers = host
            .query_code(&query(
                &receipt,
                CodeQuery::Impact {
                    target: "src/public/lib.rs#leaf".into(),
                },
                &["src/public"],
            ))
            .unwrap();
        assert!(callers
            .facts
            .iter()
            .any(|fact| fact.name.as_deref() == Some("caller")));
        assert!(callers
            .facts
            .iter()
            .all(|fact| fact.path.starts_with("src/public/")));
        let svelte = host
            .query_code(&query(
                &receipt,
                CodeQuery::Entities {
                    path: "src/public/Card.svelte".into(),
                },
                &["src/public"],
            ))
            .unwrap();
        assert_eq!(svelte.facts[0].kind, "file");
        assert_eq!(svelte.facts[0].name, None);
    }

    #[test]
    fn query_scope_and_limits_are_explicit_and_fail_closed() {
        let (_temp, host, mut request, _git) = fixture();
        request.scope.allowed_paths = vec!["src/public".into()];
        let receipt = host.import_derived(&request).unwrap();
        assert!(host
            .query_code(&query(
                &receipt,
                CodeQuery::Search {
                    pattern: "leaf".into(),
                    literal: true
                },
                &["."]
            ))
            .is_err());
        let mut bounded = query(
            &receipt,
            CodeQuery::Search {
                pattern: "RecordedNeedle".into(),
                literal: true,
            },
            &["src/public"],
        );
        bounded.budget.max_results = 1;
        bounded.expected_commit = "1".repeat(40);
        let result = host.query_code(&bounded).unwrap();
        assert!(result.basis.stale);
        assert!(!result.basis.coverage.complete);
        assert!(result
            .basis
            .truncation
            .contains(&QueryTruncation::ResultLimit));
        assert!(serde_json::to_vec(&result).unwrap().len() <= bounded.budget.max_bytes as usize);
        let mut changed = request;
        changed.commit = "2".repeat(40);
        assert!(host.import_derived(&changed).is_err());
    }

    #[test]
    fn a_host_restart_recovers_the_same_published_recorded_mapping() {
        let (_temp, host, request, _git) = fixture();
        let config = host.config.clone();
        let receipt = host.import_derived(&request).unwrap();
        drop(host);
        let restarted = Host::new(config).unwrap();
        assert!(restarted.reconcile().unwrap().ready);
        let found = restarted
            .query_code(&query(
                &receipt,
                CodeQuery::Search {
                    pattern: "RecordedNeedle".into(),
                    literal: true,
                },
                &["src/public"],
            ))
            .unwrap();
        assert_eq!(found.basis.index_epoch, receipt.index_epoch);
        assert_eq!(found.basis.native_state, receipt.native_state);
        assert_eq!(found.facts.len(), 2);
    }
}
