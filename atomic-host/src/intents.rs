//! Intent-owned deterministic facade over the pinned public vault primitives.
//! This is not an upstream create-with-ID guarantee. Exact journals repair the
//! known UID, manifest and materialization; they never search by title/recency.
//! Session declarations remain `DeclaredOnly`. A separately journaled versioned
//! host facade freezes actual native turn semantics before bound preparation;
//! source grants and authoring activation remain separate admission gates.

use crate::{durable, Host, HostError, Result};
use atomic_core::pristine::{VaultEntry, VaultEntryType, VaultMutTxnT, VaultTxnT, ViewScope};
use atomic_core::{Base32, MutTxnT};
use atomic_repository::{intent_bridge, Repository};
use intent_atomic_proto::intents::{
    projection_command_identity, DeclareNativeTurnRequest, IntentProjectionReceipt,
    IntentProjectionRef, NativeIntentPins, NativeProjectIdentity, NativeTaskSource,
    NativeTurnBindingStage, NativeTurnDeclaration, ProjectTaskIntentRequest,
    INTENT_PROJECTION_VERSION,
};
use intent_atomic_proto::{HostIdentity, SpoolRef, StoreBinding};
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(crate) mod control_export;
mod freeze;

#[cfg(test)]
pub(crate) mod tests;
const SOURCE_LIMIT: u64 = 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 8 * 1024 * 1024;
const CONTROL_VIEW: &str = "intent-owner-control";
fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn projection_command_bytes(request: &ProjectTaskIntentRequest) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&projection_command_identity(request))?)
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn operation_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn uid_valid(value: &str) -> bool {
    value.len() == 26
        && value.as_bytes()[0] <= b'7'
        && value
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}
fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(HostError::Invalid(
            "intent source is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(native)? > limit {
        return Err(HostError::Invalid("intent source exceeded its byte bound"));
    }
    Ok(bytes)
}
fn exact_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.symlink_metadata().is_ok() {
        if read_bytes(path, u64::try_from(bytes.len()).map_err(native)?)? != bytes {
            return Err(HostError::Invalid(
                "immutable intent artifact already contains different bytes",
            ));
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or(HostError::Invalid("intent artifact needs a parent"))?;
    let temporary = parent.join(format!(".pending-{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)?;
        std::fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result
}
fn spool_bytes(root: &Path, reference: &SpoolRef, limit: u64) -> Result<Vec<u8>> {
    if reference.name.is_empty()
        || reference.name.len() > 128
        || reference.name.contains(['/', '\\'])
        || reference.name == "."
        || reference.name == ".."
        || !hash_valid(&reference.sha256)
        || reference.length > limit
    {
        return Err(HostError::Invalid("invalid intent spool reference"));
    }
    let bytes = read_bytes(&root.join(&reference.name), limit)?;
    if u64::try_from(bytes.len()).map_err(native)? != reference.length
        || digest(&bytes) != reference.sha256
    {
        return Err(HostError::Invalid(
            "intent spool bytes differ from their retained reference",
        ));
    }
    Ok(bytes)
}
fn literal(value: &str) -> String {
    value
        .lines()
        .map(|line| format!("> {}", line.replace('&', "&amp;").replace(':', "&#58;")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlOwner {
    binding: StoreBinding,
    directory: durable::FileIdentity,
    working_copy: Option<String>,
    view_started: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Prepared,
    EntryStored,
    ManifestStored,
    Projected,
    Terminal,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    request: ProjectTaskIntentRequest,
    command_digest: String,
    retained_source: SpoolRef,
    phase: Phase,
    receipt: Option<IntentProjectionReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TurnJournal {
    request: DeclareNativeTurnRequest,
    command_digest: String,
    receipt: Option<NativeTurnDeclaration>,
}

fn validate_source(request: &ProjectTaskIntentRequest, bytes: &[u8]) -> Result<NativeTaskSource> {
    let source: NativeTaskSource = serde_json::from_slice(bytes)?;
    if source.reference != request.task_revision
        || source.reference.projection_schema_version != 1
        || source.reference.rev < 0
        || source.criteria.len() > 1024
    {
        return Err(HostError::Invalid(
            "native projection exact task revision/schema differs",
        ));
    }
    let tuple = serde_json::to_vec(&(
        source.reference.projection_schema_version,
        &source.reference.workspace_id,
        &source.reference.note_id,
        source.reference.rev,
        &source.title,
        &source.content,
        &source.task_json,
    ))?;
    if digest(&tuple) != source.reference.digest {
        return Err(HostError::Invalid(
            "retained governing task digest differs from actual source",
        ));
    }
    let task: Value = serde_json::from_str(&source.task_json)?;
    let empty = vec![];
    let criteria = task
        .get("acceptanceCriteria")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    if criteria.len() != source.criteria.len() {
        return Err(HostError::Invalid(
            "native criteria projection differs from exact task source",
        ));
    }
    let mut requirements = BTreeMap::new();
    if let Some(definition) = task.get("workDefinition").filter(|v| !v.is_null()) {
        if !matches!(
            definition["purpose"].as_str(),
            Some("source" | "research" | "review")
        ) {
            return Err(HostError::Invalid(
                "native task purpose is not explicit qualified source metadata",
            ));
        }
        let policies = definition["criteria"].as_array().ok_or(HostError::Invalid(
            "task criterion policy must be an explicit array",
        ))?;
        if policies.len() > 128 {
            return Err(HostError::Invalid(
                "task criterion policies exceed qualification budget",
            ));
        }
        for policy in policies {
            let index = policy["index"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or(HostError::Invalid("task criterion policy index is invalid"))?;
            let criterion = source.criteria.get(index).ok_or(HostError::Invalid(
                "task criterion policy names a foreign index",
            ))?;
            let kinds: Vec<String> = serde_json::from_value(policy["requiredKinds"].clone())?;
            let unique: BTreeSet<&str> = kinds.iter().map(String::as_str).collect();
            if policy["textDigest"].as_str() != Some(criterion.text_digest.as_str())
                || kinds.is_empty()
                || kinds.len() > 16
                || unique.len() != kinds.len()
                || kinds.iter().any(|kind| {
                    kind.is_empty()
                        || kind.len() > 64
                        || !kind
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
                || requirements.insert(index, kinds).is_some()
            {
                return Err(HostError::Invalid(
                    "native criterion requirements differ from exact retained task definition",
                ));
            }
        }
    }
    for (index, criterion) in source.criteria.iter().enumerate() {
        let text_hash = digest(criterion.text.as_bytes());
        let criterion_hash = digest(&serde_json::to_vec(&(
            &source.reference.digest,
            criterion.index,
            &text_hash,
        ))?);
        if usize::try_from(criterion.index).map_err(native)? != index
            || criteria[index].as_str() != Some(criterion.text.as_str())
            || criterion.text_digest != text_hash
            || criterion.criterion_id != criterion_hash
            || criterion.origin != "explicit-task-content"
            || criterion.required_kinds != requirements.get(&index).cloned().unwrap_or_default()
        {
            return Err(HostError::Invalid(
                "native criterion pins are not the exact qualified task projection",
            ));
        }
    }
    Ok(source)
}
fn source_entry(
    request: &ProjectTaskIntentRequest,
    source: &NativeTaskSource,
) -> Result<VaultEntry> {
    let task: Value = serde_json::from_str(&source.task_json)?;
    let status = match task["status"].as_str() {
        Some("not_started") => "planned",
        Some("in_progress") => "in_progress",
        Some("review_required") => "needs-review",
        Some("complete") => "done",
        _ => {
            return Err(HostError::Unsupported(
                "native projection of this task lifecycle state is not qualified",
            ));
        }
    };
    let uid = &request.identity.native_intent_id;
    let mut body = format!(":::why\n{}\n:::\n\n", literal(&source.content));
    for (index, criterion) in source.criteria.iter().enumerate() {
        writeln!(
            body,
            ":::acceptance-criterion{{#{uid}-ac-{} status=open requiredKinds=\"{}\"}}\n{}\n:::\n",
            index + 1,
            criterion.required_kinds.join(","),
            literal(&criterion.text)
        )
        .map_err(native)?;
    }
    if let Some(definition) = task.get("workDefinition").filter(|v| !v.is_null()) {
        let files = definition["files"].as_array().ok_or(HostError::Invalid(
            "task file references must be an explicit array",
        ))?;
        if files.len() > 512 {
            return Err(HostError::Invalid(
                "task file references exceed projection budget",
            ));
        }
        let mut planned = Vec::new();
        let mut seen = BTreeSet::new();
        for file in files {
            let root = file["rootId"]
                .as_str()
                .ok_or(HostError::Invalid("planned file root is missing"))?;
            let path = file["path"]
                .as_str()
                .ok_or(HostError::Invalid("planned file path is missing"))?;
            let role = file["role"]
                .as_str()
                .ok_or(HostError::Invalid("planned file role is missing"))?;
            if root.is_empty()
                || root.len() > 256
                || !root
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || path.is_empty()
                || path.len() > 4096
                || path.contains(['\\', ':'])
                || path.chars().any(char::is_control)
                || (path != "."
                    && path
                        .split('/')
                        .any(|p| p.is_empty() || p == "." || p == ".."))
                || !seen.insert((root, path))
                || !matches!(role, "reference" | "in-scope" | "out-of-scope")
            {
                return Err(HostError::Invalid(
                    "planned file scope differs from qualified retained task definition",
                ));
            }
            if root != request.root_id || role == "reference" {
                writeln!(
                    body,
                    "\nReference only (root {}): {}",
                    literal(root),
                    literal(path)
                )
                .map_err(native)?;
                continue;
            }
            if path.contains(['"', '\'', '{', '}']) {
                return Err(HostError::Unsupported(
                    "this exact planned path cannot yet be represented by native directive attributes",
                ));
            }
            if role == "in-scope" {
                planned.push(path);
            } else {
                writeln!(
                    body,
                    ":::scope-out\nPlanned excluded file\n::file-ref{{path=\"{path}\"}}\n:::\n"
                )
                .map_err(native)?;
            }
        }
        if !planned.is_empty() {
            writeln!(body,":::task{{#{uid}-1 status=open}}\nExplicit planned files; this is neither a write grant nor observed execution.").map_err(native)?;
            for path in planned {
                writeln!(body, "::file-ref{{path=\"{path}\"}}").map_err(native)?;
            }
            body.push_str(":::\n\n");
        }
    }
    let frontmatter = json!({"uid":uid,"id":request.identity.display_key,"project":"INTENT","author":uid.to_ascii_lowercase(),"seq":1,"title":source.title,"status":status,"created_at":source.created_at,"view":CONTROL_VIEW,"intentWorkspaceId":source.reference.workspace_id,"intentNoteId":source.reference.note_id,"intentTaskRevision":source.reference.rev,"intentTaskDigest":source.reference.digest,"intentProjectionVersion":INTENT_PROJECTION_VERSION,"intentProjectionRevision":request.projection_revision,"intentProjectionOperation":request.operation_id});
    Ok(VaultEntry::new(
        VaultEntryType::Intent,
        body.into_bytes(),
        serde_json::to_string(&frontmatter)?,
        source.created_at.clone(),
    ))
}
fn same_entry(actual: &VaultEntry, expected: &VaultEntry) -> bool {
    actual.entry_type == expected.entry_type
        && actual.content_bytes == expected.content_bytes
        && actual.frontmatter_json == expected.frontmatter_json
        && actual.created_at == expected.created_at
        && actual.updated_at == expected.updated_at
        && actual.content_hash == expected.content_hash
}
fn entry_pins(entry: &VaultEntry, bytes: &[u8]) -> Result<NativeIntentPins> {
    let inputs = intent_bridge::inputs_from_entry(entry).map_err(native)?;
    let canonical = intent_bridge::lift(&inputs).map_err(native)?;
    Ok(NativeIntentPins {
        source_sha256: digest(bytes),
        parsed_source_hash: intent_bridge::source_content_hash(&inputs),
        canonical_content_hash: canonical.compute_content_hash(),
        substance_hash: atomic_canonical::intent_substance_hash(&canonical),
    })
}

impl Host {
    fn intent_journals(&self) -> Result<PathBuf> {
        if durable::identity(&self.journal_dir, true)? != self.journal_root_identity {
            return Err(HostError::StaleBinding);
        }
        let root = self.config.config_dir.join("intent-operations");
        durable::private_dir(&root)?;
        Ok(root)
    }
    fn intent_journal_path(&self, operation: &str) -> Result<PathBuf> {
        if !operation_valid(operation) {
            return Err(HostError::Invalid(
                "invalid native intent operation identity",
            ));
        }
        Ok(self
            .intent_journals()?
            .join(format!("{}.json", digest(operation.as_bytes()))))
    }
    fn intent_store(
        &self,
        binding: &StoreBinding,
    ) -> Result<std::sync::Arc<crate::native::NativeStore>> {
        if let Ok(cached) = self.cached_store(binding) {
            return Ok(cached);
        }
        let proof = self.verify_marker(binding)?;
        let store = std::sync::Arc::new(crate::native::NativeStore::open_owned_recovery(
            binding, &proof,
        )?);
        self.stores
            .lock()
            .map_err(|_| HostError::Poisoned)?
            .insert(binding.repository_id.clone(), store.clone());
        Ok(store)
    }
    fn control_repository(&self, binding: &StoreBinding) -> Result<Repository> {
        let store = self.intent_store(binding)?;
        let parent = self.binding_path(binding)?;
        let root = parent.join("intent-control");
        durable::private_dir(&root)?;
        let owner_path = parent.join("intent-control.json");
        let mut owner = if owner_path.symlink_metadata().is_ok() {
            let owner: ControlOwner = durable::read_json(&owner_path)?;
            if owner.binding != *binding || owner.directory != durable::identity(&root, true)? {
                return Err(HostError::StaleBinding);
            }
            owner
        } else {
            if std::fs::read_dir(&root)?.next().is_some() {
                return Err(HostError::Uncertain(
                    "unowned native intent control workspace".into(),
                ));
            }
            let owner = ControlOwner {
                binding: binding.clone(),
                directory: durable::identity(&root, true)?,
                working_copy: None,
                view_started: false,
            };
            durable::write_json(&owner_path, &owner, false)?;
            owner
        };
        let atomic = root.join(".atomic");
        durable::private_dir(&atomic)?;
        let pointer = binding.store_path.join(".atomic");
        exact_bytes(
            &atomic.join("repository"),
            pointer
                .to_str()
                .ok_or(HostError::Invalid("native store path must be UTF-8"))?
                .as_bytes(),
        )?;
        let mut repository =
            Repository::open_with_pristine(&root, store.shared_pristine()).map_err(native)?;
        if repository.database_path() != store.repository().database_path() {
            return Err(HostError::StaleBinding);
        }
        let working_copy = repository.require_working_copy_id().map_err(native)?;
        if owner
            .working_copy
            .as_ref()
            .is_some_and(|id| id != &working_copy.to_string())
        {
            return Err(HostError::StaleBinding);
        }
        if !owner.view_started {
            if repository.get_view_info(CONTROL_VIEW).is_ok() {
                return Err(HostError::Invalid(
                    "native control view already exists without its creation journal",
                ));
            }
            owner.view_started = true;
            durable::write_json(&owner_path, &owner, true)?;
        }
        match repository.get_view_info(CONTROL_VIEW) {
            Ok(info)
                if info.scope == ViewScope::Draft
                    && info.parent_name.is_none()
                    && info.is_empty() => {}
            Ok(_) => {
                return Err(HostError::Invalid(
                    "native control view acquired code membership or an external parent",
                ));
            }
            Err(_) => repository
                .create_view_with_identity(CONTROL_VIEW, ViewScope::Draft, None)
                .map_err(native)?,
        }
        if repository.current_view() != CONTROL_VIEW {
            repository
                .align_to_view(working_copy, CONTROL_VIEW)
                .map_err(native)?;
        }
        owner.working_copy = Some(working_copy.to_string());
        durable::sync_tree(&atomic)?;
        durable::write_json(&owner_path, &owner, true)?;
        Ok(repository)
    }

    /// Read the actual established project identity before reserving portable refs.
    /// # Errors
    /// Refuses unopened/stale stores or absent native project identity.
    pub fn native_project_identity(&self, binding: &StoreBinding) -> Result<NativeProjectIdentity> {
        let store = self.cached_store(binding)?;
        let identity = store
            .repository()
            .project_identity()
            .map_err(native)?
            .ok_or(HostError::Invalid("native project identity is unavailable"))?;
        Ok(NativeProjectIdentity {
            host: HostIdentity::default(),
            binding: binding.clone(),
            project_id: identity.project_id().map_err(native)?.to_base32(),
            project_identity_hash: identity.hash.to_base32(),
        })
    }

    /// Native projection facade for exact private daemon requests. Intent
    /// remains the authority for the original task and source admission.
    /// # Errors
    /// Refuses changed identity/source, conflicting replay or unrecoverable partial effects.
    pub fn project_task_intent(
        &self,
        request: &ProjectTaskIntentRequest,
    ) -> Result<IntentProjectionReceipt> {
        // Native vault initialization and entry writes resolve embedding
        // providers from the process environment. Refuse before journals or
        // native effects; the supervised process also clears its environment.
        crate::embedding_policy::refuse_ambient_embedding()?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.binding_path(&request.binding)?;
        self.cached_store(&request.binding)?;
        let operation_path = self.intent_journal_path(&request.operation_id)?;
        let source = if operation_path.symlink_metadata().is_ok() {
            let prior: Journal = durable::read_json(&operation_path)?;
            if prior.command_digest != digest(&projection_command_bytes(request)?) {
                return Err(HostError::Invalid(
                    "conflicting native intent operation replay",
                ));
            }
            spool_bytes(&self.config.spool_dir, &prior.retained_source, SOURCE_LIMIT)?
        } else {
            spool_bytes(&self.config.spool_dir, &request.source, SOURCE_LIMIT)?
        };
        validate_source(request, &source)?;
        let live = self.begin_live_write()?;
        let receipt = self.project_intent_observed(request, |_| Ok(()))?;
        live.complete()?;
        Ok(receipt)
    }

    fn project_intent_observed(
        &self,
        request: &ProjectTaskIntentRequest,
        mut observe: impl FnMut(Phase) -> Result<()>,
    ) -> Result<IntentProjectionReceipt> {
        // Recovery invokes this route directly. It must apply the same
        // provider refusal before replay can initialize/store native vault data.
        crate::embedding_policy::refuse_ambient_embedding()?;
        self.binding_path(&request.binding)?;
        let store = self.intent_store(&request.binding)?;
        let identity = store
            .repository()
            .project_identity()
            .map_err(native)?
            .ok_or(HostError::Invalid("native project identity is unavailable"))?;
        if request.root_id.is_empty()
            || request.root_id.len() > 256
            || !request
                .root_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || request.identity.project_id != identity.project_id().map_err(native)?.to_base32()
            || request.identity.project_identity_hash != identity.hash.to_base32()
            || !uid_valid(&request.identity.native_intent_id)
            || request.identity.canonical_resource
                != format!("urn:atomic:intent:{}", request.identity.native_intent_id)
            || request.identity.display_key
                != format!(
                    "INTENT::{}::1",
                    request.identity.native_intent_id.to_ascii_lowercase()
                )
            || request.projection_revision == 0
            || request
                .previous
                .as_ref()
                .map_or(request.projection_revision != 1, |prior| {
                    prior.projection_revision.checked_add(1) != Some(request.projection_revision)
                })
        {
            return Err(HostError::Invalid(
                "native intent stable identity or exact projection predecessor differs",
            ));
        }
        let path = self.intent_journal_path(&request.operation_id)?;
        let command_digest = digest(&projection_command_bytes(request)?);
        let prior = if path.symlink_metadata().is_ok() {
            let retained: Journal = durable::read_json(&path)?;
            if retained.command_digest != command_digest
                || digest(&projection_command_bytes(&retained.request)?) != command_digest
            {
                return Err(HostError::Invalid(
                    "conflicting native intent operation replay",
                ));
            }
            Some(retained)
        } else {
            None
        };
        let source_bytes = spool_bytes(
            &self.config.spool_dir,
            prior
                .as_ref()
                .map_or(&request.source, |journal| &journal.retained_source),
            SOURCE_LIMIT,
        )?;
        let source = validate_source(request, &source_bytes)?;
        let expected = source_entry(request, &source)?;
        let mut journal = if let Some(prior) = prior {
            prior
        } else {
            let retained_source = SpoolRef {
                name: format!(
                    "native-task-{}.json",
                    digest(request.operation_id.as_bytes())
                ),
                length: u64::try_from(source_bytes.len()).map_err(native)?,
                sha256: digest(&source_bytes),
            };
            exact_bytes(
                &self.config.spool_dir.join(&retained_source.name),
                &source_bytes,
            )?;
            let journal = Journal {
                request: request.clone(),
                command_digest: command_digest.clone(),
                retained_source,
                phase: Phase::Prepared,
                receipt: None,
            };
            durable::write_json(&path, &journal, false)?;
            observe(Phase::Prepared)?;
            journal
        };
        if journal.retained_source.sha256 != request.source.sha256
            || journal.retained_source.length != request.source.length
            || journal.retained_source.name
                != format!(
                    "native-task-{}.json",
                    digest(request.operation_id.as_bytes())
                )
        {
            return Err(HostError::Invalid(
                "retained native source differs from its command byte identity",
            ));
        }
        if matches!(journal.phase, Phase::Terminal | Phase::Projected) {
            let receipt = journal.receipt.clone().ok_or(HostError::Invalid(
                "terminal native intent operation has no receipt",
            ))?;
            let artifact = spool_bytes(&self.config.spool_dir, &receipt.artifact, ARTIFACT_LIMIT)?;
            if receipt.host != HostIdentity::default()
                || receipt.binding != request.binding
                || receipt.identity != request.identity
                || receipt.projection.operation_id != request.operation_id
                || receipt.projection.projection_revision != request.projection_revision
                || receipt.projection.task_revision != request.task_revision
                || receipt.projection_version != INTENT_PROJECTION_VERSION
                || receipt.request_digest != command_digest
                || receipt.task_source != journal.retained_source
                || receipt.control_view != CONTROL_VIEW
                || receipt.vault_path
                    != format!("intents/{}/intent.md", request.identity.native_intent_id)
                || receipt.projection.pins != entry_pins(&expected, &artifact)?
            {
                return Err(HostError::Invalid(
                    "retained native intent receipt differs from its exact original source",
                ));
            }
            if journal.phase == Phase::Projected {
                journal.phase = Phase::Terminal;
                durable::write_json(&path, &journal, true)?;
                observe(Phase::Terminal)?;
            }
            return Ok(receipt);
        }
        let repository = self.control_repository(&request.binding)?;
        // The shared pristine may already have vault tables, including after a
        // crash between upstream's table commit and its filesystem creation.
        // has_vault never proves this distinct owned working copy has dirs.
        durable::private_dir(&repository.vault_dir())?;
        for subdir in ["goals", "memory", "skills", "intents", "scratch", "prompts"] {
            durable::private_dir(&repository.vault_dir().join(subdir))?;
        }
        repository.ensure_vault().map_err(native)?;
        // Native vault initialization uses ordinary directory modes. This is
        // the owner-only control workspace, never selected code/user content.
        durable::sync_tree(&repository.vault_dir())?;
        let vault_path = format!("intents/{}/intent.md", request.identity.native_intent_id);
        let current = repository.vault_retrieve(&vault_path).map_err(native)?;
        match current {
            Some(actual) if same_entry(&actual, &expected) => {}
            Some(actual) => {
                let Some(prior) = &request.previous else {
                    return Err(HostError::Invalid(
                        "native UID already contains unowned or conflicting source",
                    ));
                };
                let fm: Value = serde_json::from_str(&actual.frontmatter_json)?;
                if fm["intentProjectionOperation"].as_str() != Some(prior.operation_id.as_str())
                    || fm["intentTaskDigest"].as_str() != Some(prior.task_revision.digest.as_str())
                    || fm["intentProjectionRevision"].as_u64() != Some(prior.projection_revision)
                {
                    return Err(HostError::Invalid(
                        "native source changed after its selected predecessor",
                    ));
                }
                let disk = repository.vault_dir().join(&vault_path);
                let bytes = read_bytes(&disk, ARTIFACT_LIMIT)?;
                if entry_pins(&actual, &bytes)? != prior.pins {
                    return Err(HostError::Invalid(
                        "native predecessor source/canonical/substance pins changed",
                    ));
                }
                repository
                    .vault_store_entry(&vault_path, &expected)
                    .map_err(native)?;
            }
            None if request.previous.is_none() => {
                repository
                    .vault_store_entry(&vault_path, &expected)
                    .map_err(native)?;
            }
            None => return Err(HostError::Invalid("native predecessor intent is missing")),
        }
        journal.phase = Phase::EntryStored;
        durable::write_json(&path, &journal, true)?;
        observe(Phase::EntryStored)?;
        repository
            .vault_reconcile_intent_manifest()
            .map_err(native)?;
        // Public reconciliation repairs missing rows but intentionally leaves
        // existing title/status alone. Mirror those authoritative source fields
        // only; never mint native verification or completed-substance stamps.
        let fm: Value = serde_json::from_str(&expected.frontmatter_json)?;
        {
            let mut txn = repository.pristine().write_txn().map_err(native)?;
            let mut manifest = txn.get_vault_manifest().map_err(native)?;
            let summary = manifest
                .intents
                .get_mut(&request.identity.display_key)
                .ok_or(HostError::Invalid(
                    "native intent summary was not reconstructed",
                ))?;
            if summary.uid != request.identity.native_intent_id
                || summary.vault_path != vault_path
                || summary.project != "INTENT"
                || summary.human_key != request.identity.display_key
            {
                return Err(HostError::Invalid(
                    "native intent manifest identity conflicts with the requested UID",
                ));
            }
            summary.title.clone_from(&source.title);
            summary.status = fm["status"]
                .as_str()
                .ok_or(HostError::Invalid(
                    "native projected task status is missing",
                ))?
                .into();
            txn.put_vault_manifest(&manifest).map_err(native)?;
            txn.commit().map_err(native)?;
        }
        journal.phase = Phase::ManifestStored;
        durable::write_json(&path, &journal, true)?;
        observe(Phase::ManifestStored)?;
        let disk = repository.vault_dir().join(&vault_path);
        let parent = disk
            .parent()
            .ok_or(HostError::Invalid("native artifact has no parent"))?;
        let vault = repository.vault_dir();
        durable::private_dir(&vault)?;
        durable::private_dir(&vault.join("intents"))?;
        durable::private_dir(parent)?;
        if disk.symlink_metadata().is_ok() {
            durable::identity(&disk, false)?;
        }
        repository.vault_materialize(&vault_path).map_err(native)?;
        durable::sync_tree(parent)?;
        durable::sync_parent(parent)?;
        let bytes = read_bytes(&disk, ARTIFACT_LIMIT)?;
        let actual = repository
            .vault_retrieve(&vault_path)
            .map_err(native)?
            .ok_or(HostError::Invalid(
                "native intent disappeared after projection",
            ))?;
        if !same_entry(&actual, &expected) {
            return Err(HostError::Invalid(
                "native intent source differs after projection",
            ));
        }
        let inputs = intent_bridge::inputs_from_entry(&actual).map_err(native)?;
        let canonical = intent_bridge::lift(&inputs).map_err(native)?;
        if canonical.id != request.identity.canonical_resource {
            return Err(HostError::Invalid(
                "native canonical resource differs from the reserved identity",
            ));
        }
        let artifact = SpoolRef {
            name: format!(
                "native-intent-{}.md",
                digest(request.operation_id.as_bytes())
            ),
            length: u64::try_from(bytes.len()).map_err(native)?,
            sha256: digest(&bytes),
        };
        exact_bytes(&self.config.spool_dir.join(&artifact.name), &bytes)?;
        let receipt = IntentProjectionReceipt {
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            identity: request.identity.clone(),
            projection: IntentProjectionRef {
                operation_id: request.operation_id.clone(),
                projection_revision: request.projection_revision,
                task_revision: request.task_revision.clone(),
                pins: entry_pins(&actual, &bytes)?,
            },
            request_digest: command_digest,
            projection_version: INTENT_PROJECTION_VERSION,
            control_working_copy_id: repository
                .require_working_copy_id()
                .map_err(native)?
                .to_string(),
            control_view: CONTROL_VIEW.into(),
            vault_path,
            vault_manifest_merkle: repository
                .vault_manifest_merkle()
                .map_err(native)?
                .to_base32(),
            task_source: journal.retained_source.clone(),
            artifact,
            observed_unix_seconds: i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(native)?
                    .as_secs(),
            )
            .map_err(native)?,
        };
        journal.receipt = Some(receipt.clone());
        journal.phase = Phase::Projected;
        durable::write_json(&path, &journal, true)?;
        observe(Phase::Projected)?;
        journal.phase = Phase::Terminal;
        durable::write_json(&path, &journal, true)?;
        observe(Phase::Terminal)?;
        Ok(receipt)
    }

    /// Repair only journals whose exact prepared task source is still retained.
    /// Caller holds the host writer lane during reconciliation.
    pub(crate) fn reconcile_intents(&self) -> Result<Vec<String>> {
        let mut journals = Vec::new();
        for file in std::fs::read_dir(self.intent_journals()?)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: Journal = durable::read_json(&file.path())?;
            if self.intent_journal_path(&journal.request.operation_id)? != file.path()
                || digest(&projection_command_bytes(&journal.request)?) != journal.command_digest
            {
                return Err(HostError::Invalid(
                    "native intent journal command identity changed",
                ));
            }
            journals.push(journal);
        }
        journals.sort_by(|a, b| {
            (
                &a.request.identity.native_intent_id,
                a.request.projection_revision,
            )
                .cmp(&(
                    &b.request.identity.native_intent_id,
                    b.request.projection_revision,
                ))
        });
        let mut uncertain = Vec::new();
        for journal in journals {
            if self
                .project_intent_observed(&journal.request, |_| Ok(()))
                .is_err()
            {
                uncertain.push(journal.request.operation_id);
            }
        }
        let declarations = self.config.config_dir.join("intent-declarations");
        if declarations.symlink_metadata().is_ok() {
            durable::identity(&declarations, true)?;
            for file in std::fs::read_dir(&declarations)? {
                let file = file?;
                if file.file_name().to_string_lossy().starts_with(".pending-") {
                    continue;
                }
                let declaration: TurnJournal = durable::read_json(&file.path())?;
                if self.recover_turn_declaration(&file.path()).is_err() {
                    uncertain.push(declaration.request.operation_id);
                }
            }
        }
        uncertain.extend(self.reconcile_intent_freezes()?);
        Ok(uncertain)
    }

    pub(crate) fn owned_intent_recovery(&self, binding: &StoreBinding) -> Result<bool> {
        for file in std::fs::read_dir(self.intent_journals()?)? {
            let file = file?;
            if file.file_name().to_string_lossy().starts_with(".pending-") {
                continue;
            }
            let journal: Journal = durable::read_json(&file.path())?;
            if journal.request.binding == *binding && journal.phase != Phase::Terminal {
                if self.intent_journal_path(&journal.request.operation_id)? != file.path()
                    || digest(&projection_command_bytes(&journal.request)?)
                        != journal.command_digest
                    || journal.retained_source.sha256 != journal.request.source.sha256
                    || journal.retained_source.length != journal.request.source.length
                    || journal.retained_source.name
                        != format!(
                            "native-task-{}.json",
                            digest(journal.request.operation_id.as_bytes())
                        )
                {
                    return Err(HostError::Invalid(
                        "native intent recovery journal identity changed",
                    ));
                }
                let bytes = spool_bytes(
                    &self.config.spool_dir,
                    &journal.retained_source,
                    SOURCE_LIMIT,
                )?;
                validate_source(&journal.request, &bytes)?;
                return Ok(true);
            }
        }
        let root = self.config.config_dir.join("intent-declarations");
        if root.symlink_metadata().is_ok() {
            durable::identity(&root, true)?;
            for file in std::fs::read_dir(root)? {
                let file = file?;
                if file.file_name().to_string_lossy().starts_with(".pending-") {
                    continue;
                }
                let journal: TurnJournal = durable::read_json(&file.path())?;
                if journal.request.binding != *binding || journal.receipt.is_some() {
                    continue;
                }
                if self.turn_journal_path(&journal.request.operation_id)? != file.path()
                    || digest(&serde_json::to_vec(&journal.request)?) != journal.command_digest
                {
                    return Err(HostError::Invalid(
                        "pending native declaration journal identity changed",
                    ));
                }
                self.original_projection(
                    binding,
                    &journal.request.projection,
                    &journal.request.native_intent_id,
                )?;
                let sessions = binding.store_path.join(".atomic/sessions");
                durable::identity(&sessions, true)?;
                let actual = atomic_agent::turn::SessionStore::new(sessions).map_err(native)?;
                let session = actual
                    .load(&journal.request.session_id)
                    .map_err(native)?
                    .ok_or(HostError::Invalid(
                        "pending native declaration session disappeared",
                    ))?;
                if !session.is_turn_active()
                    || session.is_ended()
                    || session.incomplete().is_some()
                    || session.turn_count.checked_add(1) != Some(journal.request.expected_turn)
                {
                    return Err(HostError::Invalid(
                        "pending native declaration turn changed",
                    ));
                }
                if let Some(declared) = actual
                    .turn_intent_binding(&journal.request.session_id, journal.request.expected_turn)
                    .map_err(native)?
                {
                    if declared.intent_uid != journal.request.native_intent_id {
                        return Err(HostError::Invalid("pending native declaration UID changed"));
                    }
                }
                return Ok(true);
            }
        }
        self.owned_pending_freeze_recovery(binding)
    }

    /// Actual native next-turn declaration, expressly not a frozen record ack.
    /// # Errors
    /// Refuses stale task projection, absent/inactive sessions or changed turn identity.
    pub fn declare_native_turn_intent(
        &self,
        request: &DeclareNativeTurnRequest,
    ) -> Result<NativeTurnDeclaration> {
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        self.binding_path(&request.binding)?;
        self.cached_store(&request.binding)?;
        if !operation_valid(&request.operation_id)
            || !operation_valid(&request.session_id)
            || request.expected_turn == 0
        {
            return Err(HostError::Invalid(
                "native declaration requires exact operation/session/turn identities",
            ));
        }
        let path = self.turn_journal_path(&request.operation_id)?;
        let command_digest = digest(&serde_json::to_vec(request)?);
        if path.symlink_metadata().is_ok() {
            let prior: TurnJournal = durable::read_json(&path)?;
            if prior.request != *request || prior.command_digest != command_digest {
                return Err(HostError::Invalid(
                    "conflicting native turn declaration operation replay",
                ));
            }
        } else {
            durable::write_json(
                &path,
                &TurnJournal {
                    request: request.clone(),
                    command_digest,
                    receipt: None,
                },
                false,
            )?;
        }
        let live = self.begin_live_write()?;
        let result = self.recover_turn_declaration(&path)?;
        live.complete()?;
        Ok(result)
    }

    fn turn_journal_path(&self, operation: &str) -> Result<PathBuf> {
        self.intent_journals()?;
        if !operation_valid(operation) {
            return Err(HostError::Invalid(
                "invalid native declaration operation identity",
            ));
        }
        let root = self.config.config_dir.join("intent-declarations");
        durable::private_dir(&root)?;
        Ok(root.join(format!("{}.json", digest(operation.as_bytes()))))
    }

    fn recover_turn_declaration(&self, path: &Path) -> Result<NativeTurnDeclaration> {
        let mut journal: TurnJournal = durable::read_json(path)?;
        let request = &journal.request;
        if self.turn_journal_path(&request.operation_id)? != path
            || journal.command_digest != digest(&serde_json::to_vec(request)?)
        {
            return Err(HostError::Invalid(
                "native declaration journal identity changed",
            ));
        }
        let project: Journal =
            durable::read_json(&self.intent_journal_path(&request.projection.operation_id)?)?;
        let receipt = project.receipt.ok_or(HostError::Invalid(
            "native task projection receipt is unavailable",
        ))?;
        if project.phase != Phase::Terminal
            || receipt.binding != request.binding
            || receipt.projection != request.projection
            || receipt.identity.native_intent_id != request.native_intent_id
        {
            return Err(HostError::Invalid(
                "native turn declaration source projection differs",
            ));
        }
        let store = self.intent_store(&request.binding)?;
        let sessions = store.repository().dot_dir().join("sessions");
        durable::private_dir(&sessions)?;
        let session_store = atomic_agent::turn::SessionStore::new(&sessions).map_err(native)?;
        let binding = if let Some(binding) = session_store
            .turn_intent_binding(&request.session_id, request.expected_turn)
            .map_err(native)?
        {
            if binding.intent_uid != request.native_intent_id {
                return Err(HostError::Invalid(
                    "native turn already declares another intent",
                ));
            }
            binding
        } else {
            let parent = self.binding_path(&request.binding)?;
            let control = parent.join("intent-control");
            let owner: ControlOwner = durable::read_json(&parent.join("intent-control.json"))?;
            if owner.binding != request.binding
                || owner.directory != durable::identity(&control, true)?
            {
                return Err(HostError::StaleBinding);
            }
            let entry = store
                .repository()
                .vault_retrieve(&receipt.vault_path)
                .map_err(native)?
                .ok_or(HostError::Invalid("native declared intent is unavailable"))?;
            let artifact = control.join(".vault").join(&receipt.vault_path);
            for directory in [
                control.join(".vault"),
                control.join(".vault/intents"),
                artifact
                    .parent()
                    .ok_or(HostError::Invalid("native intent source has no parent"))?
                    .to_path_buf(),
            ] {
                durable::identity(&directory, true)?;
            }
            let bytes = read_bytes(&artifact, ARTIFACT_LIMIT)?;
            if entry_pins(&entry, &bytes)? != request.projection.pins {
                return Err(HostError::Invalid(
                    "native intent changed before turn declaration",
                ));
            }
            session_store
                .bind_turn_intent(
                    &request.session_id,
                    Some(request.expected_turn),
                    &request.native_intent_id,
                )
                .map_err(native)?
        };
        let result = NativeTurnDeclaration {
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            operation_id: request.operation_id.clone(),
            projection: request.projection.clone(),
            session_id: binding.session_id,
            turn: binding.turn_number,
            native_intent_id: binding.intent_uid,
            stage: NativeTurnBindingStage::DeclaredOnly,
        };
        if let Some(retained) = journal.receipt {
            if retained != result {
                return Err(HostError::Invalid(
                    "retained native turn declaration differs from actual native binding",
                ));
            }
        } else {
            journal.receipt = Some(result.clone());
            durable::write_json(path, &journal, true)?;
        }
        Ok(result)
    }
}
