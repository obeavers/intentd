//! Durable native `SessionStore` ownership for one fresh authoring turn.
//! Ending this metadata turn never clears provider/callback custody.

use std::path::{Path, PathBuf};

use atomic_agent::turn::{phase::Phase, AgentSession, SessionStore};
use intent_atomic_proto::sessions::{
    BeginNativeSessionRequest, CloseNativeSessionRequest, NativeSessionCloseReceipt,
    NativeSessionReceipt,
};
use intent_atomic_proto::{HostIdentity, StoreBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{durable, Host, HostError, Result};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginJournal {
    request: BeginNativeSessionRequest,
    session: AgentSession,
    receipt: NativeSessionReceipt,
    terminal: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseJournal {
    request: CloseNativeSessionRequest,
    session: AgentSession,
    receipt: NativeSessionCloseReceipt,
    terminal: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    binding: StoreBinding,
    session_id: String,
    begin_operation: String,
    command_digest: String,
    directory: durable::FileIdentity,
    close_operation: Option<String>,
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn native(error: impl std::fmt::Display) -> HostError {
    HostError::Native(error.to_string())
}

impl Host {
    fn session_journal_path(&self, kind: &str, operation: &str) -> Result<PathBuf> {
        if !bounded(operation) {
            return Err(HostError::Invalid(
                "native session needs a bounded operation identity",
            ));
        }
        let root = self
            .config
            .config_dir
            .join(format!("native-session-{kind}"));
        durable::private_dir(&root)?;
        Ok(root.join(format!("{}.json", digest(&operation)?)))
    }

    fn session_directory(&self, binding: &StoreBinding) -> Result<PathBuf> {
        // All production callers hold the host writer lane, including global
        // reconciliation. Reopen only a proven existing store; replay must not
        // depend on an ephemeral OpenStore request from the lost process.
        let proof = self.verify_marker(binding)?;
        let store = {
            let mut stores = self.stores.lock().map_err(|_| HostError::Poisoned)?;
            if let Some(store) = stores.get(&binding.repository_id) {
                store.validate(binding, &proof)?;
                store.clone()
            } else {
                let store = std::sync::Arc::new(crate::native::NativeStore::open(binding, &proof)?);
                stores.insert(binding.repository_id.clone(), store.clone());
                store
            }
        };
        let directory = store.repository().dot_dir().join("sessions");
        durable::private_dir(&directory)?;
        Ok(directory)
    }

    fn session_owner_path(&self, binding: &StoreBinding, id: &str) -> Result<PathBuf> {
        if !session_id(id) {
            return Err(HostError::Invalid("unsafe native session identifier"));
        }
        let root = self.config.config_dir.join("native-session-owners");
        durable::private_dir(&root)?;
        Ok(root.join(format!("{}.json", digest(&(binding, id))?)))
    }

    /// Create an actual fresh native session, journaled before its first save.
    /// # Errors
    /// Refuses foreign sessions, stale bindings and conflicting operation replay.
    pub fn begin_native_session(
        &self,
        request: &BeginNativeSessionRequest,
    ) -> Result<NativeSessionReceipt> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        if !session_id(&request.session_id)
            || ![
                &request.work_binding_id,
                &request.turn_attempt,
                &request.agent_id,
                &request.agent_name,
            ]
            .into_iter()
            .all(|value| bounded(value))
        {
            return Err(HostError::Invalid("native session context is incomplete"));
        }
        let path = self.session_journal_path("begin", &request.operation_id)?;
        let directory = self.session_directory(&request.binding)?;
        if path.symlink_metadata().is_err() {
            let owner_path = self.session_owner_path(&request.binding, &request.session_id)?;
            if owner_path.symlink_metadata().is_ok()
                || directory
                    .join(format!("{}.json", request.session_id))
                    .symlink_metadata()
                    .is_ok()
                || directory
                    .join(&request.session_id)
                    .symlink_metadata()
                    .is_ok()
            {
                return Err(HostError::Invalid(
                    "native session allocation is already owned",
                ));
            }
            let mut session =
                AgentSession::new(&request.session_id, &request.agent_id, &request.agent_name);
            session.explicit_record_files = true;
            session.begin_turn();
            session.phase = Phase::Active;
            let receipt = NativeSessionReceipt {
                host: HostIdentity::default(),
                binding: request.binding.clone(),
                operation_id: request.operation_id.clone(),
                session_id: request.session_id.clone(),
                work_binding_id: request.work_binding_id.clone(),
                turn_attempt: request.turn_attempt.clone(),
                agent_id: request.agent_id.clone(),
                turn: 1,
                command_digest: digest(request)?,
                native_session_sha256: digest(&session)?,
                provider_custody_verified: false,
            };
            durable::write_json(
                &path,
                &BeginJournal {
                    request: request.clone(),
                    session,
                    receipt,
                    terminal: false,
                },
                false,
            )?;
        }
        let journal: BeginJournal = durable::read_json(&path)?;
        if journal.request != *request {
            return Err(HostError::Invalid(
                "conflicting native session begin replay",
            ));
        }
        let live = self.begin_live_write()?;
        let receipt = self.recover_native_session_begin(&path)?;
        live.complete()?;
        Ok(receipt)
    }

    fn recover_native_session_begin(&self, path: &Path) -> Result<NativeSessionReceipt> {
        let mut journal: BeginJournal = durable::read_json(path)?;
        let request = &journal.request;
        if self.session_journal_path("begin", &request.operation_id)? != path
            || !journal.receipt.matches_request(request)
            || journal.receipt.command_digest != digest(request)?
            || journal.receipt.native_session_sha256 != digest(&journal.session)?
            || journal.session.session_id != request.session_id
            || journal.session.agent_name != request.agent_id
            || journal.session.agent_display_name != request.agent_name
            || !journal.session.explicit_record_files
            || !journal.session.is_turn_active()
            || journal.session.turn_count != 0
        {
            return Err(HostError::Invalid("native session begin journal changed"));
        }
        let directory = self.session_directory(&request.binding)?;
        let owner_path = self.session_owner_path(&request.binding, &request.session_id)?;
        let owner = Owner {
            binding: request.binding.clone(),
            session_id: request.session_id.clone(),
            begin_operation: request.operation_id.clone(),
            command_digest: journal.receipt.command_digest.clone(),
            directory: durable::identity(&directory, true)?,
            close_operation: None,
        };
        if owner_path.symlink_metadata().is_ok() {
            let actual: Owner = durable::read_json(&owner_path)?;
            if actual.binding != owner.binding
                || actual.session_id != owner.session_id
                || actual.begin_operation != owner.begin_operation
                || actual.command_digest != owner.command_digest
                || actual.directory != owner.directory
            {
                return Err(HostError::StaleBinding);
            }
            if let Some(close) = actual.close_operation {
                let closed: CloseJournal =
                    durable::read_json(&self.session_journal_path("close", &close)?)?;
                if closed.request.session != journal.receipt {
                    return Err(HostError::StaleBinding);
                }
                return Ok(journal.receipt);
            }
        } else {
            if journal.terminal {
                return Err(HostError::Invalid("native session owner disappeared"));
            }
            durable::write_json(&owner_path, &owner, false)?;
        }
        let actual_path = directory.join(format!("{}.json", request.session_id));
        if actual_path.symlink_metadata().is_ok() {
            let actual: AgentSession = durable::read_json(&actual_path)?;
            if digest(&actual)? != journal.receipt.native_session_sha256 {
                return Err(HostError::StaleBinding);
            }
        } else {
            if journal.terminal {
                return Err(HostError::Invalid("native session data disappeared"));
            }
            SessionStore::new(&directory)
                .map_err(native)?
                .save(&journal.session)
                .map_err(native)?;
        }
        durable::sync_tree(&actual_path)?;
        durable::sync_parent(&actual_path)?;
        if durable::identity(&directory, true)? != owner.directory
            || digest(&durable::read_json::<AgentSession>(&actual_path)?)?
                != journal.receipt.native_session_sha256
        {
            return Err(HostError::StaleBinding);
        }
        journal.terminal = true;
        durable::write_json(path, &journal, true)?;
        Ok(journal.receipt)
    }

    /// End native turn metadata. No physical provider/callback owner is released.
    /// # Errors
    /// Requires the exact retained begin and refuses a changed native session.
    pub fn close_native_session(
        &self,
        request: &CloseNativeSessionRequest,
    ) -> Result<NativeSessionCloseReceipt> {
        let _writer = self.writer.lock().map_err(|_| HostError::Poisoned)?;
        if !*self.recovered.lock().map_err(|_| HostError::Poisoned)? {
            return Err(HostError::RecoveryRequired);
        }
        let begin: BeginJournal = durable::read_json(
            &self.session_journal_path("begin", &request.session.operation_id)?,
        )?;
        if !begin.terminal
            || begin.receipt != request.session
            || !begin.receipt.matches_request(&begin.request)
            || begin.receipt.command_digest != digest(&begin.request)?
        {
            return Err(HostError::Invalid(
                "native session close has no retained begin proof",
            ));
        }
        let path = self.session_journal_path("close", &request.operation_id)?;
        let directory = self.session_directory(&request.session.binding)?;
        let owner: Owner = durable::read_json(
            &self.session_owner_path(&request.session.binding, &request.session.session_id)?,
        )?;
        if owner.binding != request.session.binding
            || owner.session_id != request.session.session_id
            || owner.begin_operation != request.session.operation_id
            || owner.command_digest != request.session.command_digest
            || owner.directory != durable::identity(&directory, true)?
            || owner
                .close_operation
                .as_ref()
                .is_some_and(|operation| operation != &request.operation_id)
        {
            return Err(HostError::StaleBinding);
        }
        if path.symlink_metadata().is_err() {
            if owner.close_operation.is_some() {
                return Err(HostError::Invalid(
                    "native session close journal disappeared",
                ));
            }
            let actual: AgentSession = durable::read_json(
                &directory.join(format!("{}.json", request.session.session_id)),
            )?;
            if digest(&actual)? != request.session.native_session_sha256 {
                return Err(HostError::StaleBinding);
            }
            let mut session = begin.session;
            if session.end_turn() != request.session.turn {
                return Err(HostError::Invalid("native session turn counter changed"));
            }
            // Phase::Ended would assert process exit. Closing a metadata turn
            // establishes only Idle; runtime custody remains independently owned.
            session.phase = Phase::Idle;
            let receipt = NativeSessionCloseReceipt {
                host: HostIdentity::default(),
                binding: request.session.binding.clone(),
                operation_id: request.operation_id.clone(),
                session_id: request.session.session_id.clone(),
                begin_operation_id: request.session.operation_id.clone(),
                turn: request.session.turn,
                command_digest: digest(request)?,
                native_session_sha256: digest(&session)?,
                provider_custody_verified: false,
            };
            durable::write_json(
                &path,
                &CloseJournal {
                    request: request.clone(),
                    session,
                    receipt,
                    terminal: false,
                },
                false,
            )?;
        }
        let journal: CloseJournal = durable::read_json(&path)?;
        if journal.request != *request {
            return Err(HostError::Invalid(
                "conflicting native session close replay",
            ));
        }
        let live = self.begin_live_write()?;
        let receipt = self.recover_native_session_close(&path)?;
        live.complete()?;
        Ok(receipt)
    }

    fn recover_native_session_close(&self, path: &Path) -> Result<NativeSessionCloseReceipt> {
        let mut journal: CloseJournal = durable::read_json(path)?;
        let request = &journal.request;
        if self.session_journal_path("close", &request.operation_id)? != path
            || !journal.receipt.matches_request(request)
            || journal.receipt.command_digest != digest(request)?
            || journal.receipt.native_session_sha256 != digest(&journal.session)?
            || journal.session.phase != Phase::Idle
            || journal.session.turn_count != 1
        {
            return Err(HostError::Invalid("native session close journal changed"));
        }
        let begin: BeginJournal = durable::read_json(
            &self.session_journal_path("begin", &request.session.operation_id)?,
        )?;
        if !begin.terminal || begin.receipt != request.session {
            return Err(HostError::StaleBinding);
        }
        let mut expected = begin.session;
        if expected.end_turn() != request.session.turn {
            return Err(HostError::Invalid(
                "native close does not own the original turn",
            ));
        }
        expected.phase = Phase::Idle;
        if journal.session.session_id != request.session.session_id
            || digest(&journal.session)? != digest(&expected)?
        {
            return Err(HostError::Invalid(
                "native close post-state differs from its retained begin",
            ));
        }
        let directory = self.session_directory(&request.session.binding)?;
        let owner_path =
            self.session_owner_path(&request.session.binding, &request.session.session_id)?;
        let mut owner: Owner = durable::read_json(&owner_path)?;
        if owner.binding != request.session.binding
            || owner.session_id != request.session.session_id
            || owner.begin_operation != request.session.operation_id
            || owner.command_digest != request.session.command_digest
            || owner.directory != durable::identity(&directory, true)?
            || owner
                .close_operation
                .as_ref()
                .is_some_and(|operation| operation != &request.operation_id)
        {
            return Err(HostError::StaleBinding);
        }
        owner.close_operation = Some(request.operation_id.clone());
        durable::write_json(&owner_path, &owner, true)?;
        let actual_path = directory.join(format!("{}.json", request.session.session_id));
        let actual: AgentSession = durable::read_json(&actual_path)?;
        let actual_digest = digest(&actual)?;
        if actual_digest != journal.receipt.native_session_sha256 {
            if journal.terminal || actual_digest != request.session.native_session_sha256 {
                return Err(HostError::StaleBinding);
            }
            SessionStore::new(&directory)
                .map_err(native)?
                .save(&journal.session)
                .map_err(native)?;
        }
        durable::sync_tree(&actual_path)?;
        durable::sync_parent(&actual_path)?;
        if durable::identity(&directory, true)? != owner.directory
            || digest(&durable::read_json::<AgentSession>(&actual_path)?)?
                != journal.receipt.native_session_sha256
        {
            return Err(HostError::StaleBinding);
        }
        journal.terminal = true;
        durable::write_json(path, &journal, true)?;
        Ok(journal.receipt)
    }

    /// Called under the host writer lock by global reconciliation.
    pub(crate) fn reconcile_native_sessions(&self) -> Result<()> {
        for kind in ["begin", "close"] {
            let directory = self
                .config
                .config_dir
                .join(format!("native-session-{kind}"));
            if directory.symlink_metadata().is_err() {
                continue;
            }
            durable::identity(&directory, true)?;
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                if entry.file_name().to_string_lossy().starts_with(".pending-") {
                    continue;
                }
                if kind == "begin" {
                    self.recover_native_session_begin(&entry.path())?;
                } else {
                    self.recover_native_session_close(&entry.path())?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostConfig;
    use intent_atomic_proto::intents::{DeclareNativeTurnRequest, FreezeNativeTurnRequest};

    fn request(binding: StoreBinding, suffix: &str) -> BeginNativeSessionRequest {
        BeginNativeSessionRequest {
            operation_id: format!("begin-{suffix}"),
            binding,
            session_id: format!("native-{suffix}"),
            work_binding_id: format!("binding-{suffix}"),
            turn_attempt: format!("attempt-{suffix}"),
            agent_id: "logical-agent".into(),
            agent_name: "Original agent".into(),
        }
    }

    fn config(host: &Host) -> HostConfig {
        HostConfig {
            stores_dir: host.config.stores_dir.clone(),
            config_dir: host.config.config_dir.clone(),
            spool_dir: host.config.spool_dir.clone(),
        }
    }

    fn actual(host: &Host, receipt: &NativeSessionReceipt) -> AgentSession {
        durable::read_json(
            &host
                .session_directory(&receipt.binding)
                .unwrap()
                .join(format!("{}.json", receipt.session_id)),
        )
        .unwrap()
    }

    #[test]
    fn actual_native_session_can_declare_and_freeze_then_close_only_metadata() {
        let (_directory, host, projection_request) = crate::intents::tests::fixture();
        let projection = host.project_task_intent(&projection_request).unwrap();
        let begin = request(projection_request.binding, "original-turn");
        let receipt = host.begin_native_session(&begin).unwrap();
        assert!(receipt.matches_request(&begin));
        assert!(!receipt.provider_custody_verified);
        assert!(actual(&host, &receipt).is_turn_active());
        host.declare_native_turn_intent(&DeclareNativeTurnRequest {
            operation_id: "declare-actual-session".into(),
            binding: receipt.binding.clone(),
            projection: projection.projection.clone(),
            native_intent_id: projection.identity.native_intent_id.clone(),
            session_id: receipt.session_id.clone(),
            expected_turn: receipt.turn,
        })
        .unwrap();
        let frozen = host
            .freeze_native_turn_for_record(&FreezeNativeTurnRequest {
                operation_id: "record-actual-session".into(),
                work_binding_id: receipt.work_binding_id.clone(),
                binding: receipt.binding.clone(),
                projection: projection.projection,
                native_intent_id: projection.identity.native_intent_id,
                session_id: receipt.session_id.clone(),
                expected_turn: receipt.turn,
            })
            .unwrap();
        assert_eq!(frozen.session_id, receipt.session_id);
        let close = CloseNativeSessionRequest {
            operation_id: "close-actual-session".into(),
            session: receipt.clone(),
        };
        let closed = host.close_native_session(&close).unwrap();
        assert!(closed.matches_request(&close));
        assert!(!closed.provider_custody_verified);
        let stored = actual(&host, &receipt);
        assert_eq!(stored.phase, Phase::Idle);
        assert_eq!(stored.turn_count, 1);
        assert!(
            !stored.is_ended(),
            "native metadata must not assert a process exited"
        );
        assert_eq!(host.close_native_session(&close).unwrap(), closed);
        let other = CloseNativeSessionRequest {
            operation_id: "different-close".into(),
            ..close
        };
        assert!(host.close_native_session(&other).is_err());
        assert!(
            host.reconcile().unwrap().ready,
            "a refused close must not poison recovery"
        );
    }

    #[test]
    fn session_allocation_and_original_context_cannot_be_rebound_on_replay() {
        let (_directory, host, projection) = crate::intents::tests::fixture();
        let original = request(projection.binding, "bound");
        let receipt = host.begin_native_session(&original).unwrap();
        assert_eq!(host.begin_native_session(&original).unwrap(), receipt);
        let changed = BeginNativeSessionRequest {
            turn_attempt: "other-attempt".into(),
            ..original.clone()
        };
        assert!(host.begin_native_session(&changed).is_err());
        let stolen = BeginNativeSessionRequest {
            operation_id: "different-begin".into(),
            ..original.clone()
        };
        assert!(host.begin_native_session(&stolen).is_err());
        let second = request(original.binding, "second-turn");
        let fresh = host.begin_native_session(&second).unwrap();
        assert_ne!(fresh.session_id, receipt.session_id);
        assert_eq!(fresh.agent_id, receipt.agent_id);
        assert!(host.reconcile().unwrap().ready);
    }

    #[test]
    fn retained_pending_birth_and_close_recover_exactly_after_restart() {
        let (_directory, host, projection) = crate::intents::tests::fixture();
        let begin = request(projection.binding, "recover");
        let receipt = host.begin_native_session(&begin).unwrap();
        let path = host
            .session_journal_path("begin", &begin.operation_id)
            .unwrap();
        let mut journal: BeginJournal = durable::read_json(&path).unwrap();
        journal.terminal = false;
        durable::write_json(&path, &journal, true).unwrap();
        std::fs::remove_file(
            host.session_directory(&receipt.binding)
                .unwrap()
                .join(format!("{}.json", receipt.session_id)),
        )
        .unwrap();
        let saved = config(&host);
        drop(host);
        let host = Host::new(saved).unwrap();
        assert!(host.reconcile().unwrap().ready);
        assert_eq!(host.begin_native_session(&begin).unwrap(), receipt);
        let close = CloseNativeSessionRequest {
            operation_id: "recover-close".into(),
            session: receipt,
        };
        let closed = host.close_native_session(&close).unwrap();
        let path = host
            .session_journal_path("close", &close.operation_id)
            .unwrap();
        let mut journal: CloseJournal = durable::read_json(&path).unwrap();
        journal.terminal = false;
        durable::write_json(&path, &journal, true).unwrap();
        let saved = config(&host);
        drop(host);
        let host = Host::new(saved).unwrap();
        assert!(host.reconcile().unwrap().ready);
        assert_eq!(host.close_native_session(&close).unwrap(), closed);
        assert_eq!(actual(&host, &close.session).turn_count, 1);
    }

    #[test]
    fn coherently_changed_close_journal_cannot_overwrite_another_native_session() {
        let (_directory, host, projection) = crate::intents::tests::fixture();
        let original = host
            .begin_native_session(&request(projection.binding.clone(), "original"))
            .unwrap();
        let foreign = host
            .begin_native_session(&request(projection.binding, "foreign"))
            .unwrap();
        let original_before = digest(&actual(&host, &original)).unwrap();
        let foreign_before = digest(&actual(&host, &foreign)).unwrap();
        let close = CloseNativeSessionRequest {
            operation_id: "coherent-tamper".into(),
            session: original.clone(),
        };
        let mut session = actual(&host, &foreign);
        session.end_turn();
        session.phase = Phase::Idle;
        let receipt = NativeSessionCloseReceipt {
            host: HostIdentity::default(),
            binding: original.binding.clone(),
            operation_id: close.operation_id.clone(),
            session_id: original.session_id.clone(),
            begin_operation_id: original.operation_id.clone(),
            turn: 1,
            command_digest: digest(&close).unwrap(),
            native_session_sha256: digest(&session).unwrap(),
            provider_custody_verified: false,
        };
        let path = host
            .session_journal_path("close", &close.operation_id)
            .unwrap();
        durable::write_json(
            &path,
            &CloseJournal {
                request: close.clone(),
                session,
                receipt,
                terminal: false,
            },
            false,
        )
        .unwrap();
        assert!(host.close_native_session(&close).is_err());
        assert_eq!(digest(&actual(&host, &original)).unwrap(), original_before);
        assert_eq!(digest(&actual(&host, &foreign)).unwrap(), foreign_before);
        let owner: Owner = durable::read_json(
            &host
                .session_owner_path(&original.binding, &original.session_id)
                .unwrap(),
        )
        .unwrap();
        assert!(owner.close_operation.is_none());
    }
}
