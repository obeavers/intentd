//! Narrow T1 admission and original-run carrier. Wire metadata and the current
//! assignment cannot construct the carrier used by automatic recording.

use std::future::Future;
use std::sync::Arc;

use intent_core::{now_iso, AgentId, AgentStatus, Error, Result, WorkspaceId};

use super::{
    text_prompt, AgentManager, ContentBlock, PersistedStatusTransition, TurnAdmission, TurnOptions,
};
use crate::auto_commit::recording::OriginalRecordSource;

tokio::task_local! {
    static RECORD_SOURCE: Option<Arc<OriginalRecordSource>>;
}

pub(crate) fn capture_recording_source() -> Option<Arc<OriginalRecordSource>> {
    RECORD_SOURCE.try_with(Clone::clone).ok().flatten()
}

pub(crate) fn scope<F: Future>(
    source: Option<Arc<OriginalRecordSource>>,
    future: F,
) -> impl Future<Output = F::Output> {
    RECORD_SOURCE.scope(source, future)
}

impl AgentManager {
    /// Persist status and the original governing source in one transaction,
    /// before a provider may execute. The manager's claim and Store's durable
    /// assignment/status fence both have to remain current.
    pub(super) async fn persist_bound_turn_start(
        &self,
        agent: &AgentId,
        workspace: &WorkspaceId,
        admission: TurnAdmission,
    ) -> Result<()> {
        if !self.owns_admission(agent, admission) {
            return Err(Error::InvalidParams(
                "turn admission was replaced or cancelled".into(),
            ));
        }
        let fence = self
            .services
            .store
            .read_work_turn_fence(workspace, agent)
            .await?;
        let registered = self
            .services
            .store
            .vcs_root_binding(workspace, "primary")
            .await?;
        if registered
            .as_ref()
            .is_some_and(|root| root.kind == intent_core::vcs::VcsKind::Atomic)
        {
            return Err(Error::Forbidden(
                "Atomic roots require a separately qualified execution owner".into(),
            ));
        }
        // Legacy taskless turns retain their existing lifecycle behavior and
        // do not acquire a new repository requirement merely to write Active.
        let root = if fence.requires_work_binding() {
            let source_workspace = self.services.store.get_workspace(workspace).await?;
            if source_workspace.plain_folder {
                None
            } else if let Some(path) = crate::git_ops::worktree_path(&source_workspace) {
                Some(
                    self.services
                        .git_engine_binding(&source_workspace, None, &path)
                        .await?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let baseline = if let Some(root) = root.as_ref() {
            let engine = self.services.git_workspace_engine();
            let source = root.clone();
            Some(
                tokio::task::spawn_blocking(move || engine.recorded_state(&source))
                    .await
                    .map_err(|error| {
                        Error::Internal(format!("turn baseline observation failed: {error}"))
                    })?
                    .map_err(crate::vcs_ops::engine_error)?,
            )
        } else {
            None
        };
        if !self.owns_admission(agent, admission) {
            return Err(Error::InvalidParams(
                "turn admission was replaced or cancelled".into(),
            ));
        }
        let timestamp = now_iso();
        self.services
            .store
            .admit_work_turn(
                &fence,
                &admission.attempt_id.to_string(),
                root.as_ref(),
                baseline.as_ref(),
                &timestamp,
            )
            .await?;
        if !self.owns_admission(agent, admission) {
            self.services
                .store
                .retire_work_turn(workspace, agent, &admission.attempt_id.to_string())
                .await?;
            return Err(Error::InvalidParams(
                "turn admission was replaced or cancelled".into(),
            ));
        }
        self.publish_persisted_status(
            agent,
            workspace,
            PersistedStatusTransition {
                status: AgentStatus::Active,
                is_active: true,
                stop_reason: Some(None),
                turn_boundary: true,
                timestamp,
            },
        )
        .await;
        Ok(())
    }

    /// Reconstruct the prompt only from this exact retained attempt. Later
    /// reassignment or note edits cannot silently change the governing task.
    pub(super) async fn build_bound_turn_prompt(
        &self,
        agent: &AgentId,
        workspace: &WorkspaceId,
        admission: TurnAdmission,
        content: &str,
        options: &TurnOptions,
    ) -> Result<Vec<ContentBlock>> {
        if !self.owns_admission(agent, admission) {
            return Err(Error::InvalidParams(
                "turn admission is no longer owned".into(),
            ));
        }
        let binding = self
            .services
            .store
            .work_turn_binding(workspace, agent, &admission.attempt_id.to_string())
            .await?;
        let definition = match binding {
            Some(binding) if binding.active => {
                let revision = self
                    .services
                    .store
                    .task_revision(&binding.task_revision)
                    .await?
                    .ok_or_else(|| Error::Internal("admitted task revision is missing".into()))?;
                Some(
                    serde_json::to_string(&revision).map_err(|error| {
                        Error::Internal(format!("encode admitted task: {error}"))
                    })?,
                )
            }
            Some(_) => {
                return Err(Error::InvalidParams(
                    "turn work binding is no longer active".into(),
                ))
            }
            None => None,
        };
        let mut prompt = self
            .build_turn_prompt(agent, workspace, content, options)
            .await?;
        if !self.owns_admission(agent, admission) {
            return Err(Error::InvalidParams(
                "turn admission changed during prompt assembly".into(),
            ));
        }
        if let Some(definition) = definition {
            let mut bound = text_prompt(&format!(
                "Admitted task definition\n\nThe retained definition below governs this turn attempt. Its revision and digest are fixed at admission. Later requirement edits require a new admission. Conversation history and later note reads are context; they do not replace this definition. Keep agent claims distinct from observed check results. Completion of this bound task is a human action.\n\n{definition}\n\n"
            ));
            bound.append(&mut prompt);
            prompt = bound;
        }
        Ok(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_manager::SlotClaimLoss;
    use intent_core::{AgentSession, Workspace};

    async fn taskless_manager() -> (
        crate::agent_manager::tests::TempDb,
        AgentManager,
        WorkspaceId,
        AgentId,
    ) {
        let (db, manager) = crate::agent_manager::tests::manager().await;
        let workspace = WorkspaceId::from("t1-taskless-workspace");
        let agent = AgentId::from("t1-taskless-agent");
        let now = now_iso();
        manager
            .services
            .store
            .insert_workspace(&Workspace {
                id: workspace.clone(),
                title: "Legacy taskless workspace".into(),
                // This is deliberately not a Git checkout. A taskless turn must
                // not gain a new source-repository requirement from this port.
                worktree_path: Some("/nonexistent/t1-taskless-checkout".into()),
                created_at: now.clone(),
                updated_at: now.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        manager
            .services
            .store
            .insert_agent_session(&AgentSession {
                id: agent.clone(),
                workspace_id: workspace.clone(),
                name: "Legacy taskless agent".into(),
                status: AgentStatus::Idle,
                is_active: false,
                created_at: now.clone(),
                updated_at: now,
                ..Default::default()
            })
            .await
            .unwrap();
        (db, manager, workspace, agent)
    }

    fn claim(manager: &AgentManager, workspace: &WorkspaceId, agent: &AgentId) -> TurnAdmission {
        match manager.claim_slot_sync(agent, workspace, || Ok::<(), std::convert::Infallible>(())) {
            Ok(((), admission)) => admission,
            Err(SlotClaimLoss::Busy | SlotClaimLoss::ReapClaimed) => {
                panic!("fresh test admission must be available")
            }
            Err(SlotClaimLoss::Refused(never)) => match never {},
        }
    }

    #[tokio::test]
    async fn taskless_admission_preserves_normal_active_transition_without_git() {
        let (_db, manager, workspace, agent) = taskless_manager().await;
        let admission = claim(&manager, &workspace, &agent);
        manager
            .persist_bound_turn_start(&agent, &workspace, admission)
            .await
            .unwrap();
        let session = manager
            .services
            .store
            .get_agent_session_summary(&agent)
            .await
            .unwrap();
        assert_eq!(session.status, AgentStatus::Active);
        assert!(session.is_active);
        assert!(manager
            .services
            .store
            .work_turn_binding(&workspace, &agent, &admission.attempt_id.to_string(),)
            .await
            .unwrap()
            .is_none());
        manager.release_slot_sync(&agent);
    }

    #[tokio::test]
    async fn replaced_manager_claim_cannot_activate_or_admit_its_original_attempt() {
        let (_db, manager, workspace, agent) = taskless_manager().await;
        let original = claim(&manager, &workspace, &agent);
        manager.release_slot_sync(&agent);
        let replacement = claim(&manager, &workspace, &agent);
        assert_ne!(original.attempt_id, replacement.attempt_id);
        assert!(manager
            .persist_bound_turn_start(&agent, &workspace, original)
            .await
            .is_err());
        let session = manager
            .services
            .store
            .get_agent_session_summary(&agent)
            .await
            .unwrap();
        assert_eq!(session.status, AgentStatus::Idle);
        assert!(!session.is_active);
        manager.release_slot_sync(&agent);
    }
}
