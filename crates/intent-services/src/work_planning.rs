//! Prepared explicit task requirements. Agent suggestions remain ordinary
//! proposals until an actual authenticated human edits the governing source.

use intent_core::work_evidence::planning::{TaskConfigureWorkDefinitionResult, TaskWorkDefinition};
use intent_core::{
    current_caller, now_iso, Caller, Error, Note, NoteId, Result, TaskStatus, WorkspaceId,
};

use crate::{publish_event, Services};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

fn source_text_digest(text: &str) -> intent_core::vcs::ContentDigest {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(text.as_bytes()) {
        write!(&mut hex, "{byte:02x}").expect("writing a digest into a string");
    }
    intent_core::vcs::ContentDigest(hex)
}

impl Services {
    /// Update declared work requirements under the existing note CAS/lock.
    /// No native scope, grant, execution, criterion result or task completion is
    /// inferred. The public planning RPC additionally writes exact criteria.
    /// # Errors
    /// Refuses nonhuman callers, unavailable membership, completed/non-task
    /// notes, stale revisions and requirements detached from exact source text.
    #[doc(hidden)]
    pub async fn configure_task_work_definition(
        &self,
        workspace: &WorkspaceId,
        note_id: &NoteId,
        expected_rev: i64,
        definition: Option<TaskWorkDefinition>,
    ) -> Result<Note> {
        if !matches!(current_caller(), Some(Caller::Wire { .. })) {
            return Err(Error::Forbidden(
                "Governing task requirements need the actual authenticated human caller.".into(),
            ));
        }
        let criteria = self
            .store
            .get_note(workspace, note_id)
            .await?
            .metadata
            .task
            .ok_or_else(|| Error::InvalidParams("The governing note is not a task.".into()))?
            .acceptance_criteria;
        self.configure_task_work_definition_complete(
            workspace,
            note_id,
            expected_rev,
            criteria,
            definition,
        )
        .await
        .map(|result| result.note)
    }

    /// Persist the exact reviewed draft in one note/revision transaction. Agent
    /// proposals and client-provided digests never become governing source pins.
    /// # Errors
    /// Refuses nonhuman callers, unavailable membership, completed tasks, stale
    /// note versions and invalid requirements without any partial note write.
    pub async fn configure_task_work_definition_complete(
        &self,
        workspace: &WorkspaceId,
        note_id: &NoteId,
        expected_rev: i64,
        acceptance_criteria: Vec<String>,
        mut definition: Option<TaskWorkDefinition>,
    ) -> Result<TaskConfigureWorkDefinitionResult> {
        let _mutation = self.workspace_mutations.enter(workspace)?;
        if !matches!(current_caller(), Some(Caller::Wire { .. })) {
            return Err(Error::Forbidden(
                "Governing task requirements need the actual authenticated human caller.".into(),
            ));
        }
        self.require_member(workspace).await?;
        let lock = self.lock_note_content(workspace, note_id).await;
        let mut note = self.store.get_note(workspace, note_id).await?;
        if note.rev != expected_rev {
            return Err(Error::Conflict {
                current: serde_json::to_value(note)
                    .map_err(|error| Error::Internal(error.to_string()))?,
            });
        }
        let task = note
            .metadata
            .task
            .as_mut()
            .ok_or_else(|| Error::InvalidParams("The governing note is not a task.".into()))?;
        if matches!(task.status, TaskStatus::Complete | TaskStatus::Cancelled) {
            return Err(Error::Forbidden(
                "Reopen the task before changing its governing requirements.".into(),
            ));
        }
        if acceptance_criteria.len() > 256
            || acceptance_criteria.iter().map(String::len).sum::<usize>() > 256 * 1024
            || acceptance_criteria
                .iter()
                .any(|text| text.trim().is_empty() || text.len() > 16 * 1024)
        {
            return Err(Error::InvalidParams(
                "Acceptance criteria must be bounded nonempty source strings.".into(),
            ));
        }
        if let Some(definition) = &mut definition {
            for criterion in &mut definition.criteria {
                let text = usize::try_from(criterion.index)
                    .ok()
                    .and_then(|index| acceptance_criteria.get(index))
                    .ok_or_else(|| {
                        Error::InvalidParams(
                            "A criterion requirement has no corresponding source text.".into(),
                        )
                    })?;
                criterion.text_digest = source_text_digest(text);
            }
        }
        task.acceptance_criteria = acceptance_criteria;
        task.work_definition = definition;
        note.updated_at = now_iso();
        let revision = self
            .store
            .persist_task_work_definition(&lock, &note, expected_rev)
            .await?;
        note.rev = revision.reference.rev;
        drop(lock);
        publish_event(
            self.event_bus.as_ref(),
            crate::note_change_event(
                workspace,
                note_id,
                &note.title,
                intent_core::events::NOTE_UPDATED,
                "update",
            ),
        )
        .await;
        Ok(TaskConfigureWorkDefinitionResult {
            note,
            task_revision: revision.reference,
        })
    }
}

#[cfg(test)]
mod tests;
