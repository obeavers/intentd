//! Persisted engine selection for authorized, existing workspace roots.
//!
//! Callers resolve membership and their root selector before reaching this
//! module. A filesystem path never creates repository authority or selects an
//! engine. Legacy roots enroll with a random, retained repository identity.

use std::path::Path;

use intent_core::vcs::{RootBinding, VcsKind};
use intent_core::{Error, Result, Workspace, WorkspaceGitRootId};

use crate::Services;

impl Services {
    /// Resolve a Git operation's persisted root binding before scheduling its
    /// blocking mechanics. Secondary roots must belong to this workspace.
    pub(crate) async fn git_engine_binding(
        &self,
        workspace: &Workspace,
        git_root_id: Option<&WorkspaceGitRootId>,
        path: &Path,
    ) -> Result<RootBinding> {
        if workspace.plain_folder {
            return Err(Error::Unsupported(
                "Git repository operations are unavailable in a plain-folder workspace".into(),
            ));
        }
        let root_id = if let Some(id) = git_root_id {
            let root = self.store.get_workspace_git_root(id).await?;
            if root.workspace_id != workspace.id {
                return Err(Error::Forbidden(
                    "Git root does not belong to this workspace".into(),
                ));
            }
            if Path::new(&root.path) != path {
                return Err(Error::InvalidParams(
                    "Repository root locator changed before engine admission".into(),
                ));
            }
            id.0.as_str()
        } else {
            let expected = crate::git_ops::worktree_path(workspace)
                .ok_or_else(|| Error::NotFound("Workspace has no Git working copy".into()))?;
            if expected != path {
                return Err(Error::InvalidParams(
                    "Workspace working-copy locator changed before engine admission".into(),
                ));
            }
            "primary"
        };

        // Existing Git records carry no stable forge repository identifier.
        // Enroll a scoped UUID instead of guessing a shared identity from the
        // path or a display slug. Replays reuse the persisted binding.
        self.store
            .ensure_vcs_root_binding(&workspace.id, root_id, None, path, VcsKind::Git, 1)
            .await
    }
}
