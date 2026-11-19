//! Construction seam only; native mechanics remain explicitly unavailable.

use std::sync::Arc;

use intent_core::vcs::{VcsCapabilities, VcsKind, WorkspaceEngine};

use crate::HostSupervisor;

pub struct AtomicWorkspaceEngine {
    host: Arc<HostSupervisor>,
}

impl AtomicWorkspaceEngine {
    #[must_use]
    pub fn new(host: Arc<HostSupervisor>) -> Self {
        Self { host }
    }

    #[must_use]
    pub fn host(&self) -> &Arc<HostSupervisor> {
        &self.host
    }
}

impl WorkspaceEngine for AtomicWorkspaceEngine {
    fn kind(&self) -> VcsKind {
        VcsKind::Atomic
    }

    fn capabilities(&self) -> VcsCapabilities {
        VcsCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostLaunchConfig;
    use intent_core::vcs::{RepositoryId, RootBinding, VcsError};

    #[test]
    fn construction_does_not_advertise_unqualified_native_mechanics() {
        let config = HostLaunchConfig::new(
            "/unconfigured/intent-atomic-host".into(),
            "/uncreated/daemon".into(),
            "/uncreated/stores".into(),
        );
        let engine = AtomicWorkspaceEngine::new(Arc::new(HostSupervisor::new(config).unwrap()));
        assert_eq!(engine.kind(), VcsKind::Atomic);
        assert_eq!(engine.capabilities(), VcsCapabilities::default());
        let root = RootBinding {
            workspace_id: "workspace".into(),
            root_id: "root".into(),
            repository_id: RepositoryId::from_string("repository"),
            kind: VcsKind::Atomic,
            locator: "/uncreated/workspace".into(),
            epoch: 1,
        };
        assert!(matches!(
            engine.status(&root),
            Err(VcsError::Unsupported {
                kind: VcsKind::Atomic,
                ..
            })
        ));
    }
}
