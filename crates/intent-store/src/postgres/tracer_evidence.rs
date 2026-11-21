//! Tenant-scoped transaction adapter for T1 retained task/source evidence.
use super::{PgStore, WriteTx};
use crate::tracer_evidence::{database, AgentState, EvidenceTx, SourceNote};
use crate::NoteWriteLock;
use intent_core::{AgentId, AgentSession, Note, NoteId, Result, WorkspaceId};
use sqlx::{PgConnection, Row};

enum Connection {
    Read(sqlx::Transaction<'static, sqlx::Postgres>),
    Write(WriteTx),
}
pub(crate) struct PgEvidenceTx<'a> {
    store: &'a PgStore,
    connection: Connection,
}
impl<'a> PgEvidenceTx<'a> {
    pub(crate) async fn begin(store: &'a PgStore, write: bool) -> Result<Self> {
        let connection = if write {
            Connection::Write(store.begin_write().await?)
        } else {
            Connection::Read(store.begin_read_snapshot().await?)
        };
        Ok(Self { store, connection })
    }
    fn conn(&mut self) -> &mut PgConnection {
        match &mut self.connection {
            Connection::Read(tx) => tx,
            Connection::Write(tx) => tx,
        }
    }
    fn writer(&mut self) -> Result<&mut WriteTx> {
        match &mut self.connection {
            Connection::Write(tx) => Ok(tx),
            Connection::Read(_) => Err(database("T1 mutation requires a locked write transaction")),
        }
    }
    pub(crate) async fn finish<T>(self, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => {
                match self.connection {
                    Connection::Read(tx) => tx.commit().await,
                    Connection::Write(tx) => tx.commit().await,
                }
                .map_err(database)?;
                Ok(value)
            }
            Err(error) => {
                drop(self.connection);
                Err(error)
            }
        }
    }
}
impl EvidenceTx for PgEvidenceTx<'_> {
    async fn admission_count(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        limit: u32,
    ) -> Result<i64> {
        let tenant = self.store.tenant().to_owned();
        sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT 1 FROM work_t1_evidence WHERE tenant_id=$1 AND record_kind='admission' AND owner_id=$2 AND workspace_id=$3 LIMIT $4) AS bounded_admissions")
            .bind(tenant).bind(agent.as_str()).bind(workspace.as_str()).bind(i64::from(limit)).fetch_one(self.conn()).await.map_err(database)
    }
    async fn contributions(
        &mut self,
        workspace: &WorkspaceId,
        owner: &intent_core::vcs::OperationId,
        limit: u32,
    ) -> Result<Vec<String>> {
        let tenant = self.store.tenant().to_owned();
        sqlx::query_scalar("SELECT payload_json FROM work_t1_evidence WHERE tenant_id=$1 AND record_kind='contribution' AND owner_id=$2 AND workspace_id=$3 ORDER BY record_sequence LIMIT $4")
            .bind(tenant).bind(owner.as_str()).bind(workspace.as_str()).bind(i64::from(limit)).fetch_all(self.conn()).await.map_err(database)
    }
    async fn root_epoch(&mut self, workspace: &WorkspaceId, root: &str) -> Result<Option<u64>> {
        let tenant = self.store.tenant().to_owned();
        let (kind, id) = if root == "primary" {
            ("primary", "")
        } else {
            ("registered", root)
        };
        let epoch: Option<i64> = sqlx::query_scalar("SELECT root_incarnation FROM repository_selection_state WHERE tenant_id=$1 AND workspace_id=$2 AND root_kind=$3 AND root_id=$4 AND root_present=1")
            .bind(tenant).bind(workspace.as_str()).bind(kind).bind(id).fetch_optional(self.conn()).await.map_err(database)?;
        epoch
            .map(|epoch| u64::try_from(epoch).map_err(database))
            .transpose()
    }
    async fn object(&mut self, kind: &str, key: &str) -> Result<Option<(i64, String)>> {
        let tenant = self.store.tenant().to_owned();
        sqlx::query_as("SELECT record_sequence,payload_json FROM work_t1_evidence WHERE tenant_id=$1 AND record_kind=$2 AND record_key=$3")
            .bind(tenant).bind(kind).bind(key).fetch_optional(self.conn()).await.map_err(database)
    }
    async fn insert(&mut self, kind: &str, key: &str, raw: &str) -> Result<i64> {
        let tenant = self.store.tenant().to_owned();
        insert_on(self.writer()?, &tenant, kind, key, raw).await
    }
    async fn active(
        &mut self,
        agent: &AgentId,
        binding: Option<&intent_core::vcs::OperationId>,
    ) -> Result<()> {
        let tenant = self.store.tenant().to_owned();
        active_on(self.writer()?, &tenant, agent, binding).await
    }
    async fn note(&mut self, workspace: &WorkspaceId, note: &NoteId) -> Result<Option<SourceNote>> {
        let tenant = self.store.tenant().to_owned();
        let row = sqlx::query("SELECT rev,title,content,content_type,task_json FROM note WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3")
            .bind(tenant).bind(workspace.as_str()).bind(note.as_str()).fetch_optional(self.conn()).await.map_err(database)?;
        row.map(|r| {
            Ok(SourceNote {
                rev: r.try_get("rev").map_err(database)?,
                title: r.try_get("title").map_err(database)?,
                content: r.try_get("content").map_err(database)?,
                content_type: r.try_get("content_type").map_err(database)?,
                task_json: r.try_get("task_json").map_err(database)?,
            })
        })
        .transpose()
    }
    async fn locator(&mut self, workspace: &WorkspaceId, root: &str) -> Result<Option<String>> {
        let tenant = self.store.tenant().to_owned();
        let row = sqlx::query("SELECT worktree_path,repository_path,status,is_remote FROM workspace WHERE tenant_id=$1 AND id=$2")
            .bind(&tenant).bind(workspace.as_str()).fetch_optional(self.conn()).await.map_err(database)?;
        let Some(row) = row else { return Ok(None) };
        let status: String = row.try_get("status").map_err(database)?;
        if matches!(
            crate::enum_from_db::<intent_core::WorkspaceStatus>(&status)?,
            intent_core::WorkspaceStatus::Deleted | intent_core::WorkspaceStatus::Retired
        ) || row.try_get::<i64, _>("is_remote").map_err(database)? != 0
        {
            return Ok(None);
        }
        if root == "primary" {
            Ok(row
                .try_get::<Option<String>, _>("worktree_path")
                .map_err(database)?
                .or(row.try_get("repository_path").map_err(database)?))
        } else {
            sqlx::query_scalar("SELECT path FROM workspace_git_root WHERE tenant_id=$1 AND workspace_id=$2 AND id=$3")
                .bind(tenant).bind(workspace.as_str()).bind(root).fetch_optional(self.conn()).await.map_err(database)
        }
    }
    async fn agent(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
    ) -> Result<Option<AgentState>> {
        let tenant = self.store.tenant().to_owned();
        let row = sqlx::query("SELECT a.task_note_id,a.status,a.retired_at,w.status AS workspace_status,f.revision,f.assignment_revision FROM agent_session a JOIN workspace w ON w.tenant_id=$1 AND w.id=a.workspace_id JOIN work_t1_agent_fence f ON f.tenant_id=$1 AND f.agent_id=a.id AND f.workspace_id=a.workspace_id WHERE a.tenant_id=$1 AND a.workspace_id=$2 AND a.id=$3")
            .bind(tenant).bind(workspace.as_str()).bind(agent.as_str()).fetch_optional(self.conn()).await.map_err(database)?;
        row.map(|r| {
            Ok(AgentState {
                task_note_id: r.try_get("task_note_id").map_err(database)?,
                status: r.try_get("status").map_err(database)?,
                retired_at: r.try_get("retired_at").map_err(database)?,
                workspace_status: r.try_get("workspace_status").map_err(database)?,
                revision: r.try_get("revision").map_err(database)?,
                assignment_revision: r.try_get("assignment_revision").map_err(database)?,
            })
        })
        .transpose()
    }
    async fn activate(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        timestamp: &str,
    ) -> Result<()> {
        let tenant = self.store.tenant().to_owned();
        activate_on(self.writer()?, &tenant, workspace, agent, timestamp).await
    }
    async fn write_note(
        &mut self,
        lock: &NoteWriteLock,
        note: &Note,
        expected: i64,
    ) -> Result<i64> {
        lock.ensure_covers(&self.store.note_write_lanes, note)?;
        let Connection::Write(tx) = &mut self.connection else {
            return Err(database("note mutation requires owning write transaction"));
        };
        super::notes::exec_update_note(
            self.store,
            tx,
            note,
            Some(expected),
            crate::note_repo::NoteUpdateScope::Metadata,
            None,
        )
        .await?
        .ok_or_else(|| {
            crate::tracer_evidence::invalid("task changed before reviewed definition persisted")
        })
    }
    async fn insert_agent(
        &mut self,
        session: &AgentSession,
        graph: bool,
        remember: bool,
    ) -> Result<()> {
        let Connection::Write(tx) = &mut self.connection else {
            return Err(database("allocation requires owning write transaction"));
        };
        self.store
            .insert_session_row(tx, session, graph)
            .await?
            .map_err(database)?;
        if remember {
            self.store.remember_specialist(tx, session).await?;
        }
        Ok(())
    }
}

async fn insert_on(
    tx: &mut WriteTx,
    tenant: &str,
    kind: &str,
    key: &str,
    raw: &str,
) -> Result<i64> {
    sqlx::query_scalar("INSERT INTO work_t1_evidence(tenant_id,record_kind,record_key,payload_json,created_at) VALUES($1,$2,$3,$4,$5) RETURNING record_sequence")
        .bind(tenant).bind(kind).bind(key).bind(raw).bind(intent_core::now_iso())
        .fetch_one(&mut **tx).await.map_err(database)
}
async fn active_on(
    tx: &mut WriteTx,
    tenant: &str,
    agent: &AgentId,
    binding: Option<&intent_core::vcs::OperationId>,
) -> Result<()> {
    sqlx::query("INSERT INTO work_t1_evidence(tenant_id,record_kind,record_key,payload_json,created_at) VALUES($1,'active-binding',$2,$3,$4) ON CONFLICT(tenant_id,record_kind,record_key) DO UPDATE SET payload_json=excluded.payload_json")
        .bind(tenant).bind(agent.as_str()).bind(serde_json::to_string(&binding).map_err(database)?).bind(intent_core::now_iso())
        .execute(&mut **tx).await.map_err(database)?;
    Ok(())
}
async fn activate_on(
    tx: &mut WriteTx,
    tenant: &str,
    workspace: &WorkspaceId,
    agent: &AgentId,
    timestamp: &str,
) -> Result<()> {
    sqlx::query("UPDATE agent_session SET status=$1,is_active=1,updated_at=$2,stop_reason=NULL,stop_reason_timestamp=NULL WHERE tenant_id=$3 AND workspace_id=$4 AND id=$5")
        .bind(crate::enum_to_db(&intent_core::AgentStatus::Active)?).bind(timestamp).bind(tenant).bind(workspace.as_str()).bind(agent.as_str())
        .execute(&mut **tx).await.map_err(database)?;
    Ok(())
}
