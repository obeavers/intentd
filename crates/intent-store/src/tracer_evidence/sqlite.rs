//! `SQLite` transaction adapter for the small T1 evidence ledger.
use intent_core::{AgentId, AgentSession, Note, NoteId, Result, WorkspaceId};
use sqlx::{Row, SqliteConnection};

use super::{database, AgentState, EvidenceTx, SourceNote};
use crate::{note_write_connection::NoteWriteConnection, NoteWriteLock, SqliteStore};

enum Connection {
    Read(sqlx::Transaction<'static, sqlx::Sqlite>),
    Write(NoteWriteConnection),
}

pub(super) struct SqliteEvidenceTx<'a> {
    store: &'a SqliteStore,
    connection: Connection,
}
impl<'a> SqliteEvidenceTx<'a> {
    pub(super) async fn begin(store: &'a SqliteStore, write: bool) -> Result<Self> {
        let connection = if write {
            Connection::Write(NoteWriteConnection::begin(store).await?)
        } else {
            Connection::Read(store.read_pool().begin().await.map_err(database)?)
        };
        Ok(Self { store, connection })
    }
    fn conn(&mut self) -> &mut SqliteConnection {
        match &mut self.connection {
            Connection::Read(tx) => tx,
            Connection::Write(tx) => tx,
        }
    }
    pub(super) async fn finish<T>(self, result: Result<T>) -> Result<T> {
        match self.connection {
            Connection::Write(tx) => tx.finish(result, "commit T1 evidence").await,
            Connection::Read(tx) => match result {
                Ok(value) => {
                    tx.commit().await.map_err(database)?;
                    Ok(value)
                }
                Err(error) => {
                    tx.rollback().await.map_err(database)?;
                    Err(error)
                }
            },
        }
    }
}

impl EvidenceTx for SqliteEvidenceTx<'_> {
    async fn admission_count(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
        limit: u32,
    ) -> Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM (SELECT 1 FROM work_t1_evidence WHERE record_kind='admission' AND owner_id=? AND workspace_id=? LIMIT ?)")
            .bind(agent.as_str()).bind(workspace.as_str()).bind(i64::from(limit)).fetch_one(self.conn()).await.map_err(database)
    }
    async fn contributions(
        &mut self,
        workspace: &WorkspaceId,
        owner: &intent_core::vcs::OperationId,
        limit: u32,
    ) -> Result<Vec<String>> {
        sqlx::query_scalar("SELECT payload_json FROM work_t1_evidence WHERE record_kind='contribution' AND owner_id=? AND workspace_id=? ORDER BY record_sequence LIMIT ?")
            .bind(owner.as_str()).bind(workspace.as_str()).bind(i64::from(limit)).fetch_all(self.conn()).await.map_err(database)
    }
    async fn root_epoch(&mut self, workspace: &WorkspaceId, root: &str) -> Result<Option<u64>> {
        let (kind, id) = if root == "primary" {
            ("primary", "")
        } else {
            ("registered", root)
        };
        let epoch: Option<i64> = sqlx::query_scalar("SELECT root_incarnation FROM repository_selection_state WHERE workspace_id=? AND root_kind=? AND root_id=? AND root_present=1")
            .bind(workspace.as_str()).bind(kind).bind(id).fetch_optional(self.conn()).await.map_err(database)?;
        epoch
            .map(|epoch| u64::try_from(epoch).map_err(database))
            .transpose()
    }
    async fn object(&mut self, kind: &str, key: &str) -> Result<Option<(i64, String)>> {
        sqlx::query_as("SELECT record_sequence,payload_json FROM work_t1_evidence WHERE record_kind=? AND record_key=?")
            .bind(kind).bind(key).fetch_optional(self.conn()).await.map_err(database)
    }
    async fn insert(&mut self, kind: &str, key: &str, raw: &str) -> Result<i64> {
        sqlx::query_scalar("INSERT INTO work_t1_evidence(record_kind,record_key,payload_json,created_at) VALUES(?,?,?,?) RETURNING record_sequence")
            .bind(kind).bind(key).bind(raw).bind(intent_core::now_iso()).fetch_one(self.conn()).await.map_err(database)
    }
    async fn active(
        &mut self,
        agent: &AgentId,
        binding: Option<&intent_core::vcs::OperationId>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO work_t1_evidence(record_kind,record_key,payload_json,created_at) VALUES('active-binding',?,?,?) ON CONFLICT(record_kind,record_key) DO UPDATE SET payload_json=excluded.payload_json")
            .bind(agent.as_str()).bind(super::encode(&binding)?).bind(intent_core::now_iso())
            .execute(self.conn()).await.map_err(database)?;
        Ok(())
    }
    async fn note(&mut self, workspace: &WorkspaceId, note: &NoteId) -> Result<Option<SourceNote>> {
        let row = sqlx::query("SELECT rev,title,content,content_type,task_json FROM note WHERE workspace_id=? AND id=?")
            .bind(workspace.as_str()).bind(note.as_str()).fetch_optional(self.conn()).await.map_err(database)?;
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
        let row = sqlx::query(
            "SELECT worktree_path,repository_path,status,is_remote FROM workspace WHERE id=?",
        )
        .bind(workspace.as_str())
        .fetch_optional(self.conn())
        .await
        .map_err(database)?;
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
            sqlx::query_scalar("SELECT path FROM workspace_git_root WHERE workspace_id=? AND id=?")
                .bind(workspace.as_str())
                .bind(root)
                .fetch_optional(self.conn())
                .await
                .map_err(database)
        }
    }
    async fn agent(
        &mut self,
        workspace: &WorkspaceId,
        agent: &AgentId,
    ) -> Result<Option<AgentState>> {
        let row = sqlx::query("SELECT a.task_note_id,a.status,a.retired_at,w.status AS workspace_status,f.revision,f.assignment_revision FROM agent_session a JOIN workspace w ON w.id=a.workspace_id JOIN work_t1_agent_fence f ON f.agent_id=a.id AND f.workspace_id=a.workspace_id WHERE a.workspace_id=? AND a.id=?")
            .bind(workspace.as_str()).bind(agent.as_str()).fetch_optional(self.conn()).await.map_err(database)?;
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
        sqlx::query("UPDATE agent_session SET status=?,is_active=1,updated_at=?,stop_reason=NULL,stop_reason_timestamp=NULL WHERE workspace_id=? AND id=?")
            .bind(crate::enum_to_db(&intent_core::AgentStatus::Active)?).bind(timestamp).bind(workspace.as_str()).bind(agent.as_str())
            .execute(self.conn()).await.map_err(database)?;
        Ok(())
    }
    async fn write_note(
        &mut self,
        lock: &NoteWriteLock,
        note: &Note,
        expected: i64,
    ) -> Result<i64> {
        lock.ensure_covers(&self.store.note_write_lanes, note)?;
        crate::note_repo::exec_update_note(
            self.conn(),
            note,
            Some(expected),
            crate::note_repo::NoteUpdateScope::Metadata,
        )
        .await?
        .ok_or_else(|| super::invalid("task changed before reviewed definition persisted"))
    }
    async fn insert_agent(
        &mut self,
        session: &AgentSession,
        graph: bool,
        remember: bool,
    ) -> Result<()> {
        let sql = format!("INSERT INTO agent_session ({}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", crate::agent_repo::SESSION_COLUMNS);
        crate::agent_repo::bind_session_insert(
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str())),
            session,
            graph,
        )?
        .execute(self.conn())
        .await
        .map_err(database)?;
        if remember {
            crate::settings_repo::remember_agent_specialist_on(self.conn(), session).await?;
        }
        Ok(())
    }
}
