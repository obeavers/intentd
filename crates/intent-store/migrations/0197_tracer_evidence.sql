-- T1's local source/evidence identities. These deliberately survive workspace
-- deletion and are excluded from transfer; JSON is a typed retained receipt,
-- never authority supplied by a client. Native/review/acceptance tables follow
-- in later stages rather than importing the experimental 0191-0209 migrations.
CREATE TABLE work_t1_evidence (
    record_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    record_kind TEXT NOT NULL,
    record_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    owner_id TEXT GENERATED ALWAYS AS (CASE WHEN record_kind='contribution' THEN json_extract(payload_json,'$.bindingId') WHEN record_kind='admission' THEN json_extract(payload_json,'$.agent') END) STORED,
    workspace_id TEXT GENERATED ALWAYS AS (CASE WHEN record_kind='contribution' THEN json_extract(payload_json,'$.taskRevision.workspaceId') WHEN record_kind='admission' THEN json_extract(payload_json,'$.workspace') END) STORED,
    created_at TEXT NOT NULL,
    UNIQUE(record_kind, record_key)
);
CREATE INDEX work_t1_evidence_owner ON work_t1_evidence(record_kind,owner_id,workspace_id,record_sequence);
CREATE TRIGGER work_t1_evidence_immutable_update BEFORE UPDATE ON work_t1_evidence
WHEN OLD.record_kind <> 'active-binding'
 OR NEW.record_kind <> OLD.record_kind OR NEW.record_key <> OLD.record_key
 OR NEW.record_sequence <> OLD.record_sequence OR NEW.created_at <> OLD.created_at
BEGIN SELECT RAISE(ABORT, 'T1 evidence records are immutable'); END;
CREATE TRIGGER work_t1_evidence_immutable_delete BEFORE DELETE ON work_t1_evidence
BEGIN SELECT RAISE(ABORT, 'T1 evidence must remain retained'); END;

CREATE TABLE work_t1_agent_fence (
    agent_id TEXT PRIMARY KEY NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision > 0),
    assignment_revision INTEGER NOT NULL CHECK(typeof(assignment_revision)='integer' AND assignment_revision > 0)
);
INSERT INTO work_t1_agent_fence(agent_id, workspace_id, revision, assignment_revision)
SELECT id, workspace_id, 1, 1 FROM agent_session;
CREATE TRIGGER work_t1_agent_fence_insert AFTER INSERT ON agent_session
BEGIN
    INSERT INTO work_t1_agent_fence(agent_id, workspace_id, revision, assignment_revision)
    VALUES(NEW.id, NEW.workspace_id, 1, 1)
    ON CONFLICT(agent_id) DO UPDATE SET workspace_id=excluded.workspace_id,
      revision=revision+1, assignment_revision=assignment_revision+1;
END;
CREATE TRIGGER work_t1_agent_fence_update
AFTER UPDATE OF status,is_active,retired_at,task_note_id,workspace_id ON agent_session
BEGIN
    UPDATE work_t1_agent_fence SET workspace_id=NEW.workspace_id, revision=revision+1,
      assignment_revision=assignment_revision+
        CASE WHEN OLD.task_note_id IS NOT NEW.task_note_id OR OLD.workspace_id IS NOT NEW.workspace_id THEN 1 ELSE 0 END
    WHERE agent_id=NEW.id;
END;
CREATE TRIGGER work_t1_agent_fence_delete AFTER DELETE ON agent_session
BEGIN
    UPDATE work_t1_agent_fence SET revision=revision+1, assignment_revision=assignment_revision+1
    WHERE agent_id=OLD.id;
END;
