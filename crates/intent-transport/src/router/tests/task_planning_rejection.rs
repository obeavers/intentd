//! An unavailable planning constraint must refuse before agent allocation.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use intent_core::{AgentCreateExtra, AgentId, BoxFuture, Result, WorkspaceApi, WorkspaceId};
use serde_json::{json, Value};

use super::super::handle_message;

#[derive(Default)]
struct CountingCreateApi {
    calls: AtomicUsize,
    saw_revision: AtomicBool,
}

impl WorkspaceApi for CountingCreateApi {
    fn agent_create(
        &self,
        _workspace_id: WorkspaceId,
        _name: Option<String>,
        _model: Option<String>,
        _specialist_id: Option<String>,
        _parent_agent_id: Option<AgentId>,
        _idempotency_key: Option<String>,
        extra: AgentCreateExtra,
    ) -> BoxFuture<'_, Result<Value>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.saw_revision
            .store(extra.expected_task_revision.is_some(), Ordering::SeqCst);
        Box::pin(async { Ok(json!({"agent":{"id":"created-once"}})) })
    }
}

async fn create(api: &CountingCreateApi, params: Value) -> Value {
    let request = json!({"jsonrpc":"2.0","id":7,"method":"agent.create","params":params});
    let response = handle_message(api, &request.to_string()).await.unwrap();
    serde_json::from_str(&response).unwrap()
}

fn revision() -> Value {
    json!({
        "workspaceId":"ws-1", "noteId":"task-1", "rev":3,
        "digest":"a".repeat(64), "projectionSchemaVersion":1
    })
}

#[tokio::test]
async fn any_present_revision_refuses_before_service_or_allocation() {
    let api = CountingCreateApi::default();
    for value in [
        Value::Null,
        json!(false),
        json!(0),
        json!(""),
        json!([]),
        json!({}),
        revision(),
    ] {
        let response = create(
            &api,
            json!({"workspaceId":"ws-1","expectedTaskRevision":value}),
        )
        .await;
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32602);
        let message = response["error"]["message"].as_str().unwrap();
        assert!(message.contains("expectedTaskRevision"), "{response}");
        assert!(message.contains("taskPlanning"), "{response}");
        assert_eq!(api.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn ordinary_creation_without_revision_keeps_legacy_dispatch() {
    let api = CountingCreateApi::default();
    let response = create(&api, json!({"workspaceId":"ws-1","name":"Ordinary task"})).await;
    assert_eq!(response["result"]["agent"]["id"], "created-once");
    assert_eq!(api.calls.load(Ordering::SeqCst), 1);
    assert!(!api.saw_revision.load(Ordering::SeqCst));
}

#[tokio::test]
async fn stale_client_agent_id_keeps_its_documented_error_priority() {
    let api = CountingCreateApi::default();
    let response = create(
        &api,
        json!({"agentId":"client-chosen","expectedTaskRevision":revision()}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("server-assigned"));
    assert_eq!(api.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn null_legacy_agent_id_does_not_hide_a_present_revision_constraint() {
    let api = CountingCreateApi::default();
    let response = create(
        &api,
        json!({"agentId":null,"workspaceId":"ws-1","expectedTaskRevision":null}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("expectedTaskRevision"));
    assert_eq!(api.calls.load(Ordering::SeqCst), 0);
}
