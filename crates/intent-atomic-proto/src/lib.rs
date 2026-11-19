//! Private daemon-to-host contract. This crate never links Atomic or opens stores.
//!
//! Each JSON message has a four-byte big-endian length prefix. The prefix excludes
//! itself; messages must contain between one and `MAX_FRAME_BYTES` bytes. Larger
//! bodies travel as validated spool references. A peer must complete an exact
//! identity handshake and recovery before opening or operating on any store.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod baselines;
pub mod closures;
pub mod composition;
pub mod execution;
pub mod intents;
pub mod knowledge;
pub mod provenance;
pub mod recorded_closures;
pub mod recording;
pub mod sealed_record_source;
pub mod sessions;
pub mod triage;
pub mod working_copies;

pub const CONTRACT_VERSION: u32 = 3;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const ATOMIC_REVISION: &str = "bf9893adb57dccbaa8f7e14277e02d060d74bf53";
/// `atomic-core/src/pristine/schema.rs::SCHEMA_VERSION` at `ATOMIC_REVISION`.
pub const STORE_FORMAT: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub contract_version: u32,
    pub atomic_revision: String,
    pub store_format: u64,
}

impl Default for HostIdentity {
    fn default() -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            atomic_revision: ATOMIC_REVISION.to_owned(),
            store_format: STORE_FORMAT,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreBinding {
    pub repository_id: String,
    pub binding_epoch: u64,
    /// A locator only. The host validates its own allowed root and persisted identity.
    pub store_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateToken {
    pub view: String,
    pub effective_state: String,
    pub own_merkle: String,
}

/// References name one owner-private file directly beneath the daemon spool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpoolRef {
    pub name: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase", deny_unknown_fields)]
pub enum Command {
    Handshake {
        identity: HostIdentity,
    },
    /// The host enumerates its durable journal; callers cannot omit uncertain work.
    Reconcile,
    Ping,
    InitializeStore {
        binding: StoreBinding,
        operation_id: String,
    },
    OpenStore {
        binding: StoreBinding,
    },
    ReadState {
        binding: StoreBinding,
    },
    CloseStore {
        binding: StoreBinding,
    },
    ImportDerived {
        request: knowledge::ImportDerivedRequest,
    },
    QueryCode {
        request: knowledge::CodeQueryRequest,
    },
    ClassifyTool {
        request: provenance::ClassifyToolRequest,
    },
    ImportBaseline {
        request: baselines::ImportBaselineRequest,
    },
    ReadBaseline {
        baseline: baselines::BaselineRef,
    },
    MaterializeBaseline {
        request: baselines::MaterializeBaselineRequest,
    },
    ExportBaselineClosure {
        request: closures::ExportBaselineClosureRequest,
    },
    RestoreBaselineClosure {
        request: Box<closures::RestoreBaselineClosureRequest>,
    },
    CaptureCompositionTarget {
        request: composition::CaptureCompositionTargetRequest,
    },
    ComposePrivate {
        input: SpoolRef,
    },
    IssueExecutionGrant {
        request: Box<execution::IssueExecutionGrantRequest>,
    },
    ReadGrantedFile {
        request: execution::ReadGrantedFileRequest,
    },
    CloseExecutionGrant {
        request: execution::CloseExecutionGrantRequest,
    },
    ReadNativeProject {
        binding: StoreBinding,
    },
    ProjectTaskIntent {
        request: Box<intents::ProjectTaskIntentRequest>,
    },
    DeclareNativeTurn {
        request: intents::DeclareNativeTurnRequest,
    },
    FreezeNativeTurn {
        request: intents::FreezeNativeTurnRequest,
    },
    PrepareExactRecord {
        request: Box<recording::PrepareRecordRequest>,
    },
    PrepareBoundExactRecord {
        request: Box<recording::PrepareRecordRequest>,
        freeze: Box<intents::NativeTurnFreezeReceipt>,
    },
    /// Only the exact retained operation may resolve an interrupted admission.
    /// This command never authorizes preparation or a different source mutation.
    AdmitExactRecord {
        prepared: Box<recording::PreparedNativeRecord>,
    },
    CaptureNativeControl {
        request: triage::CaptureNativeControlRequest,
    },
    PrepareNativeTriage {
        request: Box<triage::PrepareNativeTriageRequest>,
    },
    RegisterWorkingCopyCapture {
        request: Box<working_copies::RegisterWorkingCopyCaptureRequest>,
    },
    CaptureRegisteredWorkingCopy {
        request: Box<working_copies::CaptureRegisteredWorkingCopyRequest>,
    },
    BeginNativeSession {
        request: sessions::BeginNativeSessionRequest,
    },
    CloseNativeSession {
        request: sessions::CloseNativeSessionRequest,
    },
    ExportRecordedClosure {
        request: Box<recorded_closures::ExportRecordedClosureRequest>,
    },
    RestoreRecordedClosure {
        request: Box<recorded_closures::RestoreRecordedClosureRequest>,
    },
    SealRecordSource {
        request: Box<sealed_record_source::SealRecordSourceRequest>,
    },
    Shutdown,
}

impl Command {
    /// Named immutable observations that may share an already-recovered host
    /// with a known live writer. Spool-producing operations stay serialized.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::ReadState { .. }
                | Self::ReadBaseline { .. }
                | Self::QueryCode { .. }
                | Self::ClassifyTool { .. }
                | Self::ReadGrantedFile { .. }
                | Self::ReadNativeProject { .. }
        )
    }

    #[must_use]
    pub const fn requires_recovery(&self) -> bool {
        matches!(
            self,
            Self::InitializeStore { .. }
                | Self::OpenStore { .. }
                | Self::ReadState { .. }
                | Self::CloseStore { .. }
                | Self::ImportDerived { .. }
                | Self::QueryCode { .. }
                | Self::ClassifyTool { .. }
                | Self::ImportBaseline { .. }
                | Self::ReadBaseline { .. }
                | Self::MaterializeBaseline { .. }
                | Self::ExportBaselineClosure { .. }
                | Self::RestoreBaselineClosure { .. }
                | Self::CaptureCompositionTarget { .. }
                | Self::ComposePrivate { .. }
                | Self::IssueExecutionGrant { .. }
                | Self::ReadGrantedFile { .. }
                | Self::ReadNativeProject { .. }
                | Self::ProjectTaskIntent { .. }
                | Self::DeclareNativeTurn { .. }
                | Self::FreezeNativeTurn { .. }
                | Self::PrepareExactRecord { .. }
                | Self::PrepareBoundExactRecord { .. }
                | Self::CaptureNativeControl { .. }
                | Self::PrepareNativeTriage { .. }
                | Self::RegisterWorkingCopyCapture { .. }
                | Self::CaptureRegisteredWorkingCopy { .. }
                | Self::BeginNativeSession { .. }
                | Self::CloseNativeSession { .. }
                | Self::ExportRecordedClosure { .. }
                | Self::RestoreRecordedClosure { .. }
                | Self::SealRecordSource { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub command: Command,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryReport {
    pub ready: bool,
    pub unresolved_operation_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "camelCase", deny_unknown_fields)]
pub enum Reply {
    RecordSourceSealed {
        source: Box<sealed_record_source::SealedRecordSource>,
    },
    Handshake {
        identity: HostIdentity,
    },
    Reconciled {
        recovery: RecoveryReport,
    },
    Pong,
    StoreInitialized {
        binding: StoreBinding,
        operation_id: String,
    },
    StoreOpened {
        binding: StoreBinding,
    },
    State {
        binding: StoreBinding,
        state: StateToken,
    },
    StoreClosed {
        binding: StoreBinding,
    },
    DerivedImported {
        receipt: knowledge::DerivedReceipt,
    },
    CodeQuery {
        result: knowledge::CodeQueryResult,
    },
    ToolClassified {
        receipt: provenance::ToolClassificationReceipt,
    },
    BaselineImported {
        receipt: baselines::BaselineReceipt,
    },
    Baseline {
        receipt: baselines::BaselineReceipt,
    },
    BaselineMaterialized {
        receipt: baselines::BaselineMaterialization,
    },
    BaselineClosureExported {
        receipt: closures::BaselineClosure,
    },
    BaselineClosureRestored {
        receipt: baselines::BaselineReceipt,
    },
    CompositionTargetCaptured {
        capture: composition::CapturedCompositionTarget,
    },
    PrivateComposed {
        outcome: Box<composition::PrivateCompositionOutcome>,
    },
    ExecutionGrantIssued {
        issued: Box<execution::NativeExecutionGrantIssued>,
    },
    GrantedFile {
        receipt: execution::GrantedFileReceipt,
    },
    ExecutionGrantClosed {
        receipt: execution::ExecutionGrantClosed,
    },
    NativeProject {
        identity: intents::NativeProjectIdentity,
    },
    TaskIntentProjected {
        receipt: Box<intents::IntentProjectionReceipt>,
    },
    NativeTurnDeclared {
        receipt: intents::NativeTurnDeclaration,
    },
    NativeTurnFrozen {
        receipt: Box<intents::NativeTurnFreezeReceipt>,
    },
    ExactRecordPrepared {
        outcome: Box<recording::RecordPreparation>,
    },
    ExactRecordAdmitted {
        receipt: recording::NativeRecordReceipt,
    },
    NativeControlCaptured {
        snapshot: triage::NativeControlSnapshotRef,
    },
    NativeTriagePrepared {
        outcome: Box<triage::NativeTriagePreparation>,
    },
    WorkingCopyCaptureRegistered {
        registration: Box<working_copies::WorkingCopyCaptureRegistration>,
    },
    WorkingCopyCaptured {
        capture: Box<execution::WarmWorkingCopyCapture>,
    },
    NativeSessionBegan {
        receipt: sessions::NativeSessionReceipt,
    },
    NativeSessionClosed {
        receipt: sessions::NativeSessionCloseReceipt,
    },
    RecordedClosureExported {
        receipt: Box<recorded_closures::RecordedClosure>,
    },
    RecordedClosureRestored {
        receipt: Box<recorded_closures::RecordedClosureRestore>,
    },
    Shutdown,
}

impl Reply {
    #[must_use]
    pub fn matches_command(&self, command: &Command) -> bool {
        match (self, command) {
            (Self::RecordSourceSealed { source }, Command::SealRecordSource { request }) => {
                source.matches_request(request)
            }
            (
                Self::RecordedClosureExported { receipt },
                Command::ExportRecordedClosure { request },
            ) => {
                receipt.host == HostIdentity::default()
                    && receipt.format == recorded_closures::RECORDED_CLOSURE_FORMAT
                    && receipt.reader_version == recorded_closures::RECORDED_CLOSURE_READER
                    && receipt.operation_id == request.operation_id
                    && receipt.scope == request.scope
                    && receipt.capture_revision == request.capture_revision
                    && receipt.source_state == request.expected_state
                    && !receipt.project_id.is_empty()
                    && !receipt.project_identity_hash.is_empty()
                    && !receipt.payload.name.is_empty()
            }
            (
                Self::RecordedClosureRestored { receipt },
                Command::RestoreRecordedClosure { request },
            ) => {
                receipt.host == HostIdentity::default()
                    && receipt.operation_id == request.operation_id
                    && receipt.scope == request.expected_scope
                    && receipt.scope == request.closure.scope
                    && receipt.capture_revision == request.closure.capture_revision
                    && receipt.source_state == request.closure.source_state
                    && receipt.restored_state.view == request.closure.source_state.view
                    && receipt.restored_state.own_merkle == request.closure.source_state.own_merkle
                    && receipt.project_id == request.closure.project_id
                    && receipt.project_identity_hash == request.closure.project_identity_hash
                    && receipt.view_manifest_digest == request.closure.view_manifest_digest
                    && receipt.materialization_manifest_digest
                        == request.closure.materialization_manifest_digest
                    && receipt.materialization_id == request.closure.materialization_id
                    && receipt.object_count == request.closure.object_count
                    && receipt.native_conflict_hash
                        == request
                            .closure
                            .conflict
                            .as_ref()
                            .map(|conflict| conflict.native_hash.clone())
                    && !receipt.native_path.as_os_str().is_empty()
                    && !receipt.path.as_os_str().is_empty()
                    && !receipt.receipt_digest.is_empty()
            }
            (
                Self::StoreInitialized {
                    binding: actual_binding,
                    operation_id: actual_operation,
                },
                Command::InitializeStore {
                    binding,
                    operation_id,
                },
            ) => actual_binding == binding && actual_operation == operation_id,
            (
                Self::WorkingCopyCaptureRegistered { registration },
                Command::RegisterWorkingCopyCapture { request },
            ) => {
                registration.host == HostIdentity::default()
                    && registration.facade_version
                        == working_copies::WORKING_COPY_CAPTURE_FACADE_VERSION
                    && registration.operation_id == request.operation_id
                    && registration.binding == request.binding
                    && registration.baseline == request.baseline
                    && registration.working_root == request.working_root
                    && registration.working_copy_id == request.working_copy_id
                    && !registration.registration_id.is_empty()
                    && !registration.host_generation.is_empty()
            }
            (
                Self::WorkingCopyCaptured { capture },
                Command::CaptureRegisteredWorkingCopy { request },
            ) => {
                capture.operation_id == request.operation_id
                    && capture.repository_id == request.registration.binding.repository_id
                    && capture.binding_epoch == request.registration.binding.binding_epoch
                    && capture.parent_working_copy_id == request.registration.working_copy_id
                    && capture.parent_root == request.registration.working_root
                    && capture.baseline == request.registration.baseline
                    && capture.selection_digest.is_none()
                    && capture.capture_generation > 0
            }
            (Self::NativeSessionBegan { receipt }, Command::BeginNativeSession { request }) => {
                receipt.matches_request(request)
            }
            (Self::NativeSessionClosed { receipt }, Command::CloseNativeSession { request }) => {
                receipt.matches_request(request)
            }
            (Self::NativeProject { identity }, Command::ReadNativeProject { binding }) => {
                identity.host == HostIdentity::default()
                    && identity.binding == *binding
                    && !identity.project_id.is_empty()
                    && !identity.project_identity_hash.is_empty()
            }
            (Self::TaskIntentProjected { receipt }, Command::ProjectTaskIntent { request }) => {
                receipt.host == HostIdentity::default()
                    && receipt.binding == request.binding
                    && receipt.identity == request.identity
                    && receipt.projection.operation_id == request.operation_id
                    && receipt.projection.projection_revision == request.projection_revision
                    && receipt.projection.task_revision == request.task_revision
                    && receipt.projection_version == intents::INTENT_PROJECTION_VERSION
                    && receipt.task_source.length == request.source.length
                    && receipt.task_source.sha256 == request.source.sha256
            }
            (Self::NativeTurnDeclared { receipt }, Command::DeclareNativeTurn { request }) => {
                receipt.host == HostIdentity::default()
                    && receipt.binding == request.binding
                    && receipt.operation_id == request.operation_id
                    && receipt.projection == request.projection
                    && receipt.session_id == request.session_id
                    && receipt.turn == request.expected_turn
                    && receipt.native_intent_id == request.native_intent_id
            }
            (Self::NativeTurnFrozen { receipt }, Command::FreezeNativeTurn { request }) => {
                receipt.host == HostIdentity::default()
                    && receipt.binding == request.binding
                    && receipt.operation_id == request.operation_id
                    && receipt.work_binding_id == request.work_binding_id
                    && receipt.projection == request.projection
                    && receipt.session_id == request.session_id
                    && receipt.turn == request.expected_turn
                    && receipt.native_intent_id == request.native_intent_id
            }
            (
                Self::ExactRecordPrepared { outcome },
                Command::PrepareExactRecord { request }
                | Command::PrepareBoundExactRecord { request, .. },
            ) => match outcome.as_ref() {
                recording::RecordPreparation::Prepared { record } => {
                    record.host == HostIdentity::default()
                        && record.operation_id == request.operation_id
                        && record.binding == request.binding
                        && record.expected_state == request.expected_state
                }
                recording::RecordPreparation::NoChanges {
                    operation_id,
                    expected_state,
                    ..
                } => {
                    operation_id == &request.operation_id
                        && expected_state == &request.expected_state
                }
            },
            (Self::ExactRecordAdmitted { receipt }, Command::AdmitExactRecord { prepared }) => {
                receipt.operation_id == prepared.operation_id
                    && receipt.change_hash == prepared.change_hash
                    && receipt.encoding_sha256 == prepared.bytes.sha256
                    && receipt.encoding_length == prepared.bytes.length
                    && receipt.before == prepared.expected_state
                    && receipt.after.view == prepared.expected_state.view
                    && !receipt.after.effective_state.is_empty()
                    && !receipt.after.own_merkle.is_empty()
            }
            (
                Self::NativeControlCaptured { snapshot },
                Command::CaptureNativeControl { request },
            ) => {
                snapshot.host == HostIdentity::default()
                    && snapshot.binding == request.binding
                    && snapshot.operation_id == request.operation_id
                    && snapshot.snapshot_digest == snapshot.descriptor.sha256
            }
            (Self::NativeTriagePrepared { outcome }, Command::PrepareNativeTriage { request }) => {
                match outcome.as_ref() {
                    triage::NativeTriagePreparation::Produced { receipt } => {
                        receipt.host == HostIdentity::default()
                            && receipt.operation_id == request.operation_id
                            && receipt.scope == request.composition.scope
                            && receipt.evidence.host == HostIdentity::default()
                    }
                    triage::NativeTriagePreparation::Stale { .. }
                    | triage::NativeTriagePreparation::Unavailable { .. }
                    | triage::NativeTriagePreparation::Malformed { .. } => true,
                }
            }
            (Self::ExecutionGrantIssued { issued }, Command::IssueExecutionGrant { request }) => {
                issued.receipt.host == HostIdentity::default()
                    && issued.receipt.facade_version == execution::EXECUTION_FACADE_VERSION
                    && issued.receipt.binding == request.binding
                    && issued.receipt.operation_id == request.operation_id
                    && issued.receipt.claim == request.claim
                    && issued.receipt.capture == request.capture
                    && issued.receipt.native_state == request.expected_state
            }
            (Self::GrantedFile { receipt }, Command::ReadGrantedFile { request }) => {
                receipt.request_id == request.request_id
                    && receipt.grant_id == request.grant_id
                    && receipt.grant_receipt_digest == request.grant_receipt_digest
                    && receipt.path == request.path
                    && receipt.basis == execution::GrantedReadBasis::PinnedGrantManifest
            }
            (Self::ExecutionGrantClosed { receipt }, Command::CloseExecutionGrant { request }) => {
                receipt.grant_id == request.grant_id
                    && receipt.grant_receipt_digest == request.grant_receipt_digest
                    && receipt.admitted_reads_drained
            }
            (
                Self::CompositionTargetCaptured { capture },
                Command::CaptureCompositionTarget { request },
            ) => {
                capture.operation_id == request.operation_id
                    && capture.scope == request.scope
                    && capture.binding == request.binding
                    && capture.state == request.expected_state
                    && capture.state.view == request.view
                    && capture.host == HostIdentity::default()
            }
            (Self::PrivateComposed { outcome }, Command::ComposePrivate { input }) => {
                match outcome.as_ref() {
                    composition::PrivateCompositionOutcome::Composed { receipt } => {
                        receipt.command_digest == input.sha256
                            && receipt.host == HostIdentity::default()
                    }
                    composition::PrivateCompositionOutcome::InheritedBaselineRequired {
                        command_digest,
                        host,
                        missing_count,
                        ..
                    } => {
                        command_digest == &input.sha256
                            && host == &HostIdentity::default()
                            && *missing_count > 0
                            && *missing_count <= 4096
                    }
                }
            }
            (
                Self::BaselineClosureExported { receipt },
                Command::ExportBaselineClosure { request },
            ) => {
                receipt.scope == request.scope
                    && receipt.capture_revision == request.capture_revision
                    && receipt.baseline.baseline == request.baseline
                    && receipt.host == HostIdentity::default()
                    && receipt.format == closures::CLOSURE_FORMAT
            }
            (
                Self::BaselineClosureRestored { receipt },
                Command::RestoreBaselineClosure { request },
            ) => {
                receipt == &request.closure.baseline
                    && receipt.baseline.repository_id == request.expected_scope.repository_id
                    && receipt.baseline.binding_epoch == request.expected_scope.binding_epoch
            }
            (Self::BaselineImported { receipt }, Command::ImportBaseline { request }) => {
                receipt.baseline.repository_id == request.binding.repository_id
                    && receipt.baseline.binding_epoch == request.binding.binding_epoch
                    && receipt.source_commit == request.commit
                    && receipt.previous == request.previous
                    && receipt.policy == request.policy
                    && receipt.host == HostIdentity::default()
            }
            (Self::Baseline { receipt }, Command::ReadBaseline { baseline }) => {
                receipt.baseline == *baseline && receipt.host == HostIdentity::default()
            }
            (Self::BaselineMaterialized { receipt }, Command::MaterializeBaseline { request }) => {
                receipt.baseline == request.baseline
            }
            (Self::ToolClassified { receipt }, Command::ClassifyTool { request }) => {
                receipt.observation_id == request.observation.observation_id
                    && receipt.input_digest == request.input_digest
                    && receipt.atomic_revision == ATOMIC_REVISION
                    && receipt.classifier_version == provenance::CLASSIFIER_VERSION
            }
            (Self::DerivedImported { receipt }, Command::ImportDerived { request }) => {
                receipt.index.repository_id == request.scope.repository_id
                    && receipt.index.root_id == request.scope.root_id
                    && receipt.index.root_epoch == request.scope.root_epoch
                    && receipt.commit == request.commit
            }
            (Self::CodeQuery { result }, Command::QueryCode { request }) => {
                result.basis.index == request.index
                    && result.basis.stale == (result.basis.commit != request.expected_commit)
            }
            (Self::StoreOpened { binding: actual }, Command::OpenStore { binding: expected })
            | (
                Self::State {
                    binding: actual, ..
                },
                Command::ReadState { binding: expected },
            )
            | (Self::StoreClosed { binding: actual }, Command::CloseStore { binding: expected }) => {
                actual == expected
            }
            pair => matches!(
                pair,
                (Self::Handshake { .. }, Command::Handshake { .. })
                    | (Self::Reconciled { .. }, Command::Reconcile)
                    | (Self::Pong, Command::Ping)
                    | (Self::Shutdown, Command::Shutdown)
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FailureCode {
    IncompatibleHost,
    RecoveryRequired,
    StaleBinding,
    InvalidRequest,
    Unsupported,
    Unavailable,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFailure {
    pub code: FailureCode,
    pub message: String,
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Outcome {
    Success(Box<Reply>),
    Failure(HostFailure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub id: u64,
    pub outcome: Outcome,
}

/// Host sequences are process-local. A restart requires recovery and a new snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateChanged {
    pub sequence: u64,
    pub binding: StoreBinding,
    pub state: StateToken,
    pub operation_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_request() -> recording::PrepareRecordRequest {
        recording::PrepareRecordRequest {
            operation_id: "record-operation".into(),
            binding: StoreBinding {
                repository_id: "repository".into(),
                binding_epoch: 1,
                store_path: "/uncreated/store".into(),
            },
            sealed_source: "/uncreated/sealed".into(),
            expected_state: StateToken {
                view: "draft".into(),
                effective_state: "effective".into(),
                own_merkle: "own".into(),
            },
            files: vec![],
            message: "exact source".into(),
            author_name: "Intent".into(),
            author_email: None,
            unix_seconds: 1,
            context_json: "{}".into(),
        }
    }

    #[test]
    fn identity_matches_qualified_candidate_pin() {
        let pin: serde_json::Value =
            serde_json::from_str(include_str!("../../../atomic-host/upstream.json")).unwrap();
        assert_eq!(pin["revision"], HostIdentity::default().atomic_revision);
    }

    #[test]
    fn contract_refuses_unknown_commands_and_extra_identity_fields() {
        assert!(serde_json::from_str::<Command>(r#"{"command":"record"}"#).is_err());
        assert!(serde_json::from_str::<HostIdentity>(
            r#"{"contractVersion":1,"atomicRevision":"pin","storeFormat":2,"fallback":true}"#
        )
        .is_err());
    }

    #[test]
    fn typed_native_commands_round_trip_without_accepting_unversioned_fields() {
        let command = Command::PrepareExactRecord {
            request: Box::new(record_request()),
        };
        let mut value = serde_json::to_value(&command).unwrap();
        assert_eq!(value["command"], "prepareExactRecord");
        assert_eq!(
            serde_json::from_value::<Command>(value.clone()).unwrap(),
            command
        );
        value["request"]["taskAuthority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Command>(value).is_err());
        assert_eq!(CONTRACT_VERSION, 3);
    }

    #[test]
    fn only_retained_admission_has_the_exact_record_recovery_lane() {
        let request = record_request();
        let prepared = recording::PreparedNativeRecord {
            operation_id: request.operation_id.clone(),
            host: HostIdentity::default(),
            binding: request.binding.clone(),
            expected_state: request.expected_state.clone(),
            command_digest: "command".into(),
            selection_digest: "selection".into(),
            metadata_digest: "metadata".into(),
            change_hash: "change".into(),
            bytes: SpoolRef {
                name: "record.payload".into(),
                length: 1,
                sha256: "encoding".into(),
            },
            recorded_paths: vec![],
            deleted_paths: vec![],
        };
        assert!(Command::PrepareExactRecord {
            request: Box::new(request.clone())
        }
        .requires_recovery());
        let command = Command::AdmitExactRecord {
            prepared: Box::new(prepared.clone()),
        };
        assert!(!command.requires_recovery());
        assert!(!command.is_read_only());
        let receipt = recording::NativeRecordReceipt {
            operation_id: prepared.operation_id.clone(),
            change_hash: prepared.change_hash.clone(),
            encoding_sha256: prepared.bytes.sha256.clone(),
            encoding_length: prepared.bytes.length,
            before: prepared.expected_state.clone(),
            after: prepared.expected_state.clone(),
            replayed: true,
        };
        assert!(Reply::ExactRecordAdmitted {
            receipt: receipt.clone()
        }
        .matches_command(&command));
        let mut foreign = receipt.clone();
        foreign.operation_id = "different-operation".into();
        assert!(!Reply::ExactRecordAdmitted { receipt: foreign }.matches_command(&command));
        let mut changed = receipt;
        changed.encoding_sha256 = "different-encoding".into();
        assert!(!Reply::ExactRecordAdmitted { receipt: changed }.matches_command(&command));
    }

    #[test]
    fn no_change_reply_is_bound_to_the_original_record_and_state() {
        let request = record_request();
        let outcome = recording::RecordPreparation::NoChanges {
            operation_id: request.operation_id.clone(),
            command_digest: "command".into(),
            expected_state: request.expected_state.clone(),
            selection_digest: "selection".into(),
        };
        let reply = Reply::ExactRecordPrepared {
            outcome: Box::new(outcome),
        };
        assert!(reply.matches_command(&Command::PrepareExactRecord {
            request: Box::new(request.clone())
        }));
        let mut changed = request;
        changed.expected_state.effective_state = "different-state".into();
        assert!(!reply.matches_command(&Command::PrepareExactRecord {
            request: Box::new(changed)
        }));
    }
}
