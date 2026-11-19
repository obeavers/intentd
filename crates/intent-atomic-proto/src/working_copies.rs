//! Private capture-owner references. These values do not confer provider access,
//! prove that a source turn exited, or qualify a child for authoring.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::baselines::BaselineRef;
use crate::{HostIdentity, StoreBinding};

pub const WORKING_COPY_CAPTURE_FACADE_VERSION: u32 = 1;
pub const MAX_CAPTURE_DRAIN_MILLIS: u32 = 30_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterWorkingCopyCaptureRequest {
    pub operation_id: String,
    pub binding: StoreBinding,
    pub baseline: BaselineRef,
    pub working_root: PathBuf,
    pub working_copy_id: String,
}

/// A lookup reference to an actual retained host owner. The host compares every
/// field with its registry and durable marker; deserializing it mints no owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkingCopyCaptureRegistration {
    pub host: HostIdentity,
    pub facade_version: u32,
    pub registration_id: String,
    pub host_generation: String,
    pub operation_id: String,
    pub binding: StoreBinding,
    pub baseline: BaselineRef,
    pub working_root: PathBuf,
    pub working_copy_id: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureRegisteredWorkingCopyRequest {
    pub operation_id: String,
    pub registration: WorkingCopyCaptureRegistration,
    /// Zero requests an immediate drain check, never a forced release.
    pub drain_timeout_ms: u32,
}
