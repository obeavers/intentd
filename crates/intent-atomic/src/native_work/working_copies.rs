//! References to actual host-owned capture objects. No reference serializes a
//! writer lease, proves provider exit, or authorizes agent source access.

use intent_atomic_proto::{
    execution::WarmWorkingCopyCapture,
    working_copies::{
        CaptureRegisteredWorkingCopyRequest, RegisterWorkingCopyCaptureRequest,
        WorkingCopyCaptureRegistration, MAX_CAPTURE_DRAIN_MILLIS,
        WORKING_COPY_CAPTURE_FACADE_VERSION,
    },
    Command, HostIdentity, Reply, SpoolRef,
};

use super::{digest, invalid, sha_valid, AtomicNativeWorkClient};
use crate::Result;

#[derive(Clone)]
pub struct OwnedWorkingCopyRegistration {
    registration: WorkingCopyCaptureRegistration,
    envelope: SpoolRef,
}

impl OwnedWorkingCopyRegistration {
    #[must_use]
    pub fn registration(&self) -> &WorkingCopyCaptureRegistration {
        &self.registration
    }

    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedRegisteredCapture {
    request: CaptureRegisteredWorkingCopyRequest,
    envelope: SpoolRef,
    registration: OwnedWorkingCopyRegistration,
}

impl OwnedRegisteredCapture {
    #[must_use]
    pub fn request(&self) -> &CaptureRegisteredWorkingCopyRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub struct RetainedWarmWorkingCopyCapture {
    pub capture: WarmWorkingCopyCapture,
    pub envelope: SpoolRef,
}

impl AtomicNativeWorkClient {
    /// Enroll an actual host capture owner; this is not authoring admission.
    /// # Errors
    /// Refuses another root, stale epoch or a changed registry observation.
    pub async fn register_working_copy(
        &self,
        request: RegisterWorkingCopyCaptureRequest,
    ) -> Result<OwnedWorkingCopyRegistration> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || !request.working_root.is_absolute()
            || request.working_copy_id.is_empty()
            || request.baseline.repository_id != request.binding.repository_id
            || request.baseline.binding_epoch != request.binding.binding_epoch
        {
            return Err(invalid(
                "native capture enrollment differs from baseline/root binding",
            ));
        }
        self.open_store(&request.binding).await?;
        let command = self.retain_command(&request).await?;
        let Reply::WorkingCopyCaptureRegistered { registration } = self
            .host
            .request(Command::RegisterWorkingCopyCapture {
                request: Box::new(request.clone()),
            })
            .await?
        else {
            return Err(invalid("expected actual native capture registration"));
        };
        self.verify_command(&command, &request).await?;
        if registration.host != HostIdentity::default()
            || registration.facade_version != WORKING_COPY_CAPTURE_FACADE_VERSION
            || registration.operation_id != request.operation_id
            || registration.binding != request.binding
            || registration.baseline != request.baseline
            || registration.working_root != request.working_root
            || registration.working_copy_id != request.working_copy_id
            || registration.request_digest != digest(&serde_json::to_vec(&request)?)
            || !canonical_uuid(&registration.registration_id)
            || !canonical_uuid(&registration.host_generation)
        {
            return Err(invalid(
                "native capture registration differs from retained enrollment",
            ));
        }
        let envelope = self.retain_command(registration.as_ref()).await?;
        Ok(OwnedWorkingCopyRegistration {
            registration: *registration,
            envelope,
        })
    }

    /// # Errors
    /// Refuses a changed owner receipt, absent operation or excessive drain bound.
    pub async fn retain_registered_capture(
        &self,
        registration: &OwnedWorkingCopyRegistration,
        operation_id: String,
        drain_timeout_ms: u32,
    ) -> Result<OwnedRegisteredCapture> {
        if operation_id.is_empty()
            || operation_id.len() > 256
            || drain_timeout_ms > MAX_CAPTURE_DRAIN_MILLIS
        {
            return Err(invalid(
                "native registered capture exceeds its operation/drain bound",
            ));
        }
        self.verify_command(&registration.envelope, &registration.registration)
            .await?;
        let request = CaptureRegisteredWorkingCopyRequest {
            operation_id,
            registration: registration.registration.clone(),
            drain_timeout_ms,
        };
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedRegisteredCapture {
            request,
            envelope,
            registration: registration.clone(),
        })
    }

    /// # Errors
    /// Refuses live/unknown source owners, changed filesystem or foreign output.
    pub async fn capture_registered(
        &self,
        pending: &OwnedRegisteredCapture,
    ) -> Result<RetainedWarmWorkingCopyCapture> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.verify_command(
            &pending.registration.envelope,
            &pending.registration.registration,
        )
        .await?;
        let Reply::WorkingCopyCaptured { capture } = self
            .host
            .request(Command::CaptureRegisteredWorkingCopy {
                request: Box::new(pending.request.clone()),
            })
            .await?
        else {
            return Err(invalid("expected actual registered working-copy capture"));
        };
        let original = &pending.registration.registration;
        let parent = self.host.spool_path().join("working-copy-captures");
        if capture.operation_id != pending.request.operation_id
            || capture.repository_id != original.binding.repository_id
            || capture.binding_epoch != original.binding.binding_epoch
            || capture.parent_working_copy_id != original.working_copy_id
            || capture.parent_root != original.working_root
            || capture.baseline != original.baseline
            || capture.capture_generation == 0
            || capture.selection_digest.is_some()
            || capture.path.parent() != Some(parent.as_path())
            || !capture
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(sha_valid)
            || !sha_valid(&capture.baseline_manifest_digest)
            || !sha_valid(&capture.working_digest)
            || !matches!(
                capture.mechanism.as_str(),
                "apfs-directory-clone" | "parallel-reflink"
            )
        {
            return Err(invalid(
                "native child capture differs from actual registered source owner",
            ));
        }
        let envelope = self.retain_command(capture.as_ref()).await?;
        Ok(RetainedWarmWorkingCopyCapture {
            capture: *capture,
            envelope,
        })
    }
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}
