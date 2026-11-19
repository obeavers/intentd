//! Actual native session metadata remains separate from provider custody.

use intent_atomic_proto::{
    sessions::{
        BeginNativeSessionRequest, CloseNativeSessionRequest, NativeSessionCloseReceipt,
        NativeSessionReceipt,
    },
    Command, Reply, SpoolRef,
};

use super::{digest, invalid, AtomicNativeWorkClient};
use crate::Result;

#[derive(Clone)]
pub struct OwnedNativeSessionBegin {
    request: BeginNativeSessionRequest,
    envelope: SpoolRef,
}

impl OwnedNativeSessionBegin {
    #[must_use]
    pub fn request(&self) -> &BeginNativeSessionRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

#[derive(Clone)]
pub struct OwnedNativeSessionClose {
    request: CloseNativeSessionRequest,
    envelope: SpoolRef,
}

impl OwnedNativeSessionClose {
    #[must_use]
    pub fn request(&self) -> &CloseNativeSessionRequest {
        &self.request
    }
    #[must_use]
    pub fn envelope(&self) -> &SpoolRef {
        &self.envelope
    }
}

pub struct RetainedNativeSession {
    pub receipt: NativeSessionReceipt,
    pub envelope: Option<SpoolRef>,
    pub post_effect_retention_error: Option<String>,
}

pub struct RetainedNativeSessionClose {
    pub receipt: NativeSessionCloseReceipt,
    pub envelope: Option<SpoolRef>,
    pub post_effect_retention_error: Option<String>,
}

impl AtomicNativeWorkClient {
    /// # Errors
    /// Refuses invalid native session context or unavailable exact store ownership.
    pub async fn retain_session_begin(
        &self,
        request: BeginNativeSessionRequest,
    ) -> Result<OwnedNativeSessionBegin> {
        if [
            &request.operation_id,
            &request.session_id,
            &request.work_binding_id,
            &request.turn_attempt,
            &request.agent_id,
            &request.agent_name,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 256 || value.chars().any(char::is_control))
        {
            return Err(invalid(
                "native session requires exact bounded original context",
            ));
        }
        self.open_store(&request.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedNativeSessionBegin { request, envelope })
    }

    /// Begin only the exact retained native allocation. A metadata receipt does
    /// not certify the physical ACP/provider process or callback lifetime.
    /// # Errors
    /// Returns host/transport uncertainty or a foreign native session receipt.
    pub async fn begin_session(
        &self,
        pending: &OwnedNativeSessionBegin,
    ) -> Result<RetainedNativeSession> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.binding).await?;
        let Reply::NativeSessionBegan { receipt } = self
            .host
            .request(Command::BeginNativeSession {
                request: pending.request.clone(),
            })
            .await?
        else {
            return Err(invalid("expected actual native session allocation"));
        };
        if !receipt.matches_request(&pending.request)
            || receipt.command_digest != digest(&serde_json::to_vec(&pending.request)?)
        {
            return Err(invalid(
                "native session receipt differs from retained allocation request",
            ));
        }
        let (envelope, post_effect_retention_error) =
            retention(self.retain_command(&receipt).await);
        Ok(RetainedNativeSession {
            receipt,
            envelope,
            post_effect_retention_error,
        })
    }

    /// # Errors
    /// Refuses an invalid metadata-only close request or unavailable store.
    pub async fn retain_session_close(
        &self,
        request: CloseNativeSessionRequest,
    ) -> Result<OwnedNativeSessionClose> {
        if request.operation_id.is_empty()
            || request.operation_id.len() > 256
            || request.session.host != intent_atomic_proto::HostIdentity::default()
            || request.session.provider_custody_verified
            || request.session.turn != 1
        {
            return Err(invalid(
                "native metadata close requires its original unqualified-custody session",
            ));
        }
        self.open_store(&request.session.binding).await?;
        let envelope = self.retain_command(&request).await?;
        Ok(OwnedNativeSessionClose { request, envelope })
    }

    /// # Errors
    /// Returns host refusal/uncertainty or a changed original close identity.
    pub async fn close_session(
        &self,
        pending: &OwnedNativeSessionClose,
    ) -> Result<RetainedNativeSessionClose> {
        self.verify_command(&pending.envelope, &pending.request)
            .await?;
        self.open_store(&pending.request.session.binding).await?;
        let Reply::NativeSessionClosed { receipt } = self
            .host
            .request(Command::CloseNativeSession {
                request: pending.request.clone(),
            })
            .await?
        else {
            return Err(invalid("expected actual native session metadata close"));
        };
        if !receipt.matches_request(&pending.request)
            || receipt.command_digest != digest(&serde_json::to_vec(&pending.request)?)
        {
            return Err(invalid(
                "native close receipt differs from retained original session",
            ));
        }
        let (envelope, post_effect_retention_error) =
            retention(self.retain_command(&receipt).await);
        Ok(RetainedNativeSessionClose {
            receipt,
            envelope,
            post_effect_retention_error,
        })
    }
}

fn retention(result: Result<SpoolRef>) -> (Option<SpoolRef>, Option<String>) {
    match result {
        Ok(envelope) => (Some(envelope), None),
        Err(error) => (None, Some(error.to_string())),
    }
}
