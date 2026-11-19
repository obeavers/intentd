//! Mechanical native capability. Task permission is deliberately composed in
//! Services using an exact opaque Store origin, never a deserialized binding.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use intent_atomic_proto::execution::{
    CloseExecutionGrantRequest, ExecutionGrantClosed, GrantedFileReceipt, GrantedReadBasis,
    IssueExecutionGrantRequest, NativeExecutionGrantIssued, NativeExecutionGrantReceipt,
    ReadGrantedFileRequest, EXECUTION_FACADE_VERSION, MAX_GRANTED_READ_BYTES,
};
use intent_atomic_proto::{Command, HostIdentity, Reply};
use sha2::{Digest, Sha256};

use crate::{HostError, HostSupervisor, Result};

pub struct NativeGrantLease {
    host: Arc<HostSupervisor>,
    issued: NativeExecutionGrantIssued,
    closed: AtomicBool,
    deadline: tokio::time::Instant,
}
fn hash(bytes: &[u8]) -> String {
    crate::spool::hex(&Sha256::digest(bytes))
}
fn invalid(reason: &'static str) -> HostError {
    HostError::Protocol(reason)
}
fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("native grant clock precedes epoch"))?
            .as_millis(),
    )
    .map_err(|_| invalid("native grant clock exceeds expiry range"))
}
fn decode_hex(text: &str) -> Result<Vec<u8>> {
    fn nibble(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(invalid("native recorded bytes are not canonical hex")),
        }
    }
    if text.len() > MAX_GRANTED_READ_BYTES * 2 || !text.len().is_multiple_of(2) {
        return Err(invalid("native recorded bytes exceed bound"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

impl NativeGrantLease {
    /// Request an actual mechanical native read lease. This is not execution
    /// permission: Services must still admit its exact original retained turn.
    /// # Errors
    /// Returns actual host refusal, transport uncertainty or receipt mismatch.
    pub async fn issue(
        host: Arc<HostSupervisor>,
        request: IssueExecutionGrantRequest,
    ) -> Result<Self> {
        let expected = request.clone();
        let Reply::ExecutionGrantIssued { issued } = host
            .request(Command::IssueExecutionGrant {
                request: Box::new(request),
            })
            .await?
        else {
            return Err(invalid("expected actual native grant receipt"));
        };
        let issued = *issued;
        let receipt = &issued.receipt;
        if receipt.host != HostIdentity::default()
            || receipt.facade_version != EXECUTION_FACADE_VERSION
            || receipt.binding != expected.binding
            || receipt.operation_id != expected.operation_id
            || receipt.claim != expected.claim
            || receipt.native_state != expected.expected_state
            || receipt.capture != expected.capture
            || receipt.native_view_id == 0
            || receipt.freeze_digest != hash(&serde_json::to_vec(&expected.freeze)?)
            || receipt.token_sha256 != hash(issued.token.as_bytes())
            || receipt.native_capabilities != ["sandbox.read".to_owned()]
            || receipt.native_grant_id.is_empty()
            || receipt.host_generation.is_empty()
        {
            return Err(invalid(
                "native lease differs from original frozen grant request",
            ));
        }
        let expiry = receipt
            .claim
            .expires_at_unix_ms
            .min(receipt.native_expires_at_unix_ms);
        let remaining = expiry
            .checked_sub(now_ms()?)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| invalid("native lease expired before receipt"))?;
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| invalid("native grant deadline exceeds monotonic clock range"))?;
        Ok(Self {
            host,
            issued,
            closed: AtomicBool::new(false),
            deadline,
        })
    }

    #[must_use]
    pub fn receipt(&self) -> &NativeExecutionGrantReceipt {
        &self.issued.receipt
    }

    /// Local synchronous denial only. Native close below still owns/revokes the
    /// real registry token and drains the actual counted native operations.
    pub fn close_admission(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Fetch exact pinned recorded bytes through the native shared-handle
    /// facade. A current working overlay is never inferred from these bytes.
    /// # Errors
    /// Refuses a retired lease, actual host denial or any content/scope mismatch.
    pub async fn read_recorded_file(
        &self,
        request_id: &str,
        path: &str,
    ) -> Result<(GrantedFileReceipt, Vec<u8>)> {
        if self.closed.load(Ordering::SeqCst) || tokio::time::Instant::now() >= self.deadline {
            return Err(invalid("original native lease admission is closed"));
        }
        let grant = &self.issued.receipt;
        let receipt_digest = hash(&serde_json::to_vec(grant)?);
        let request = ReadGrantedFileRequest {
            request_id: request_id.into(),
            grant_id: grant.claim.grant_id.clone(),
            grant_receipt_digest: receipt_digest.clone(),
            token: self.issued.token.clone(),
            path: path.into(),
        };
        let Reply::GrantedFile { receipt } = self
            .host
            .request(Command::ReadGrantedFile { request })
            .await?
        else {
            return Err(invalid("expected pinned native file receipt"));
        };
        if receipt.request_id != request_id
            || receipt.grant_id != grant.claim.grant_id
            || receipt.grant_receipt_digest != receipt_digest
            || receipt.path != path
            || receipt.grant_state != grant.native_state
            || receipt.basis != GrantedReadBasis::PinnedGrantManifest
        {
            return Err(invalid(
                "native recorded read differs from original grant scope",
            ));
        }
        let bytes = decode_hex(&receipt.content_hex)?;
        if hash(&bytes) != receipt.content_sha256 {
            return Err(invalid(
                "native recorded read digest differs from exact bytes",
            ));
        }
        Ok((receipt, bytes))
    }

    /// Close the actual native token and wait for its real drain receipt.
    /// # Errors
    /// Returns host/transport uncertainty or a mismatched closure receipt.
    pub async fn close(&self) -> Result<ExecutionGrantClosed> {
        self.close_admission();
        let grant = &self.issued.receipt;
        let digest = hash(&serde_json::to_vec(grant)?);
        let request = CloseExecutionGrantRequest {
            grant_id: grant.claim.grant_id.clone(),
            grant_receipt_digest: digest.clone(),
            token: self.issued.token.clone(),
        };
        let Reply::ExecutionGrantClosed { receipt } = self
            .host
            .request(Command::CloseExecutionGrant { request })
            .await?
        else {
            return Err(invalid("expected actual native grant closure receipt"));
        };
        if receipt.grant_id != grant.claim.grant_id
            || receipt.grant_receipt_digest != digest
            || !receipt.admitted_reads_drained
        {
            return Err(invalid(
                "native grant closure did not acknowledge original operation drain",
            ));
        }
        Ok(receipt)
    }
}

impl Drop for NativeGrantLease {
    fn drop(&mut self) {
        self.close_admission();
    }
}
