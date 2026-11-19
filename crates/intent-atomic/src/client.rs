//! Sequential typed requests. Cancellation poisons the connection, never replays work.

use intent_atomic_proto::{Command, FailureCode, HostIdentity, Outcome, Reply, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{codec, HostError, Result};

pub struct HostClient<S> {
    stream: S,
    next_id: u64,
    usable: bool,
    recovery_ready: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HostClient<S> {
    /// Validate the exact host build, then reconcile before any store admission.
    /// # Errors
    /// Refuses incompatible identities, framing violations and transport failures.
    pub async fn connect(stream: S, expected: &HostIdentity) -> Result<Self> {
        let mut client = Self {
            stream,
            next_id: 1,
            usable: true,
            recovery_ready: false,
        };
        let response = client
            .exchange(Command::Handshake {
                identity: expected.clone(),
            })
            .await?;
        if !matches!(response, Reply::Handshake { identity } if identity == *expected) {
            return Err(HostError::IdentityMismatch);
        }
        client.request(Command::Reconcile).await?;
        Ok(client)
    }

    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    #[must_use]
    pub const fn recovery_ready(&self) -> bool {
        self.recovery_ready
    }

    /// Send once. A timeout or dropped future leaves this connection unusable.
    /// # Errors
    /// Returns recovery-required, protocol/transport errors or a typed host rejection.
    pub async fn request(&mut self, command: Command) -> Result<Reply> {
        if matches!(command, Command::Handshake { .. }) {
            return Err(HostError::Protocol(
                "handshake is only valid on connection setup",
            ));
        }
        if command.requires_recovery() && !self.recovery_ready {
            return Err(HostError::RecoveryRequired);
        }
        let reply = self.exchange(command).await?;
        if let Reply::Reconciled { recovery } = &reply {
            if recovery.ready && !recovery.unresolved_operation_ids.is_empty() {
                self.usable = false;
                return Err(HostError::Protocol(
                    "ready recovery retains uncertain operations",
                ));
            }
            self.recovery_ready = recovery.ready;
        }
        Ok(reply)
    }

    async fn exchange(&mut self, command: Command) -> Result<Reply> {
        if !self.usable {
            return Err(HostError::ConnectionUncertain);
        }
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or(HostError::Protocol("request id exhausted"))?;
        // Set before the first await: cancellation cannot leave a partially used
        // stream available to a later request with an unknown response boundary.
        self.usable = false;
        let request = Request { id, command };
        codec::write_frame(&mut self.stream, &request).await?;
        let response: Response = codec::read_frame(&mut self.stream).await?;
        if response.id != id {
            return Err(HostError::Protocol("response id mismatch"));
        }
        match response.outcome {
            Outcome::Success(reply) if reply.matches_command(&request.command) => {
                if matches!(reply.as_ref(), Reply::State { state, .. } if state.view.is_empty() ||
                    state.effective_state.is_empty() || state.own_merkle.is_empty())
                {
                    return Err(HostError::Protocol(
                        "host returned an empty native state identity",
                    ));
                }
                self.usable = true;
                Ok(*reply)
            }
            Outcome::Failure(error) => {
                if matches!(
                    error.code,
                    FailureCode::Uncertain | FailureCode::RecoveryRequired
                ) {
                    self.recovery_ready = false;
                }
                self.usable = error.code != FailureCode::IncompatibleHost;
                Err(HostError::Rejected(error))
            }
            Outcome::Success(_) => Err(HostError::Protocol("response type mismatch")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_atomic_proto::{RecoveryReport, StoreBinding};
    use tokio::io::DuplexStream;

    async fn respond(stream: &mut DuplexStream, id: u64, reply: Reply) {
        codec::write_frame(
            stream,
            &Response {
                id,
                outcome: Outcome::Success(Box::new(reply)),
            },
        )
        .await
        .unwrap();
    }

    async fn handshake(stream: &mut DuplexStream, recovery: RecoveryReport) {
        let request: Request = codec::read_frame(stream).await.unwrap();
        assert!(matches!(request.command, Command::Handshake { .. }));
        respond(
            stream,
            request.id,
            Reply::Handshake {
                identity: HostIdentity::default(),
            },
        )
        .await;
        let request: Request = codec::read_frame(stream).await.unwrap();
        assert_eq!(request.command, Command::Reconcile);
        respond(stream, request.id, Reply::Reconciled { recovery }).await;
    }

    fn ready() -> RecoveryReport {
        RecoveryReport {
            ready: true,
            unresolved_operation_ids: vec![],
        }
    }

    fn binding() -> StoreBinding {
        StoreBinding {
            repository_id: "repo".to_owned(),
            binding_epoch: 1,
            store_path: "/owned/native".into(),
        }
    }

    #[tokio::test]
    async fn every_handshake_identity_mismatch_refuses_before_recovery_or_store_open() {
        for index in 0..3 {
            let (client, mut server) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                let request: Request = codec::read_frame(&mut server).await.unwrap();
                let mut identity = HostIdentity::default();
                match index {
                    0 => identity.contract_version += 1,
                    1 => identity.atomic_revision = "different-build".to_owned(),
                    _ => identity.store_format += 1,
                }
                respond(&mut server, request.id, Reply::Handshake { identity }).await;
                let next: Result<Request> = codec::read_frame(&mut server).await;
                assert!(
                    next.is_err(),
                    "incompatible peer must not receive a store operation"
                );
            });
            assert!(matches!(
                HostClient::connect(client, &HostIdentity::default()).await,
                Err(HostError::IdentityMismatch)
            ));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn unresolved_recovery_refuses_store_admission() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            handshake(
                &mut server,
                RecoveryReport {
                    ready: false,
                    unresolved_operation_ids: vec!["uncertain-attempt".to_owned()],
                },
            )
            .await;
        });
        let mut client = HostClient::connect(client, &HostIdentity::default())
            .await
            .unwrap();
        assert!(!client.recovery_ready());
        assert!(matches!(
            client
                .request(Command::OpenStore { binding: binding() })
                .await,
            Err(HostError::RecoveryRequired)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_waiter_poisoned_connection_cannot_replay_a_request() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (sent, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            handshake(&mut server, ready()).await;
            let request: Request = codec::read_frame(&mut server).await.unwrap();
            assert_eq!(request.command, Command::Ping);
            sent.send(()).unwrap();
        });
        let mut client = HostClient::connect(client, &HostIdentity::default())
            .await
            .unwrap();
        let mut future = Box::pin(client.request(Command::Ping));
        tokio::select! {
            biased;
            result = received => result.unwrap(),
            result = &mut future => panic!("peer did not reply: {result:?}"),
        }
        drop(future);
        assert!(!client.is_usable());
        assert!(matches!(
            client.request(Command::Ping).await,
            Err(HostError::ConnectionUncertain)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_binding_in_a_response_poisoned_the_connection() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, ready()).await;
            let request: Request = codec::read_frame(&mut server).await.unwrap();
            let mut other = binding();
            other.binding_epoch += 1;
            respond(
                &mut server,
                request.id,
                Reply::StoreOpened { binding: other },
            )
            .await;
        });
        let mut client = HostClient::connect(client, &HostIdentity::default())
            .await
            .unwrap();
        assert!(matches!(
            client
                .request(Command::OpenStore { binding: binding() })
                .await,
            Err(HostError::Protocol("response type mismatch"))
        ));
        assert!(!client.is_usable());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn recovery_cannot_claim_ready_while_retaining_uncertain_operations() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            handshake(
                &mut server,
                RecoveryReport {
                    ready: true,
                    unresolved_operation_ids: vec!["uncertain".to_owned()],
                },
            )
            .await;
        });
        assert!(matches!(
            HostClient::connect(client, &HostIdentity::default()).await,
            Err(HostError::Protocol(
                "ready recovery retains uncertain operations"
            ))
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn host_uncertainty_closes_admission_until_reconciliation() {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, ready()).await;
            let request: Request = codec::read_frame(&mut server).await.unwrap();
            codec::write_frame(
                &mut server,
                &Response {
                    id: request.id,
                    outcome: Outcome::Failure(intent_atomic_proto::HostFailure {
                        code: FailureCode::Uncertain,
                        message: "retained attempt".to_owned(),
                        operation_id: Some("attempt".to_owned()),
                    }),
                },
            )
            .await
            .unwrap();
        });
        let mut client = HostClient::connect(client, &HostIdentity::default())
            .await
            .unwrap();
        assert!(matches!(
            client
                .request(Command::OpenStore { binding: binding() })
                .await,
            Err(HostError::Rejected(_))
        ));
        assert!(!client.recovery_ready());
        assert!(matches!(
            client
                .request(Command::OpenStore { binding: binding() })
                .await,
            Err(HostError::RecoveryRequired)
        ));
        task.await.unwrap();
    }
}
