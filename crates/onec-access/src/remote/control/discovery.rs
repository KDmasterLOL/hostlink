//! Capability negotiation and carrier-aware TCP probing.

use crate::AppResult;
use crate::remote::control::request::RequestTiming;
use crate::remote::model::{RemoteAgentClient, RemoteCarrier, RemoteProbeResult};
use crate::remote::protocol::{read_response_unbuffered, write_request};
use hostlink_protocol::{AgentRequest, AgentRequestKind, AgentResponseKind};
use std::time::Duration;

impl RemoteAgentClient {
    async fn capabilities(&self) -> AppResult<Vec<String>> {
        self.capabilities_with_timing(None).await
    }

    async fn capabilities_with_timing(
        &self,
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<Vec<String>> {
        if self.capabilities.get().is_none() {
            let response = self.hello_with_timing(timing).await?;
            if !matches!(response, AgentResponseKind::Hello { .. }) {
                return Err(crate::invalid_config(
                    "remote agent returned a non-hello response".to_owned(),
                ));
            }
        }
        self.capabilities
            .get()
            .cloned()
            .ok_or_else(|| crate::invalid_config("remote agent did not publish capabilities"))
    }

    /// Returns whether the remote agent advertises one exact capability.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when Hello/capability discovery fails.
    pub async fn supports_capability(&self, required: &str) -> AppResult<bool> {
        Ok(self
            .capabilities()
            .await?
            .iter()
            .any(|capability| capability == required))
    }

    /// Requires one exact capability before a controller operation proceeds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when discovery fails or the capability is absent.
    pub async fn require_capability(&self, required: &str) -> AppResult<()> {
        self.require_capabilities(&[required]).await
    }

    /// Requires every capability in the supplied set.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when discovery fails or any capability is absent.
    pub async fn require_capabilities(&self, required: &[&str]) -> AppResult<()> {
        self.require_capabilities_with_timing(required, None).await
    }

    pub(super) async fn require_capability_with_timing(
        &self,
        required: &str,
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<()> {
        self.require_capabilities_with_timing(&[required], timing)
            .await
    }

    async fn require_capabilities_with_timing(
        &self,
        required: &[&str],
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<()> {
        let capabilities = match timing {
            Some(timing) => self.capabilities_with_timing(Some(timing)).await?,
            None => self.capabilities().await?,
        };
        if let Some(required) = required.iter().find(|required| {
            !capabilities
                .iter()
                .any(|capability| capability == **required)
        }) {
            return Err(crate::invalid_config(format!(
                "remote agent {} does not support required capability {required:?}; update onec-agent",
                self.server.name
            )));
        }
        Ok(())
    }

    /// Requires the capability for a read-only durable-job observation.
    ///
    /// If discovery is cold, one typed approved-route establishment failure may consume the
    /// observation's single reconnect allowance. Generic capability discovery remains unchanged.
    pub(crate) async fn require_job_observation_capability(
        &self,
        required: &str,
    ) -> AppResult<bool> {
        let retried_hello = if self.capabilities.get().is_none() {
            match self.hello().await {
                Ok(AgentResponseKind::Hello { .. }) => false,
                Ok(_) => {
                    return Err(crate::invalid_config(
                        "remote agent returned a non-hello response".to_owned(),
                    ));
                }
                Err(error) if super::request::may_retry_pre_submission_route(&error) => {
                    match self.hello().await? {
                        AgentResponseKind::Hello { .. } => true,
                        _ => {
                            return Err(crate::invalid_config(
                                "remote agent returned a non-hello response".to_owned(),
                            ));
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        } else {
            false
        };

        self.require_capability(required).await?;
        Ok(retried_hello)
    }

    /// Probes one remote TCP target through the selected carrier without opening a persistent relay.
    ///
    /// Target-SSH probes use an embedded direct-tcpip channel; gateway-control probes use the
    /// resident agent protocol.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for invalid host/port/timeout, control-protocol failures, or an
    /// unexpected protocol response. Ordinary target-connect failure is represented in the result.
    pub async fn probe(
        &self,
        host: impl Into<String>,
        port: u16,
        timeout_ms: u64,
    ) -> AppResult<RemoteProbeResult> {
        let host = host.into();
        if host.trim().is_empty() || port == 0 || timeout_ms == 0 {
            return Err(crate::invalid_config(
                "remote TCP probe requires a non-empty host, non-zero port, and positive timeout"
                    .to_owned(),
            ));
        }
        if self.server.carrier == RemoteCarrier::TargetSsh {
            return match self
                .open_target_tcp_channel(&host, port, Duration::from_millis(timeout_ms))
                .await
            {
                Ok(mut channel) => match channel.finish().await {
                    Ok(()) => Ok(RemoteProbeResult {
                        reachable: true,
                        error: None,
                    }),
                    Err(error) => Ok(RemoteProbeResult {
                        reachable: false,
                        error: Some(error.to_string()),
                    }),
                },
                Err(error) => Ok(RemoteProbeResult {
                    reachable: false,
                    error: Some(error.to_string()),
                }),
            };
        }

        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::TcpConnect {
                host,
                port,
                timeout_ms,
            },
        );
        let mut channel = self.open_channel().await?;
        write_request(&mut channel, &request)
            .await
            .map_err(|source| {
                crate::invalid_config(format!("failed to send TCP probe request: {source}"))
            })?;
        let response = read_response_unbuffered(&mut channel).await?;
        let transport = channel.finish().await;
        if !response.ok {
            return Ok(RemoteProbeResult {
                reachable: false,
                error: Some(
                    response
                        .error
                        .unwrap_or_else(|| "remote target connection failed".to_owned()),
                ),
            });
        }
        transport?;
        match response.response {
            Some(AgentResponseKind::TcpReady) => Ok(RemoteProbeResult {
                reachable: true,
                error: None,
            }),
            other => Err(crate::invalid_config(format!(
                "agent returned unexpected TCP probe response: {other:?}"
            ))),
        }
    }
}
