//! Client construction and identity/capability discovery.

use crate::AppResult;
use crate::remote::control::request::RequestTiming;
use crate::remote::model::{RemoteAgentClient, RemoteServer};
use hostlink_protocol::{AgentRequestKind, AgentResponseKind};

impl RemoteAgentClient {
    /// Creates a remote-agent client after validating the projected server/trust contract.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the server projection is invalid.
    pub fn new(server: RemoteServer) -> AppResult<Self> {
        server.validate()?;
        Ok(Self {
            server,
            capabilities: Default::default(),
        })
    }

    /// Returns the immutable projected remote-server configuration.
    pub fn server(&self) -> &RemoteServer {
        &self.server
    }

    /// Performs agent Hello negotiation and caches advertised capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the control channel/request/response fails.
    pub async fn hello(&self) -> AppResult<AgentResponseKind> {
        self.hello_with_timing(None).await
    }

    pub(super) async fn hello_with_timing(
        &self,
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<AgentResponseKind> {
        let response = self
            .request_with_timing(AgentRequestKind::Hello, timing)
            .await?;
        if let AgentResponseKind::Hello { capabilities, .. } = &response {
            let _ = self.capabilities.set(capabilities.clone());
        }
        Ok(response)
    }
}
