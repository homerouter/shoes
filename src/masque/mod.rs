pub mod auth;
pub mod connect;
pub mod h2_server;
pub mod h3_server;
#[allow(dead_code)] // Wired into MASQUE UDP/IP handlers in Tasks 4-6.
pub mod wire;

#[cfg(test)]
mod tests;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::MasqueServerConfig;
use crate::resolver::Resolver;
use crate::resources::Budget;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

use auth::MasqueAuth;

#[derive(Clone)]
pub(crate) struct MasqueConnCtx {
    pub(crate) config: Arc<MasqueServerConfig>,
    pub(crate) auth: Arc<MasqueAuth>,
    pub(crate) selector: Arc<ClientProxySelector>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) peer: SocketAddr,
    pub(crate) peer_authenticated_by_mtls: bool,
}

#[derive(Debug, Clone)]
pub struct MasqueServer {
    config: Arc<MasqueServerConfig>,
    auth: Arc<MasqueAuth>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    requests: Arc<Budget>,
}

impl MasqueServer {
    pub fn new(
        config: MasqueServerConfig,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        config.validate()?;
        let users = config.users.clone().into_vec();
        let auth = Arc::new(MasqueAuth::from_users(&users, config.stealth_404)?);
        let requests = Arc::new(Budget::new(Some(config.max_concurrent_requests)));
        Ok(Self {
            config: Arc::new(config),
            auth,
            selector,
            resolver,
            requests,
        })
    }

    pub(crate) fn conn_ctx(
        &self,
        peer: SocketAddr,
        peer_authenticated_by_mtls: bool,
    ) -> MasqueConnCtx {
        MasqueConnCtx {
            config: self.config.clone(),
            auth: self.auth.clone(),
            selector: self.selector.clone(),
            resolver: self.resolver.clone(),
            peer,
            peer_authenticated_by_mtls,
        }
    }

    pub async fn serve_h3(&self, connection: quinn::Connection) -> io::Result<()> {
        h3_server::serve_h3(self, connection).await
    }

    pub async fn serve_h2_stream<IO: AsyncStream + 'static>(
        &self,
        stream: IO,
        peer: SocketAddr,
        peer_authenticated_by_mtls: bool,
    ) -> io::Result<()> {
        h2_server::serve_h2_stream(self, stream, peer, peer_authenticated_by_mtls).await
    }
}

#[async_trait]
impl TcpServerHandler for MasqueServer {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let server = self.clone();
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            if let Err(err) = server.serve_h2_stream(stream, peer, false).await {
                log::debug!("MASQUE H2 session ended: {err}");
            }
        })))
    }
}
