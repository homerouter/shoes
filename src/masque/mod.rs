pub mod auth;
pub mod connect;
pub mod connect_ip;
pub mod connect_udp;
pub mod h2_server;
pub mod h3_server;
pub mod ip_pool;
pub mod wire;

#[cfg(test)]
mod tests;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3_datagram::datagram_handler::SendDatagramError;
use http::{Response, StatusCode};

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::MasqueServerConfig;
use crate::resolver::Resolver;
use crate::resources::Budget;

use auth::MasqueAuth;
use connect_ip::MasqueIpEngine;
use wire::{Capsule, CapsuleDecoder, IpUriTemplate, UdpUriTemplate, encode_capsule};

const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
/// Request header block limit, shared by H2 and H3.
pub(crate) const MAX_HEADER_BYTES: u32 = 64 * 1024;
/// Largest capsule accepted from a client: one maximal UDP payload or IP packet plus framing.
pub(crate) const MAX_CAPSULE_BYTES: usize = 64 * 1024 + 16;
/// An H2 connection with no requests is closed after this long.
pub(crate) const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
/// A send that the peer does not grant flow-control credit for fails after this long.
const SEND_STALL_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn capsule_decoder() -> CapsuleDecoder {
    CapsuleDecoder::with_max_capsule_size(MAX_CAPSULE_BYTES)
}

fn send_stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "MASQUE peer stopped reading")
}

pub(crate) fn capsule_ok_response() -> Response<()> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CAPSULE_PROTOCOL_HEADER, "?1")
        .body(())
        .expect("valid capsule response")
}

pub(crate) fn status_response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .body(())
        .expect("valid status response")
}

pub(crate) fn feed_capsule_buf(decoder: &mut CapsuleDecoder, chunk: &mut impl Buf) {
    while chunk.has_remaining() {
        let bytes = chunk.chunk();
        decoder.feed(bytes);
        let len = bytes.len();
        chunk.advance(len);
    }
}

pub(crate) fn feed_h2_capsule_chunk(
    recv: &mut h2::RecvStream,
    decoder: &mut CapsuleDecoder,
    chunk: &[u8],
) -> io::Result<()> {
    decoder.feed(chunk);
    if !chunk.is_empty() {
        recv.flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
    }
    Ok(())
}

pub(crate) async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = loop {
            let current = send.capacity();
            if current > 0 {
                break current;
            }
            let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx));
            match tokio::time::timeout(SEND_STALL_TIMEOUT, capacity)
                .await
                .map_err(|_| send_stalled())?
            {
                Some(Ok(_)) => continue,
                Some(Err(err)) => return Err(io::Error::other(err)),
                None => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        };
        let n = cap.min(data.len());
        send.send_data(data.split_to(n), false)
            .map_err(io::Error::other)?;
    }
    Ok(())
}

pub(crate) async fn send_h3_data_with_timeout<S: h3::quic::SendStream<Bytes>>(
    send_stream: &mut h3::server::RequestStream<S, Bytes>,
    data: Bytes,
    timeout: Duration,
) -> io::Result<()> {
    tokio::time::timeout(timeout, send_stream.send_data(data))
        .await
        .map_err(|_| send_stalled())?
        .map_err(io::Error::other)
}

pub(crate) async fn send_h3_data<S: h3::quic::SendStream<Bytes>>(
    send_stream: &mut h3::server::RequestStream<S, Bytes>,
    data: Bytes,
) -> io::Result<()> {
    send_h3_data_with_timeout(send_stream, data, SEND_STALL_TIMEOUT).await
}

pub(crate) async fn send_h3_datagram_or_capsule<S: h3::quic::SendStream<Bytes>>(
    dgram_sender: &mut h3_server::H3DatagramSender,
    send_stream: &mut h3::server::RequestStream<S, Bytes>,
    datagrams_unavailable: &mut bool,
    encoded_context0: Bytes,
    fallback_on_too_large: bool,
) -> io::Result<()> {
    if !*datagrams_unavailable {
        match dgram_sender.send_datagram(encoded_context0.clone()) {
            Ok(()) => return Ok(()),
            Err(SendDatagramError::NotAvailable { .. }) => {
                *datagrams_unavailable = true;
            }
            Err(SendDatagramError::TooLarge { .. }) => {
                if !fallback_on_too_large {
                    log::debug!(
                        "MASQUE H3 datagram too large ({} bytes); dropping",
                        encoded_context0.len()
                    );
                    return Ok(());
                }
            }
            Err(err @ SendDatagramError::ConnectionError { .. }) => {
                return Err(io::Error::other(err));
            }
            Err(_) => {
                *datagrams_unavailable = true;
            }
        }
    }
    let capsule = encode_capsule(&Capsule::Datagram(encoded_context0));
    send_h3_data(send_stream, capsule).await
}

#[derive(Clone)]
pub(crate) struct MasqueConnCtx {
    pub(crate) config: Arc<MasqueServerConfig>,
    pub(crate) auth: Arc<MasqueAuth>,
    pub(crate) udp_template: Arc<UdpUriTemplate>,
    pub(crate) ip_template: Arc<IpUriTemplate>,
    pub(crate) ip_engine: Option<Arc<MasqueIpEngine>>,
    pub(crate) selector: Arc<ClientProxySelector>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) peer: SocketAddr,
    pub(crate) peer_authenticated_by_mtls: bool,
}

#[derive(Debug, Clone)]
pub struct MasqueServer {
    config: Arc<MasqueServerConfig>,
    auth: Arc<MasqueAuth>,
    udp_template: Arc<UdpUriTemplate>,
    ip_template: Arc<IpUriTemplate>,
    ip_engine: Option<Arc<MasqueIpEngine>>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
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
        let udp_template = Arc::new(UdpUriTemplate::parse(&config.udp_template)?);
        let ip_template = Arc::new(IpUriTemplate::parse(&config.ip_template)?);
        let ip_engine = if config.ip_enabled {
            Some(MasqueIpEngine::new(
                &config,
                selector.clone(),
                resolver.clone(),
            )?)
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            auth,
            udp_template,
            ip_template,
            ip_engine,
            selector,
            resolver,
        })
    }

    /// Request slots for one connection, so one client cannot starve the others.
    pub(crate) fn connection_budget(&self) -> Arc<Budget> {
        Arc::new(Budget::new(Some(self.config.max_concurrent_requests)))
    }

    #[cfg(test)]
    pub fn ip_engine(&self) -> Option<&Arc<MasqueIpEngine>> {
        self.ip_engine.as_ref()
    }

    pub(crate) fn conn_ctx(
        &self,
        peer: SocketAddr,
        peer_authenticated_by_mtls: bool,
    ) -> MasqueConnCtx {
        MasqueConnCtx {
            config: self.config.clone(),
            auth: self.auth.clone(),
            udp_template: self.udp_template.clone(),
            ip_template: self.ip_template.clone(),
            ip_engine: self.ip_engine.clone(),
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
