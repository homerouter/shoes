use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{ready, Context, Poll};

use argon2::{Config as Argon2Config, ThreadMode, Variant, Version};
use async_trait::async_trait;
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::aead::{snell_kdf, Aead};
use super::auth::SnellAuth;
use super::client_pool::{drain_server, write_zero_chunk, SnellClientPool};
pub use super::obfs::SnellObfsMode;
use super::obfs::{HttpObfsStream, TlsObfsClientStream};
use super::quic_proxy::SnellQuicProxyStream;
use super::replay::SaltReplayCache;
use super::snell_fixed_target_stream::SnellFixedTargetStream;
use super::snell_udp_stream::{SnellUdpClientStream, SnellUdpStream};
use super::v4::{V4Conn, MAX_PAYLOAD_LENGTH};
use super::v6::{SnellV6Mode, V6Codec, V6Conn, MAX_RECORD_PAYLOAD};
use super::v6_shape::ShapeProfile;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{handle_h2mux_session, MUX_DESTINATION_HOST, MUX_DESTINATION_PORT};
use crate::prepend_stream::PrependStream;
use crate::resolver::Resolver;
use crate::shadowsocks::{
    ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::stream_reader::StreamReader;
use crate::tcp::carrier_dialer::CarrierDialer;
use crate::tcp::tcp_handler::{
    ClientTransport, ReusableTcpStream, TcpClientHandler, TcpClientSetupResult, TcpServerHandler,
    TcpServerSetupResult, TcpSession,
};
use crate::util::write_all;

const SNELL_SALT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnellVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
}

impl SnellVersion {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "1" | "v1" => Some(Self::V1),
            "2" | "v2" => Some(Self::V2),
            "3" | "v3" => Some(Self::V3),
            "4" | "v4" => Some(Self::V4),
            "5" | "v5" => Some(Self::V5),
            "6" | "v6" => Some(Self::V6),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V4 => "v4",
            Self::V5 => "v5",
            Self::V6 => "v6",
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
        }
    }
}

pub enum SnellFramedStream<S> {
    V3(ShadowsocksStream),
    V4(V4Conn<S>),
    V6(V6Conn<S>),
}

impl<S: AsyncStream> SnellFramedStream<S> {
    pub fn max_payload_len(&self) -> usize {
        match self {
            Self::V3(_) => ShadowsocksStreamType::Aead.max_payload_len(),
            Self::V4(_) => MAX_PAYLOAD_LENGTH,
            Self::V6(_) => MAX_RECORD_PAYLOAD,
        }
    }
}

impl<S: AsyncStream> AsyncRead for SnellFramedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_read(cx, buf),
            Self::V4(s) => Pin::new(s).poll_read(cx, buf),
            Self::V6(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncStream> AsyncWrite for SnellFramedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_write(cx, buf),
            Self::V4(s) => Pin::new(s).poll_write(cx, buf),
            Self::V6(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_flush(cx),
            Self::V4(s) => Pin::new(s).poll_flush(cx),
            Self::V6(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_shutdown(cx),
            Self::V4(s) => Pin::new(s).poll_shutdown(cx),
            Self::V6(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl<S: AsyncStream> AsyncPing for SnellFramedStream<S> {
    fn supports_ping(&self) -> bool {
        match self {
            Self::V3(s) => s.supports_ping(),
            Self::V4(s) => s.supports_ping(),
            Self::V6(s) => s.supports_ping(),
        }
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_write_ping(cx),
            Self::V4(s) => Pin::new(s).poll_write_ping(cx),
            Self::V6(s) => Pin::new(s).poll_write_ping(cx),
        }
    }
}

impl<S: AsyncStream> AsyncStream for SnellFramedStream<S> {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::V3(s) => s.local_addr(),
            Self::V4(s) => s.local_addr(),
            Self::V6(s) => s.local_addr(),
        }
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::V3(s) => s.peer_addr(),
            Self::V4(s) => s.peer_addr(),
            Self::V6(s) => s.peer_addr(),
        }
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        match self {
            Self::V3(s) => AsyncStream::flow(s),
            Self::V4(s) => AsyncStream::flow(s),
            Self::V6(s) => AsyncStream::flow(s),
        }
    }
}

impl<S: AsyncStream> AsyncReadMessage for SnellFramedStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_read_message(cx, buf),
            Self::V4(s) => Pin::new(s).poll_read_message(cx, buf),
            Self::V6(s) => Pin::new(s).poll_read_message(cx, buf),
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for SnellFramedStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_write_message(cx, buf),
            Self::V4(s) => Pin::new(s).poll_write_message(cx, buf),
            Self::V6(s) => Pin::new(s).poll_write_message(cx, buf),
        }
    }
}

impl<S: AsyncStream> AsyncFlushMessage for SnellFramedStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_flush_message(cx),
            Self::V4(s) => Pin::new(s).poll_flush_message(cx),
            Self::V6(s) => Pin::new(s).poll_flush_message(cx),
        }
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for SnellFramedStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::V3(s) => Pin::new(s).poll_shutdown_message(cx),
            Self::V4(s) => Pin::new(s).poll_shutdown_message(cx),
            Self::V6(s) => Pin::new(s).poll_shutdown_message(cx),
        }
    }
}

impl<S: AsyncStream> AsyncMessageStream for SnellFramedStream<S> {
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        match self {
            Self::V3(s) => AsyncMessageStream::flow(s),
            Self::V4(s) => AsyncMessageStream::flow(s),
            Self::V6(s) => AsyncMessageStream::flow(s),
        }
    }
}

// Handshake reads must not coalesce the following UDP packet into the header buffer.
struct HeaderReader<'a, S: AsyncStream>(&'a mut SnellFramedStream<S>);

impl<S: AsyncStream> AsyncRead for HeaderReader<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read_message(cx, buf)
    }
}

// Snell protocol Argon2 parameters
const SNELL_ARGON2_CONFIG: Argon2Config<'static> = Argon2Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 8,  // 8 KB
    time_cost: 3, // 3 iterations
    lanes: 1,     // parallelism = 1
    thread_mode: ThreadMode::Sequential,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

#[derive(Debug, Clone)]
struct SnellKey {
    password_bytes: Box<[u8]>,
    key_len: usize,
}

impl SnellKey {
    pub fn new(password: &str, key_len: usize) -> Self {
        Self {
            password_bytes: password.as_bytes().to_vec().into_boxed_slice(),
            key_len,
        }
    }
}

impl ShadowsocksKey for SnellKey {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let output = argon2::hash_raw(&self.password_bytes, salt, &SNELL_ARGON2_CONFIG).unwrap();

        if self.key_len == 32 {
            output.into_boxed_slice()
        } else {
            output[0..self.key_len].to_vec().into_boxed_slice()
        }
    }
}

#[derive(Debug)]
pub struct SnellServerHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    password: String,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    version: Option<SnellVersion>,
    v6_mode: SnellV6Mode,
    auth: Arc<SnellAuth>,
    replay: Arc<SaltReplayCache>,
    obfs_mode: Option<SnellObfsMode>,
}

impl SnellServerHandler {
    pub fn new(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        version: Option<&str>,
        mode: Option<&str>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        let parsed_version = version.and_then(SnellVersion::parse);
        let v6_mode = mode.and_then(SnellV6Mode::parse).unwrap_or_default();
        Self {
            cipher,
            key,
            password: password.to_string(),
            udp_enabled,
            proxy_selector,
            resolver,
            version: parsed_version,
            v6_mode,
            auth: Arc::new(SnellAuth::Single),
            replay: Arc::new(SaltReplayCache::new()),
            obfs_mode: None,
        }
    }

    /// Multi-user authentication (`users`); without it the shared password
    /// authenticates.
    pub fn with_auth(mut self, auth: SnellAuth) -> Self {
        self.auth = Arc::new(auth);
        self
    }

    pub fn with_obfs(mut self, mode: Option<SnellObfsMode>) -> Self {
        self.obfs_mode = mode;
        self
    }

    /// psk mode: frames the stream with the PSK of the user whose key opens
    /// its first header.
    async fn frame_psk_user(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<(SnellFramedStream<Box<dyn AsyncStream>>, Option<[u8; 16]>)> {
        let mut head = vec![0u8; self.auth.psk_head_len()];
        server_stream.read_exact(&mut head).await?;
        let user = self.auth.match_psk(&head).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "snell: authentication failed: no matching PSK",
            )
        })?;
        debug!("Snell user authenticated: {}", user.name);
        let salt: [u8; 16] = head[..16].try_into().unwrap();
        let prepended: Box<dyn AsyncStream> =
            Box::new(PrependStream::new(server_stream, Some(head.into_boxed_slice())));
        Ok(match &user.v6 {
            Some(codec) => (
                SnellFramedStream::V6(V6Conn::new(prepended, user.psk.clone(), codec.clone())),
                None,
            ),
            None => (
                SnellFramedStream::V4(V4Conn::new(prepended, user.psk.clone())),
                Some(salt),
            ),
        })
    }

    async fn detect_and_frame_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<(SnellFramedStream<Box<dyn AsyncStream>>, Option<[u8; 16]>)> {
        let psk = self.password.as_bytes();
        if self.auth.is_psk() {
            return self.frame_psk_user(server_stream).await;
        }

        // If explicit version is configured:
        match self.version {
            Some(SnellVersion::V4 | SnellVersion::V5) => {
                let mut salt = [0u8; 16];
                server_stream.read_exact(&mut salt).await?;
                let prepended: Box<dyn AsyncStream> =
                    Box::new(PrependStream::new(server_stream, Some(Box::from(salt))));
                return Ok((
                    SnellFramedStream::V4(V4Conn::new(prepended, Arc::from(psk))),
                    Some(salt),
                ));
            }
            Some(SnellVersion::V6) => {
                let conn = V6Conn::new(
                    server_stream,
                    Arc::from(psk),
                    V6Codec::new(self.v6_mode, psk),
                );
                return Ok((SnellFramedStream::V6(conn), None));
            }
            Some(SnellVersion::V1 | SnellVersion::V2 | SnellVersion::V3) => {
                let ss_stream = ShadowsocksStream::new(
                    server_stream,
                    ShadowsocksStreamType::Aead,
                    self.cipher.algorithm(),
                    SNELL_SALT_LEN,
                    self.key.clone(),
                    None,
                );
                return Ok((SnellFramedStream::V3(ss_stream), None));
            }
            None => {}
        }

        // If cipher is not AES-128-GCM, v4/v5/v6 official specs are not
        // applicable; fall back to V3 directly.
        if self.cipher.name() != "aes-128-gcm" {
            let ss_stream = ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                self.cipher.algorithm(),
                SNELL_SALT_LEN,
                self.key.clone(),
                None,
            );
            return Ok((SnellFramedStream::V3(ss_stream), None));
        }

        // Auto-detection between V6 (default mode), V4/V5, and V3:
        let v6_profile = ShapeProfile::new(psk);
        let v6_min = v6_profile.salt_block_len() + v6_profile.prefix_len(0) + 23;
        let needed = v6_min.max(39);

        let mut initial_buf = Vec::with_capacity(needed + 128);
        let mut tmp = [0u8; 512];

        loop {
            let n = server_stream.read(&mut tmp).await?;
            if n == 0 {
                if initial_buf.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF before Snell handshake",
                    ));
                }
                break;
            }
            initial_buf.extend_from_slice(&tmp[..n]);

            // 1. Try Snell v6 default mode
            if initial_buf.len() >= v6_min {
                let salt = v6_profile.read_salt_block(&initial_buf[..v6_profile.salt_block_len()]);
                let session_key = snell_kdf(psk, &salt, 16);
                let aead = Aead::aes_128_gcm(&session_key);
                let prefix_start = v6_profile.salt_block_len();
                let prefix_end = prefix_start + v6_profile.prefix_len(0);
                let prefix = &initial_buf[prefix_start..prefix_end];
                let hdr_bytes = &initial_buf[prefix_end..prefix_end + 23];
                let mut hdr_plain = hdr_bytes[..7].to_vec();
                if aead
                    .open_detached(&[0; 12], prefix, &mut hdr_plain, &hdr_bytes[7..23])
                    .is_ok()
                    && hdr_plain[0] == 4
                {
                    let prepended: Box<dyn AsyncStream> = Box::new(PrependStream::new(
                        server_stream,
                        Some(initial_buf.into_boxed_slice()),
                    ));
                    let conn = V6Conn::new(
                        prepended,
                        Arc::from(psk),
                        V6Codec::new(SnellV6Mode::Default, psk),
                    );
                    return Ok((SnellFramedStream::V6(conn), None));
                }
            }

            // 2. Try Snell v4 / v5
            if initial_buf.len() >= 39 {
                let salt: [u8; 16] = initial_buf[..16].try_into().unwrap();
                let session_key = snell_kdf(psk, &salt, 16);
                let aead = Aead::aes_128_gcm(&session_key);
                let hdr_bytes = &initial_buf[16..39];
                let mut hdr_plain = hdr_bytes[..7].to_vec();
                if aead
                    .open_detached(&[0; 12], &[], &mut hdr_plain, &hdr_bytes[7..23])
                    .is_ok()
                    && hdr_plain[0] == 4
                {
                    let prepended: Box<dyn AsyncStream> = Box::new(PrependStream::new(
                        server_stream,
                        Some(initial_buf.into_boxed_slice()),
                    ));
                    let conn = V4Conn::new(prepended, Arc::from(psk));
                    return Ok((SnellFramedStream::V4(conn), Some(salt)));
                }
            }

            // 3. Try Snell v3
            if initial_buf.len() >= 34 {
                let salt = &initial_buf[..16];
                let session_key = snell_kdf(psk, salt, 16);
                let aead = Aead::aes_128_gcm(&session_key);
                let len_bytes = &initial_buf[16..34];
                let mut len_plain = len_bytes[..2].to_vec();
                if aead
                    .open_detached(&[0; 12], &[], &mut len_plain, &len_bytes[2..18])
                    .is_ok()
                {
                    let chunk_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
                    if chunk_len <= 0x3FFF {
                        let prepended: Box<dyn AsyncStream> = Box::new(PrependStream::new(
                            server_stream,
                            Some(initial_buf.into_boxed_slice()),
                        ));
                        let ss_stream = ShadowsocksStream::new(
                            prepended,
                            ShadowsocksStreamType::Aead,
                            self.cipher.algorithm(),
                            SNELL_SALT_LEN,
                            self.key.clone(),
                            None,
                        );
                        return Ok((SnellFramedStream::V3(ss_stream), None));
                    }
                }
            }

            if initial_buf.len() >= needed {
                break;
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to detect Snell protocol version (invalid PSK or unrecognized framing)",
        ))
    }
}

const TCP_TUNNEL_RESPONSE: &[u8] = &[0x0];
const UDP_READY_RESPONSE: &[u8] = TCP_TUNNEL_RESPONSE;

const CMD_PING: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_CONNECT_V2: u8 = 5;
const CMD_UDP: u8 = 6;

/// A parsed Snell request header.
struct SnellRequest {
    command: u8,
    /// Names the user in userkey authentication.
    client_id: Box<[u8]>,
    /// Destination of a connect request.
    location: Option<NetLocation>,
}

/// Reads one request header. Ping stops after the command byte, without
/// consuming its client-id bytes (snell-server v5.0.1, per sing-snell).
async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut StreamReader,
    stream: &mut R,
) -> std::io::Result<SnellRequest> {
    let version = reader.read_u8(stream).await?;
    if version != 1 {
        return Err(std::io::Error::other(format!(
            "unexpected snell version: {version}"
        )));
    }
    let command = reader.read_u8(stream).await?;
    if command == CMD_PING {
        return Ok(SnellRequest {
            command,
            client_id: Box::default(),
            location: None,
        });
    }
    if !matches!(command, CMD_CONNECT | CMD_CONNECT_V2 | CMD_UDP) {
        return Err(std::io::Error::other(format!(
            "Got unknown command: {command}"
        )));
    }
    let client_id_len = reader.read_u8(stream).await? as usize;
    let client_id: Box<[u8]> = reader.read_slice(stream, client_id_len).await?.into();
    if command == CMD_UDP {
        return Ok(SnellRequest {
            command,
            client_id,
            location: None,
        });
    }
    let hostname_len = reader.read_u8(stream).await? as usize;
    let hostname_and_port_bytes = reader.read_slice(stream, hostname_len + 2).await?;
    let hostname_str = match std::str::from_utf8(&hostname_and_port_bytes[0..hostname_len]) {
        Ok(s) => s,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode hostname: {e}"),
            ));
        }
    };
    let port = u16::from_be_bytes(hostname_and_port_bytes[hostname_len..].try_into().unwrap());
    Ok(SnellRequest {
        command,
        client_id,
        location: Some(NetLocation::new(Address::from(hostname_str)?, port)),
    })
}

/// Starts a UDP relay after a cmd 6 request. `leftover` holds bytes read
/// past the request header.
async fn udp_relay(
    mut stream: SnellFramedStream<Box<dyn AsyncStream>>,
    leftover: &[u8],
    udp_enabled: bool,
    proxy_selector: &Arc<ClientProxySelector>,
) -> std::io::Result<TcpServerSetupResult> {
    if !udp_enabled {
        return Err(std::io::Error::other("snell UDP requested but not enabled"));
    }
    // snell-server v6.0.0b4 (per sing-snell): the first datagram must not
    // share the request's record.
    if matches!(stream, SnellFramedStream::V6(_)) && !leftover.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UDP tunnel request",
        ));
    }
    let max_payload_len = stream.max_payload_len();
    write_all(&mut stream, UDP_READY_RESPONSE).await?;
    let peer = stream.peer_addr();
    let udp_stream = SnellUdpStream::new(Box::new(stream), max_payload_len).with_peer(peer);
    Ok(TcpServerSetupResult::MultiDirectionalUdp {
        stream: Box::new(udp_stream),
        need_initial_flush: true,
        proxy_selector: proxy_selector.clone(),
    })
}

/// Reply when the remote ends a reusable session before sending anything.
const REMOTE_EOF_REPLY: &[u8] = b"\x02\x65\x0aRemote EOF";
/// v4/v5 reply when the remote ends a cmd 1 tunnel before sending anything.
const END_OF_FILE_REPLY: &[u8] = b"\x02\xff\x0bend of file";
/// Client bytes discarded after the server's zero chunk before giving up
/// (sing-snell `reuse.WaitingDiscardLimit`).
const DRAIN_LIMIT: usize = 0x80001;

/// Write side of one tunnel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelWrite {
    /// Nothing sent yet: the first payload carries the `0x00` reply.
    ReplyPending,
    /// `0x00 ++ payload` is staged in the inner stream; its count is owed.
    ReplyStaged,
    Open,
    /// Writing the session's last record: a zero chunk (`b""`) or an error reply.
    Ending { record: &'static [u8], close: bool },
    Flushing { close: bool },
    /// Zero chunk sent: client data is discarded until its zero chunk.
    Draining,
    /// The connection is closed.
    Closed,
}

/// A v4/v5/v6 server tunnel that replies and ends sessions as sing-snell
/// does. With `reuse` (cmd 5) the connection carries further requests.
struct SnellTunnelStream {
    inner: SnellFramedStream<Box<dyn AsyncStream>>,
    reuse: bool,
    write: TunnelWrite,
    read_eof: bool,
    drained: usize,
    scratch: Vec<u8>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    auth: Arc<SnellAuth>,
}

impl SnellTunnelStream {
    fn new(
        inner: SnellFramedStream<Box<dyn AsyncStream>>,
        reuse: bool,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        auth: Arc<SnellAuth>,
    ) -> Self {
        Self {
            inner,
            reuse,
            write: TunnelWrite::ReplyPending,
            read_eof: false,
            drained: 0,
            scratch: Vec::new(),
            udp_enabled,
            proxy_selector,
            auth,
        }
    }
}

impl AsyncRead for SnellTunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write == TunnelWrite::Closed || this.read_eof || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.write == TunnelWrite::Draining {
            let mut tmp = [0u8; 4096];
            loop {
                let mut discard = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut discard))?;
                let n = discard.filled().len();
                if n == 0 {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.drained += n;
                if this.drained >= DRAIN_LIMIT {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snell: read too much data after request end",
                    )));
                }
            }
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.read_eof = buf.filled().len() == before;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnellTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.write {
            TunnelWrite::ReplyPending => {
                this.scratch.clear();
                this.scratch.push(0x00);
                this.scratch.extend_from_slice(buf);
                this.write = TunnelWrite::ReplyStaged;
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                this.write = TunnelWrite::Open;
                Poll::Ready(Ok(n.saturating_sub(1)))
            }
            // The inner stream finishes the staged frame first and reports its count.
            TunnelWrite::ReplyStaged => {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                this.write = TunnelWrite::Open;
                Poll::Ready(Ok(n.saturating_sub(1)))
            }
            TunnelWrite::Open => Pin::new(&mut this.inner).poll_write(cx, buf),
            _ => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "snell session write side closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write == TunnelWrite::Closed {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    /// Ends the session's write side: a zero chunk after data (reuse), else
    /// an error reply or a close, per sing-snell.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            this.write = match this.write {
                TunnelWrite::ReplyPending if this.reuse => TunnelWrite::Ending {
                    record: REMOTE_EOF_REPLY,
                    close: true,
                },
                TunnelWrite::ReplyPending if matches!(this.inner, SnellFramedStream::V4(_)) => {
                    TunnelWrite::Ending {
                        record: END_OF_FILE_REPLY,
                        close: true,
                    }
                }
                TunnelWrite::ReplyPending => TunnelWrite::Flushing { close: true },
                TunnelWrite::ReplyStaged => {
                    ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                    TunnelWrite::Open
                }
                TunnelWrite::Open if this.reuse => TunnelWrite::Ending {
                    record: b"",
                    close: false,
                },
                TunnelWrite::Open => TunnelWrite::Flushing { close: true },
                TunnelWrite::Ending { record, close } => {
                    ready!(Pin::new(&mut this.inner).poll_write(cx, record))?;
                    TunnelWrite::Flushing { close }
                }
                TunnelWrite::Flushing { close: false } => {
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    TunnelWrite::Draining
                }
                TunnelWrite::Flushing { close: true } => {
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
                    TunnelWrite::Closed
                }
                TunnelWrite::Draining | TunnelWrite::Closed => return Poll::Ready(Ok(())),
            };
        }
    }
}

impl AsyncPing for SnellTunnelStream {
    // A ping record could precede the deferred reply.
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for SnellTunnelStream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        AsyncStream::flow(&self.inner)
    }
}

#[async_trait]
impl ReusableTcpStream for SnellTunnelStream {
    /// Serves the next request after a clean session, as sing-snell's reuse
    /// loop does: connect (cmd 1 or 5) continues, UDP becomes the final
    /// session, ping pongs and closes, TCP EOF closes quietly.
    async fn next_request(
        mut self: Box<Self>,
    ) -> std::io::Result<Option<TcpServerSetupResult>> {
        if self.write == TunnelWrite::Closed {
            return Ok(None);
        }
        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let mut header = HeaderReader(&mut self.inner);
        match stream_reader.peek_u8(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Snell connection closed mid-record between requests: {e}");
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        let request = read_request(&mut stream_reader, &mut header).await?;
        if request.command != CMD_PING {
            self.auth.check_client_id(&request.client_id)?;
        }
        match request.command {
            CMD_PING => {
                write_all(&mut self.inner, &[0x01]).await?;
                self.inner.flush().await?;
                Ok(None)
            }
            CMD_UDP => {
                let this = *self;
                udp_relay(
                    this.inner,
                    stream_reader.unparsed_data(),
                    this.udp_enabled,
                    &this.proxy_selector,
                )
                .await
                .map(Some)
            }
            _ => {
                let remote_location = request
                    .location
                    .expect("connect requests carry a location");
                if let Address::Hostname(host) = remote_location.address()
                    && host == MUX_DESTINATION_HOST
                    && remote_location.port() == MUX_DESTINATION_PORT
                {
                    return Err(std::io::Error::other("snell: h2mux on a reused connection"));
                }
                self.write = TunnelWrite::ReplyPending;
                self.read_eof = false;
                self.drained = 0;
                let session = TcpSession {
                    remote_location,
                    need_initial_flush: true,
                    connection_success_response: None,
                    connection_failure_response: None,
                    initial_remote_data: stream_reader.unparsed_data_owned(),
                    proxy_selector: self.proxy_selector.clone(),
                };
                Ok(Some(TcpServerSetupResult::ReusableTcpForward {
                    stream: self,
                    session,
                }))
            }
        }
    }
}

#[async_trait]
impl TcpServerHandler for SnellServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let server_stream: Box<dyn AsyncStream> = match self.obfs_mode {
            Some(SnellObfsMode::Http) => Box::new(HttpObfsStream::new_server(server_stream)),
            _ => server_stream,
        };
        let (mut server_stream, v4_salt) = self.detect_and_frame_stream(server_stream).await?;

        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let request =
            read_request(&mut stream_reader, &mut HeaderReader(&mut server_stream)).await?;
        // snell-server v5.0.1 checks the salt once the first record decrypts.
        if let Some(salt) = v4_salt
            && self.replay.check_and_add(&salt)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "snell: duplicated salt",
            ));
        }
        if request.command != CMD_PING
            && let Some(name) = self.auth.check_client_id(&request.client_id)?
        {
            debug!("Snell user authenticated: {name}");
        }
        let remote_location = match request.command {
            CMD_PING => {
                write_all(&mut server_stream, &[0x01]).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::other("responded to ping"));
            }
            CMD_UDP => {
                return udp_relay(
                    server_stream,
                    stream_reader.unparsed_data(),
                    self.udp_enabled,
                    &self.proxy_selector,
                )
                .await;
            }
            _ => request
                .location
                .expect("connect requests carry a location"),
        };

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            write_all(&mut server_stream, TCP_TUNNEL_RESPONSE).await?;
            server_stream.flush().await?;

            let proxy_selector = self.proxy_selector.clone();
            let resolver = self.resolver.clone();
            let udp_enabled = self.udp_enabled;

            let initial_data = stream_reader.unparsed_data_owned();

            return Ok(TcpServerSetupResult::Session(Box::pin(async move {
                if let Err(e) = handle_h2mux_session(
                    Box::new(server_stream),
                    initial_data,
                    udp_enabled,
                    proxy_selector,
                    resolver,
                )
                .await
                {
                    debug!("Snell h2mux session ended: {}", e);
                }
            })));
        }

        let initial_remote_data = stream_reader.unparsed_data_owned();
        if matches!(server_stream, SnellFramedStream::V3(_)) {
            return Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                connection_failure_response: None,
                initial_remote_data,
                proxy_selector: self.proxy_selector.clone(),
            });
        }

        // v4+: the tunnel stream sends the reply with the first remote payload.
        let reuse = request.command == CMD_CONNECT_V2;
        let stream = SnellTunnelStream::new(
            server_stream,
            reuse,
            self.udp_enabled,
            self.proxy_selector.clone(),
            self.auth.clone(),
        );
        if reuse {
            return Ok(TcpServerSetupResult::ReusableTcpForward {
                stream: Box::new(stream),
                session: TcpSession {
                    remote_location,
                    need_initial_flush: true,
                    connection_success_response: None,
                    connection_failure_response: None,
                    initial_remote_data,
                    proxy_selector: self.proxy_selector.clone(),
                },
            });
        }
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(stream),
            need_initial_flush: true,
            connection_success_response: None,
            connection_failure_response: None,
            initial_remote_data,
            proxy_selector: self.proxy_selector.clone(),
        })
    }
}

#[derive(Debug)]
enum ClientRequestState {
    Pending(Vec<u8>),
    Staged { request_len: usize },
    Sent,
}

/// Client tunnel stream that lazily sends the request header with the first payload chunk
/// and consumes the server's reply on first read.
pub(crate) struct SnellReplyStream {
    inner: Option<SnellFramedStream<Box<dyn AsyncStream>>>,
    request: ClientRequestState,
    scratch: Vec<u8>,
    /// Reply bytes read so far; `None` once the tunnel reply is consumed.
    reply: Option<Vec<u8>>,
    read_eof: bool,
    write_closed: bool,
    broken: bool,
    pool: Option<Weak<SnellClientPool>>,
    route: Option<Arc<dyn CarrierDialer>>,
}

impl SnellReplyStream {
    fn attach_pool(&mut self, pool: &Arc<SnellClientPool>, route: Arc<dyn CarrierDialer>) {
        self.pool = Some(Arc::downgrade(pool));
        self.route = Some(route);
    }

    fn poll_flush_request(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = self.inner.as_mut().expect("stream active");
        loop {
            match &mut self.request {
                ClientRequestState::Pending(req) => {
                    let req_len = req.len();
                    self.scratch.clear();
                    self.scratch.extend_from_slice(req);
                    self.request = ClientRequestState::Staged {
                        request_len: req_len,
                    };
                }
                ClientRequestState::Staged { .. } => {
                    let n = ready!(Pin::new(&mut *inner).poll_write(cx, &self.scratch))?;
                    if n >= self.scratch.len() {
                        self.request = ClientRequestState::Sent;
                        self.scratch.clear();
                    } else {
                        self.scratch.drain(..n);
                    }
                }
                ClientRequestState::Sent => {
                    return Pin::new(&mut *inner).poll_flush(cx);
                }
            }
        }
    }

    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = self.inner.as_mut().expect("stream active");
        while let Some(head) = &mut self.reply {
            let need = match head.as_slice() {
                [] => 1,
                [0x00] => {
                    self.reply = None;
                    break;
                }
                [0x02] | [0x02, _] => 3,
                [0x02, code, len, msg @ ..] if msg.len() == *len as usize => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "snell error 0x{code:02x}: {}",
                        String::from_utf8_lossy(msg)
                    ))));
                }
                [0x02, _, len, ..] => 3 + *len as usize,
                [other, ..] => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "Got non-tunnel response ({other})"
                    ))));
                }
            };
            let mut tmp = [0u8; 258];
            let mut buf = ReadBuf::new(&mut tmp[..need - head.len()]);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF when reading tunnel response",
                )));
            }
            head.extend_from_slice(buf.filled());
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SnellReplyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.broken {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "snell stream broken",
            )));
        }
        if this.read_eof {
            return Poll::Ready(Ok(()));
        }
        if !matches!(this.request, ClientRequestState::Sent) {
            if let Err(e) = ready!(this.poll_flush_request(cx)) {
                this.broken = true;
                return Poll::Ready(Err(e));
            }
        }
        if let Err(e) = ready!(this.poll_reply(cx)) {
            this.broken = true;
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        let inner = this.inner.as_mut().expect("stream active");
        let res = Pin::new(inner).poll_read(cx, buf);
        match &res {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() == before {
                    this.read_eof = true;
                }
            }
            Poll::Ready(Err(_)) => {
                this.broken = true;
            }
            Poll::Pending => {}
        }
        res
    }
}

impl AsyncWrite for SnellReplyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.broken || this.write_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "snell stream write closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let inner = this.inner.as_mut().expect("stream active");
        loop {
            match &mut this.request {
                ClientRequestState::Pending(req) => {
                    let req_len = req.len();
                    this.scratch.clear();
                    this.scratch.extend_from_slice(req);
                    this.scratch.extend_from_slice(buf);
                    this.request = ClientRequestState::Staged {
                        request_len: req_len,
                    };
                }
                ClientRequestState::Staged { request_len } => {
                    let req_len = *request_len;
                    let n = match ready!(Pin::new(&mut *inner).poll_write(cx, &this.scratch)) {
                        Ok(n) => n,
                        Err(e) => {
                            this.broken = true;
                            return Poll::Ready(Err(e));
                        }
                    };
                    if n <= req_len {
                        this.scratch.drain(..n);
                        *request_len -= n;
                        if *request_len == 0 {
                            this.request = ClientRequestState::Sent;
                            this.scratch.clear();
                        }
                    } else {
                        let written_from_buf = n - req_len;
                        this.request = ClientRequestState::Sent;
                        this.scratch.clear();
                        return Poll::Ready(Ok(written_from_buf));
                    }
                }
                ClientRequestState::Sent => {
                    let res = Pin::new(&mut *inner).poll_write(cx, buf);
                    if let Poll::Ready(Err(_)) = &res {
                        this.broken = true;
                    }
                    return res;
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.broken {
            return Poll::Ready(Ok(()));
        }
        if !matches!(this.request, ClientRequestState::Sent) {
            if let Err(e) = ready!(this.poll_flush_request(cx)) {
                this.broken = true;
                return Poll::Ready(Err(e));
            }
        }
        let inner = this.inner.as_mut().expect("stream active");
        let res = Pin::new(inner).poll_flush(cx);
        if let Poll::Ready(Err(_)) = &res {
            this.broken = true;
        }
        res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.broken || this.write_closed {
            return Poll::Ready(Ok(()));
        }
        if !matches!(this.request, ClientRequestState::Sent) {
            if let Err(e) = ready!(this.poll_flush_request(cx)) {
                this.broken = true;
                return Poll::Ready(Err(e));
            }
        }
        let inner = this.inner.as_mut().expect("stream active");
        if this.pool.is_some() {
            if let Err(e) = ready!(Pin::new(&mut *inner).poll_write(cx, &[])) {
                this.broken = true;
                return Poll::Ready(Err(e));
            }
            if let Err(e) = ready!(Pin::new(&mut *inner).poll_flush(cx)) {
                this.broken = true;
                return Poll::Ready(Err(e));
            }
            this.write_closed = true;
            Poll::Ready(Ok(()))
        } else {
            this.write_closed = true;
            Pin::new(inner).poll_shutdown(cx)
        }
    }
}

impl Drop for SnellReplyStream {
    fn drop(&mut self) {
        let (Some(inner), Some(pool), Some(route)) = (
            self.inner.take(),
            self.pool.take().and_then(|p| p.upgrade()),
            self.route.take(),
        ) else {
            return;
        };
        if self.broken || !matches!(self.request, ClientRequestState::Sent) {
            return;
        }
        let write_closed = self.write_closed;
        let read_eof = self.read_eof;
        if write_closed && read_eof {
            pool.put(route, inner);
        } else {
            tokio::spawn(async move {
                let mut inner = inner;
                if !write_closed && write_zero_chunk(&mut inner).await.is_err() {
                    return;
                }
                if !read_eof && drain_server(&mut inner).await.is_err() {
                    return;
                }
                pool.put(route, inner);
            });
        }
    }
}

impl AsyncPing for SnellReplyStream {
    fn supports_ping(&self) -> bool {
        self.inner.as_ref().is_some_and(|s| s.supports_ping())
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(self.get_mut().inner.as_mut().expect("stream active")).poll_write_ping(cx)
    }
}

impl AsyncStream for SnellReplyStream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.as_ref().and_then(|s| s.local_addr())
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.as_ref().and_then(|s| s.peer_addr())
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.as_ref().and_then(|s| AsyncStream::flow(s))
    }
}

#[derive(Debug, Clone)]
pub struct SnellClientHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    password: String,
    udp_enabled: bool,
    version: SnellVersion,
    v6_mode: SnellV6Mode,
    userkey: Option<String>,
    #[allow(dead_code)]
    reuse: bool,
    quic_proxy_mode: bool,
    pool: Option<Arc<SnellClientPool>>,
    obfs_mode: Option<SnellObfsMode>,
    obfs_host: Option<String>,
    obfs_uri: Option<String>,
}

impl SnellClientHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        version: Option<&str>,
        mode: Option<&str>,
        userkey: Option<&str>,
        reuse: bool,
        quic_proxy_mode: bool,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        let parsed_version = version
            .and_then(SnellVersion::parse)
            .unwrap_or(if cipher.name() == "aes-128-gcm" {
                SnellVersion::V4
            } else {
                SnellVersion::V3
            });
        let v6_mode = mode.and_then(SnellV6Mode::parse).unwrap_or_default();
        Self {
            cipher,
            key,
            password: password.to_string(),
            udp_enabled,
            version: parsed_version,
            v6_mode,
            userkey: userkey.map(|s| s.to_string()),
            reuse,
            quic_proxy_mode,
            pool: if reuse && parsed_version >= SnellVersion::V4 {
                Some(SnellClientPool::new())
            } else {
                None
            },
            obfs_mode: None,
            obfs_host: None,
            obfs_uri: None,
        }
    }

    pub fn with_obfs(
        mut self,
        mode: Option<SnellObfsMode>,
        host: Option<&str>,
        uri: Option<&str>,
    ) -> Self {
        self.obfs_mode = mode;
        self.obfs_host = host.map(|s| s.to_string());
        self.obfs_uri = uri.map(|s| s.to_string());
        self
    }

    fn wrap_obfs(&self, stream: Box<dyn AsyncStream>) -> Box<dyn AsyncStream> {
        match self.obfs_mode {
            Some(SnellObfsMode::Http) => Box::new(HttpObfsStream::new_client(
                stream,
                self.obfs_host.as_deref(),
                self.obfs_uri.as_deref(),
            )),
            Some(SnellObfsMode::Tls) => Box::new(TlsObfsClientStream::new(
                stream,
                self.obfs_host.as_deref(),
            )),
            _ => stream,
        }
    }

    fn frame_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> SnellFramedStream<Box<dyn AsyncStream>> {
        let stream = self.wrap_obfs(stream);
        let psk = self.password.as_bytes();
        match self.version {
            SnellVersion::V4 | SnellVersion::V5 => {
                SnellFramedStream::V4(V4Conn::new(stream, Arc::from(psk)))
            }
            SnellVersion::V6 => SnellFramedStream::V6(V6Conn::new(
                stream,
                Arc::from(psk),
                V6Codec::new(self.v6_mode, psk),
            )),
            SnellVersion::V1 | SnellVersion::V2 | SnellVersion::V3 => {
                let ss = ShadowsocksStream::new(
                    stream,
                    ShadowsocksStreamType::Aead,
                    self.cipher.algorithm(),
                    SNELL_SALT_LEN,
                    self.key.clone(),
                    None,
                );
                SnellFramedStream::V3(ss)
            }
        }
    }

    fn setup_framed_client_stream(
        &self,
        client_stream: SnellFramedStream<Box<dyn AsyncStream>>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<SnellReplyStream> {
        let hostname_bytes = remote_location.address().to_string().into_bytes();

        if hostname_bytes.len() > 255 {
            return Err(std::io::Error::other("hostname is too long"));
        }

        let cmd = match self.version {
            SnellVersion::V1 | SnellVersion::V3 => 1, // Connect
            SnellVersion::V2 | SnellVersion::V4 | SnellVersion::V5 | SnellVersion::V6 => 5,
        };

        // Header and initial payload are lazily packed in the first record.
        let client_id = self.userkey.as_deref().unwrap_or("").as_bytes();
        let mut request = Vec::with_capacity(6 + client_id.len() + hostname_bytes.len());
        request.extend_from_slice(&[
            1, // snell header version
            cmd,
            client_id.len() as u8,
        ]);
        request.extend_from_slice(client_id);
        request.push(hostname_bytes.len() as u8);
        request.extend_from_slice(&hostname_bytes);
        request.extend_from_slice(&remote_location.location().port().to_be_bytes());

        Ok(SnellReplyStream {
            inner: Some(client_stream),
            request: ClientRequestState::Pending(request),
            scratch: Vec::new(),
            reply: Some(Vec::new()),
            read_eof: false,
            write_closed: false,
            broken: false,
            pool: None,
            route: None,
        })
    }

    async fn setup_udp_over_tcp(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let mut stream = self.frame_stream(client_stream);
        let max_payload_len = stream.max_payload_len();

        write_all(
            &mut stream,
            &[
                1, // snell version
                6, // UDP command
                0, // client id length
            ],
        )
        .await?;
        stream.flush().await?;

        let mut response = [0u8; 1];
        let n = stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading UDP ready response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-UDP-ready response ({})",
                response[0]
            )));
        }

        let snell_udp_client_stream =
            SnellUdpClientStream::new(Box::new(stream), max_payload_len);
        let fixed_target_stream =
            SnellFixedTargetStream::new(snell_udp_client_stream, target);

        Ok(Box::new(fixed_target_stream))
    }
}

#[async_trait]
impl TcpClientHandler for SnellClientHandler {
    fn has_session_pool(&self) -> bool {
        self.pool.is_some()
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(pool) = &self.pool {
            let route = transport.route.clone();
            let route_key = route.route_key();
            let (framed, route) = if let Some((s, r)) = pool.take(route_key) {
                (s, r)
            } else {
                let raw = transport.open.await?;
                (self.frame_stream(raw), route)
            };
            let mut stream = self.setup_framed_client_stream(framed, target)?;
            stream.attach_pool(pool, route);
            Ok(TcpClientSetupResult {
                client_stream: Box::new(stream),
                early_data: None,
            })
        } else {
            self.setup_client_tcp_stream(transport.open.await?, target).await
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let stream = self.setup_framed_client_stream(
            self.frame_stream(client_stream),
            remote_location,
        )?;
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled && self.version >= SnellVersion::V3
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.version < SnellVersion::V3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "snell: UDP requires version 3 or above",
            ));
        }

        let target_location = target.into_location();
        if self.quic_proxy_mode && self.version >= SnellVersion::V5 {
            let server_addr = client_stream.peer_addr();
            let psk: Arc<[u8]> = Arc::from(self.password.as_bytes());
            let userkey = self.userkey.as_deref().unwrap_or("").as_bytes().to_vec();
            let handler = Arc::new(self.clone());
            let stream = SnellQuicProxyStream::new(
                client_stream,
                target_location,
                server_addr,
                psk,
                userkey,
                Box::new(move |raw, target| {
                    Box::pin(async move { handler.setup_udp_over_tcp(raw, target).await })
                }),
            );
            return Ok(Box::new(stream));
        }

        self.setup_udp_over_tcp(client_stream, target_location).await
    }
}

