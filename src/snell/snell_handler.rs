use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use argon2::{Config as Argon2Config, ThreadMode, Variant, Version};
use async_trait::async_trait;
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::aead::{snell_kdf, Aead};
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
use crate::tcp::tcp_handler::{
    ReusableTcpStream, TcpClientHandler, TcpClientSetupResult, TcpServerHandler,
    TcpServerSetupResult, TcpSession,
};
use crate::util::write_all;

const SNELL_SALT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellVersion {
    V3,
    V4,
    V5,
    V6,
}

impl SnellVersion {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
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
            Self::V3 => "v3",
            Self::V4 => "v4",
            Self::V5 => "v5",
            Self::V6 => "v6",
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
        }
    }

    async fn detect_and_frame_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<SnellFramedStream<Box<dyn AsyncStream>>> {
        let psk = self.password.as_bytes();

        // If explicit version is configured:
        match self.version {
            Some(SnellVersion::V4 | SnellVersion::V5) => {
                let conn = V4Conn::new(server_stream, Arc::from(psk));
                return Ok(SnellFramedStream::V4(conn));
            }
            Some(SnellVersion::V6) => {
                let conn = V6Conn::new(
                    server_stream,
                    Arc::from(psk),
                    V6Codec::new(self.v6_mode, psk),
                );
                return Ok(SnellFramedStream::V6(conn));
            }
            Some(SnellVersion::V3) => {
                let ss_stream = ShadowsocksStream::new(
                    server_stream,
                    ShadowsocksStreamType::Aead,
                    self.cipher.algorithm(),
                    SNELL_SALT_LEN,
                    self.key.clone(),
                    None,
                );
                return Ok(SnellFramedStream::V3(ss_stream));
            }
            None => {}
        }

        // If cipher is not AES-128-GCM, v4/v5/v6 official specs are not applicable; fall back to V3 directly.
        if self.cipher.name() != "aes-128-gcm" {
            let ss_stream = ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                self.cipher.algorithm(),
                SNELL_SALT_LEN,
                self.key.clone(),
                None,
            );
            return Ok(SnellFramedStream::V3(ss_stream));
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
                    return Ok(SnellFramedStream::V6(conn));
                }
            }

            // 2. Try Snell v4 / v5
            if initial_buf.len() >= 39 {
                let salt = &initial_buf[..16];
                let session_key = snell_kdf(psk, salt, 16);
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
                    return Ok(SnellFramedStream::V4(conn));
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
                        return Ok(SnellFramedStream::V3(ss_stream));
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
    /// Checked per request by the authentication sub-project (roadmap B).
    #[allow(dead_code)]
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
}

impl SnellTunnelStream {
    fn new(
        inner: SnellFramedStream<Box<dyn AsyncStream>>,
        reuse: bool,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
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
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        }
        let request = read_request(&mut stream_reader, &mut header).await?;
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
        let mut server_stream = self.detect_and_frame_stream(server_stream).await?;

        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let request =
            read_request(&mut stream_reader, &mut HeaderReader(&mut server_stream)).await?;
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

/// Client tunnel stream that consumes the server's reply on first read:
/// sing-snell and snell-server send it with the first remote payload.
struct SnellReplyStream {
    inner: SnellFramedStream<Box<dyn AsyncStream>>,
    /// Reply bytes read so far; `None` once the tunnel reply is consumed.
    reply: Option<Vec<u8>>,
}

impl SnellReplyStream {
    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
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
        ready!(this.poll_reply(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SnellReplyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncPing for SnellReplyStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl AsyncStream for SnellReplyStream {
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

#[derive(Debug)]
pub struct SnellClientHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    password: String,
    udp_enabled: bool,
    version: SnellVersion,
    v6_mode: SnellV6Mode,
}

impl SnellClientHandler {
    pub fn new(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        version: Option<&str>,
        mode: Option<&str>,
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
        }
    }

    fn frame_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> SnellFramedStream<Box<dyn AsyncStream>> {
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
            SnellVersion::V3 => {
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
}

#[async_trait]
impl TcpClientHandler for SnellClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_stream = self.frame_stream(client_stream);

        let hostname_bytes = remote_location.address().to_string().into_bytes();

        if hostname_bytes.len() > 255 {
            return Err(std::io::Error::other("hostname is too long"));
        }

        let cmd = match self.version {
            SnellVersion::V3 => 1, // Connect
            SnellVersion::V4 | SnellVersion::V5 | SnellVersion::V6 => 5, // Connect v2 (reuse-ready)
        };

        write_all(
            &mut client_stream,
            &[
                1, // snell header version
                cmd,
                0, // client id length
                hostname_bytes.len() as u8,
            ],
        )
        .await?;

        write_all(&mut client_stream, &hostname_bytes).await?;

        let port = remote_location.location().port();

        write_all(
            &mut client_stream,
            &[(port >> 8) as u8, (port & 0xff) as u8],
        )
        .await?;

        client_stream.flush().await?;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(SnellReplyStream {
                inner: client_stream,
                reply: Some(Vec::new()),
            }),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
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
            SnellFixedTargetStream::new(snell_udp_client_stream, target.into_location());

        Ok(Box::new(fixed_target_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::duplex;

    fn test_server(version: Option<&str>, mode: Option<&str>) -> SnellServerHandler {
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        SnellServerHandler::new(
            cipher,
            "test-psk-12345",
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(crate::resolver::NativeResolver::new()),
            version,
            mode,
        )
    }

    fn test_client(version: Option<&str>, mode: Option<&str>) -> SnellClientHandler {
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        SnellClientHandler::new(cipher, "test-psk-12345", true, version, mode)
    }

    async fn run_tcp_echo(
        client_version: Option<&str>,
        client_mode: Option<&str>,
        server_version: Option<&str>,
        server_mode: Option<&str>,
        expect_reusable: bool,
    ) {
        let server = test_server(server_version, server_mode);
        let client = test_client(client_version, client_mode);

        let (client_io, server_io) = duplex(65536);
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();

        let client_task = tokio::spawn(async move {
            let mut result = client
                .setup_client_tcp_stream(Box::new(client_io), target)
                .await
                .unwrap();
            result
                .client_stream
                .write_all(b"hello from client")
                .await
                .unwrap();
            result.client_stream.flush().await.unwrap();
            let mut buf = [0u8; 17];
            result.client_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"reply from server");
        });

        let server_task = tokio::spawn(async move {
            let result = server.setup_server_stream(Box::new(server_io)).await.unwrap();
            let reusable = matches!(result, TcpServerSetupResult::ReusableTcpForward { .. });
            let (remote_location, mut stream, connection_success_response) = match result {
                TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream,
                    connection_success_response,
                    ..
                } => (remote_location, stream, connection_success_response),
                TcpServerSetupResult::ReusableTcpForward { stream, session } => (
                    session.remote_location,
                    stream as Box<dyn AsyncStream>,
                    session.connection_success_response,
                ),
                _ => panic!("expected a TCP forward"),
            };
            assert_eq!(reusable, expect_reusable);
            assert_eq!(remote_location.to_string(), "example.com:443");
            if let Some(resp) = connection_success_response {
                stream.write_all(&resp).await.unwrap();
                stream.flush().await.unwrap();
            }
            let mut buf = [0u8; 17];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello from client");
            stream.write_all(b"reply from server").await.unwrap();
            stream.flush().await.unwrap();
        });

        tokio::try_join!(client_task, server_task).unwrap();
    }

    #[tokio::test]
    async fn snell_v3_client_auto_detect_server() {
        run_tcp_echo(Some("v3"), None, None, None, false).await;
    }

    #[tokio::test]
    async fn snell_v4_client_auto_detect_server() {
        run_tcp_echo(Some("v4"), None, None, None, true).await;
    }

    #[tokio::test]
    async fn snell_v5_client_auto_detect_server() {
        run_tcp_echo(Some("v5"), None, None, None, true).await;
    }

    #[tokio::test]
    async fn snell_v6_client_auto_detect_server_default_mode() {
        run_tcp_echo(Some("v6"), None, None, None, true).await;
    }

    #[tokio::test]
    async fn snell_v6_client_server_unshaped_mode() {
        run_tcp_echo(
            Some("v6"),
            Some("unshaped"),
            Some("v6"),
            Some("unshaped"),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn snell_v6_client_server_unsafe_raw_mode() {
        run_tcp_echo(
            Some("v6"),
            Some("unsafe-raw"),
            Some("v6"),
            Some("unsafe-raw"),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn snell_udp_relay_v4_client_auto_detect_server() {
        let server = test_server(None, None);
        let client = test_client(Some("v4"), None);

        let (client_io, server_io) = duplex(65536);
        let target_location = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let target: ResolvedLocation = target_location.clone().into();

        let target_loc_clone = target_location.clone();
        let client_task = tokio::spawn(async move {
            let mut client_stream = client
                .setup_client_udp_bidirectional(Box::new(client_io), target)
                .await
                .unwrap();
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_write_message(cx, b"dns-query"))
                .await
                .unwrap();
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_flush_message(cx))
                .await
                .unwrap();

            let mut storage = vec![0u8; 1024];
            let mut buf = ReadBuf::new(&mut storage);
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), b"dns-response");
        });

        let server_task = tokio::spawn(async move {
            let result = server.setup_server_stream(Box::new(server_io)).await.unwrap();
            let TcpServerSetupResult::MultiDirectionalUdp { mut stream, .. } = result else {
                panic!("expected MultiDirectionalUdp");
            };
            let mut storage = vec![0u8; 1024];
            let mut buf = ReadBuf::new(&mut storage);
            let src_loc =
                poll_fn(|cx| Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut buf))
                    .await
                    .unwrap();
            assert_eq!(src_loc, target_loc_clone);
            assert_eq!(buf.filled(), b"dns-query");

            poll_fn(|cx| {
                Pin::new(&mut *stream)
                    .poll_write_sourced_message(cx, b"dns-response", &target_loc_clone)
            })
            .await
            .unwrap();
            poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
                .await
                .unwrap();
        });

        tokio::try_join!(client_task, server_task).unwrap();
    }

    #[tokio::test]
    async fn snell_udp_relay_v6_client_auto_detect_server() {
        let server = test_server(None, None);
        let client = test_client(Some("v6"), None);

        let (client_io, server_io) = duplex(65536);
        let target_location = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let target: ResolvedLocation = target_location.clone().into();

        let target_loc_clone = target_location.clone();
        let client_task = tokio::spawn(async move {
            let mut client_stream = client
                .setup_client_udp_bidirectional(Box::new(client_io), target)
                .await
                .unwrap();
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_write_message(cx, b"dns-query-v6"))
                .await
                .unwrap();
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_flush_message(cx))
                .await
                .unwrap();

            let mut storage = vec![0u8; 1024];
            let mut buf = ReadBuf::new(&mut storage);
            poll_fn(|cx| Pin::new(&mut *client_stream).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), b"dns-response-v6");
        });

        let server_task = tokio::spawn(async move {
            let result = server.setup_server_stream(Box::new(server_io)).await.unwrap();
            let TcpServerSetupResult::MultiDirectionalUdp { mut stream, .. } = result else {
                panic!("expected MultiDirectionalUdp");
            };
            let mut storage = vec![0u8; 1024];
            let mut buf = ReadBuf::new(&mut storage);
            let src_loc =
                poll_fn(|cx| Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut buf))
                    .await
                    .unwrap();
            assert_eq!(src_loc, target_loc_clone);
            assert_eq!(buf.filled(), b"dns-query-v6");

            poll_fn(|cx| {
                Pin::new(&mut *stream)
                    .poll_write_sourced_message(cx, b"dns-response-v6", &target_loc_clone)
            })
            .await
            .unwrap();
            poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
                .await
                .unwrap();
        });

        tokio::try_join!(client_task, server_task).unwrap();
    }

    #[tokio::test]
    async fn snell_wrong_password_rejected() {
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        let server = SnellServerHandler::new(
            cipher,
            "correct-psk",
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(crate::resolver::NativeResolver::new()),
            None,
            None,
        );
        let client = SnellClientHandler::new(cipher, "wrong-psk", true, Some("v4"), None);

        let (client_io, server_io) = duplex(65536);
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();

        let client_task = tokio::spawn(async move {
            let _ = client.setup_client_tcp_stream(Box::new(client_io), target).await;
        });

        let server_task = tokio::spawn(async move {
            let res = server.setup_server_stream(Box::new(server_io)).await;
            assert!(res.is_err());
        });

        let _ = tokio::join!(client_task, server_task);
    }

    #[tokio::test]
    async fn snell_client_returns_before_reply() {
        let client = test_client(Some("v4"), None);
        let (client_io, _server_io) = duplex(65536);
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.setup_client_tcp_stream(Box::new(client_io), target),
        )
        .await
        .expect("setup must not wait for the reply")
        .unwrap();
    }

    #[tokio::test]
    async fn snell_client_surfaces_error_reply() {
        let server = test_server(None, None);
        let client = test_client(Some("v4"), None);
        let (client_io, server_io) = duplex(65536);
        // The server side runs concurrently so a client that waits for the
        // reply during setup fails instead of hanging.
        let server_task = tokio::spawn(async move {
            let mut framed = server
                .detect_and_frame_stream(Box::new(server_io))
                .await
                .unwrap();
            let mut request = [0u8; 64];
            let _ = framed.read(&mut request).await.unwrap();
            write_all(&mut framed, b"\x02\x65\x0aRemote EOF").await.unwrap();
            framed.flush().await.unwrap();
            framed
        });
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();
        let mut result = client
            .setup_client_tcp_stream(Box::new(client_io), target)
            .await
            .unwrap();
        let err = result.client_stream.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.to_string(), "snell error 0x65: Remote EOF");
        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn snell_v6_udp_rejects_datagram_in_request_record() {
        let server = test_server(None, None);
        let client = test_client(Some("v6"), None);
        let (client_io, server_io) = duplex(65536);
        let mut framed = client.frame_stream(Box::new(client_io));
        // Request and first datagram in one write, so one v6 record.
        write_all(&mut framed, &[1, 6, 0, 0xde, 0xad]).await.unwrap();
        framed.flush().await.unwrap();
        let err = server
            .setup_server_stream(Box::new(server_io))
            .await
            .err()
            .expect("v6 UDP with a datagram in the request record must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    const PSK: &[u8] = b"test-psk-12345";
    type Framed = SnellFramedStream<Box<dyn AsyncStream>>;

    fn frame_duplex(io: tokio::io::DuplexStream, v6: bool) -> Framed {
        let io: Box<dyn AsyncStream> = Box::new(io);
        if v6 {
            SnellFramedStream::V6(V6Conn::new(
                io,
                Arc::from(PSK),
                V6Codec::new(SnellV6Mode::Default, PSK),
            ))
        } else {
            SnellFramedStream::V4(V4Conn::new(io, Arc::from(PSK)))
        }
    }

    fn framed_pair(v6: bool) -> (Framed, Framed) {
        let (a, b) = duplex(1 << 20);
        (frame_duplex(a, v6), frame_duplex(b, v6))
    }

    fn tunnel_pair(v6: bool, reuse: bool) -> (SnellTunnelStream, Framed) {
        let (server, peer) = framed_pair(v6);
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        (SnellTunnelStream::new(server, reuse, true, selector), peer)
    }

    async fn send_zero_chunk(conn: &mut Framed) {
        poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, &[]))
            .await
            .unwrap();
        conn.flush().await.unwrap();
    }

    async fn read_to_eof<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                return got;
            }
            got.extend_from_slice(&buf[..n]);
        }
    }

    /// True when a further read stays pending: a zero chunk, not a closed connection.
    async fn still_open(conn: &mut Framed) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.read(&mut [0u8; 1]),
        )
        .await
        .is_err()
    }

    #[tokio::test]
    async fn tunnel_reply_rides_with_first_payload() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"data").await.unwrap();
            server.flush().await.unwrap();
            let mut record = [0u8; 64];
            let mut buf = ReadBuf::new(&mut record);
            poll_fn(|cx| Pin::new(&mut peer).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), b"\x00data", "v6={v6}");
        }
    }

    #[tokio::test]
    async fn tunnel_reply_survives_pending_inner_write() {
        for v6 in [false, true] {
            let (a, b) = duplex(64);
            let selector = Arc::new(ClientProxySelector::new(Vec::new()));
            let mut server = SnellTunnelStream::new(frame_duplex(a, v6), true, true, selector);
            let mut peer = frame_duplex(b, v6);
            let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            let expected = [&[0u8][..], &payload].concat();
            let reader = tokio::spawn(async move {
                let mut got = vec![0u8; expected.len()];
                peer.read_exact(&mut got).await.unwrap();
                assert!(got == expected, "v6={v6}");
            });
            server.write_all(&payload).await.unwrap();
            server.flush().await.unwrap();
            reader.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reuse_shutdown_after_data_sends_zero_chunk() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"x").await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(read_to_eof(&mut peer).await, b"\x00x", "v6={v6}");
            assert!(still_open(&mut peer).await, "zero chunk, not close: v6={v6}");
        }
    }

    #[tokio::test]
    async fn reuse_shutdown_before_data_replies_remote_eof_and_closes() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.shutdown().await.unwrap();
            let got = read_to_eof(&mut peer).await;
            assert_eq!(got, REMOTE_EOF_REPLY, "v6={v6}");
            assert!(!still_open(&mut peer).await, "closed: v6={v6}");
            assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn single_shutdown_before_data() {
        let (mut server, mut peer) = tunnel_pair(false, false);
        server.shutdown().await.unwrap();
        assert_eq!(read_to_eof(&mut peer).await, END_OF_FILE_REPLY);
        let (mut server, mut peer) = tunnel_pair(true, false);
        server.shutdown().await.unwrap();
        let err = peer.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn single_shutdown_after_data_closes_without_zero_chunk() {
        for v6 in [false, true] {
            let (a, mut raw) = duplex(1 << 16);
            let selector = Arc::new(ClientProxySelector::new(Vec::new()));
            let mut server = SnellTunnelStream::new(frame_duplex(a, v6), false, true, selector);

            server.write_all(b"x").await.unwrap();
            server.flush().await.unwrap();

            let mut discard = [0u8; 1024];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    raw.read(&mut discard),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {}
                    _ => break,
                }
            }

            server.shutdown().await.unwrap();
            let mut rest = Vec::new();
            raw.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "expected no bytes after shutdown: v6={v6}");
            assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
        }

        // Mirror assertion for reuse mode: shutdown produces a zero chunk and stays open.
        for v6 in [false, true] {
            let (a, mut raw) = duplex(1 << 16);
            let selector = Arc::new(ClientProxySelector::new(Vec::new()));
            let mut server = SnellTunnelStream::new(frame_duplex(a, v6), true, true, selector);

            server.write_all(b"x").await.unwrap();
            server.flush().await.unwrap();

            let mut discard = [0u8; 1024];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    raw.read(&mut discard),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {}
                    _ => break,
                }
            }

            server.shutdown().await.unwrap();
            let mut zero_chunk = [0u8; 1024];
            let n = raw.read(&mut zero_chunk).await.unwrap();
            assert!(n > 0, "expected zero chunk on raw transport: v6={v6}");
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    raw.read(&mut [0u8; 1]),
                )
                .await
                .is_err(),
                "expected raw transport to stay open: v6={v6}"
            );
        }
    }

    #[tokio::test]
    async fn drain_discards_until_client_zero_chunk() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"x").await.unwrap();
            server.shutdown().await.unwrap();
            peer.write_all(&[7u8; 1000]).await.unwrap();
            send_zero_chunk(&mut peer).await;
            assert_eq!(server.read(&mut [0u8; 64]).await.unwrap(), 0, "v6={v6}");
        }
    }

    #[tokio::test]
    async fn drain_errors_past_limit() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        server.write_all(b"x").await.unwrap();
        server.shutdown().await.unwrap();
        let writer = tokio::spawn(async move {
            let chunk = [7u8; 16 * 1024];
            for _ in 0..(DRAIN_LIMIT / chunk.len() + 1) {
                if peer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = peer.flush().await;
            peer
        });
        let err = server.read(&mut [0u8; 64]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        drop(server);
        let _ = writer.await;
    }

    fn request(cmd: u8) -> Vec<u8> {
        let mut r = vec![1, cmd, 0];
        if cmd == CMD_CONNECT || cmd == CMD_CONNECT_V2 {
            let host = b"example.com";
            r.push(host.len() as u8);
            r.extend_from_slice(host);
            r.extend_from_slice(&443u16.to_be_bytes());
        }
        r
    }

    /// Runs one data session to completion: reply, zero chunks both ways.
    async fn end_session(server: &mut SnellTunnelStream, peer: &mut Framed) {
        server.write_all(b"x").await.unwrap();
        server.shutdown().await.unwrap();
        assert_eq!(read_to_eof(peer).await, b"\x00x");
        send_zero_chunk(peer).await;
        assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn next_request_connect_commands_continue() {
        for v6 in [false, true] {
            for cmd in [CMD_CONNECT_V2, CMD_CONNECT] {
                let (mut server, mut peer) = tunnel_pair(v6, true);
                end_session(&mut server, &mut peer).await;
                write_all(&mut peer, &request(cmd)).await.unwrap();
                peer.flush().await.unwrap();
                let next = Box::new(server).next_request().await.unwrap();
                let Some(TcpServerSetupResult::ReusableTcpForward { session, .. }) = next else {
                    panic!("expected another session: v6={v6} cmd={cmd}");
                };
                assert_eq!(session.remote_location.to_string(), "example.com:443");
                assert!(session.connection_success_response.is_none());
            }
        }
    }

    #[tokio::test]
    async fn next_request_udp_becomes_relay() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &request(CMD_UDP)).await.unwrap();
        peer.flush().await.unwrap();
        let next = Box::new(server).next_request().await.unwrap();
        assert!(matches!(next, Some(TcpServerSetupResult::MultiDirectionalUdp { .. })));
        let mut reply = [0u8; 1];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x00]);
    }

    #[tokio::test]
    async fn next_request_v6_udp_rejects_datagram_in_request_record() {
        let (mut server, mut peer) = tunnel_pair(true, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &[1, CMD_UDP, 0, 0xde, 0xad]).await.unwrap();
        peer.flush().await.unwrap();
        let err = Box::new(server).next_request().await.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn next_request_ping_pongs_and_closes() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &request(CMD_PING)).await.unwrap();
        peer.flush().await.unwrap();
        assert!(Box::new(server).next_request().await.unwrap().is_none());
        let mut pong = [0u8; 1];
        peer.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [0x01]);
    }

    #[tokio::test]
    async fn next_request_client_close_ends_quietly() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        drop(peer);
        assert!(Box::new(server).next_request().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn next_request_unknown_command_errors() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &[1, 9, 0]).await.unwrap();
        peer.flush().await.unwrap();
        assert!(Box::new(server).next_request().await.is_err());
    }

    #[tokio::test]
    async fn first_cmd1_is_single_tunnel() {
        let server = test_server(None, None);
        let (client_io, server_io) = duplex(65536);
        let mut framed = test_client(Some("v4"), None).frame_stream(Box::new(client_io));
        write_all(&mut framed, &request(CMD_CONNECT)).await.unwrap();
        framed.flush().await.unwrap();
        let result = server.setup_server_stream(Box::new(server_io)).await.unwrap();
        let TcpServerSetupResult::TcpForward {
            connection_success_response,
            ..
        } = result
        else {
            panic!("cmd 1 must be a single TcpForward");
        };
        assert!(connection_success_response.is_none(), "reply is deferred");
    }

    /// Serves every connect from a fresh echo task (or refuses it).
    #[derive(Debug)]
    struct EchoConnector {
        refuse: bool,
    }

    #[async_trait]
    impl crate::tcp::socket_connector::SocketConnector for EchoConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            if self.refuse {
                return Err(std::io::ErrorKind::ConnectionRefused.into());
            }
            let (ours, mut theirs) = duplex(1 << 20);
            tokio::spawn(async move {
                let mut data = Vec::new();
                if theirs.read_to_end(&mut data).await.is_ok() {
                    let _ = theirs.write_all(&data).await;
                    let _ = theirs.shutdown().await;
                }
            });
            Ok(Box::new(ours))
        }

        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// A raw client connection to a Snell server running in `process_stream`.
    fn connect_e2e(
        version: &str,
        mode: Option<&str>,
        refuse: bool,
    ) -> (Framed, tokio::task::JoinHandle<std::io::Result<()>>) {
        use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
        use crate::client_proxy_selector::{ConnectAction, ConnectRule};
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(EchoConnector { refuse }))],
            vec![],
        );
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::ANY],
            ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
        )]));
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let server = SnellServerHandler::new(
            cipher,
            "test-psk-12345",
            true,
            selector,
            resolver.clone(),
            mode.map(|_| version),
            mode,
        );
        let (client_io, server_io) = duplex(1 << 20);
        let task = tokio::spawn(crate::tcp::tcp_server::process_stream(
            server_io,
            Arc::new(server),
            resolver,
        ));
        let framed = test_client(Some(version), mode).frame_stream(Box::new(client_io));
        (framed, task)
    }

    /// One session: request + payload, zero chunk, everything until EOF.
    async fn e2e_session(conn: &mut Framed, cmd: u8, payload: &[u8]) -> Vec<u8> {
        write_all(conn, &[request(cmd), payload.to_vec()].concat()).await.unwrap();
        send_zero_chunk(conn).await;
        read_to_eof(conn).await
    }

    fn e2e_cases() -> [(&'static str, Option<&'static str>); 5] {
        [
            ("v4", None),
            ("v5", None),
            ("v6", None),
            ("v6", Some("unshaped")),
            ("v6", Some("unsafe-raw")),
        ]
    }

    #[tokio::test]
    async fn reuse_serves_mixed_sessions_then_ping() {
        for (version, mode) in e2e_cases() {
            let (mut conn, task) = connect_e2e(version, mode, false);
            for (i, cmd) in [CMD_CONNECT_V2, CMD_CONNECT, CMD_CONNECT_V2].into_iter().enumerate() {
                let payload = format!("session {i}");
                let got = e2e_session(&mut conn, cmd, payload.as_bytes()).await;
                assert_eq!(got, [b"\x00", payload.as_bytes()].concat(), "{version} {mode:?} #{i}");
            }
            write_all(&mut conn, &request(CMD_PING)).await.unwrap();
            conn.flush().await.unwrap();
            assert_eq!(read_to_eof(&mut conn).await, [0x01], "{version} {mode:?} pong");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pipelined_request_is_served() {
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            write_all(&mut conn, &[request(CMD_CONNECT_V2), b"one".to_vec()].concat())
                .await
                .unwrap();
            send_zero_chunk(&mut conn).await;
            // Second request goes out before the first reply is read.
            write_all(&mut conn, &[request(CMD_CONNECT_V2), b"two".to_vec()].concat())
                .await
                .unwrap();
            send_zero_chunk(&mut conn).await;
            assert_eq!(read_to_eof(&mut conn).await, b"\x00one", "{version} {mode:?}");
            assert_eq!(read_to_eof(&mut conn).await, b"\x00two", "{version} {mode:?}");
        }
    }

    #[tokio::test]
    async fn large_payload_round_trips() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            let got = e2e_session(&mut conn, CMD_CONNECT_V2, &payload).await;
            assert_eq!(got[0], 0x00, "{version} {mode:?}");
            assert!(got[1..] == payload[..], "{version} {mode:?}");
        }
    }

    #[tokio::test]
    async fn fifty_sessions_on_one_connection() {
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            for i in 0..50u32 {
                let payload = i.to_be_bytes();
                let got = e2e_session(&mut conn, CMD_CONNECT_V2, &payload).await;
                assert_eq!(got, [&[0u8][..], &payload].concat(), "{version} {mode:?} #{i}");
            }
        }
    }

    #[tokio::test]
    async fn refused_connect_replies_remote_eof() {
        for (version, mode) in e2e_cases() {
            let (mut conn, task) = connect_e2e(version, mode, true);
            let got = e2e_session(&mut conn, CMD_CONNECT_V2, b"x").await;
            assert_eq!(got, REMOTE_EOF_REPLY, "{version} {mode:?}");
            assert!(task.await.unwrap().is_err(), "connect failure is reported");
        }
    }

    #[tokio::test]
    async fn client_disconnect_ends_connection() {
        let (mut conn, task) = connect_e2e("v4", None, false);
        write_all(&mut conn, &[request(CMD_CONNECT_V2), b"half".to_vec()].concat())
            .await
            .unwrap();
        conn.flush().await.unwrap();
        drop(conn);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("server task must finish after the client disconnects")
            .unwrap()
            .ok();
    }
}
