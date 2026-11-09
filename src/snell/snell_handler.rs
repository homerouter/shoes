use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
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

#[async_trait]
impl TcpServerHandler for SnellServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut server_stream = self.detect_and_frame_stream(server_stream).await?;
        let max_payload_len = server_stream.max_payload_len();

        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let mut header_stream = HeaderReader(&mut server_stream);

        let version = stream_reader.read_u8(&mut header_stream).await?;
        if version != 1 {
            return Err(std::io::Error::other(format!(
                "unexpected snell version: {version}"
            )));
        }

        let command_type = stream_reader.read_u8(&mut header_stream).await?;
        let is_udp = match command_type {
            0 => {
                // Ping command
                write_all(&mut server_stream, &[0x01]).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::other("responded to ping"));
            }
            1 | 5 => {
                // 1 is Connect (Snell v3 / v4)
                // 5 is Connect v2 (Snell v2 / v4 / v5 / v6 reuse)
                false
            }
            6 => {
                // UDP command
                if !self.udp_enabled {
                    return Err(std::io::Error::other("snell UDP requested but not enabled"));
                }
                true
            }
            unknown_command => {
                return Err(std::io::Error::other(format!(
                    "Got unknown command: {unknown_command}"
                )));
            }
        };

        let client_id_len = stream_reader.read_u8(&mut header_stream).await?;
        if client_id_len > 0 {
            stream_reader
                .read_slice(&mut header_stream, client_id_len as usize)
                .await?;
        }

        if !is_udp {
            let hostname_len = stream_reader.read_u8(&mut header_stream).await? as usize;

            let hostname_and_port_bytes = stream_reader
                .read_slice(&mut header_stream, hostname_len + 2)
                .await?;

            let hostname_str = match std::str::from_utf8(&hostname_and_port_bytes[0..hostname_len])
            {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode hostname: {e}"),
                    ));
                }
            };

            let port =
                u16::from_be_bytes(hostname_and_port_bytes[hostname_len..].try_into().unwrap());

            let remote_location = NetLocation::new(Address::from(hostname_str)?, port);

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

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),

                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                connection_failure_response: None,
                initial_remote_data: stream_reader.unparsed_data_owned(),
                proxy_selector: self.proxy_selector.clone(),
            })
        } else {
            write_all(&mut server_stream, UDP_READY_RESPONSE).await?;

            let peer = server_stream.peer_addr();
            let udp_stream =
                SnellUdpStream::new(Box::new(server_stream), max_payload_len).with_peer(peer);

            Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(udp_stream),
                need_initial_flush: true,
                proxy_selector: self.proxy_selector.clone(),
            })
        }
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

        let mut response = [0u8; 1];
        let n = client_stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading tunnel response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-tunnel response ({})",
                response[0]
            )));
        }

        Ok(TcpClientSetupResult {
            client_stream: Box::new(client_stream),
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
            let TcpServerSetupResult::TcpForward {
                remote_location,
                mut stream,
                connection_success_response,
                ..
            } = result
            else {
                panic!("expected TcpForward");
            };
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
        run_tcp_echo(Some("v3"), None, None, None).await;
    }

    #[tokio::test]
    async fn snell_v4_client_auto_detect_server() {
        run_tcp_echo(Some("v4"), None, None, None).await;
    }

    #[tokio::test]
    async fn snell_v5_client_auto_detect_server() {
        run_tcp_echo(Some("v5"), None, None, None).await;
    }

    #[tokio::test]
    async fn snell_v6_client_auto_detect_server_default_mode() {
        run_tcp_echo(Some("v6"), None, None, None).await;
    }

    #[tokio::test]
    async fn snell_v6_client_server_unshaped_mode() {
        run_tcp_echo(
            Some("v6"),
            Some("unshaped"),
            Some("v6"),
            Some("unshaped"),
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
}
