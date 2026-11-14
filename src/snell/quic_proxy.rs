use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::Rng;
use tokio::io::ReadBuf;

use super::aead::{snell_kdf, Aead, NONCE_LEN, TAG_LEN};
use super::auth::SnellAuth;
use super::v4::increment_nonce;
use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;
use tokio::sync::{mpsc, Semaphore};

const HEADER_VERSION: u8 = 4;
const REQUEST_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const HEADER_PLAIN_LEN: usize = 7;
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN; // 23
#[allow(dead_code)]
const MAX_PLAINTEXT_PER_FRAME: usize = 1417;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Init decodes run at once (Argon2 per try); sing-box `quic_auth.go`.
const AUTH_WORKERS: usize = 4;
/// Decodes queued or running; more inits are dropped.
const AUTH_QUEUE_SIZE: usize = 1024;
/// Packets held per source while its init is decoded.
const PENDING_PACKET_LIMIT: usize = 8;
const PENDING_BYTES_LIMIT: usize = 64 * 1024;
/// Datagrams queued per session relay, as sing-box `quic_nat.go`; holds the
/// init payload and every held packet.
const RELAY_QUEUE_SIZE: usize = 64;

/// An authenticated QUIC proxy init.
#[derive(Debug)]
pub struct QuicInit {
    /// The PSK that opened the init; duplicate inits of the session use it.
    pub psk: Arc<[u8]>,
    pub target: NetLocation,
    pub payload: Vec<u8>,
    /// The authenticated user, with `users`.
    pub user: Option<String>,
}

/// Check if the first byte of a UDP packet looks like a QUIC packet.
///
/// In QUIC (RFC 9000):
/// - Long header: first byte has bit 7 set and bit 6 set (>= 0xc0)
/// - Short header: first byte has bit 7 clear and bit 6 set (0x40..=0x7f)
#[inline]
pub fn is_quic_looking(first: u8) -> bool {
    first >= 0xc0 || (0x40..=0x7f).contains(&first)
}

/// Check if a packet is a QUIC Initial packet.
#[allow(dead_code)]
pub fn is_quic_initial(packet: &[u8]) -> bool {
    if packet.len() < 5 || (packet[0] & 0xc0) != 0xc0 {
        return false;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version == 0 {
        return false;
    }
    let packet_type = packet[0] & 0x30;
    // RFC 9369 assigns type 1 (0x10) to Initial packets in QUIC v2.
    // RFC 9000 / draft versions assign type 0 (0x00) to Initial packets in QUIC v1.
    if version == 0x6b33_43cf {
        packet_type == 0x10
    } else {
        packet_type == 0x00
    }
}

/// Decodes a Snell v5 QUIC Proxy datagram frame into raw plaintext bytes.
pub fn decode_quic_proxy_frame(psk: &[u8], mut data: &[u8]) -> std::io::Result<Vec<u8>> {
    if data.len() < SALT_LEN + HEADER_CIPHER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "snell quic proxy: datagram too short",
        ));
    }

    if is_quic_looking(data[0]) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: salt looks like QUIC",
        ));
    }

    let salt = &data[..SALT_LEN];
    let key = snell_kdf(psk, salt, 16);
    let aead = Aead::aes_128_gcm(&key);
    let mut nonce = [0u8; NONCE_LEN];

    data = &data[SALT_LEN..];
    let mut plain = Vec::new();

    while !data.is_empty() {
        if data.len() < HEADER_CIPHER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "snell quic proxy: truncated frame header",
            ));
        }

        let mut header_buf = [0u8; HEADER_PLAIN_LEN];
        header_buf.copy_from_slice(&data[..HEADER_PLAIN_LEN]);
        let header_tag = &data[HEADER_PLAIN_LEN..HEADER_CIPHER_LEN];

        aead.open_detached(&nonce, &[], &mut header_buf, header_tag)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "snell quic proxy: header authentication failed",
                )
            })?;
        increment_nonce(&mut nonce);

        if header_buf[0] != HEADER_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snell quic proxy: unexpected header version",
            ));
        }

        let padding_len = u16::from_be_bytes([header_buf[3], header_buf[4]]);
        if padding_len != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snell quic proxy: unexpected padding in quic proxy frame",
            ));
        }

        let payload_len = u16::from_be_bytes([header_buf[5], header_buf[6]]) as usize;
        let frame_len = HEADER_CIPHER_LEN + payload_len + TAG_LEN;
        if payload_len == 0 || data.len() < frame_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snell quic proxy: invalid payload length",
            ));
        }

        let mut body_buf = vec![0u8; payload_len];
        body_buf.copy_from_slice(&data[HEADER_CIPHER_LEN..HEADER_CIPHER_LEN + payload_len]);
        let body_tag = &data[HEADER_CIPHER_LEN + payload_len..frame_len];

        aead.open_detached(&nonce, &[], &mut body_buf, body_tag)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "snell quic proxy: payload authentication failed",
                )
            })?;
        increment_nonce(&mut nonce);

        plain.extend_from_slice(&body_buf);
        data = &data[frame_len..];
    }

    Ok(plain)
}

/// Encodes raw plaintext into a Snell v5 QUIC Proxy datagram frame.
#[allow(dead_code)]
pub fn encode_quic_proxy_frame(psk: &[u8], mut plain: &[u8]) -> std::io::Result<Vec<u8>> {
    if plain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snell quic proxy: empty init payload",
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    loop {
        rand::rng().fill_bytes(&mut salt);
        if !is_quic_looking(salt[0]) {
            break;
        }
    }

    let key = snell_kdf(psk, &salt, 16);
    let aead = Aead::aes_128_gcm(&key);
    let mut nonce = [0u8; NONCE_LEN];

    let mut frame = Vec::with_capacity(SALT_LEN + plain.len() + 64);
    frame.extend_from_slice(&salt);

    while !plain.is_empty() {
        let chunk_len = plain.len().min(MAX_PLAINTEXT_PER_FRAME);
        let mut header = [0u8; HEADER_PLAIN_LEN];
        header[0] = HEADER_VERSION;
        header[5..7].copy_from_slice(&(chunk_len as u16).to_be_bytes());

        let mut header_tag = [0u8; TAG_LEN];
        aead.seal_detached(&nonce, &[], &mut header, &mut header_tag)
            .map_err(|_| std::io::Error::other("snell quic proxy: header seal failed"))?;
        increment_nonce(&mut nonce);

        frame.extend_from_slice(&header);
        frame.extend_from_slice(&header_tag);

        let mut body = plain[..chunk_len].to_vec();
        let mut body_tag = [0u8; TAG_LEN];
        aead.seal_detached(&nonce, &[], &mut body, &mut body_tag)
            .map_err(|_| std::io::Error::other("snell quic proxy: body seal failed"))?;
        increment_nonce(&mut nonce);

        frame.extend_from_slice(&body);
        frame.extend_from_slice(&body_tag);

        plain = &plain[chunk_len..];
    }

    Ok(frame)
}

/// Parses the decrypted plaintext of an Init request into `(target, userkey, initial_payload)`.
pub fn parse_quic_proxy_init(plain: &[u8]) -> std::io::Result<(NetLocation, Vec<u8>, Vec<u8>)> {
    if plain.len() < 5 || plain[0] != REQUEST_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: invalid init request version",
        ));
    }

    let mut index = 1;
    let user_key_len = plain[index] as usize;
    index += 1;

    if index + user_key_len + 3 > plain.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "snell quic proxy: truncated user key",
        ));
    }
    let user_key = plain[index..index + user_key_len].to_vec();
    index += user_key_len;

    let host_len = plain[index] as usize;
    index += 1;
    if index + host_len + 2 > plain.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "snell quic proxy: truncated target host",
        ));
    }

    let host_str = std::str::from_utf8(&plain[index..index + host_len]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: target host is not valid UTF-8",
        )
    })?;
    index += host_len;

    let port = u16::from_be_bytes([plain[index], plain[index + 1]]);
    index += 2;

    if port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: invalid target port 0",
        ));
    }

    let address = Address::from(host_str)?;
    let target = NetLocation::new(address, port);

    let payload = plain[index..].to_vec();
    if payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: init request does not contain a payload",
        ));
    }

    if !is_quic_looking(payload[0]) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snell quic proxy: initial payload does not have QUIC fixed bit set",
        ));
    }

    Ok((target, user_key, payload))
}

/// Encodes an Init frame given target location and initial payload.
#[allow(dead_code)]
pub fn encode_quic_proxy_init(
    psk: &[u8],
    user_key: &[u8],
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    if user_key.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snell quic proxy: user key too long",
        ));
    }
    let host_str = target.address().to_string();
    if host_str.is_empty() || host_str.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snell quic proxy: invalid target host length",
        ));
    }

    let mut plain = Vec::with_capacity(2 + user_key.len() + 1 + host_str.len() + 2 + payload.len());
    plain.push(REQUEST_VERSION);
    plain.push(user_key.len() as u8);
    plain.extend_from_slice(user_key);
    plain.push(host_str.len() as u8);
    plain.extend_from_slice(host_str.as_bytes());
    plain.extend_from_slice(&target.port().to_be_bytes());
    plain.extend_from_slice(payload);

    encode_quic_proxy_frame(psk, &plain)
}

/// Decodes an Init frame given the datagram received over UDP.
pub fn decode_quic_proxy_init(
    psk: &[u8],
    data: &[u8],
) -> std::io::Result<(NetLocation, Vec<u8>, Vec<u8>)> {
    let plain = decode_quic_proxy_frame(psk, data)?;
    parse_quic_proxy_init(&plain)
}

/// A UDP stream that sends QUIC datagrams to a Snell QUIC proxy listener.
///
/// An authenticated `Init` frame is sent on the first write and whenever a
/// packet is a QUIC Initial. Subsequent short-header QUIC packets are sent
/// raw over UDP directly.
pub struct QuicUdpStream {
    socket: tokio::net::UdpSocket,
    psk: Arc<[u8]>,
    userkey: Vec<u8>,
    target: NetLocation,
    pending_write: Option<Vec<u8>>,
}

impl QuicUdpStream {
    pub fn new(
        socket: tokio::net::UdpSocket,
        psk: Arc<[u8]>,
        userkey: Vec<u8>,
        target: NetLocation,
    ) -> Self {
        Self {
            socket,
            psk,
            userkey,
            target,
            pending_write: None,
        }
    }

    #[allow(dead_code)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl AsyncReadMessage for QuicUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().socket.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for QuicUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = &this.pending_write {
            let n = ready!(this.socket.poll_send(cx, pending))?;
            if n < pending.len() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short udp write",
                )));
            }
            this.pending_write = None;
            return Poll::Ready(Ok(()));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let frame = if is_quic_initial(buf) || !is_quic_looking(buf[0]) {
            encode_quic_proxy_init(&this.psk, &this.userkey, &this.target, buf)?
        } else {
            buf.to_vec()
        };

        match this.socket.poll_send(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n < frame.len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "short udp write",
                    )));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                this.pending_write = Some(frame);
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncFlushMessage for QuicUdpStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = &this.pending_write {
            let n = ready!(this.socket.poll_send(cx, pending))?;
            if n < pending.len() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "short udp write",
                )));
            }
            this.pending_write = None;
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for QuicUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for QuicUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for QuicUdpStream {}

pub type FallbackUdp = Box<
    dyn FnOnce(
            Box<dyn AsyncStream>,
            NetLocation,
        )
            -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncMessageStream>>> + Send>>
        + Send,
>;

type FallbackConnectFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncMessageStream>>> + Send>>;

pub struct SnellQuicProxyStream {
    state: QuicProxyStreamState,
}

enum QuicProxyStreamState {
    Sniffing {
        client_stream: Option<Box<dyn AsyncStream>>,
        target: NetLocation,
        server_addr: Option<SocketAddr>,
        psk: Arc<[u8]>,
        userkey: Vec<u8>,
        fallback: FallbackUdp,
    },
    ConnectingTcp(FallbackConnectFuture),
    Quic(QuicUdpStream),
    TcpRelay(Box<dyn AsyncMessageStream>),
    Failed(std::io::ErrorKind, String),
}

impl SnellQuicProxyStream {
    pub fn new(
        client_stream: Box<dyn AsyncStream>,
        target: NetLocation,
        server_addr: Option<SocketAddr>,
        psk: Arc<[u8]>,
        userkey: Vec<u8>,
        fallback: FallbackUdp,
    ) -> Self {
        Self {
            state: QuicProxyStreamState::Sniffing {
                client_stream: Some(client_stream),
                target,
                server_addr,
                psk,
                userkey,
                fallback,
            },
        }
    }

    fn try_start_quic(
        server_addr: SocketAddr,
        psk: Arc<[u8]>,
        userkey: Vec<u8>,
        target: NetLocation,
    ) -> std::io::Result<QuicUdpStream> {
        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.connect(server_addr)?;
        std_sock.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(QuicUdpStream::new(socket, psk, userkey, target))
    }
}

impl AsyncReadMessage for SnellQuicProxyStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.state {
                QuicProxyStreamState::Sniffing {
                    client_stream,
                    target,
                    fallback,
                    ..
                } => {
                    let stream = client_stream.take().expect("client stream present");
                    let target_loc = target.clone();
                    let dummy: FallbackUdp = Box::new(|_, _| unreachable!());
                    let fallback_fn = std::mem::replace(fallback, dummy);
                    let fut = fallback_fn(stream, target_loc);
                    this.state = QuicProxyStreamState::ConnectingTcp(fut);
                }
                QuicProxyStreamState::ConnectingTcp(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(relay)) => {
                        this.state = QuicProxyStreamState::TcpRelay(relay);
                    }
                    Poll::Ready(Err(e)) => {
                        let kind = e.kind();
                        let msg = e.to_string();
                        this.state = QuicProxyStreamState::Failed(kind, msg);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                QuicProxyStreamState::Quic(quic) => {
                    return Pin::new(quic).poll_read_message(cx, buf);
                }
                QuicProxyStreamState::TcpRelay(relay) => {
                    return Pin::new(relay).poll_read_message(cx, buf);
                }
                QuicProxyStreamState::Failed(kind, msg) => {
                    return Poll::Ready(Err(std::io::Error::new(*kind, msg.as_str())));
                }
            }
        }
    }
}

impl AsyncWriteMessage for SnellQuicProxyStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.state {
                QuicProxyStreamState::Sniffing {
                    client_stream,
                    target,
                    server_addr,
                    psk,
                    userkey,
                    fallback,
                } => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if (is_quic_looking(buf[0]) || is_quic_initial(buf))
                        && let Some(s_addr) = *server_addr
                        && let Ok(mut quic) = Self::try_start_quic(
                            s_addr,
                            psk.clone(),
                            userkey.clone(),
                            target.clone(),
                        )
                    {
                        let res = Pin::new(&mut quic).poll_write_message(cx, buf);
                        this.state = QuicProxyStreamState::Quic(quic);
                        return res;
                    }
                    let stream = client_stream.take().expect("client stream present");
                    let target_loc = target.clone();
                    let dummy: FallbackUdp = Box::new(|_, _| unreachable!());
                    let fallback_fn = std::mem::replace(fallback, dummy);
                    let fut = fallback_fn(stream, target_loc);
                    this.state = QuicProxyStreamState::ConnectingTcp(fut);
                }
                QuicProxyStreamState::ConnectingTcp(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(relay)) => {
                        this.state = QuicProxyStreamState::TcpRelay(relay);
                    }
                    Poll::Ready(Err(e)) => {
                        let kind = e.kind();
                        let msg = e.to_string();
                        this.state = QuicProxyStreamState::Failed(kind, msg);
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                QuicProxyStreamState::Quic(quic) => {
                    return Pin::new(quic).poll_write_message(cx, buf);
                }
                QuicProxyStreamState::TcpRelay(relay) => {
                    return Pin::new(relay).poll_write_message(cx, buf);
                }
                QuicProxyStreamState::Failed(kind, msg) => {
                    return Poll::Ready(Err(std::io::Error::new(*kind, msg.as_str())));
                }
            }
        }
    }
}

impl AsyncFlushMessage for SnellQuicProxyStream {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.as_mut().get_mut().state {
            QuicProxyStreamState::Quic(quic) => Pin::new(quic).poll_flush_message(cx),
            QuicProxyStreamState::TcpRelay(relay) => Pin::new(relay).poll_flush_message(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncShutdownMessage for SnellQuicProxyStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.as_mut().get_mut().state {
            QuicProxyStreamState::Quic(quic) => Pin::new(quic).poll_shutdown_message(cx),
            QuicProxyStreamState::TcpRelay(relay) => Pin::new(relay).poll_shutdown_message(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncPing for SnellQuicProxyStream {
    fn supports_ping(&self) -> bool {
        match &self.state {
            QuicProxyStreamState::Quic(quic) => quic.supports_ping(),
            QuicProxyStreamState::TcpRelay(relay) => relay.supports_ping(),
            _ => false,
        }
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        match &mut self.as_mut().get_mut().state {
            QuicProxyStreamState::Quic(quic) => Pin::new(quic).poll_write_ping(cx),
            QuicProxyStreamState::TcpRelay(relay) => Pin::new(relay).poll_write_ping(cx),
            _ => Poll::Ready(Ok(false)),
        }
    }
}

impl AsyncMessageStream for SnellQuicProxyStream {}

struct QuicProxySession {
    relay: Arc<UdpRelay>,
    target: NetLocation,
    /// Opens this session's duplicate inits.
    psk: Arc<[u8]>,
    /// Only client packets refresh it; target replies do not.
    last_client: Instant,
    return_task: tokio::task::AbortHandle,
}

impl Drop for QuicProxySession {
    fn drop(&mut self) {
        self.return_task.abort();
    }
}

/// Packets from a source whose init is being decoded.
#[derive(Default)]
struct Pending {
    packets: Vec<Vec<u8>>,
    bytes: usize,
}

impl Pending {
    fn hold(&mut self, packet: &[u8]) {
        if self.packets.len() < PENDING_PACKET_LIMIT
            && self.bytes + packet.len() <= PENDING_BYTES_LIMIT
        {
            self.bytes += packet.len();
            self.packets.push(packet.to_vec());
        }
    }
}

/// A new source's decoded init, sent back to the receive loop.
struct Decoded(SocketAddr, std::io::Result<QuicInit>);

/// Runs init decodes off the receive loop, `AUTH_WORKERS` at a time.
struct Decoder {
    permits: Arc<Semaphore>,
    done: mpsc::UnboundedSender<Decoded>,
    /// Decodes queued or running.
    queued: usize,
}

impl Decoder {
    /// Queues `job`; false when the queue is full. `lost` is reported if the
    /// job panics, so its source is not left pending.
    fn submit(
        &mut self,
        job: impl FnOnce() -> Decoded + Send + 'static,
        lost: Decoded,
    ) -> bool {
        if self.queued >= AUTH_QUEUE_SIZE {
            return false;
        }
        self.queued += 1;
        let (permits, done) = (self.permits.clone(), self.done.clone());
        tokio::spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            let decoded = tokio::task::spawn_blocking(job).await.unwrap_or(lost);
            let _ = done.send(decoded);
        });
        true
    }
}

/// Opens the relay for a new session and forwards the init payload.
fn create_session(
    socket: &Arc<tokio::net::UdpSocket>,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    client_addr: SocketAddr,
    init: QuicInit,
) -> Option<QuicProxySession> {
    log::info!("Snell QUIC proxy: new session from {client_addr} to {}", init.target);
    let relay = UdpRelay::with_queue_size(
        proxy_selector.clone(),
        resolver.clone(),
        Some(client_addr),
        RELAY_QUEUE_SIZE,
    );
    let relay = match relay {
        Ok(r) => Arc::new(r),
        Err(e) => {
            log::error!("Snell QUIC proxy: failed to create UdpRelay: {e}");
            return None;
        }
    };

    let _ = relay.send_to(Bytes::from(init.payload), init.target.clone());

    let socket_clone = socket.clone();
    let relay_clone = relay.clone();
    let return_task = tokio::spawn(async move {
        while let Ok((data, _from)) = relay_clone.recv().await {
            if socket_clone.send_to(&data, client_addr).await.is_err() {
                break;
            }
        }
    })
    .abort_handle();

    Some(QuicProxySession {
        relay,
        target: init.target,
        psk: init.psk,
        last_client: Instant::now(),
        return_task,
    })
}

/// Forwards `packet` on `client_addr`'s live session: raw QUIC directly, a
/// duplicate init after decoding it with the session's PSK (to the session's
/// original target). Duplicates are decoded inline, as sing-box does: one
/// KDF, and they keep their place among the session's packets. False when
/// there is no live session.
fn session_packet(
    sessions: &mut HashMap<SocketAddr, QuicProxySession>,
    client_addr: SocketAddr,
    packet: &[u8],
    idle_timeout: Duration,
) -> bool {
    let Some(session) = sessions.get_mut(&client_addr) else {
        return false;
    };
    if session.last_client.elapsed() >= idle_timeout {
        sessions.remove(&client_addr);
        return false;
    }
    let data = if is_quic_looking(packet[0]) {
        Bytes::copy_from_slice(packet)
    } else {
        match decode_quic_proxy_init(&session.psk, packet) {
            Ok((_, _, payload)) => Bytes::from(payload),
            Err(e) => {
                log::debug!("Snell QUIC proxy: reject duplicate init from {client_addr}: {e}");
                return true;
            }
        }
    };
    // Only accepted client packets refresh the session.
    session.last_client = Instant::now();
    if session.relay.send_to(data, session.target.clone()).is_err() {
        sessions.remove(&client_addr);
    }
    true
}

/// Runs the Snell QUIC Proxy UDP listener loop on a bound UDP socket.
/// `psk` is the server's shared password; `auth` its users.
pub async fn run_snell_quic_proxy_listener(
    socket: Arc<tokio::net::UdpSocket>,
    psk: Arc<[u8]>,
    auth: Arc<SnellAuth>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    run_listener(socket, psk, auth, proxy_selector, resolver, SESSION_IDLE_TIMEOUT).await
}

async fn run_listener(
    socket: Arc<tokio::net::UdpSocket>,
    psk: Arc<[u8]>,
    auth: Arc<SnellAuth>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut sessions: HashMap<SocketAddr, QuicProxySession> = HashMap::new();
    let mut pending: HashMap<SocketAddr, Pending> = HashMap::new();
    let (done, mut decoded) = mpsc::unbounded_channel();
    let mut decoder = Decoder {
        permits: Arc::new(Semaphore::new(AUTH_WORKERS)),
        done,
        queued: 0,
    };
    let mut sweep = tokio::time::interval(idle_timeout.min(Duration::from_secs(10)));

    loop {
        tokio::select! {
            _ = sweep.tick() => {
                sessions.retain(|_, session| session.last_client.elapsed() < idle_timeout);
            }
            Some(result) = decoded.recv() => {
                decoder.queued -= 1;
                let Decoded(client_addr, result) = result;
                let Some(held) = pending.remove(&client_addr) else {
                    continue;
                };
                let init = match result {
                    Ok(init) => init,
                    Err(e) => {
                        log::debug!(
                            "Snell QUIC proxy: reject init from {client_addr}: {e}"
                        );
                        continue;
                    }
                };
                if let Some(user) = &init.user {
                    log::debug!("Snell QUIC proxy user authenticated: {user}");
                }
                let Some(session) =
                    create_session(&socket, &proxy_selector, &resolver, client_addr, init)
                else {
                    continue;
                };
                sessions.insert(client_addr, session);
                for packet in held.packets {
                    session_packet(&mut sessions, client_addr, &packet, idle_timeout);
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (n, client_addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("Snell QUIC proxy UDP listener error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                let packet = &buf[..n];
                if session_packet(&mut sessions, client_addr, packet, idle_timeout) {
                    continue;
                }
                if let Some(held) = pending.get_mut(&client_addr) {
                    held.hold(packet);
                    continue;
                }
                if is_quic_looking(packet[0]) {
                    log::debug!(
                        "Snell QUIC proxy: discard packet without session from {client_addr}"
                    );
                    continue;
                }
                let (auth, psk, data) = (auth.clone(), psk.clone(), packet.to_vec());
                let lost = Decoded(client_addr, Err(std::io::Error::other("decoder panicked")));
                let job = move || Decoded(client_addr, auth.open_quic_init(&psk, &data));
                if decoder.submit(job, lost) {
                    pending.insert(client_addr, Pending::default());
                } else {
                    log::debug!(
                        "Snell QUIC proxy: decode queue full, drop init from {client_addr}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_initial_detection() {
        assert!(is_quic_initial(&[0xc0, 0, 0, 0, 1]));
        assert!(is_quic_initial(&[0xd0, 0x6b, 0x33, 0x43, 0xcf]));
        assert!(!is_quic_initial(&[0xe0, 0, 0, 0, 1]));
        assert!(!is_quic_initial(&[0xc0, 0, 0, 0, 0]));
        assert!(!is_quic_initial(&[0xc0, 1, 2, 3]));
    }

    #[test]
    fn test_quic_looking() {
        assert!(is_quic_looking(0xc0));
        assert!(is_quic_looking(0xff));
        assert!(is_quic_looking(0x40));
        assert!(is_quic_looking(0x7f));
        assert!(!is_quic_looking(0x00));
        assert!(!is_quic_looking(0x3f));
        assert!(!is_quic_looking(0x80));
        assert!(!is_quic_looking(0xbf));
    }

    #[test]
    fn test_quic_proxy_init_roundtrip() {
        let psk = b"test-snell-psk";
        let user_key = b"alice";
        let target = NetLocation::from_str("example.com:443", None).unwrap();
        let payload = vec![0xc0, 0, 0, 0, 1, 1, 2, 3, 4, 5];

        let encoded = encode_quic_proxy_init(psk, user_key, &target, &payload).unwrap();

        // Ensure salt does not look like QUIC
        assert!(!is_quic_looking(encoded[0]));

        let (decoded_target, decoded_user_key, decoded_payload) =
            decode_quic_proxy_init(psk, &encoded).unwrap();

        assert_eq!(decoded_target, target);
        assert_eq!(decoded_user_key, user_key);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_quic_proxy_multi_frame_roundtrip() {
        let psk = b"test-snell-psk";
        let user_key = b"";
        let target = NetLocation::from_str("1.1.1.1:443", None).unwrap();
        let payload = vec![0x40u8; 3500]; // Multi-frame chunking test (> 1417)

        let encoded = encode_quic_proxy_init(psk, user_key, &target, &payload).unwrap();
        let (decoded_target, decoded_user_key, decoded_payload) =
            decode_quic_proxy_init(psk, &encoded).unwrap();

        assert_eq!(decoded_target, target);
        assert_eq!(decoded_user_key, user_key);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_quic_proxy_wrong_psk_fails() {
        let psk = b"test-snell-psk";
        let wrong_psk = b"wrong-snell-psk";
        let target = NetLocation::from_str("example.com:443", None).unwrap();
        let payload = vec![0xc0, 0, 0, 0, 1];

        let encoded = encode_quic_proxy_init(psk, b"", &target, &payload).unwrap();
        assert!(decode_quic_proxy_init(wrong_psk, &encoded).is_err());
    }

    #[test]
    fn test_quic_proxy_truncated_fails() {
        let psk = b"test-snell-psk";
        let target = NetLocation::from_str("example.com:443", None).unwrap();
        let payload = vec![0xc0, 0, 0, 0, 1];

        let encoded = encode_quic_proxy_init(psk, b"", &target, &payload).unwrap();
        assert!(decode_quic_proxy_init(psk, &encoded[..encoded.len() - 1]).is_err());
    }

    use crate::config::SnellUserConfig;
    use crate::snell::auth::SnellAuth;

    const SHARED: &[u8] = b"snell-secret-psk-12345";

    /// UDP echo server; replies are `tag` + the datagram.
    async fn echo_server(tag: &'static [u8]) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&[tag, &buf[..n]].concat(), src).await;
            }
        });
        addr
    }

    /// Echoes each datagram, then repeats it every 100 ms four more times.
    async fn chatty_server() -> SocketAddr {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                let (socket, data) = (socket.clone(), buf[..n].to_vec());
                tokio::spawn(async move {
                    for _ in 0..5 {
                        let _ = socket.send_to(&data, src).await;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                });
            }
        });
        addr
    }

    fn users(authentication: &str, secrets: &[&str]) -> SnellAuth {
        let users: Vec<SnellUserConfig> = secrets
            .iter()
            .enumerate()
            .map(|(i, secret)| SnellUserConfig {
                name: format!("user{i}"),
                userkey: (authentication == "userkey").then(|| secret.to_string()),
                password: (authentication == "psk").then(|| secret.to_string()),
            })
            .collect();
        SnellAuth::new(&users, Some(authentication), None)
    }

    /// Starts a listener; returns its address.
    async fn listener(auth: SnellAuth, idle_timeout: Duration) -> SocketAddr {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![crate::config::ResolvedRuleConfig::default()],
                resolver.clone(),
            )
            .unwrap(),
        );
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        tokio::spawn(run_listener(
            socket,
            Arc::from(SHARED),
            Arc::new(auth),
            selector,
            resolver,
            idle_timeout,
        ));
        addr
    }

    async fn client() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    fn init(psk: &[u8], key: &[u8], target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let target = NetLocation::from_str(&target.to_string(), None).unwrap();
        encode_quic_proxy_init(psk, key, &target, payload).unwrap()
    }

    /// The next datagram within `wait`, if any.
    async fn recv(client: &tokio::net::UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(wait, client.recv(&mut buf)).await.ok()?.ok()?;
        Some(buf[..n].to_vec())
    }

    const REPLY: Duration = Duration::from_secs(3);
    const SILENCE: Duration = Duration::from_millis(500);

    #[tokio::test]
    async fn shared_password_session_forwards_both_ways() {
        let echo = echo_server(b"").await;
        let proxy = listener(SnellAuth::new(&[], None, None), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", echo, b"\xc0first"), proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0first");
        client.send_to(b"\x40follow-up", proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\x40follow-up");
    }

    #[tokio::test]
    async fn userkey_init_needs_a_known_key() {
        let echo = echo_server(b"").await;
        let proxy = listener(users("userkey", &["alice-key"]), SESSION_IDLE_TIMEOUT).await;
        let good = client().await;
        good.send_to(&init(SHARED, b"alice-key", echo, b"\xc0ok"), proxy).await.unwrap();
        assert_eq!(recv(&good, REPLY).await.unwrap(), b"\xc0ok");
        let bad = client().await;
        bad.send_to(&init(SHARED, b"mallory", echo, b"\xc0no"), proxy).await.unwrap();
        assert_eq!(recv(&bad, SILENCE).await, None);
        bad.send_to(b"\x40no-session", proxy).await.unwrap();
        assert_eq!(recv(&bad, SILENCE).await, None);
    }

    #[tokio::test]
    async fn psk_users_each_open_their_own_session() {
        let echo = echo_server(b"").await;
        let secrets = ["alice-psk-0001", "bob-psk-000002"];
        let proxy = listener(users("psk", &secrets), SESSION_IDLE_TIMEOUT).await;
        for secret in secrets {
            let client = client().await;
            client.send_to(&init(secret.as_bytes(), b"", echo, b"\xc0hi"), proxy).await.unwrap();
            assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0hi", "{secret}");
            // A duplicate init is decoded with this user's PSK, not a shared one.
            client.send_to(&init(secret.as_bytes(), b"", echo, b"\xc0again"), proxy).await.unwrap();
            assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0again", "{secret}");
        }
        let stranger = client().await;
        stranger.send_to(&init(b"nobody-psk-01", b"", echo, b"\xc0x"), proxy).await.unwrap();
        assert_eq!(recv(&stranger, SILENCE).await, None);
    }

    #[tokio::test]
    async fn duplicate_init_keeps_the_original_target() {
        let first = echo_server(b"first:").await;
        let second = echo_server(b"second:").await;
        let proxy = listener(SnellAuth::new(&[], None, None), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", first, b"\xc0a"), proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"first:\xc0a");
        client.send_to(&init(SHARED, b"", second, b"\xc0b"), proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"first:\xc0b");
    }

    #[tokio::test]
    async fn duplicate_init_stays_in_order() {
        let echo = echo_server(b"").await;
        let proxy = listener(SnellAuth::new(&[], None, None), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", echo, b"\xc0open"), proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0open");
        client.send_to(&init(SHARED, b"", echo, b"\xc0dup"), proxy).await.unwrap();
        client.send_to(b"\x40raw", proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0dup");
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\x40raw");
    }

    #[tokio::test]
    async fn empty_payload_init_is_refused() {
        let echo = echo_server(b"").await;
        let proxy = listener(SnellAuth::new(&[], None, None), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", echo, b""), proxy).await.unwrap();
        client.send_to(b"\x40after-empty", proxy).await.unwrap();
        assert_eq!(recv(&client, SILENCE).await, None);
    }

    #[tokio::test]
    async fn packets_during_authentication_are_forwarded() {
        let echo = echo_server(b"").await;
        // The matching user is tried last, so the init takes a while to open.
        let secrets: Vec<String> = (0..8).map(|i| format!("user-psk-{i:04}")).collect();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let proxy = listener(users("psk", &secrets), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(b"user-psk-0007", b"", echo, b"\xc00"), proxy).await.unwrap();
        // Two held packets: with the init payload they fit UdpRelay's queue of 4.
        for packet in [b"\x401", b"\x402"] {
            client.send_to(packet, proxy).await.unwrap();
        }
        for expected in [b"\xc00", b"\x401", b"\x402"] {
            assert_eq!(recv(&client, REPLY).await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn pending_buffer_is_bounded() {
        let echo = echo_server(b"").await;
        let secrets: Vec<String> = (0..8).map(|i| format!("user-psk-{i:04}")).collect();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let proxy = listener(users("psk", &secrets), SESSION_IDLE_TIMEOUT).await;
        let client = client().await;
        client.send_to(&init(b"user-psk-0007", b"", echo, b"\xc0init"), proxy).await.unwrap();
        for i in 0..20u8 {
            client.send_to(&[0x40, i], proxy).await.unwrap();
        }
        let mut replies = Vec::new();
        while let Some(reply) = recv(&client, SILENCE).await {
            replies.push(reply);
        }
        assert_eq!(replies[0], b"\xc0init");
        // Exactly 8 packets were held while the init was decoded, and all of
        // them reach the target.
        assert_eq!(replies.len(), 1 + PENDING_PACKET_LIMIT, "{replies:?}");
    }

    #[tokio::test]
    async fn idle_session_expires() {
        let echo = echo_server(b"").await;
        let idle = Duration::from_millis(300);
        let proxy = listener(SnellAuth::new(&[], None, None), idle).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", echo, b"\xc0open"), proxy).await.unwrap();
        assert_eq!(recv(&client, REPLY).await.unwrap(), b"\xc0open");
        tokio::time::sleep(Duration::from_millis(450)).await;
        client.send_to(b"\x40late", proxy).await.unwrap();
        assert_eq!(recv(&client, SILENCE).await, None);
    }

    #[tokio::test]
    async fn replies_do_not_refresh_idle() {
        let chatty = chatty_server().await;
        let idle = Duration::from_millis(300);
        let proxy = listener(SnellAuth::new(&[], None, None), idle).await;
        let client = client().await;
        client.send_to(&init(SHARED, b"", chatty, b"\xc0open"), proxy).await.unwrap();
        // Replies keep arriving every 100 ms, but the client stays quiet.
        tokio::time::sleep(Duration::from_millis(450)).await;
        client.send_to(b"\x40fresh", proxy).await.unwrap();
        let deadline = tokio::time::Instant::now() + SILENCE;
        while let Some(reply) =
            recv(&client, deadline.saturating_duration_since(tokio::time::Instant::now())).await
        {
            assert_ne!(reply, b"\x40fresh", "the session outlived its idle timeout");
        }
    }

    #[tokio::test]
    async fn init_flood_does_not_stall_a_live_session() {
        let echo = echo_server(b"").await;
        let secrets: Vec<String> = (0..16).map(|i| format!("user-psk-{i:04}")).collect();
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let proxy = listener(users("psk", &secrets), SESSION_IDLE_TIMEOUT).await;
        let live = client().await;
        live.send_to(&init(b"user-psk-0000", b"", echo, b"\xc0open"), proxy).await.unwrap();
        assert_eq!(recv(&live, REPLY).await.unwrap(), b"\xc0open");
        // Each garbage init costs 16 failed KDF tries. Blocking sockets queue
        // the whole flood before the listener gets to run.
        let flood: Vec<_> = (0..64)
            .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        for source in &flood {
            source.send_to(&[0x01; 200], proxy).unwrap();
        }
        let started = std::time::Instant::now();
        live.send_to(b"\x40still-here", proxy).await.unwrap();
        assert_eq!(recv(&live, REPLY).await.unwrap(), b"\x40still-here");
        assert!(started.elapsed() < Duration::from_millis(300), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn client_quic_udp_stream_sends_init_and_receives_echo() {
        let echo = echo_server(b"echo:").await;
        let proxy = listener(SnellAuth::new(&[], None, None), SESSION_IDLE_TIMEOUT).await;
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(proxy).await.unwrap();

        let mut stream = QuicUdpStream::new(
            sock,
            Arc::from(SHARED),
            vec![],
            NetLocation::from_str(&echo.to_string(), None).unwrap(),
        );
        assert!(stream.local_addr().is_ok());

        // Send Initial packet (starts with 0xc0, version != 0)
        let init_pkt = b"\xc0\x00\x00\x00\x01\x00payload";
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_message(cx, init_pkt)
        })
        .await
        .unwrap();

        let mut buf = [0u8; 100];
        let mut read_buf = ReadBuf::new(&mut buf);
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
        })
        .await
        .unwrap();
        assert_eq!(read_buf.filled(), b"echo:\xc0\x00\x00\x00\x01\x00payload");

        // Send short header packet (starts with 0x40): should go raw
        let raw_pkt = b"\x40subsequent-data";
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_message(cx, raw_pkt)
        })
        .await
        .unwrap();

        let mut buf2 = [0u8; 100];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_message(cx, &mut read_buf2)
        })
        .await
        .unwrap();
        assert_eq!(read_buf2.filled(), b"echo:\x40subsequent-data");
    }

    #[tokio::test]
    async fn client_quic_proxy_stream_falls_back_on_non_quic() {
        let fallback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fc = fallback_called.clone();
        let written = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let written_clone = written.clone();
        let (c1, _s1) = tokio::io::duplex(1024);

        struct MockMessageStream(Arc<parking_lot::Mutex<Vec<Vec<u8>>>>);
        impl AsyncReadMessage for MockMessageStream {
            fn poll_read_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWriteMessage for MockMessageStream {
            fn poll_write_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<()>> {
                self.0.lock().push(buf.to_vec());
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncFlushMessage for MockMessageStream {
            fn poll_flush_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncShutdownMessage for MockMessageStream {
            fn poll_shutdown_message(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncPing for MockMessageStream {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncMessageStream for MockMessageStream {}

        let stream = SnellQuicProxyStream::new(
            Box::new(c1),
            NetLocation::from_str("example.com:53", None).unwrap(),
            Some("127.0.0.1:9999".parse().unwrap()),
            Arc::from(SHARED),
            vec![],
            Box::new(move |raw, _target| {
                fc.store(true, std::sync::atomic::Ordering::SeqCst);
                let w = written_clone.clone();
                drop(raw);
                Box::pin(async move {
                    Ok(Box::new(MockMessageStream(w)) as Box<dyn AsyncMessageStream>)
                })
            }),
        );
        let mut stream = stream;
        // Non-QUIC packet: first byte 0x00
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_message(cx, b"\x00dns-request")
        })
        .await
        .unwrap();
        assert!(fallback_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            written.lock().as_slice(),
            &[b"\x00dns-request".to_vec()]
        );
    }
}
