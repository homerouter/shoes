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
    ConnectingTcp(
        Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncMessageStream>>> + Send>>,
    ),
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
                    if is_quic_looking(buf[0]) || is_quic_initial(buf) {
                        if let Some(s_addr) = *server_addr {
                            if let Ok(mut quic) = Self::try_start_quic(
                                s_addr,
                                psk.clone(),
                                userkey.clone(),
                                target.clone(),
                            ) {
                                let res = Pin::new(&mut quic).poll_write_message(cx, buf);
                                this.state = QuicProxyStreamState::Quic(quic);
                                return res;
                            }
                        }
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

