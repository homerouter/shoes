#![allow(dead_code)]

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

pub const DEFAULT_HTTP_OBFS_HOST: &str = "bing.com";
pub const DEFAULT_HTTP_OBFS_URI: &str = "/";
pub const DEFAULT_TLS_OBFS_HOST: &str = "cloudfront.net";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnellObfsMode {
    None,
    Http,
    Tls,
}

impl SnellObfsMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" | "" => Some(Self::None),
            "http" => Some(Self::Http),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpObfsRole {
    Client,
    Server,
}

enum HttpReadState {
    Headers(Vec<u8>),
    Passthrough,
}

enum HttpWriteState {
    Initial,
    PendingHeader {
        staging: Vec<u8>,
        written: usize,
        user_len: usize,
    },
    Passthrough,
}

pub struct HttpObfsStream<S> {
    inner: S,
    role: HttpObfsRole,
    host: String,
    uri: String,
    read_state: HttpReadState,
    write_state: HttpWriteState,
    read_buffer: Vec<u8>,
    read_buffer_offset: usize,
}

impl<S> HttpObfsStream<S> {
    pub fn new_client(inner: S, host: Option<&str>, uri: Option<&str>) -> Self {
        let host = host.unwrap_or(DEFAULT_HTTP_OBFS_HOST);
        let host = if host.is_empty() {
            DEFAULT_HTTP_OBFS_HOST
        } else {
            host
        };
        let uri = uri.unwrap_or(DEFAULT_HTTP_OBFS_URI);
        let uri = if uri.is_empty() {
            DEFAULT_HTTP_OBFS_URI
        } else {
            uri
        };
        Self {
            inner,
            role: HttpObfsRole::Client,
            host: host.to_string(),
            uri: uri.to_string(),
            read_state: HttpReadState::Headers(Vec::with_capacity(512)),
            write_state: HttpWriteState::Initial,
            read_buffer: Vec::new(),
            read_buffer_offset: 0,
        }
    }

    pub fn new_server(inner: S) -> Self {
        Self {
            inner,
            role: HttpObfsRole::Server,
            host: String::new(),
            uri: String::new(),
            read_state: HttpReadState::Headers(Vec::with_capacity(512)),
            write_state: HttpWriteState::Initial,
            read_buffer: Vec::new(),
            read_buffer_offset: 0,
        }
    }

    fn generate_client_request(&self, payload_len: usize) -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let key_bytes: [u8; 16] = rand::random();
        let key = STANDARD.encode(key_bytes);

        let os_ver = 9 + rand::rng().random_range(0..6);
        let ff_ver = 22 + rand::rng().random_range(0..43);
        let user_agent = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{os_ver}; rv:64.0) \
             Gecko/20100101 Firefox/{ff_ver}.0"
        );

        format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Content-Length: {}\r\n\
             Sec-WebSocket-Key: {}\r\n\r\n",
            self.uri, self.host, user_agent, payload_len, key
        )
        .into_bytes()
    }

    fn generate_server_response() -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let accept_bytes: [u8; 16] = rand::random();
        let accept = STANDARD.encode(accept_bytes);

        let major = rand::rng().random_range(0..14);
        let minor = rand::rng().random_range(0..12);

        format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Server: nginx/1.{major}.{minor}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept
        )
        .into_bytes()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        // 1. Drain any buffered bytes first
        if this.read_buffer_offset < this.read_buffer.len() {
            let available = &this.read_buffer[this.read_buffer_offset..];
            let to_read = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_read]);
            this.read_buffer_offset += to_read;
            if this.read_buffer_offset == this.read_buffer.len() {
                this.read_buffer.clear();
                this.read_buffer_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 2. State machine
        loop {
            match &mut this.read_state {
                HttpReadState::Headers(staging) => {
                    let mut temp = [0u8; 1024];
                    let mut read_buf = ReadBuf::new(&mut temp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read_buf))?;
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF before HTTP obfs headers completed",
                        )));
                    }
                    staging.extend_from_slice(filled);
                    if staging.len() > 16384 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "oversized HTTP obfs header",
                        )));
                    }
                    if let Some(pos) = staging.windows(4).position(|w| w == b"\r\n\r\n") {
                        let payload_start = pos + 4;
                        let remaining = staging[payload_start..].to_vec();
                        this.read_state = HttpReadState::Passthrough;
                        if !remaining.is_empty() {
                            let to_read = remaining.len().min(buf.remaining());
                            buf.put_slice(&remaining[..to_read]);
                            if to_read < remaining.len() {
                                this.read_buffer = remaining;
                                this.read_buffer_offset = to_read;
                            }
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                HttpReadState::Passthrough => {
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.write_state {
                HttpWriteState::Initial => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let header = match this.role {
                        HttpObfsRole::Client => this.generate_client_request(buf.len()),
                        HttpObfsRole::Server => Self::generate_server_response(),
                    };
                    let mut staging = Vec::with_capacity(header.len() + buf.len());
                    staging.extend_from_slice(&header);
                    staging.extend_from_slice(buf);
                    this.write_state = HttpWriteState::PendingHeader {
                        staging,
                        written: 0,
                        user_len: buf.len(),
                    };
                }
                HttpWriteState::PendingHeader {
                    staging,
                    written,
                    user_len,
                } => {
                    while *written < staging.len() {
                        let n = ready!(
                            Pin::new(&mut this.inner).poll_write(cx, &staging[*written..])
                        )?;
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "failed to write HTTP obfs header",
                            )));
                        }
                        *written += n;
                    }
                    let ret = *user_len;
                    this.write_state = HttpWriteState::Passthrough;
                    return Poll::Ready(Ok(ret));
                }
                HttpWriteState::Passthrough => {
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let HttpWriteState::PendingHeader { staging, written, .. } = &mut this.write_state {
            while *written < staging.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &staging[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write HTTP obfs header",
                    )));
                }
                *written += n;
            }
            this.write_state = HttpWriteState::Passthrough;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let HttpWriteState::PendingHeader { staging, written, .. } = &mut this.write_state {
            while *written < staging.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &staging[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write HTTP obfs header",
                    )));
                }
                *written += n;
            }
            this.write_state = HttpWriteState::Passthrough;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for HttpObfsStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for HttpObfsStream<S> {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
}

enum TlsReadState {
    Discard { needed: usize, progress: usize },
    Length { buf: [u8; 2], progress: usize },
    Payload { remain: usize },
}

enum TlsWriteState {
    Idle,
    Writing {
        buffer: Vec<u8>,
        written: usize,
        user_len: usize,
    },
}

pub struct TlsObfsClientStream<S> {
    inner: S,
    server: String,
    first_write: bool,
    first_read: bool,
    read_state: TlsReadState,
    write_state: TlsWriteState,
}

impl<S> TlsObfsClientStream<S> {
    pub fn new(inner: S, host: Option<&str>) -> Self {
        let host = host.unwrap_or(DEFAULT_TLS_OBFS_HOST);
        let host = if host.is_empty() {
            DEFAULT_TLS_OBFS_HOST
        } else {
            host
        };
        Self {
            inner,
            server: host.to_string(),
            first_write: true,
            first_read: true,
            read_state: TlsReadState::Discard {
                needed: 105,
                progress: 0,
            },
            write_state: TlsWriteState::Idle,
        }
    }
}

fn make_client_hello_msg(data: &[u8], server: &str) -> Vec<u8> {
    use rand::Rng;

    let mut random_bytes = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);
    rand::rng().fill_bytes(&mut session_id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let server_bytes = server.as_bytes();
    let total_len = 212 + data.len() + server_bytes.len();
    let mut buf = Vec::with_capacity(5 + total_len);

    // TLS record header: Handshake, TLS 1.0 (0x0301), length
    buf.push(0x16);
    buf.extend_from_slice(&[0x03, 0x01]);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());

    // Handshake: ClientHello (1), length (3 bytes), TLS 1.2 (0x0303)
    let handshake_len = 208 + data.len() + server_bytes.len();
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]);

    // Random: timestamp (4 bytes) + random (28 bytes)
    buf.extend_from_slice(&now.to_be_bytes());
    buf.extend_from_slice(&random_bytes);

    // Session ID: len (32) + session_id (32 bytes)
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // Cipher suites: length (56) + 28 suites
    buf.extend_from_slice(&[0x00, 0x38]);
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
        0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
        0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
        0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // Compression: length 1, 0x00
    buf.extend_from_slice(&[0x01, 0x00]);

    // Extensions length
    let ext_len = 79 + data.len() + server_bytes.len();
    buf.extend_from_slice(&(ext_len as u16).to_be_bytes());

    // Extension: Session Ticket (0x0023)
    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    // Extension: Server Name (0x0000)
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((server_bytes.len() + 5) as u16).to_be_bytes());
    buf.extend_from_slice(&((server_bytes.len() + 3) as u16).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(server_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(server_bytes);

    // Extension: EC point formats (0x000b)
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // Extension: Supported groups (0x000a)
    buf.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);

    // Extension: Signature algorithms (0x000d)
    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
        0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
        0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // Extension: Encrypt-then-MAC (0x0016)
    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // Extension: Extended Master Secret (0x0017)
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsObfsClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.read_state {
                TlsReadState::Discard { needed, progress } => {
                    let need = *needed - *progress;
                    let mut tmp = [0u8; 105];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        if *progress == 0 && !this.first_read {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while reading TLS obfs header",
                        )));
                    }
                    *progress += n;
                    if *progress == *needed {
                        this.first_read = false;
                        this.read_state = TlsReadState::Length {
                            buf: [0u8; 2],
                            progress: 0,
                        };
                    }
                }
                TlsReadState::Length {
                    buf: len_buf,
                    progress,
                } => {
                    let need = 2 - *progress;
                    let mut tmp = [0u8; 2];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while reading TLS obfs record length",
                        )));
                    }
                    len_buf[*progress..*progress + n].copy_from_slice(&tmp[..n]);
                    *progress += n;
                    if *progress == 2 {
                        let length = u16::from_be_bytes(*len_buf) as usize;
                        this.read_state = TlsReadState::Payload { remain: length };
                    }
                }
                TlsReadState::Payload { remain } => {
                    if *remain == 0 {
                        this.read_state = TlsReadState::Discard {
                            needed: 3,
                            progress: 0,
                        };
                        continue;
                    }
                    let max_read = (*remain).min(buf.remaining());
                    if max_read == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let mut tmp = [0u8; 8192];
                    let to_read = max_read.min(tmp.len());
                    let mut rb = ReadBuf::new(&mut tmp[..to_read]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while reading TLS obfs record payload",
                        )));
                    }
                    buf.put_slice(&tmp[..n]);
                    *remain -= n;
                    if *remain == 0 {
                        this.read_state = TlsReadState::Discard {
                            needed: 3,
                            progress: 0,
                        };
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsObfsClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.write_state {
                TlsWriteState::Idle => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let chunk_len = buf.len().min(16384);
                    let chunk = &buf[..chunk_len];
                    let packet = if this.first_write {
                        this.first_write = false;
                        make_client_hello_msg(chunk, &this.server)
                    } else {
                        let mut p = Vec::with_capacity(5 + chunk_len);
                        p.extend_from_slice(&[0x17, 0x03, 0x03]);
                        p.extend_from_slice(&(chunk_len as u16).to_be_bytes());
                        p.extend_from_slice(chunk);
                        p
                    };
                    this.write_state = TlsWriteState::Writing {
                        buffer: packet,
                        written: 0,
                        user_len: chunk_len,
                    };
                }
                TlsWriteState::Writing {
                    buffer,
                    written,
                    user_len,
                } => {
                    while *written < buffer.len() {
                        let n = ready!(
                            Pin::new(&mut this.inner).poll_write(cx, &buffer[*written..])
                        )?;
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "failed to write TLS obfs packet",
                            )));
                        }
                        *written += n;
                    }
                    let ret = *user_len;
                    this.write_state = TlsWriteState::Idle;
                    return Poll::Ready(Ok(ret));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let TlsWriteState::Writing {
            buffer,
            written,
            ..
        } = &mut this.write_state
        {
            while *written < buffer.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &buffer[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write TLS obfs packet",
                    )));
                }
                *written += n;
            }
            this.write_state = TlsWriteState::Idle;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let TlsWriteState::Writing {
            buffer,
            written,
            ..
        } = &mut this.write_state
        {
            while *written < buffer.len() {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &buffer[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write TLS obfs packet",
                    )));
                }
                *written += n;
            }
            this.write_state = TlsWriteState::Idle;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for TlsObfsClientStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for TlsObfsClientStream<S> {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.flow()
    }
}

