use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncPing, AsyncStream};
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};

const DEFAULT_SERVICE_NAME: &str = "GunService";
const MAX_FRAME_SIZE: u32 = 16 * 1024;
const INITIAL_WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const INITIAL_CONN_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

fn encode_varint(mut val: usize, buf: &mut BytesMut) {
    while val >= 0x80 {
        buf.put_u8((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
    buf.put_u8(val as u8);
}

fn varint_len(mut val: usize) -> usize {
    let mut len = 1;
    while val >= 0x80 {
        len += 1;
        val >>= 7;
    }
    len
}

fn decode_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut result = 0usize;
    let mut shift = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// A stream carrying raw bidirectional payload framed using gRPC Gun format (Protobuf Hunk)
/// over an HTTP/2 stream.
pub struct GunStream {
    send: h2::SendStream<Bytes>,
    recv: Option<h2::RecvStream>,
    recv_pending: Option<h2::client::ResponseFuture>,
    read_buf: BytesMut,
    remaining_in_hunk: usize,
    pending_write: Option<Bytes>,
    shutdown_sent: bool,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl GunStream {
    pub fn new_client(
        send: h2::SendStream<Bytes>,
        recv_pending: h2::client::ResponseFuture,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            send,
            recv: None,
            recv_pending: Some(recv_pending),
            read_buf: BytesMut::with_capacity(16 * 1024),
            remaining_in_hunk: 0,
            pending_write: None,
            shutdown_sent: false,
            peer_addr,
            local_addr,
        }
    }

    pub fn new_server(
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            send,
            recv: Some(recv),
            recv_pending: None,
            read_buf: BytesMut::with_capacity(16 * 1024),
            remaining_in_hunk: 0,
            pending_write: None,
            shutdown_sent: false,
            peer_addr,
            local_addr,
        }
    }
}

impl AsyncPing for GunStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for GunStream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

impl AsyncRead for GunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let this = &mut *self;

        // Lazy response header resolution for client streams
        if this.recv.is_none() {
            if let Some(mut fut) = this.recv_pending.take() {
                match Pin::new(&mut fut).poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        if response.status() != StatusCode::OK {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "gRPC server returned non-200 status: {}",
                                response.status()
                            ))));
                        }
                        this.recv = Some(response.into_body());
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Pending => {
                        this.recv_pending = Some(fut);
                        return Poll::Pending;
                    }
                }
            } else {
                return Poll::Ready(Ok(()));
            }
        }

        let recv = this.recv.as_mut().unwrap();

        loop {
            // Deliver remaining bytes in the current Hunk payload
            if this.remaining_in_hunk > 0 {
                if !this.read_buf.is_empty() {
                    let to_read = this
                        .remaining_in_hunk
                        .min(buf.remaining())
                        .min(this.read_buf.len());
                    buf.put_slice(&this.read_buf[..to_read]);
                    this.read_buf.advance(to_read);
                    this.remaining_in_hunk -= to_read;
                    let _ = recv.flow_control().release_capacity(to_read);
                    return Poll::Ready(Ok(()));
                }

                match Pin::new(&mut *recv).poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => {
                        this.read_buf.extend_from_slice(&data);
                        continue;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Need next Gun frame header: 5 bytes gRPC header + 1 byte protobuf tag (0x0A)
            while this.read_buf.len() < 6 {
                match Pin::new(&mut *recv).poll_data(cx) {
                    Poll::Ready(Some(Ok(data))) => {
                        this.read_buf.extend_from_slice(&data);
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Ready(None) => {
                        if this.read_buf.is_empty() {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            if this.read_buf[0] != 0 {
                return Poll::Ready(Err(io::Error::other("compressed gRPC frames not supported")));
            }

            if this.read_buf[5] != 0x0A {
                return Poll::Ready(Err(io::Error::other(format!(
                    "invalid protobuf tag: expected 0x0A, got 0x{:02X}",
                    this.read_buf[5]
                ))));
            }

            let varint_slice = &this.read_buf[6..];
            match decode_varint(varint_slice) {
                Some((payload_len, varint_bytes)) => {
                    let header_len = 6 + varint_bytes;
                    this.read_buf.advance(header_len);
                    let _ = recv.flow_control().release_capacity(header_len);
                    this.remaining_in_hunk = payload_len;
                    continue;
                }
                None => {
                    match Pin::new(&mut *recv).poll_data(cx) {
                        Poll::Ready(Some(Ok(data))) => {
                            this.read_buf.extend_from_slice(&data);
                            continue;
                        }
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Err(io::Error::other(e)));
                        }
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        let this = &mut *self;

        // If there's a pending write from before, finish sending it first
        while let Some(pending) = this.pending_write.take() {
            this.send.reserve_capacity(pending.len());
            let capacity = this.send.capacity();
            if capacity != 0 {
                let to_send = pending.len().min(capacity);
                let chunk = pending.slice(..to_send);
                let rest = pending.slice(to_send..);
                if let Err(e) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                if !rest.is_empty() {
                    this.pending_write = Some(rest);
                    // continue loop to check capacity again or wait
                } else {
                    break;
                }
            } else {
                match std::task::ready!(this.send.poll_capacity(cx)) {
                    Some(Ok(_)) => {
                        this.pending_write = Some(pending);
                        continue;
                    }
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                    None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
        }

        let chunk_size = buf.len().min(16 * 1024);
        let chunk = &buf[..chunk_size];

        let vlen = varint_len(chunk.len());
        let proto_len = 1 + vlen + chunk.len();
        let total_frame_len = 5 + proto_len;

        let mut frame = BytesMut::with_capacity(total_frame_len);
        frame.put_u8(0x00);
        frame.put_u32(proto_len as u32);
        frame.put_u8(0x0A);
        encode_varint(chunk.len(), &mut frame);
        frame.put_slice(chunk);
        let frame_bytes = frame.freeze();

        this.send.reserve_capacity(frame_bytes.len());
        loop {
            let capacity = this.send.capacity();
            if capacity != 0 {
                let to_send = frame_bytes.len().min(capacity);
                let chunk = frame_bytes.slice(..to_send);
                let rest = frame_bytes.slice(to_send..);
                if let Err(e) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                if !rest.is_empty() {
                    this.pending_write = Some(rest);
                }
                return Poll::Ready(Ok(chunk_size));
            }
            match std::task::ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while let Some(pending) = this.pending_write.take() {
            this.send.reserve_capacity(pending.len());
            let capacity = this.send.capacity();
            if capacity != 0 {
                let to_send = pending.len().min(capacity);
                let chunk = pending.slice(..to_send);
                let rest = pending.slice(to_send..);
                if let Err(e) = this.send.send_data(chunk, false) {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                if !rest.is_empty() {
                    this.pending_write = Some(rest);
                }
            } else {
                match std::task::ready!(this.send.poll_capacity(cx)) {
                    Some(Ok(_)) => {
                        this.pending_write = Some(pending);
                        continue;
                    }
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                    None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let this = &mut *self;
        if !this.shutdown_sent {
            let _ = this.send.send_data(Bytes::new(), true);
            this.shutdown_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub struct GrpcTcpClientHandler {
    inner_client_handler: Arc<dyn TcpClientHandler>,
    service_name: String,
    headers: Option<HashMap<String, String>>,
    host: Option<String>,
}

impl GrpcTcpClientHandler {
    pub fn new(
        inner_client_handler: Arc<dyn TcpClientHandler>,
        service_name: Option<String>,
        headers: Option<HashMap<String, String>>,
        host: Option<String>,
    ) -> Self {
        let service_name = service_name
            .map(|s| s.trim_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
        Self {
            inner_client_handler,
            service_name,
            headers,
            host,
        }
    }
}

#[async_trait]
impl TcpClientHandler for GrpcTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let peer_addr = client_stream.peer_addr();
        let local_addr = client_stream.local_addr();

        let (mut send_request, connection) = h2::client::Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONN_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .enable_push(false)
            .handshake(client_stream)
            .await
            .map_err(io::Error::other)?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::debug!("gRPC client HTTP/2 connection error: {e}");
            }
        });

        std::future::poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .map_err(io::Error::other)?;

        let authority = self
            .host
            .clone()
            .unwrap_or_else(|| remote_location.to_string());
        let uri = format!("http://{authority}/{}/Tun", self.service_name);

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-go/1.48.0")
            .header("te", "trailers");

        if let Some(headers) = &self.headers {
            for (k, v) in headers {
                request = request.header(k.as_str(), v.as_str());
            }
        }

        let request = request.body(()).map_err(io::Error::other)?;

        let (response_future, send_stream) = send_request
            .send_request(request, false)
            .map_err(io::Error::other)?;

        let gun_stream =
            GunStream::new_client(send_stream, response_future, peer_addr, local_addr);

        self.inner_client_handler
            .setup_client_tcp_stream(Box::new(gun_stream), remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.inner_client_handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let peer_addr = client_stream.peer_addr();
        let local_addr = client_stream.local_addr();

        let (mut send_request, connection) = h2::client::Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONN_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .enable_push(false)
            .handshake(client_stream)
            .await
            .map_err(io::Error::other)?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::debug!("gRPC client HTTP/2 connection error: {e}");
            }
        });

        std::future::poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .map_err(io::Error::other)?;

        let authority = self.host.clone().unwrap_or_else(|| target.to_string());
        let uri = format!("http://{authority}/{}/Tun", self.service_name);

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-go/1.48.0")
            .header("te", "trailers");

        if let Some(headers) = &self.headers {
            for (k, v) in headers {
                request = request.header(k.as_str(), v.as_str());
            }
        }

        let request = request.body(()).map_err(io::Error::other)?;

        let (response_future, send_stream) = send_request
            .send_request(request, false)
            .map_err(io::Error::other)?;

        let gun_stream =
            GunStream::new_client(send_stream, response_future, peer_addr, local_addr);

        self.inner_client_handler
            .setup_client_udp_bidirectional(Box::new(gun_stream), target)
            .await
    }
}

#[derive(Debug)]
pub struct GrpcServerTarget {
    pub service_name: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub host: Option<String>,
    pub handler: Arc<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct GrpcTcpServerHandler {
    targets: Vec<GrpcServerTarget>,
    resolver: Arc<dyn Resolver>,
}

impl GrpcTcpServerHandler {
    pub fn new(targets: Vec<GrpcServerTarget>, resolver: Arc<dyn Resolver>) -> Self {
        Self { targets, resolver }
    }
}

#[async_trait]
impl TcpServerHandler for GrpcTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let peer_addr = server_stream.peer_addr();
        let local_addr = server_stream.local_addr();

        let mut connection = h2::server::Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONN_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .handshake(server_stream)
            .await
            .map_err(io::Error::other)?;

        let targets: Vec<Arc<dyn TcpServerHandler>> = self
            .targets
            .iter()
            .map(|t| t.handler.clone())
            .collect();
        let target_configs: Vec<(Option<String>, Option<String>, Option<HashMap<String, String>>)> =
            self.targets
                .iter()
                .map(|t| (t.service_name.clone(), t.host.clone(), t.matching_headers.clone()))
                .collect();
        let resolver = self.resolver.clone();

        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let mut tasks = tokio::task::JoinSet::new();

            loop {
                let accepted = tokio::select! {
                    accepted = connection.accept() => accepted,
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };

                let Some(accepted) = accepted else {
                    break;
                };

                let (request, mut respond) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::debug!("gRPC server accept error: {e}");
                        break;
                    }
                };

                if request.method() != Method::POST {
                    let mut res = Response::new(());
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                    let _ = respond.send_response(res, true);
                    continue;
                }

                let ct_ok = request
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.starts_with("application/grpc"))
                    .unwrap_or(false);

                if !ct_ok {
                    let mut res = Response::new(());
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    let _ = respond.send_response(res, true);
                    continue;
                }

                let path = request.uri().path().to_string();
                let normalized_path = path.trim_start_matches('/');
                let service_extracted = normalized_path
                    .strip_suffix("/Tun")
                    .unwrap_or(normalized_path);

                let mut matched_index = None;
                for (i, (expected_service, expected_host, expected_headers)) in
                    target_configs.iter().enumerate()
                {
                    if let Some(expected) = expected_service {
                        let trimmed = expected.trim_matches('/');
                        let clean = trimmed.strip_suffix("/Tun").unwrap_or(trimmed);
                        if service_extracted != clean {
                            continue;
                        }
                    }

                    if let Some(host) = expected_host {
                        let req_host = request
                            .headers()
                            .get(":authority")
                            .or_else(|| request.headers().get("host"))
                            .and_then(|v| v.to_str().ok());
                        if req_host != Some(host.as_str()) {
                            continue;
                        }
                    }

                    if let Some(headers) = expected_headers {
                        let mut ok = true;
                        for (k, v) in headers {
                            if request.headers().get(k.as_str()).and_then(|val| val.to_str().ok())
                                != Some(v.as_str())
                            {
                                ok = false;
                                break;
                            }
                        }
                        if !ok {
                            continue;
                        }
                    }

                    matched_index = Some(i);
                    break;
                }

                let Some(target_idx) = matched_index else {
                    let mut res = Response::new(());
                    *res.status_mut() = StatusCode::NOT_FOUND;
                    let _ = respond.send_response(res, true);
                    continue;
                };

                let mut res = Response::new(());
                *res.status_mut() = StatusCode::OK;
                res.headers_mut().insert(
                    "content-type",
                    HeaderValue::from_static("application/grpc"),
                );
                res.headers_mut()
                    .insert("te", HeaderValue::from_static("trailers"));

                let send_stream = match respond.send_response(res, false) {
                    Ok(s) => s,
                    Err(e) => {
                        log::debug!("gRPC failed to send 200 response: {e}");
                        continue;
                    }
                };

                let gun_stream =
                    GunStream::new_server(send_stream, request.into_body(), peer_addr, local_addr);
                let target_handler = targets[target_idx].clone();
                let resolver = resolver.clone();

                let permit = crate::resources::try_stream().unwrap_or_else(|| {
                    Arc::new(crate::resources::Budget::new(None))
                        .acquire(1)
                        .unwrap()
                });

                tasks.spawn(async move {
                    if let Err(e) = crate::tcp::tcp_server::process_stream_with_permit(
                        gun_stream,
                        target_handler,
                        resolver,
                        permit,
                        std::time::Duration::from_secs(30),
                    )
                    .await
                    {
                        log::debug!("gRPC proxied stream completed with: {e}");
                    }
                });
            }
        })))
    }
}

