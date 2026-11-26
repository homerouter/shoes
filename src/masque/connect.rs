use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::http2::stream::H2MultiStream;
use crate::tcp::ingress::PreparedTcp;
use crate::tcp::tcp_handler::TcpClientSetupResult;

use super::MasqueConnCtx;

pub(crate) fn parse_connect_target(request: &Request<()>) -> Result<NetLocation, StatusCode> {
    if request.uri().scheme().is_some() || request.uri().path_and_query().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let authority = request.uri().authority().ok_or(StatusCode::BAD_REQUEST)?;
    if authority.as_str().contains('@')
        || authority
            .port()
            .is_none_or(|port| !port.as_str().bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let target = NetLocation::from_authority(authority.as_str(), None)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if target.port() == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(target)
}

pub(crate) async fn handle_connect_h3<S>(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
) -> io::Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + Sync + 'static,
    S::SendStream: Send + Sync + 'static,
    S::RecvStream: Send + Sync + Unpin + 'static,
{
    let target = match parse_connect_target(&request) {
        Ok(target) => target,
        Err(status) => {
            return send_h3_status(&mut stream, status).await;
        }
    };

    let prepared = match PreparedTcp::new(&ctx.selector, target, Vec::new()) {
        Ok(prepared) => prepared.with_source(Some(ctx.peer)),
        Err(_) => return send_h3_status(&mut stream, StatusCode::BAD_GATEWAY).await,
    };

    if prepared.needs_sniff_read() {
        stream
            .send_response(Response::new(()))
            .await
            .map_err(io::Error::other)?;
        let (send, recv) = stream.split();
        let mut h3_stream: Box<dyn AsyncStream> = Box::new(H3ConnectStream::new(send, recv));
        let routed = crate::util::timeout_stream_setup(async {
            let route = prepared
                .route(&mut h3_stream, &ctx.selector, &ctx.resolver)
                .await?;
            route.connect(&ctx.resolver).await
        })
        .await?;
        let Some(upstream) = routed.setup else {
            return Ok(());
        };
        return relay_connect_stream(h3_stream, upstream, routed.prefix).await;
    }

    let mut no_read = tokio::io::empty();
    let result = crate::util::timeout_stream_setup(async {
        let route = prepared
            .route(&mut no_read, &ctx.selector, &ctx.resolver)
            .await?;
        route.connect(&ctx.resolver).await
    })
    .await;

    let upstream = match result {
        Ok(routed) => match routed.setup {
            Some(upstream) => upstream,
            None => return send_h3_status(&mut stream, StatusCode::FORBIDDEN).await,
        },
        Err(err) => {
            let status = if err.kind() == io::ErrorKind::TimedOut {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return send_h3_status(&mut stream, status).await;
        }
    };

    stream
        .send_response(Response::new(()))
        .await
        .map_err(io::Error::other)?;
    let (send, recv) = stream.split();
    let h3_stream: Box<dyn AsyncStream> = Box::new(H3ConnectStream::new(send, recv));
    relay_connect_stream(h3_stream, upstream, Vec::new()).await
}

pub(crate) async fn handle_connect_h2(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut respond: h2::server::SendResponse<Bytes>,
    recv: h2::RecvStream,
) -> io::Result<()> {
    let target = match parse_connect_target(&request) {
        Ok(target) => target,
        Err(status) => return send_h2_status(&mut respond, status),
    };

    let prepared = match PreparedTcp::new(&ctx.selector, target, Vec::new()) {
        Ok(prepared) => prepared.with_source(Some(ctx.peer)),
        Err(_) => return send_h2_status(&mut respond, StatusCode::BAD_GATEWAY),
    };

    if prepared.needs_sniff_read() {
        let send = respond
            .send_response(Response::new(()), false)
            .map_err(io::Error::other)?;
        let mut h2_stream = H2MultiStream::new(send, recv);
        let reset = h2_stream.reset();
        let routed = tokio::select! {
            biased;
            _ = reset => return Ok(()),
            result = crate::util::timeout_stream_setup(async {
                let route = prepared
                    .route(&mut h2_stream, &ctx.selector, &ctx.resolver)
                    .await?;
                route.connect(&ctx.resolver).await
            }) => result?,
        };
        let Some(upstream) = routed.setup else {
            return Ok(());
        };
        let reset = h2_stream.reset();
        return tokio::select! {
            biased;
            _ = reset => Ok(()),
            result = relay_connect_stream(Box::new(h2_stream), upstream, routed.prefix) => result,
        };
    }

    let mut no_read = tokio::io::empty();
    let result = tokio::select! {
        biased;
        _ = std::future::poll_fn(|cx| respond.poll_reset(cx)) => return Ok(()),
        result = crate::util::timeout_stream_setup(async {
            let route = prepared
                .route(&mut no_read, &ctx.selector, &ctx.resolver)
                .await?;
            route.connect(&ctx.resolver).await
        }) => result,
    };

    let upstream = match result {
        Ok(routed) => match routed.setup {
            Some(upstream) => upstream,
            None => return send_h2_status(&mut respond, StatusCode::FORBIDDEN),
        },
        Err(err) => {
            let status = if err.kind() == io::ErrorKind::TimedOut {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return send_h2_status(&mut respond, status);
        }
    };

    let send = respond
        .send_response(Response::new(()), false)
        .map_err(io::Error::other)?;
    let h2_stream = H2MultiStream::new(send, recv);
    let reset = h2_stream.reset();
    tokio::select! {
        biased;
        _ = reset => Ok(()),
        result = relay_connect_stream(Box::new(h2_stream), upstream, Vec::new()) => result,
    }
}

async fn send_h3_status<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: StatusCode,
) -> io::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let resp = Response::builder()
        .status(status)
        .body(())
        .expect("valid status response");
    stream
        .send_response(resp)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)
}

fn send_h2_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> io::Result<()> {
    let resp = Response::builder()
        .status(status)
        .body(())
        .expect("valid status response");
    respond
        .send_response(resp, true)
        .map(|_| ())
        .map_err(io::Error::other)
}

async fn relay_connect_stream(
    mut stream: Box<dyn AsyncStream>,
    mut upstream: TcpClientSetupResult,
    prefix: Vec<u8>,
) -> io::Result<()> {
    let flow = upstream.client_stream.flow().cloned();
    crate::control::tracked_stream::during_flow(
        flow.as_deref(),
        crate::util::timeout_stream_setup(async {
            if let Some(data) = upstream.early_data.take() {
                stream.write_all(&data).await?;
                stream.flush().await?;
            }
            if !prefix.is_empty() {
                upstream.client_stream.write_all(&prefix).await?;
                upstream.client_stream.flush().await?;
            }
            Ok(())
        }),
    )
    .await?;
    drop(prefix);

    let result = crate::copy_bidirectional::copy_bidirectional(
        &mut stream,
        &mut upstream.client_stream,
        false,
        false,
    )
    .await;
    crate::util::shutdown_stream_pair(&mut stream, &mut upstream.client_stream).await;
    result.map(|_| ())
}

type H3SendFuture<S> = Pin<
    Box<
        dyn Future<
                Output = (
                    h3::server::RequestStream<S, Bytes>,
                    Result<(), h3::error::StreamError>,
                ),
            > + Send,
    >,
>;

enum H3SendState<S> {
    Idle(Option<h3::server::RequestStream<S, Bytes>>),
    Writing(H3SendFuture<S>, usize),
    Finishing(H3SendFuture<S>),
    Closed,
}

struct H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream,
    S: h3::quic::SendStream<Bytes>,
{
    recv: h3::server::RequestStream<R, Bytes>,
    recv_buf: Bytes,
    send: Mutex<H3SendState<S>>,
}

impl<R, S> H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream,
    S: h3::quic::SendStream<Bytes>,
{
    fn new(
        send: h3::server::RequestStream<S, Bytes>,
        recv: h3::server::RequestStream<R, Bytes>,
    ) -> Self {
        Self {
            recv,
            recv_buf: Bytes::new(),
            send: Mutex::new(H3SendState::Idle(Some(send))),
        }
    }
}

impl<R, S> Drop for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream,
    S: h3::quic::SendStream<Bytes>,
{
    fn drop(&mut self) {
        if let H3SendState::Idle(Some(send)) = self.send.get_mut() {
            send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            self.recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

impl<R, S> AsyncRead for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream + Unpin,
    S: h3::quic::SendStream<Bytes>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !this.recv_buf.is_empty() {
                let count = this.recv_buf.len().min(buf.remaining());
                buf.put_slice(&this.recv_buf.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(this.recv.poll_recv_data(cx)) {
                Ok(Some(mut chunk)) => {
                    let len = chunk.remaining();
                    if len > 0 {
                        this.recv_buf = chunk.copy_to_bytes(len);
                    }
                }
                Ok(None) => return Poll::Ready(Ok(())),
                Err(err) => return Poll::Ready(Err(io::Error::other(err))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<R, S> AsyncWrite for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream + Unpin,
    S: h3::quic::SendStream<Bytes> + Send + Sync + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.send.lock();
        loop {
            match &mut *guard {
                H3SendState::Idle(slot) => {
                    let Some(mut send) = slot.take() else {
                        *guard = H3SendState::Closed;
                        return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                    };
                    let chunk = Bytes::copy_from_slice(&buf[..buf.len().min(32768)]);
                    let len = chunk.len();
                    let fut = Box::pin(async move {
                        let res = send.send_data(chunk).await;
                        (send, res)
                    });
                    *guard = H3SendState::Writing(fut, len);
                }
                H3SendState::Writing(fut, len) => {
                    let written = *len;
                    match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready((send, Ok(()))) => {
                            *guard = H3SendState::Idle(Some(send));
                            return Poll::Ready(Ok(written.min(buf.len())));
                        }
                        Poll::Ready((_, Err(err))) => {
                            *guard = H3SendState::Closed;
                            return Poll::Ready(Err(io::Error::other(err)));
                        }
                    }
                }
                H3SendState::Finishing(_) | H3SendState::Closed => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.send.lock();
        if let H3SendState::Writing(fut, _) = &mut *guard {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready((send, Ok(()))) => {
                    *guard = H3SendState::Idle(Some(send));
                }
                Poll::Ready((_, Err(err))) => {
                    *guard = H3SendState::Closed;
                    return Poll::Ready(Err(io::Error::other(err)));
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.send.lock();
        loop {
            match &mut *guard {
                H3SendState::Writing(fut, _) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready((send, Ok(()))) => {
                        *guard = H3SendState::Idle(Some(send));
                    }
                    Poll::Ready((_, Err(err))) => {
                        *guard = H3SendState::Closed;
                        return Poll::Ready(Err(io::Error::other(err)));
                    }
                },
                H3SendState::Idle(slot) => {
                    let Some(mut send) = slot.take() else {
                        *guard = H3SendState::Closed;
                        return Poll::Ready(Ok(()));
                    };
                    let fut = Box::pin(async move {
                        let res = send.finish().await;
                        (send, res)
                    });
                    *guard = H3SendState::Finishing(fut);
                }
                H3SendState::Finishing(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready((_, Ok(()))) => {
                        *guard = H3SendState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready((_, Err(err))) => {
                        *guard = H3SendState::Closed;
                        return Poll::Ready(Err(io::Error::other(err)));
                    }
                },
                H3SendState::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<R, S> AsyncPing for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream,
    S: h3::quic::SendStream<Bytes>,
{
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<R, S> Unpin for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream + Unpin,
    S: h3::quic::SendStream<Bytes>,
{
}

impl<R, S> AsyncStream for H3ConnectStream<R, S>
where
    R: h3::quic::RecvStream + Send + Sync + Unpin,
    S: h3::quic::SendStream<Bytes> + Send + Sync + 'static,
{
}
