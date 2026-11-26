use std::io;
use std::sync::Arc;

use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Response, StatusCode};
use rustc_hash::FxHashMap;
use tokio::sync::{mpsc, oneshot};

use crate::resources;

use super::{MasqueConnCtx, MasqueServer, connect, connect_udp};

const DATAGRAM_CHANNEL_CAPACITY: usize = 256;

pub(crate) type H3DatagramSender = h3_datagram::datagram_handler::DatagramSender<
    <h3_quinn::Connection as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::SendDatagramHandler,
    Bytes,
>;

type DatagramStreams = Arc<parking_lot::Mutex<FxHashMap<h3::quic::StreamId, mpsc::Sender<Bytes>>>>;

#[derive(Clone)]
pub(crate) struct H3DatagramHub {
    streams: DatagramStreams,
    sender_req_tx: mpsc::Sender<(h3::quic::StreamId, oneshot::Sender<H3DatagramSender>)>,
}

pub(crate) struct H3DatagramRxGuard {
    stream_id: h3::quic::StreamId,
    streams: DatagramStreams,
}

impl Drop for H3DatagramRxGuard {
    fn drop(&mut self) {
        self.streams.lock().remove(&self.stream_id);
    }
}

impl H3DatagramHub {
    pub(crate) fn register(
        &self,
        stream_id: h3::quic::StreamId,
    ) -> (H3DatagramRxGuard, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(DATAGRAM_CHANNEL_CAPACITY);
        self.streams.lock().insert(stream_id, tx);
        (
            H3DatagramRxGuard {
                stream_id,
                streams: self.streams.clone(),
            },
            rx,
        )
    }

    pub(crate) async fn acquire_sender(
        &self,
        stream_id: h3::quic::StreamId,
    ) -> io::Result<H3DatagramSender> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender_req_tx
            .send((stream_id, reply_tx))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "H3 connection closed"))?;
        reply_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "H3 connection closed"))
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn serve_h3(server: &MasqueServer, connection: quinn::Connection) -> io::Result<()> {
    let peer = connection.remote_address();
    let peer_authenticated_by_mtls = connection.peer_identity().is_some();
    let mut driver = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_field_section_size(64 * 1024)
        .build(h3_quinn::Connection::new(connection))
        .await
        .map_err(io::Error::other)?;

    let streams: DatagramStreams = Arc::new(parking_lot::Mutex::new(FxHashMap::default()));
    let (sender_req_tx, mut sender_req_rx) = mpsc::channel(64);
    let hub = H3DatagramHub {
        streams: streams.clone(),
        sender_req_tx,
    };

    let mut dgram_reader = driver.get_datagram_reader();
    let dgram_task = crate::network_tasks::spawn(async move {
        while let Ok(datagram) = dgram_reader.read_datagram().await {
            let stream_id = datagram.stream_id();
            let Ok(Some(payload)) = super::wire::decode_context0_datagram(datagram.into_payload())
            else {
                continue;
            };
            if let Some(tx) = streams.lock().get(&stream_id) {
                let _ = tx.try_send(payload);
            }
        }
    });
    let _dgram_guard = AbortOnDrop(dgram_task.abort_handle());

    let ctx = server.conn_ctx(peer, peer_authenticated_by_mtls);
    let mut requests = tokio::task::JoinSet::new();

    loop {
        let resolver = tokio::select! {
            result = driver.accept() => result.map_err(io::Error::other)?,
            Some((stream_id, reply)) = sender_req_rx.recv() => {
                let _ = reply.send(driver.get_datagram_sender(stream_id));
                continue;
            }
            _ = requests.join_next(), if !requests.is_empty() => continue,
        };
        let Some(resolver) = resolver else {
            drop(driver);
            drop(_dgram_guard);
            while requests.join_next().await.is_some() {}
            return Ok(());
        };
        while requests.try_join_next().is_some() {}

        let (Some(local_permit), Some(global_permit)) =
            (server.requests.acquire(1), resources::try_stream())
        else {
            drop(resolver);
            continue;
        };

        let ctx = ctx.clone();
        let hub = hub.clone();
        crate::network_tasks::spawn_in(&mut requests, async move {
            let _permits = (local_permit, global_permit);
            let Ok((request, stream)) = crate::util::timeout_stream_setup(async {
                resolver.resolve_request().await.map_err(io::Error::other)
            })
            .await
            else {
                return;
            };
            if let Err(err) = dispatch_h3_request(ctx, request, stream, hub).await {
                log::debug!("MASQUE H3 request ended: {err}");
            }
        });
    }
}

async fn dispatch_h3_request(
    ctx: MasqueConnCtx,
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    hub: H3DatagramHub,
) -> io::Result<()> {
    if request.method() != Method::CONNECT {
        return send_empty_response(
            &mut stream,
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap(),
        )
        .await;
    }

    let protocol = request.extensions().get::<h3::ext::Protocol>().copied();
    match protocol {
        None => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), false, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut stream, rejection.into_response()).await;
            }
            connect::handle_connect_h3(ctx, request, stream).await
        }
        Some(proto) if proto == h3::ext::Protocol::CONNECT_UDP => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), false, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut stream, rejection.into_response()).await;
            }
            connect_udp::handle_connect_udp_h3(ctx, request, stream, hub).await
        }
        Some(proto) if proto == h3::ext::Protocol::CONNECT_IP => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), true, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut stream, rejection.into_response()).await;
            }
            let status = if ctx.config.stealth_404 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::NOT_IMPLEMENTED
            };
            send_empty_response(
                &mut stream,
                Response::builder().status(status).body(()).unwrap(),
            )
            .await
        }
        Some(_) => {
            send_empty_response(
                &mut stream,
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap(),
            )
            .await
        }
    }
}

async fn send_empty_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: Response<()>,
) -> io::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    stream
        .send_response(response)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)
}
