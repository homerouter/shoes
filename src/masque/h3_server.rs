use std::io;

use bytes::Bytes;
use http::{Method, Response, StatusCode};

use crate::resources;

use super::{MasqueConnCtx, MasqueServer, connect};

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

    let ctx = server.conn_ctx(peer, peer_authenticated_by_mtls);
    let mut requests = tokio::task::JoinSet::new();

    loop {
        let resolver = tokio::select! {
            result = driver.accept() => result.map_err(io::Error::other)?,
            _ = requests.join_next(), if !requests.is_empty() => continue,
        };
        let Some(resolver) = resolver else {
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
        crate::network_tasks::spawn_in(&mut requests, async move {
            let _permits = (local_permit, global_permit);
            let Ok((request, stream)) = crate::util::timeout_stream_setup(async {
                resolver.resolve_request().await.map_err(io::Error::other)
            })
            .await
            else {
                return;
            };
            if let Err(err) = dispatch_h3_request(ctx, request, stream).await {
                log::debug!("MASQUE H3 request ended: {err}");
            }
        });
    }
}

async fn dispatch_h3_request(
    ctx: MasqueConnCtx,
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> io::Result<()> {
    if request.method() != Method::CONNECT {
        return send_empty_response(&mut stream, Response::builder().status(StatusCode::NOT_FOUND).body(()).unwrap()).await;
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
            let status = if ctx.config.stealth_404 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::NOT_IMPLEMENTED
            };
            send_empty_response(&mut stream, Response::builder().status(status).body(()).unwrap()).await
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
            send_empty_response(&mut stream, Response::builder().status(status).body(()).unwrap()).await
        }
        Some(_) => {
            send_empty_response(&mut stream, Response::builder().status(StatusCode::NOT_FOUND).body(()).unwrap()).await
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
