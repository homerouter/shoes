use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};

use crate::async_stream::AsyncStream;
use crate::resources;

use super::{MasqueConnCtx, MasqueServer, connect, connect_ip, connect_udp};

pub(crate) async fn serve_h2_stream<IO: AsyncStream + 'static>(
    server: &MasqueServer,
    stream: IO,
    peer: SocketAddr,
    peer_authenticated_by_mtls: bool,
) -> io::Result<()> {
    let max_streams = server.config.max_concurrent_requests.min(u32::MAX as usize) as u32;
    let mut connection = crate::util::timeout_stream_setup(async {
        h2::server::Builder::new()
            .enable_connect_protocol()
            .max_concurrent_streams(max_streams)
            .handshake(stream)
            .await
            .map_err(io::Error::other)
    })
    .await?;

    let ctx = server.conn_ctx(peer, peer_authenticated_by_mtls);
    let mut requests = tokio::task::JoinSet::new();

    loop {
        let accepted = tokio::select! {
            accepted = connection.accept() => accepted,
            _ = requests.join_next(), if !requests.is_empty() => continue,
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (request, mut respond) = accepted.map_err(io::Error::other)?;
        while requests.try_join_next().is_some() {}

        let (Some(local_permit), Some(global_permit)) =
            (server.requests.acquire(1), resources::try_stream())
        else {
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            continue;
        };

        let ctx = ctx.clone();
        crate::network_tasks::spawn_in(&mut requests, async move {
            let _permits = (local_permit, global_permit);
            let (parts, recv) = request.into_parts();
            let request = Request::from_parts(parts, ());
            if let Err(err) = dispatch_h2_request(ctx, request, respond, recv).await {
                log::debug!("MASQUE H2 request ended: {err}");
            }
        });
    }

    while requests.join_next().await.is_some() {}
    Ok(())
}

async fn dispatch_h2_request(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut respond: h2::server::SendResponse<Bytes>,
    recv: h2::RecvStream,
) -> io::Result<()> {
    if request.method() != Method::CONNECT {
        return send_empty_response(
            &mut respond,
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap(),
        );
    }

    let protocol = request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|proto| proto.as_str().to_owned());

    match protocol.as_deref() {
        None => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), false, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut respond, rejection.into_response());
            }
            connect::handle_connect_h2(ctx, request, respond, recv).await
        }
        Some("connect-udp") => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), false, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut respond, rejection.into_response());
            }
            connect_udp::handle_connect_udp_h2(ctx, request, respond, recv).await
        }
        Some("connect-ip") => {
            if let Err(rejection) =
                ctx.auth
                    .verify_headers(request.headers(), true, ctx.peer_authenticated_by_mtls)
            {
                return send_empty_response(&mut respond, rejection.into_response());
            }
            connect_ip::handle_connect_ip_h2(ctx, request, respond, recv).await
        }
        Some(_) => send_empty_response(
            &mut respond,
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap(),
        ),
    }
}

fn send_empty_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    response: Response<()>,
) -> io::Result<()> {
    respond
        .send_response(response, true)
        .map(|_| ())
        .map_err(io::Error::other)
}
