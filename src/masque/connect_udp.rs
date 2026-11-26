use std::io;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use tokio::time::Instant;

use crate::address::{Address, NetLocation};
use crate::routing::udp_relay::UdpRelay;

use super::h3_server::H3DatagramHub;
use super::wire::{
    Capsule, CapsuleDecoder, decode_context0_datagram, encode_capsule, encode_context0_datagram,
};
use super::{
    MasqueConnCtx, capsule_ok_response, feed_capsule_buf, feed_h2_capsule_chunk, send_h2_data,
    send_h3_datagram_or_capsule, status_response,
};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

enum ConnectUdpPrep {
    Ready {
        target: NetLocation,
        relay: UdpRelay,
    },
    Reject(StatusCode),
}

fn prepare_connect_udp(ctx: &MasqueConnCtx, request: &Request<()>) -> ConnectUdpPrep {
    if !ctx.config.udp_enabled {
        let status = if ctx.config.stealth_404 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::FORBIDDEN
        };
        return ConnectUdpPrep::Reject(status);
    }

    let raw_path = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path(), |pq| pq.as_str());
    let parsed = match ctx.udp_template.match_path(raw_path) {
        Ok(Some(target)) => target,
        Ok(None) => return ConnectUdpPrep::Reject(StatusCode::NOT_FOUND),
        Err(_) => return ConnectUdpPrep::Reject(StatusCode::BAD_REQUEST),
    };

    let Ok(addr) = Address::from(&parsed.host) else {
        return ConnectUdpPrep::Reject(StatusCode::BAD_REQUEST);
    };
    let target = NetLocation::new(addr, parsed.port);

    match UdpRelay::new(ctx.selector.clone(), ctx.resolver.clone(), Some(ctx.peer)) {
        Ok(relay) => ConnectUdpPrep::Ready { target, relay },
        Err(_) => ConnectUdpPrep::Reject(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn forward_udp_payload(relay: &UdpRelay, payload: Bytes, target: &NetLocation) -> bool {
    match relay.send_to(payload, target.clone()) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            log::debug!("MASQUE dropping oversized UDP payload: {err}");
            true
        }
        Err(_) => false,
    }
}

fn drain_capsules(
    decoder: &mut CapsuleDecoder,
    relay: &UdpRelay,
    target: &NetLocation,
) -> io::Result<bool> {
    while let Some(capsule) = decoder.next_capsule()? {
        if let Capsule::Datagram(payload) = capsule {
            let Some(udp_payload) = decode_context0_datagram(payload)? else {
                continue;
            };
            if !forward_udp_payload(relay, udp_payload, target) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(crate) async fn handle_connect_udp_h3(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    hub: H3DatagramHub,
) -> io::Result<()> {
    let (target, relay) = match prepare_connect_udp(&ctx, &request) {
        ConnectUdpPrep::Ready { target, relay } => (target, relay),
        ConnectUdpPrep::Reject(status) => {
            stream
                .send_response(status_response(status))
                .await
                .map_err(io::Error::other)?;
            return stream.finish().await.map_err(io::Error::other);
        }
    };

    let stream_id = stream.id();
    let (_rx_guard, mut dgram_rx) = hub.register(stream_id);
    let mut dgram_sender = hub.acquire_sender(stream_id).await?;

    stream
        .send_response(capsule_ok_response())
        .await
        .map_err(io::Error::other)?;

    let (mut send_stream, mut recv_stream) = stream.split();
    let mut decoder = CapsuleDecoder::new();
    let mut datagrams_unavailable = false;
    let idle_sleep = tokio::time::sleep(UDP_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            () = &mut idle_sleep => {
                let _ = send_stream.finish().await;
                return Ok(());
            }
            maybe_dgram = dgram_rx.recv() => {
                let Some(payload) = maybe_dgram else {
                    let _ = send_stream.finish().await;
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                if !forward_udp_payload(&relay, payload, &target) {
                    let _ = send_stream.finish().await;
                    return Ok(());
                }
            }
            recv_res = recv_stream.recv_data() => {
                match recv_res {
                    Ok(Some(mut chunk)) => {
                        idle_sleep.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                        feed_capsule_buf(&mut decoder, &mut chunk);
                        if !drain_capsules(&mut decoder, &relay, &target)? {
                            let _ = send_stream.finish().await;
                            return Ok(());
                        }
                    }
                    Ok(None) => {
                        let _ = send_stream.finish().await;
                        return Ok(());
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            reply_res = relay.recv() => {
                let Ok((data, _src)) = reply_res else {
                    let _ = send_stream.finish().await;
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                let encoded = encode_context0_datagram(&data);
                send_h3_datagram_or_capsule(
                    &mut dgram_sender,
                    &mut send_stream,
                    &mut datagrams_unavailable,
                    encoded,
                    false,
                )
                .await?;
            }
        }
    }
}

pub(crate) async fn handle_connect_udp_h2(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut respond: h2::server::SendResponse<Bytes>,
    mut recv: h2::RecvStream,
) -> io::Result<()> {
    let (target, relay) = match prepare_connect_udp(&ctx, &request) {
        ConnectUdpPrep::Ready { target, relay } => (target, relay),
        ConnectUdpPrep::Reject(status) => {
            return respond
                .send_response(status_response(status), true)
                .map(|_| ())
                .map_err(io::Error::other);
        }
    };

    let mut send = respond
        .send_response(capsule_ok_response(), false)
        .map_err(io::Error::other)?;
    let mut decoder = CapsuleDecoder::new();
    let idle_sleep = tokio::time::sleep(UDP_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            () = &mut idle_sleep => {
                let _ = send.send_data(Bytes::new(), true);
                return Ok(());
            }
            chunk_opt = recv.data() => {
                match chunk_opt {
                    Some(Ok(chunk)) => {
                        idle_sleep.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                        feed_h2_capsule_chunk(&mut recv, &mut decoder, &chunk)?;
                        if !drain_capsules(&mut decoder, &relay, &target)? {
                            let _ = send.send_data(Bytes::new(), true);
                            return Ok(());
                        }
                    }
                    Some(Err(err)) => return Err(io::Error::other(err)),
                    None => {
                        let _ = send.send_data(Bytes::new(), true);
                        return Ok(());
                    }
                }
            }
            reply_res = relay.recv() => {
                let Ok((data, _src)) = reply_res else {
                    let _ = send.send_data(Bytes::new(), true);
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + UDP_IDLE_TIMEOUT);
                let frame = encode_capsule(&Capsule::Datagram(encode_context0_datagram(&data)));
                send_h2_data(&mut send, frame).await?;
            }
        }
    }
}
