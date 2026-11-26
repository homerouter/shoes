//! End-to-end MASQUE inbound integration tests against a real `shoes` server process.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Request, StatusCode, header};
use serde_json::json;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::start_shoes_server;
use shoes_test_support::test_servers::{start_tcp_stream_echo_server, start_udp_echo_server};
use tokio::net::TcpStream;
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CAPSULE_DATAGRAM: u64 = 0x00;
const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

fn basic_auth(user: &str, pass: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {token}")
}

fn encode_varint(value: u64, out: &mut BytesMut) {
    if value <= 63 {
        out.put_u8(value as u8);
    } else if value <= 16_383 {
        let bytes = (value as u16).to_be_bytes();
        out.put_u8(bytes[0] | 0x40);
        out.put_u8(bytes[1]);
    } else if value <= 1_073_741_823 {
        let bytes = (value as u32).to_be_bytes();
        out.put_u8(bytes[0] | 0x80);
        out.put_slice(&bytes[1..4]);
    } else {
        let bytes = value.to_be_bytes();
        out.put_u8(bytes[0] | 0xc0);
        out.put_slice(&bytes[1..8]);
    }
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let val = match len {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([first & 0x3f, buf[1]])),
        4 => u64::from(u32::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
        ])),
        8 => u64::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => unreachable!(),
    };
    Some((val, len))
}

fn encode_context0(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + payload.len());
    out.put_u8(0x00);
    out.put_slice(payload);
    out.freeze()
}

fn decode_context0(payload: &[u8]) -> io::Result<Option<&[u8]>> {
    let (ctx_id, len) = decode_varint(payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated datagram context"))?;
    if ctx_id != 0 {
        return Ok(None);
    }
    Ok(Some(&payload[len..]))
}

fn encode_datagram_capsule(payload: &[u8]) -> Bytes {
    let ctx0 = encode_context0(payload);
    let mut out = BytesMut::with_capacity(8 + ctx0.len());
    encode_varint(CAPSULE_DATAGRAM, &mut out);
    encode_varint(ctx0.len() as u64, &mut out);
    out.put_slice(&ctx0);
    out.freeze()
}

#[derive(Debug)]
enum WireCapsule {
    Datagram(Bytes),
    AddressAssign(Vec<(u64, IpAddr, u8)>),
    RouteAdvertisement(usize),
    Other,
}

struct CapsuleBuf {
    buf: BytesMut,
}

impl CapsuleBuf {
    fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn next(&mut self) -> io::Result<Option<WireCapsule>> {
        let Some((cap_type, tlen)) = decode_varint(&self.buf) else {
            return Ok(None);
        };
        let Some((len, llen)) = decode_varint(&self.buf[tlen..]) else {
            return Ok(None);
        };
        let total = tlen + llen + len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        self.buf.advance(tlen + llen);
        let payload = self.buf.split_to(len as usize).freeze();
        match cap_type {
            CAPSULE_DATAGRAM => Ok(Some(WireCapsule::Datagram(payload))),
            CAPSULE_ADDRESS_ASSIGN => {
                let mut cur = &payload[..];
                let mut addrs = Vec::new();
                while !cur.is_empty() {
                    let (req_id, rlen) = decode_varint(cur)
                        .ok_or_else(|| io::Error::other("bad request_id"))?;
                    cur = &cur[rlen..];
                    let ver = cur[0];
                    cur = &cur[1..];
                    let ip = match ver {
                        4 => {
                            let ip = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&cur[..4]).unwrap()));
                            cur = &cur[4..];
                            ip
                        }
                        6 => {
                            let ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&cur[..16]).unwrap()));
                            cur = &cur[16..];
                            ip
                        }
                        _ => return Err(io::Error::other("unknown IP version in ADDRESS_ASSIGN")),
                    };
                    let prefix_len = cur[0];
                    cur = &cur[1..];
                    addrs.push((req_id, ip, prefix_len));
                }
                Ok(Some(WireCapsule::AddressAssign(addrs)))
            }
            CAPSULE_ROUTE_ADVERTISEMENT => {
                let mut cur = &payload[..];
                let mut count = 0usize;
                while !cur.is_empty() {
                    let ver = cur[0];
                    let skip = match ver {
                        4 => 1 + 4 + 4 + 1,
                        6 => 1 + 16 + 16 + 1,
                        _ => return Err(io::Error::other("unknown IP version in ROUTE_ADV")),
                    };
                    cur = &cur[skip..];
                    count += 1;
                }
                Ok(Some(WireCapsule::RouteAdvertisement(count)))
            }
            _ => Ok(Some(WireCapsule::Other)),
        }
    }
}

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv4_udp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_csum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + usize::from(udp_len));
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let udp_csum = inet_checksum(&pseudo);
    pkt[26..28].copy_from_slice(&(if udp_csum == 0 { 0xffff } else { udp_csum }).to_be_bytes());
    pkt
}

#[allow(clippy::too_many_arguments)]
fn build_ipv4_tcp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = (20 + payload.len()) as u16;
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_csum = inet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + usize::from(tcp_len));
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let tcp_csum = inet_checksum(&pseudo);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

fn generate_localhost_cert() -> TestResult<(String, String, rustls::RootCertStore)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    Ok((cert.cert.pem(), cert.signing_key.serialize_pem(), roots))
}

async fn connect_h3_client(
    addr: SocketAddr,
    roots: rustls::RootCertStore,
) -> TestResult<(
    quinn::Endpoint,
    h3::client::Connection<h3_quinn::Connection, Bytes>,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
)> {
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(quic_cfg);

    let conn = endpoint.connect(addr, "localhost")?.await?;
    let (driver, send_req) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(conn))
        .await?;
    Ok((endpoint, driver, send_req))
}

async fn connect_h2_client(
    addr: SocketAddr,
    roots: rustls::RootCertStore,
) -> TestResult<(
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<()>,
)> {
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let tcp = TcpStream::connect(addr).await?;
    let tls_stream = connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await?;
    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (send_req, conn) = h2::client::handshake(tls_stream).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((send_req, driver))
}

async fn next_h3_capsule<S>(
    recv: &mut h3::client::RequestStream<S, Bytes>,
    buf: &mut CapsuleBuf,
) -> TestResult<WireCapsule>
where
    S: h3::quic::RecvStream,
{
    loop {
        if let Some(cap) = buf.next()? {
            return Ok(cap);
        }
        let mut chunk = recv
            .recv_data()
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "H3 capsule EOF"))?;
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            buf.feed(bytes);
            let n = bytes.len();
            chunk.advance(n);
        }
    }
}

async fn next_h2_capsule(
    recv: &mut h2::RecvStream,
    buf: &mut CapsuleBuf,
) -> TestResult<WireCapsule> {
    loop {
        if let Some(cap) = buf.next()? {
            return Ok(cap);
        }
        let chunk = recv
            .data()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "H2 capsule EOF"))??;
        buf.feed(&chunk);
        recv.flow_control().release_capacity(chunk.len())?;
    }
}

#[tokio::test]
async fn masque_h3_and_h2_end_to_end() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let tcp_echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
        let udp_echo = start_udp_echo_server("127.0.0.1", 0).await?;
        let (cert_pem, key_pem, roots) = generate_localhost_cert()?;

        let mut ports = PortHelper::new();
        let (h3_ip, h3_port) = ports.get_quic_listener_port();
        let (h2_ip, h2_port) = ports.get_localhost_listener_port();

        let shoes_cfg = json!([
            {
                "address": format!("{h3_ip}:{h3_port}"),
                "transport": "quic",
                "quic_settings": {
                    "cert": cert_pem,
                    "key": key_pem,
                },
                "protocol": {
                    "type": "masque",
                    "users": [{"username": "alice", "password": "secret"}],
                    "udp_enabled": true,
                    "ip_enabled": true,
                    "tunnel_addresses": ["10.99.0.1/24"],
                    "stealth_404": false,
                }
            },
            {
                "address": format!("{h2_ip}:{h2_port}"),
                "protocol": {
                    "type": "tls",
                    "default_target": {
                        "cert": cert_pem,
                        "key": key_pem,
                        "alpn_protocols": ["h2"],
                        "protocol": {
                            "type": "masque",
                            "users": [{"username": "alice", "password": "secret"}],
                            "udp_enabled": true,
                            "ip_enabled": true,
                            "tunnel_addresses": ["10.99.1.1/24"],
                            "stealth_404": false,
                        }
                    }
                }
            }
        ]);
        let (_shoes, _shoes_cfg) = start_shoes_server(&serde_yaml::to_string(&shoes_cfg)?)?;
        ports.wait_for_all_ports().await?;

        // --- Part A: HTTP/3 over QUIC ---
        let h3_addr: SocketAddr = format!("{h3_ip}:{h3_port}").parse()?;
        let (_ep, mut driver, mut send_req) = connect_h3_client(h3_addr, roots.clone()).await?;
        let mut dgram_reader = driver.get_datagram_reader();

        // Keep H3 driver running while accessing datagram sender/reader.
        let mut connect_stream = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(tcp_echo.local_addr().to_string())
                    .body(())?,
            )
            .await?;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // 1. Unauthenticated CONNECT -> 407 Proxy Authentication Required
        connect_stream.finish().await?;
        let unauth_resp = connect_stream.recv_response().await?;
        assert_eq!(unauth_resp.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        // 2. H3 CONNECT TCP echo
        let mut tcp_stream = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(tcp_echo.local_addr().to_string())
                    .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                    .body(())?,
            )
            .await?;
        assert_eq!(tcp_stream.recv_response().await?.status(), StatusCode::OK);
        tcp_stream
            .send_data(Bytes::from_static(b"h3 connect payload"))
            .await?;
        tcp_stream.finish().await?;
        let mut echoed = Vec::new();
        while let Some(mut chunk) = tcp_stream.recv_data().await? {
            while chunk.has_remaining() {
                let s = chunk.chunk();
                echoed.extend_from_slice(s);
                let n = s.len();
                chunk.advance(n);
            }
        }
        assert_eq!(echoed, b"h3 connect payload");

        // 3. H3 CONNECT-UDP UDP echo (using Capsule::Datagram on request stream)
        let mut udp_stream = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .extension(h3::ext::Protocol::CONNECT_UDP)
                    .uri(format!(
                        "https://localhost/.well-known/masque/udp/{}/{}/",
                        udp_echo.local_addr().ip(),
                        udp_echo.local_addr().port()
                    ))
                    .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                    .header("capsule-protocol", "?1")
                    .body(())?,
            )
            .await?;
        let udp_resp = udp_stream.recv_response().await?;
        assert_eq!(udp_resp.status(), StatusCode::OK);
        assert_eq!(udp_resp.headers().get("capsule-protocol").unwrap(), "?1");
        let udp_stream_id = udp_stream.id();

        udp_stream
            .send_data(encode_datagram_capsule(b"h3 connect-udp"))
            .await?;
        let dgram = dgram_reader.read_datagram().await?;
        assert_eq!(dgram.stream_id(), udp_stream_id);
        let dgram_bytes = dgram.into_payload();
        assert_eq!(decode_context0(&dgram_bytes)?, Some(b"h3 connect-udp [ECHO]".as_slice()));
        udp_stream.finish().await?;

        // 4. H3 CONNECT-IP (ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT + raw IPv4 UDP & TCP echo)
        let mut ip_stream = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .extension(h3::ext::Protocol::CONNECT_IP)
                    .uri("https://localhost/.well-known/masque/ip/*/*/")
                    .header(header::AUTHORIZATION, basic_auth("alice", "secret"))
                    .header("capsule-protocol", "?1")
                    .body(())?,
            )
            .await?;
        let ip_resp = ip_stream.recv_response().await?;
        assert_eq!(ip_resp.status(), StatusCode::OK);
        assert_eq!(ip_resp.headers().get("capsule-protocol").unwrap(), "?1");
        let ip_stream_id = ip_stream.id();
        let (mut ip_send, mut ip_recv) = ip_stream.split();
        let mut cap_buf = CapsuleBuf::new();

        let client_ip = match next_h3_capsule(&mut ip_recv, &mut cap_buf).await? {
            WireCapsule::AddressAssign(addrs) => match addrs[0].1 {
                IpAddr::V4(v4) => v4,
                other => panic!("expected IPv4 assignment, got {other}"),
            },
            other => panic!("expected AddressAssign, got {other:?}"),
        };
        assert_eq!(client_ip, Ipv4Addr::new(10, 99, 0, 2));
        match next_h3_capsule(&mut ip_recv, &mut cap_buf).await? {
            WireCapsule::RouteAdvertisement(count) => assert!(count >= 1),
            other => panic!("expected RouteAdvertisement, got {other:?}"),
        }

        // Send raw IPv4 UDP packet via Capsule::Datagram; receive echoed IPv4 UDP via H3 datagram.
        let udp_target_ip = match udp_echo.local_addr().ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let udp_pkt = build_ipv4_udp(
            client_ip,
            41001,
            udp_target_ip,
            udp_echo.local_addr().port(),
            b"h3 ip udp",
        );
        ip_send.send_data(encode_datagram_capsule(&udp_pkt)).await?;
        let reply = loop {
            let d = dgram_reader.read_datagram().await?;
            if d.stream_id() == ip_stream_id {
                break d.into_payload();
            }
        };
        let reply_pkt = decode_context0(&reply)?.expect("context 0");
        assert_eq!(reply_pkt[9], 17);
        let ihl = usize::from(reply_pkt[0] & 0x0f) * 4;
        assert_eq!(&reply_pkt[ihl + 8..], b"h3 ip udp [ECHO]");

        // Send raw IPv4 TCP 3-way handshake + payload via Capsule::Datagram.
        let tcp_target_ip = match tcp_echo.local_addr().ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let isn = 0x2000_0000u32;
        let syn = build_ipv4_tcp(
            client_ip,
            41002,
            tcp_target_ip,
            tcp_echo.local_addr().port(),
            isn,
            0,
            0x02,
            &[],
        );
        ip_send.send_data(encode_datagram_capsule(&syn)).await?;
        let syn_ack = loop {
            let d = dgram_reader.read_datagram().await?;
            if d.stream_id() != ip_stream_id {
                continue;
            }
            let raw = d.into_payload();
            if let Some(pkt) = decode_context0(&raw)?
                && pkt.len() >= 34
                && pkt[9] == 6
                && (pkt[33] & 0x12) == 0x12
            {
                break pkt.to_vec();
            }
        };
        let srv_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
        let ack_data = build_ipv4_tcp(
            client_ip,
            41002,
            tcp_target_ip,
            tcp_echo.local_addr().port(),
            isn + 1,
            srv_isn + 1,
            0x18,
            b"h3 ip tcp",
        );
        ip_send
            .send_data(encode_datagram_capsule(&ack_data))
            .await?;
        let mut tcp_received = Vec::new();
        while tcp_received.len() < b"h3 ip tcp".len() {
            let d = dgram_reader.read_datagram().await?;
            if d.stream_id() != ip_stream_id {
                continue;
            }
            let raw = d.into_payload();
            if let Some(pkt) = decode_context0(&raw)?
                && pkt.len() >= 40
                && pkt[9] == 6
            {
                let ihl = usize::from(pkt[0] & 0x0f) * 4;
                let tcp_hdr_len = usize::from(pkt[ihl + 12] >> 4) * 4;
                let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
                tcp_received.extend_from_slice(&pkt[ihl + tcp_hdr_len..total_len]);
            }
        }
        assert_eq!(tcp_received, b"h3 ip tcp");
        ip_send.finish().await?;
        drop(send_req);
        let _ = driver_task.await;

        // --- Part B: HTTP/2 over TLS ---
        let h2_addr: SocketAddr = format!("{h2_ip}:{h2_port}").parse()?;
        let (mut h2_req, h2_driver) = connect_h2_client(h2_addr, roots).await?;

        // 1. H2 CONNECT TCP echo
        let (resp_fut, mut h2_send) = h2_req.send_request(
            Request::builder()
                .method(Method::CONNECT)
                .uri(tcp_echo.local_addr().to_string())
                .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                .body(())?,
            false,
        )?;
        let resp = resp_fut.await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let mut h2_recv = resp.into_body();
        h2_send.send_data(Bytes::from_static(b"h2 connect payload"), true)?;
        let mut echoed = Vec::new();
        while let Some(chunk) = h2_recv.data().await {
            let chunk = chunk?;
            h2_recv.flow_control().release_capacity(chunk.len())?;
            echoed.extend_from_slice(&chunk);
        }
        assert_eq!(echoed, b"h2 connect payload");

        // 2. H2 CONNECT-UDP UDP echo
        let (resp_fut, mut h2_udp_send) = h2_req.send_request(
            Request::builder()
                .method(Method::CONNECT)
                .extension(h2::ext::Protocol::from_static("connect-udp"))
                .uri(format!(
                    "https://localhost/.well-known/masque/udp/{}/{}/",
                    udp_echo.local_addr().ip(),
                    udp_echo.local_addr().port()
                ))
                .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                .header("capsule-protocol", "?1")
                .body(())?,
            false,
        )?;
        let resp = resp_fut.await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let mut h2_udp_recv = resp.into_body();
        let mut h2_udp_buf = CapsuleBuf::new();
        h2_udp_send.send_data(encode_datagram_capsule(b"h2 connect-udp"), false)?;
        let udp_reply = loop {
            if let WireCapsule::Datagram(payload) =
                next_h2_capsule(&mut h2_udp_recv, &mut h2_udp_buf).await?
                && let Some(data) = decode_context0(&payload)?
            {
                break data.to_vec();
            }
        };
        assert_eq!(udp_reply, b"h2 connect-udp [ECHO]");
        h2_udp_send.send_data(Bytes::new(), true)?;

        // 3. H2 CONNECT-IP UDP + TCP echo
        let (resp_fut, mut h2_ip_send) = h2_req.send_request(
            Request::builder()
                .method(Method::CONNECT)
                .extension(h2::ext::Protocol::from_static("connect-ip"))
                .uri("https://localhost/.well-known/masque/ip/*/*/")
                .header(header::AUTHORIZATION, basic_auth("alice", "secret"))
                .header("capsule-protocol", "?1")
                .body(())?,
            false,
        )?;
        let resp = resp_fut.await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let mut h2_ip_recv = resp.into_body();
        let mut h2_ip_buf = CapsuleBuf::new();

        let h2_client_ip = match next_h2_capsule(&mut h2_ip_recv, &mut h2_ip_buf).await? {
            WireCapsule::AddressAssign(addrs) => match addrs[0].1 {
                IpAddr::V4(v4) => v4,
                other => panic!("expected IPv4, got {other}"),
            },
            other => panic!("expected AddressAssign, got {other:?}"),
        };
        assert_eq!(h2_client_ip, Ipv4Addr::new(10, 99, 1, 2));
        match next_h2_capsule(&mut h2_ip_recv, &mut h2_ip_buf).await? {
            WireCapsule::RouteAdvertisement(count) => assert!(count >= 1),
            other => panic!("expected RouteAdvertisement, got {other:?}"),
        }

        let udp_pkt = build_ipv4_udp(
            h2_client_ip,
            42001,
            udp_target_ip,
            udp_echo.local_addr().port(),
            b"h2 ip udp",
        );
        h2_ip_send.send_data(encode_datagram_capsule(&udp_pkt), false)?;
        let h2_udp_pkt = loop {
            if let WireCapsule::Datagram(payload) =
                next_h2_capsule(&mut h2_ip_recv, &mut h2_ip_buf).await?
                && let Some(pkt) = decode_context0(&payload)?
                && pkt[9] == 17
            {
                break pkt.to_vec();
            }
        };
        let ihl = usize::from(h2_udp_pkt[0] & 0x0f) * 4;
        assert_eq!(&h2_udp_pkt[ihl + 8..], b"h2 ip udp [ECHO]");

        let h2_isn = 0x3000_0000u32;
        let syn = build_ipv4_tcp(
            h2_client_ip,
            42002,
            tcp_target_ip,
            tcp_echo.local_addr().port(),
            h2_isn,
            0,
            0x02,
            &[],
        );
        h2_ip_send.send_data(encode_datagram_capsule(&syn), false)?;
        let syn_ack = loop {
            if let WireCapsule::Datagram(payload) =
                next_h2_capsule(&mut h2_ip_recv, &mut h2_ip_buf).await?
                && let Some(pkt) = decode_context0(&payload)?
                && pkt.len() >= 34
                && pkt[9] == 6
                && (pkt[33] & 0x12) == 0x12
            {
                break pkt.to_vec();
            }
        };
        let srv_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
        let ack_data = build_ipv4_tcp(
            h2_client_ip,
            42002,
            tcp_target_ip,
            tcp_echo.local_addr().port(),
            h2_isn + 1,
            srv_isn + 1,
            0x18,
            b"h2 ip tcp",
        );
        h2_ip_send.send_data(encode_datagram_capsule(&ack_data), false)?;
        let mut h2_tcp_received = Vec::new();
        while h2_tcp_received.len() < b"h2 ip tcp".len() {
            if let WireCapsule::Datagram(payload) =
                next_h2_capsule(&mut h2_ip_recv, &mut h2_ip_buf).await?
                && let Some(pkt) = decode_context0(&payload)?
                && pkt.len() >= 40
                && pkt[9] == 6
            {
                let ihl = usize::from(pkt[0] & 0x0f) * 4;
                let tcp_hdr_len = usize::from(pkt[ihl + 12] >> 4) * 4;
                let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
                h2_tcp_received.extend_from_slice(&pkt[ihl + tcp_hdr_len..total_len]);
            }
        }
        assert_eq!(h2_tcp_received, b"h2 ip tcp");

        h2_ip_send.send_data(Bytes::new(), true)?;
        drop(h2_req);
        h2_driver.abort();
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn masque_rule_routing_and_proxy_chaining() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let tcp_echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
        let udp_echo = start_udp_echo_server("127.0.0.1", 0).await?;
        let (cert_pem, key_pem, roots) = generate_localhost_cert()?;

        let mut ports = PortHelper::new();
        let (ss_ip, ss_port) = ports.get_localhost_listener_port();
        let (h3_ip, h3_port) = ports.get_quic_listener_port();
        let (h2_ip, h2_port) = ports.get_localhost_listener_port();
        let ss_password = "masque-chain-password";

        // Downstream Shadowsocks server rewrites synthetic IPs 127.0.0.3 / 127.0.0.4 to the echo
        // servers, proving MASQUE traffic actually traversed `client_chain` and obeyed `rules`.
        let ss_cfg = json!([{
            "address": format!("{ss_ip}:{ss_port}"),
            "protocol": {
                "type": "shadowsocks",
                "cipher": "aes-256-gcm",
                "password": ss_password,
                "udp_enabled": true,
            },
            "rules": [
                {
                    "mask": "127.0.0.3/32",
                    "action": "allow",
                    "override_address": tcp_echo.local_addr().to_string(),
                },
                {
                    "mask": "127.0.0.4/32",
                    "action": "allow",
                    "override_address": udp_echo.local_addr().to_string(),
                },
                {"mask": "0.0.0.0/0", "action": "block"}
            ]
        }]);
        let (_ss, _ss_cfg) = start_shoes_server(&serde_yaml::to_string(&ss_cfg)?)?;

        let masque_rules = json!([
            {"mask": "127.0.0.2/32", "action": "block"},
            {
                "mask": "0.0.0.0/0",
                "action": "allow",
                "client_chain": [{
                    "address": format!("{ss_ip}:{ss_port}"),
                    "protocol": {
                        "type": "shadowsocks",
                        "cipher": "aes-256-gcm",
                        "password": ss_password,
                        "udp_enabled": true,
                    },
                }]
            }
        ]);
        let masque_cfg = json!([
            {
                "address": format!("{h3_ip}:{h3_port}"),
                "transport": "quic",
                "quic_settings": {"cert": cert_pem, "key": key_pem},
                "protocol": {
                    "type": "masque",
                    "users": [{"username": "alice", "password": "secret"}],
                    "udp_enabled": true,
                    "ip_enabled": true,
                    "tunnel_addresses": ["10.99.2.1/24"],
                    "stealth_404": false,
                },
                "rules": masque_rules,
            },
            {
                "address": format!("{h2_ip}:{h2_port}"),
                "protocol": {
                    "type": "tls",
                    "default_target": {
                        "cert": cert_pem,
                        "key": key_pem,
                        "alpn_protocols": ["h2"],
                        "protocol": {
                            "type": "masque",
                            "users": [{"username": "alice", "password": "secret"}],
                            "udp_enabled": true,
                            "stealth_404": false,
                        }
                    }
                },
                "rules": masque_rules,
            }
        ]);
        let (_masque, _masque_cfg) = start_shoes_server(&serde_yaml::to_string(&masque_cfg)?)?;
        ports.wait_for_all_ports().await?;

        let (_ep, mut driver, mut send_req) =
            connect_h3_client(format!("{h3_ip}:{h3_port}").parse()?, roots).await?;
        let mut dgram_reader = driver.get_datagram_reader();

        // 1. Blocked destination -> 403 Forbidden
        let mut blocked = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(format!("127.0.0.2:{}", tcp_echo.local_addr().port()))
                    .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                    .body(())?,
            )
            .await?;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        assert_eq!(blocked.recv_response().await?.status(), StatusCode::FORBIDDEN);

        // 2. Allowed CONNECT through SOCKS5 chain -> reaches tcp_echo via 127.0.0.3 override
        let mut tcp = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri("127.0.0.3:9999")
                    .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                    .body(())?,
            )
            .await?;
        assert_eq!(tcp.recv_response().await?.status(), StatusCode::OK);
        tcp.send_data(Bytes::from_static(b"chained connect")).await?;
        tcp.finish().await?;
        let mut out = Vec::new();
        while let Some(mut chunk) = tcp.recv_data().await? {
            while chunk.has_remaining() {
                let s = chunk.chunk();
                out.extend_from_slice(s);
                let n = s.len();
                chunk.advance(n);
            }
        }
        assert_eq!(out, b"chained connect");

        // 3. Allowed CONNECT-UDP through SOCKS5 chain -> reaches udp_echo via 127.0.0.4 override
        let mut udp = send_req
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .extension(h3::ext::Protocol::CONNECT_UDP)
                    .uri("https://localhost/.well-known/masque/udp/127.0.0.4/9999/")
                    .header(header::PROXY_AUTHORIZATION, basic_auth("alice", "secret"))
                    .header("capsule-protocol", "?1")
                    .body(())?,
            )
            .await?;
        assert_eq!(udp.recv_response().await?.status(), StatusCode::OK);
        let udp_id = udp.id();
        udp.send_data(encode_datagram_capsule(b"chained udp")).await?;
        let reply = loop {
            let d = dgram_reader.read_datagram().await?;
            if d.stream_id() == udp_id {
                break d.into_payload();
            }
        };
        assert_eq!(decode_context0(&reply)?, Some(b"chained udp [ECHO]".as_slice()));
        udp.finish().await?;

        drop(send_req);
        let _ = driver_task.await;
        Ok(())
    })
    .await?
}
