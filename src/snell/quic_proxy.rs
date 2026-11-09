use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::Rng;

use super::aead::{snell_kdf, Aead, NONCE_LEN, TAG_LEN};
use super::v4::increment_nonce;
use crate::address::{Address, NetLocation};
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;

const HEADER_VERSION: u8 = 4;
const REQUEST_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const HEADER_PLAIN_LEN: usize = 7;
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN; // 23
#[allow(dead_code)]
const MAX_PLAINTEXT_PER_FRAME: usize = 1417;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
            "snell quic proxy: does not contain a payload",
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
pub fn decode_quic_proxy_init(psk: &[u8], data: &[u8]) -> std::io::Result<(NetLocation, Vec<u8>, Vec<u8>)> {
    let plain = decode_quic_proxy_frame(psk, data)?;
    parse_quic_proxy_init(&plain)
}

struct QuicProxySession {
    relay: Arc<UdpRelay>,
    target: NetLocation,
    return_task: tokio::task::AbortHandle,
}

impl Drop for QuicProxySession {
    fn drop(&mut self) {
        self.return_task.abort();
    }
}

fn create_quic_session(
    socket: &Arc<tokio::net::UdpSocket>,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    sessions: &mut std::collections::HashMap<SocketAddr, QuicProxySession>,
    client_addr: SocketAddr,
    target: NetLocation,
    payload: Vec<u8>,
) {
    log::info!("Snell QUIC proxy: new session from {client_addr} to {target}");
    let relay = match UdpRelay::new(
        proxy_selector.clone(),
        resolver.clone(),
        Some(client_addr),
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            log::error!("Snell QUIC proxy: failed to create UdpRelay: {e}");
            return;
        }
    };

    let _ = relay.send_to(Bytes::copy_from_slice(&payload), target.clone());

    let socket_clone = socket.clone();
    let relay_clone = relay.clone();
    let return_task = tokio::spawn(async move {
        loop {
            match relay_clone.recv().await {
                Ok((data, _from)) => {
                    if socket_clone.send_to(&data, client_addr).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .abort_handle();

    sessions.insert(
        client_addr,
        QuicProxySession {
            relay,
            target,
            return_task,
        },
    );
}

/// Runs the Snell QUIC Proxy UDP listener loop on a bound UDP socket.
pub async fn run_snell_quic_proxy_listener(
    socket: Arc<tokio::net::UdpSocket>,
    psk: Arc<str>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut sessions: std::collections::HashMap<SocketAddr, QuicProxySession> =
        std::collections::HashMap::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                sessions.retain(|_addr, session| {
                    session.relay.idle_for() < SESSION_IDLE_TIMEOUT
                });
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

                if let Some(session) = sessions.get_mut(&client_addr) {
                    if is_quic_looking(packet[0]) {
                        // Forward follow-up raw QUIC datagram directly to target
                        if session.relay.send_to(Bytes::copy_from_slice(packet), session.target.clone()).is_err() {
                            sessions.remove(&client_addr);
                        }
                    } else {
                        // Potential retransmitted or updated Init Frame from existing client
                        let psk_clone = psk.clone();
                        let packet_vec = packet.to_vec();
                        let decoded = match tokio::task::spawn_blocking(move || {
                            decode_quic_proxy_init(psk_clone.as_bytes(), &packet_vec)
                        }).await {
                            Ok(Ok(v)) => v,
                            _ => {
                                log::debug!("Snell QUIC proxy: invalid init frame on existing session from {client_addr}");
                                continue;
                            }
                        };

                        let (new_target, _user_key, payload) = decoded;
                        if session.target == new_target {
                            let _ = session.relay.send_to(Bytes::copy_from_slice(&payload), new_target);
                        } else {
                            // Target changed: replace old session with fresh relay
                            sessions.remove(&client_addr);
                            create_quic_session(
                                &socket,
                                &proxy_selector,
                                &resolver,
                                &mut sessions,
                                client_addr,
                                new_target,
                                payload,
                            );
                        }
                    }
                } else {
                    if is_quic_looking(packet[0]) {
                        log::debug!("Snell QUIC proxy: discard unassociated packet from {client_addr}");
                        continue;
                    }

                    let psk_clone = psk.clone();
                    let packet_vec = packet.to_vec();
                    let decoded = match tokio::task::spawn_blocking(move || {
                        decode_quic_proxy_init(psk_clone.as_bytes(), &packet_vec)
                    }).await {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            log::debug!("Snell QUIC proxy: invalid init frame from {client_addr}: {e}");
                            continue;
                        }
                        Err(e) => {
                            log::error!("Snell QUIC proxy: spawn_blocking panic: {e}");
                            continue;
                        }
                    };

                    let (target, _user_key, payload) = decoded;
                    create_quic_session(
                        &socket,
                        &proxy_selector,
                        &resolver,
                        &mut sessions,
                        client_addr,
                        target,
                        payload,
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

    #[tokio::test]
    async fn test_quic_proxy_listener_integration() {
        let echo_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = echo_server.recv_from(&mut buf).await {
                let _ = echo_server.send_to(&buf[..n], src).await;
            }
        });

        let psk: Arc<str> = Arc::from("snell-secret-psk-12345");
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![crate::config::ResolvedRuleConfig::default()],
                resolver.clone(),
            )
            .unwrap(),
        );

        let listener_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listener_addr = listener_socket.local_addr().unwrap();

        let listener_handle = tokio::spawn({
            let socket = listener_socket.clone();
            let psk = psk.clone();
            let selector = selector.clone();
            let resolver = resolver.clone();
            async move {
                let _ = run_snell_quic_proxy_listener(socket, psk, selector, resolver).await;
            }
        });

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = NetLocation::from_str(&echo_addr.to_string(), None).unwrap();
        let initial_payload = vec![0xc0, 0, 0, 0, 1, 10, 20, 30];

        let init_frame =
            encode_quic_proxy_init(psk.as_bytes(), b"", &target, &initial_payload).unwrap();
        client.send_to(&init_frame, listener_addr).await.unwrap();

        let mut recv_buf = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut recv_buf))
            .await
            .expect("timeout waiting for initial echo")
            .unwrap();
        assert_eq!(&recv_buf[..n], &initial_payload);

        let follow_up = vec![0x40, 1, 2, 3, 4, 5, 6, 7];
        client.send_to(&follow_up, listener_addr).await.unwrap();

        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut recv_buf))
            .await
            .expect("timeout waiting for follow-up echo")
            .unwrap();
        assert_eq!(&recv_buf[..n], &follow_up);

        listener_handle.abort();
    }
}
