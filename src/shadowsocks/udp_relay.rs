use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use super::default_key::DefaultKey;
use super::udp_packet::{
    SlidingWindowFilter, decrypt_client_udp_packet_2022, decrypt_client_udp_packet_legacy,
    encrypt_server_udp_packet_2022, encrypt_server_udp_packet_legacy,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;

pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    Legacy(SocketAddr),
    Aead2022(u64), // Client Session ID
}

struct ShadowsocksUdpSession {
    relay: Arc<UdpRelay>,
    client_addr: Arc<Mutex<SocketAddr>>,
    filter: Option<SlidingWindowFilter>,
    return_task: tokio::task::AbortHandle,
}

impl Drop for ShadowsocksUdpSession {
    fn drop(&mut self) {
        self.return_task.abort();
    }
}

/// Runs the standard Shadowsocks UDP listener loop on a bound UDP socket.
pub async fn run_shadowsocks_udp_listener(
    socket: Arc<UdpSocket>,
    config: ShadowsocksConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut sessions: HashMap<SessionKey, ShadowsocksUdpSession> = HashMap::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(10));

    let (cipher, legacy_key, aead2022_key_bytes) = match config {
        ShadowsocksConfig::Legacy {
            cipher,
            ref password,
        } => {
            let key = DefaultKey::new(password, cipher.key_len());
            (cipher, Some(key), None)
        }
        ShadowsocksConfig::Aead2022 {
            cipher,
            ref key_bytes,
            ..
        } => (cipher, None, Some(key_bytes.clone())),
    };

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                sessions.retain(|_key, session| {
                    session.relay.idle_for() < SESSION_IDLE_TIMEOUT
                });
            }
            res = socket.recv_from(&mut buf) => {
                let (n, client_addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("Shadowsocks UDP listener recv error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                let packet_bytes = &buf[..n];

                // Decrypt incoming datagram
                if let Some(ref key) = legacy_key {
                    let (target, payload) = match decrypt_client_udp_packet_legacy(packet_bytes, key, cipher) {
                        Ok(v) => v,
                        Err(e) => {
                            log::debug!("Failed to decrypt legacy Shadowsocks UDP packet from {client_addr}: {e}");
                            continue;
                        }
                    };

                    let session_key = SessionKey::Legacy(client_addr);
                    if let Some(session) = sessions.get_mut(&session_key) {
                        *session.client_addr.lock() = client_addr;
                        let _ = session.relay.send_to(Bytes::copy_from_slice(&payload), target);
                    } else {
                        let relay = match UdpRelay::new(
                            proxy_selector.clone(),
                            resolver.clone(),
                            Some(client_addr),
                        ) {
                            Ok(r) => Arc::new(r),
                            Err(e) => {
                                log::error!("Shadowsocks UDP relay: failed to create UdpRelay: {e}");
                                continue;
                            }
                        };

                        let _ = relay.send_to(Bytes::copy_from_slice(&payload), target);

                        let socket_clone = socket.clone();
                        let relay_clone = relay.clone();
                        let key_clone = key.clone();
                        let client_addr_holder = Arc::new(Mutex::new(client_addr));
                        let client_addr_holder_clone = client_addr_holder.clone();

                        let return_task = tokio::spawn(async move {
                            loop {
                                match relay_clone.recv().await {
                                    Ok((data, origin_target)) => {
                                        match encrypt_server_udp_packet_legacy(&origin_target, &data, &key_clone, cipher) {
                                            Ok(resp_packet) => {
                                                let addr = *client_addr_holder_clone.lock();
                                                if socket_clone.send_to(&resp_packet, addr).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!("Failed to encrypt legacy server UDP packet: {e}");
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }).abort_handle();

                        sessions.insert(session_key, ShadowsocksUdpSession {
                            relay,
                            client_addr: client_addr_holder,
                            filter: None,
                            return_task,
                        });
                    }
                } else if let Some(ref key_bytes) = aead2022_key_bytes {
                    let dec = match decrypt_client_udp_packet_2022(packet_bytes, key_bytes, cipher) {
                        Ok(v) => v,
                        Err(e) => {
                            log::debug!("Failed to decrypt 2022 Shadowsocks UDP packet from {client_addr}: {e}");
                            continue;
                        }
                    };

                    let session_key = SessionKey::Aead2022(dec.session_id);
                    if let Some(session) = sessions.get_mut(&session_key) {
                        // Check anti-replay on packet_id
                        if let Some(ref mut filter) = session.filter {
                            if !filter.validate_and_update(dec.packet_id) {
                                log::debug!("Shadowsocks 2022 UDP replayed packet_id={} from {client_addr}", dec.packet_id);
                                continue;
                            }
                        }
                        *session.client_addr.lock() = client_addr;
                        let _ = session.relay.send_to(Bytes::copy_from_slice(&dec.payload), dec.target);
                    } else {
                        let mut filter = SlidingWindowFilter::new();
                        filter.validate_and_update(dec.packet_id);

                        let relay = match UdpRelay::new(
                            proxy_selector.clone(),
                            resolver.clone(),
                            Some(client_addr),
                        ) {
                            Ok(r) => Arc::new(r),
                            Err(e) => {
                                log::error!("Shadowsocks 2022 UDP relay: failed to create UdpRelay: {e}");
                                continue;
                            }
                        };

                        let _ = relay.send_to(Bytes::copy_from_slice(&dec.payload), dec.target);

                        let mut rng = rand::rng();
                        let mut server_session_bytes = [0u8; 8];
                        rand::Rng::fill_bytes(&mut rng, &mut server_session_bytes);
                        let server_session_id = u64::from_be_bytes(server_session_bytes);

                        let socket_clone = socket.clone();
                        let relay_clone = relay.clone();
                        let key_bytes_clone = key_bytes.clone();
                        let client_addr_holder = Arc::new(Mutex::new(client_addr));
                        let client_addr_holder_clone = client_addr_holder.clone();
                        let client_session_id = dec.session_id;

                        let return_task = tokio::spawn(async move {
                            let mut server_packet_id: u64 = 1;
                            loop {
                                match relay_clone.recv().await {
                                    Ok((data, origin_target)) => {
                                        match encrypt_server_udp_packet_2022(
                                            server_session_id,
                                            server_packet_id,
                                            client_session_id,
                                            &origin_target,
                                            &data,
                                            &key_bytes_clone,
                                            cipher,
                                        ) {
                                            Ok(resp_packet) => {
                                                server_packet_id = server_packet_id.wrapping_add(1);
                                                let addr = *client_addr_holder_clone.lock();
                                                if socket_clone.send_to(&resp_packet, addr).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!("Failed to encrypt 2022 server UDP packet: {e}");
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }).abort_handle();

                        sessions.insert(session_key, ShadowsocksUdpSession {
                            relay,
                            client_addr: client_addr_holder,
                            filter: Some(filter),
                            return_task,
                        });
                    }
                }
            }
        }
    }
}

