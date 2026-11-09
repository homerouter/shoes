# Shadowsocks Standard Native UDP Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add standard SIP004 (AEAD) and SIP022 (AEAD-2022) native UDP Relay to `shoes`, enabling full standard Shadowsocks UDP support alongside the existing UDP-over-TCP (UoT) mode without adding external dependencies.

**Architecture:**
1. Dual-binding UDP listener on the configured server port when `protocol == shadowsocks` and `udp_enabled == true`.
2. Dedicated packet codec for decoding/encoding SIP004 and SIP022 UDP datagrams using `shoes`'s existing `aws-lc-rs` and `blake3` primitives.
3. NAT session manager leveraging `shoes`'s `UdpRelay` (`crate::routing::udp_relay::UdpRelay`), which automatically integrates with DNS routing, outbound selectors, and rules.
4. Preserves backward compatibility: existing UoT requests over TCP continue to work seamlessly.

**Tech Stack:** Rust 2024, Tokio, AWS-LC (`aws-lc-rs`), BLAKE3, `shoes` routing subsystem.

---

### File Structure Map

* **`src/shadowsocks/udp_packet.rs`** (New): Datagram encode/decode for SIP004 and SIP022 UDP packets, SOCKS5 address serialization/deserialization for UDP, and anti-replay packet ID tracking.
* **`src/shadowsocks/udp_relay.rs`** (New): UDP listener loop (`run_shadowsocks_udp_listener`), session map with LRU expiration, and bridge to `UdpRelay`.
* **`src/shadowsocks/mod.rs`** (Modified): Export UDP listener and packet codec.
* **`src/tcp/tcp_server.rs`** (Modified): Bind `UdpSocket` alongside `TcpListener` when `ResolvedServerProxyConfig::Shadowsocks { udp_enabled: true }`.
* **`src/shadowsocks/tests/udp_test.rs`** (New): Comprehensive unit and roundtrip tests for both legacy AEAD and 2022 AEAD UDP flows.

---

### Tasks

#### Task 1: SIP004 (Legacy AEAD) UDP Packet Codec
- [ ] **Step 1.1**: Define `UdpPacket` struct representing decrypted UDP packet: `(NetLocation, Bytes)`.
- [ ] **Step 1.2**: Implement `decrypt_client_udp_packet_legacy`:
  - Input: `&[u8]`, `DefaultKey`, `ShadowsocksCipher`.
  - Extract `salt` (length matching `cipher.salt_len()`).
  - Derive subkey: HKDF-SHA1(`master_key`, `salt`, `b"ss-subkey"`).
  - Open AEAD ciphertext with `nonce = [0u8; 12]` and empty AAD.
  - Parse SOCKS5 target address (`NetLocation`) and return payload.
- [ ] **Step 1.3**: Implement `encrypt_server_udp_packet_legacy`:
  - Input: `&NetLocation`, `&[u8]`, `DefaultKey`, `ShadowsocksCipher`.
  - Generate random server salt.
  - Derive subkey: HKDF-SHA1(`master_key`, `server_salt`, `b"ss-subkey"`).
  - Seal `[SOCKS5 address + payload]` with `nonce = [0u8; 12]` and empty AAD.
  - Prepend `server_salt` and return encrypted datagram.
- [ ] **Step 1.4**: Write unit tests for legacy AEAD UDP packet roundtrip in `src/shadowsocks/udp_packet.rs`.
- [ ] **Step 1.5**: Run `cargo test --lib shadowsocks::udp_packet` and confirm passing.

#### Task 2: SIP022 (AEAD-2022) UDP Packet Codec & Anti-Replay
- [ ] **Step 2.1**: Implement Packet ID Sliding Window Filter (64-bit window) for anti-replay per session.
- [ ] **Step 2.2**: Implement `decrypt_client_udp_packet_2022`:
  - Input: `&[u8]`, `Blake3Key`, `ShadowsocksCipher`.
  - Check minimum packet size.
  - For AES-GCM: Decrypt first 16 bytes with AES-ECB (`master_key`) -> `[Session ID (8B) + Packet ID (8B)]`.
  - Nonce = `&header[4..16]`.
  - Derive session key: `blake3_key.create_session_key(&session_id)`.
  - Decrypt message with AES-GCM.
  - Validate packet type (0x00 = client payload), timestamp (drift <= 30s), padding, and extract `NetLocation` + payload.
  - For ChaCha20-Poly1305: Decrypt with prepended nonce and validate header.
- [ ] **Step 2.3**: Implement `encrypt_server_udp_packet_2022`:
  - Format: `[Server Session ID (8B) + Packet ID (8B)] AES-ECB` + `AEAD(Type=0x01, Timestamp, Client Session ID, Padding, NetLocation, Payload)`.
- [ ] **Step 2.4**: Write unit tests for 2022 UDP packet roundtrip and replay rejection in `src/shadowsocks/udp_packet.rs`.
- [ ] **Step 2.5**: Run `cargo test --lib shadowsocks::udp_packet` and confirm passing.

#### Task 3: UDP Listener & NAT Session State Machine
- [ ] **Step 3.1**: Create `src/shadowsocks/udp_relay.rs`.
- [ ] **Step 3.2**: Implement `ShadowsocksUdpSession`:
  - `relay: Arc<UdpRelay>`
  - `target: NetLocation`
  - `packet_id_out: AtomicU64`
  - `return_task: tokio::task::AbortHandle`
- [ ] **Step 3.3**: Implement `run_shadowsocks_udp_listener`:
  - Accept `Arc<UdpSocket>`, `ShadowsocksConfig`, `Arc<ClientProxySelector>`, `Arc<dyn Resolver>`.
  - Manage session map with 60-second idle retention (similar to Snell QUIC proxy session pattern).
  - On incoming packet:
    - Decrypt datagram using Task 1 / Task 2 codec.
    - Lookup or initialize session: create `UdpRelay::new(...)`, forward payload to target.
    - Spawn return task reading from `relay.recv().await`, encrypting with server response framing, and sending back to client socket via `socket.send_to`.
- [ ] **Step 3.4**: Write unit tests for session creation, packet routing, and idle cleanup.
- [ ] **Step 3.5**: Run `cargo test --lib shadowsocks::udp_relay` and confirm passing.

#### Task 4: Inbound Server Listener Integration
- [ ] **Step 4.1**: In `src/tcp/tcp_server.rs`, inside `start_tcp_servers`, inspect `ResolvedServerConfig`.
- [ ] **Step 4.2**: If `ResolvedServerProxyConfig::Shadowsocks { udp_enabled: true, .. }`, call `crate::socket_util::new_udp_listener(udp_addr)` on the server's listen address.
- [ ] **Step 4.3**: Spawn `run_shadowsocks_udp_listener` alongside the TCP server listener.
- [ ] **Step 4.4**: Ensure graceful admission cancellation token integration.
- [ ] **Step 4.5**: Run `cargo check` and existing integration tests.

#### Task 5: End-to-End Integration Verification
- [ ] **Step 5.1**: Write an end-to-end integration test creating a live `shoes` server with `protocol: shadowsocks` and `udp_enabled: true`.
- [ ] **Step 5.2**: Simulate a standard Shadowsocks UDP client sending a DNS query or UDP echo payload.
- [ ] **Step 5.3**: Verify proper response receipt, decryption, and NAT association.
- [ ] **Step 5.4**: Run `cargo test` and confirm all tests pass.

#### Task 6: Deployment & Canary Validation
- [ ] **Step 6.1**: Build release binary: `cargo build --release --target x86_64-unknown-linux-musl`.
- [ ] **Step 6.2**: Deploy canary to `dc9` via Ansible playbook.
- [ ] **Step 6.3**: Verify `shoes` service status, UDP port binding (`ss -ulpn | grep 52010`), and test live proxying.
