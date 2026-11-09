use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use rand::Rng;

use super::default_key::DefaultKey;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use crate::address::{Address, NetLocation};

pub const ADDR_TYPE_IPV4: u8 = 1;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
pub const ADDR_TYPE_IPV6: u8 = 4;

pub const TYPE_CLIENT_PAYLOAD: u8 = 0;
pub const TYPE_SERVER_PAYLOAD: u8 = 1;
pub const MAX_TIMESTAMP_DIFF_SECS: u64 = 30;

const CONTEXT_STR: &str = "shadowsocks 2022 session subkey";

pub fn derive_2022_udp_session_key(
    key_bytes: &[u8],
    session_id_bytes: &[u8],
    session_key_len: usize,
) -> Vec<u8> {
    let mut key_material = Vec::with_capacity(key_bytes.len() + session_id_bytes.len());
    key_material.extend_from_slice(key_bytes);
    key_material.extend_from_slice(session_id_bytes);

    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_STR);
    hasher.update(&key_material);
    let mut output_reader = hasher.finalize_xof();

    let mut session_key = vec![0u8; session_key_len];
    output_reader.fill(&mut session_key);
    session_key
}

/// Parse SOCKS5 target address from byte slice: returns (NetLocation, bytes_consumed).
pub fn parse_socks5_target(data: &[u8]) -> std::io::Result<(NetLocation, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty address",
        ));
    }
    match data[0] {
        ADDR_TYPE_IPV4 => {
            if data.len() < 7 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated IPv4 address",
                ));
            }
            let addr = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((NetLocation::new(Address::Ipv4(addr), port), 7))
        }
        ADDR_TYPE_IPV6 => {
            if data.len() < 19 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated IPv6 address",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let addr = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((NetLocation::new(Address::Ipv6(addr), port), 19))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            if data.len() < 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated domain length",
                ));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated domain data",
                ));
            }
            let domain = std::str::from_utf8(&data[2..2 + len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid domain UTF-8: {e}"),
                )
            })?;
            let port = u16::from_be_bytes([data[2 + len], data[2 + len + 1]]);
            Ok((NetLocation::new(Address::from(domain)?, port), 2 + len + 2))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported SOCKS address type: {other}"),
        )),
    }
}

/// Serialize SOCKS5 target address into buffer.
pub fn write_socks5_target(location: &NetLocation, buf: &mut Vec<u8>) {
    let (address, port) = location.components();
    match address {
        Address::Ipv4(v4) => {
            buf.push(ADDR_TYPE_IPV4);
            buf.extend_from_slice(&v4.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6(v6) => {
            buf.push(ADDR_TYPE_IPV6);
            buf.extend_from_slice(&v6.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Hostname(domain) => {
            buf.push(ADDR_TYPE_DOMAIN_NAME);
            let bytes = domain.as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// SIP004 Legacy AEAD UDP Codec
// ---------------------------------------------------------------------------

/// Decrypt an incoming SIP004 client UDP datagram.
/// Format: `[Salt (salt_len)] + AEAD_Encrypt(subkey, [SOCKS5 Address + Payload])`
pub fn decrypt_client_udp_packet_legacy(
    data: &[u8],
    key: &DefaultKey,
    cipher: ShadowsocksCipher,
) -> std::io::Result<(NetLocation, Vec<u8>)> {
    let salt_len = cipher.salt_len();
    let tag_len = cipher.algorithm().tag_len();
    if data.len() < salt_len + tag_len + 7 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "packet too short for legacy AEAD UDP",
        ));
    }

    let salt = &data[..salt_len];
    let session_key = key.create_session_key(salt);

    let unbound = UnboundKey::new(cipher.algorithm(), &session_key)
        .map_err(|_| std::io::Error::other("failed to create unbound key"))?;
    let less_safe = LessSafeKey::new(unbound);

    let mut in_out = data[salt_len..].to_vec();
    let nonce = Nonce::try_assume_unique_for_key(&[0u8; NONCE_LEN])
        .map_err(|_| std::io::Error::other("invalid nonce"))?;

    let plain = less_safe
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "AEAD decrypt failed")
        })?;

    let (target, addr_len) = parse_socks5_target(plain)?;
    let payload = plain[addr_len..].to_vec();

    Ok((target, payload))
}

/// Encrypt an outgoing SIP004 server UDP datagram to client.
/// Format: `[Server Salt] + AEAD_Encrypt(subkey, [Original Target + Payload])`
pub fn encrypt_server_udp_packet_legacy(
    target: &NetLocation,
    payload: &[u8],
    key: &DefaultKey,
    cipher: ShadowsocksCipher,
) -> std::io::Result<Vec<u8>> {
    let salt_len = cipher.salt_len();
    let mut salt = vec![0u8; salt_len];
    rand::rng().fill_bytes(&mut salt);

    let session_key = key.create_session_key(&salt);
    let unbound = UnboundKey::new(cipher.algorithm(), &session_key)
        .map_err(|_| std::io::Error::other("failed to create unbound key"))?;
    let less_safe = LessSafeKey::new(unbound);

    let mut body = Vec::with_capacity(19 + payload.len() + cipher.algorithm().tag_len());
    write_socks5_target(target, &mut body);
    body.extend_from_slice(payload);

    let nonce = Nonce::try_assume_unique_for_key(&[0u8; NONCE_LEN])
        .map_err(|_| std::io::Error::other("invalid nonce"))?;

    less_safe
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
        .map_err(|_| std::io::Error::other("AEAD seal failed"))?;

    let mut out = salt;
    out.extend_from_slice(&body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// SIP022 AEAD-2022 UDP Codec
// ---------------------------------------------------------------------------

/// 64-bit Sliding Window filter for anti-replay per session.
#[derive(Debug, Clone)]
pub struct SlidingWindowFilter {
    last_id: u64,
    window: u64,
}

impl Default for SlidingWindowFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindowFilter {
    pub fn new() -> Self {
        Self {
            last_id: 0,
            window: 0,
        }
    }

    /// Check and accept packet ID. Returns true if packet ID is accepted, false if replayed/too old.
    pub fn validate_and_update(&mut self, id: u64) -> bool {
        if self.window == 0 && self.last_id == 0 {
            self.last_id = id;
            self.window = 1;
            return true;
        }

        if id > self.last_id {
            let diff = id - self.last_id;
            if diff < 64 {
                self.window = (self.window << diff) | 1;
            } else {
                self.window = 1;
            }
            self.last_id = id;
            true
        } else {
            let diff = self.last_id - id;
            if diff >= 64 {
                return false; // too old
            }
            if (self.window & (1 << diff)) != 0 {
                return false; // already seen
            }
            self.window |= 1 << diff;
            true
        }
    }
}

fn get_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct DecryptedClientPacket2022 {
    pub session_id: u64,
    pub packet_id: u64,
    pub target: NetLocation,
    pub payload: Vec<u8>,
}

/// Decrypt an incoming SIP022 client UDP datagram (supports 2022-blake3-aes-128-gcm and 2022-blake3-aes-256-gcm).
pub fn decrypt_client_udp_packet_2022(
    data: &[u8],
    key_bytes: &[u8],
    cipher: ShadowsocksCipher,
) -> std::io::Result<DecryptedClientPacket2022> {
    let tag_len = cipher.algorithm().tag_len();
    let is_aes = matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm");

    if is_aes {
        // Minimum packet length: 16 (header) + tag_len + 1 (type) + 8 (timestamp) + 2 (padding size) + 7 (min target)
        let min_len = 16 + tag_len + 1 + 8 + 2 + 7;
        if data.len() < min_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "packet too short for AEAD 2022 AES-GCM",
            ));
        }

        // Decrypt the 16-byte header [Session ID (8B) + Packet ID (8B)] using AES-ECB
        let algorithm = match key_bytes.len() {
            16 => &AES_128,
            32 => &AES_256,
            _ => return Err(std::io::Error::other("invalid key length for 2022 AES-GCM")),
        };

        let unbound_cipher = UnboundCipherKey::new(algorithm, key_bytes)
            .map_err(|_| std::io::Error::other("failed to initialize AES key for header"))?;
        let decrypting_key = DecryptingKey::ecb(unbound_cipher)
            .map_err(|_| std::io::Error::other("failed to create AES-ECB decryptor"))?;

        let mut header = [0u8; 16];
        header.copy_from_slice(&data[..16]);
        decrypting_key
            .decrypt(&mut header, DecryptionContext::None)
            .map_err(|_| std::io::Error::other("failed to decrypt 2022 header"))?;

        let session_id = u64::from_be_bytes(header[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(header[8..16].try_into().unwrap());

        // Session subkey derived via BLAKE3 KDF: key_bytes + session_id (8 bytes)
        let session_key = derive_2022_udp_session_key(key_bytes, &header[0..8], cipher.key_len());
        let unbound_aead = UnboundKey::new(cipher.algorithm(), &session_key)
            .map_err(|_| std::io::Error::other("failed to initialize AEAD key"))?;
        let less_safe_aead = LessSafeKey::new(unbound_aead);

        // Nonce is the last 12 bytes of header: header[4..16]
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&header[4..16]);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce for 2022 AES-GCM"))?;

        let mut ciphertext = data[16..].to_vec();
        let plain = less_safe_aead
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "2022 AEAD decrypt failed")
            })?;

        if plain.len() < 1 + 8 + 2 + 7 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload too short",
            ));
        }

        let socket_type = plain[0];
        if socket_type != TYPE_CLIENT_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid socket type: {socket_type}"),
            ));
        }

        let timestamp = u64::from_be_bytes(plain[1..9].try_into().unwrap());
        let now = get_now_unix();
        if now.abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("timestamp drift exceeded: client={timestamp}, now={now}"),
            ));
        }

        let padding_size = u16::from_be_bytes(plain[9..11].try_into().unwrap()) as usize;
        let body_start = 11 + padding_size;
        if plain.len() < body_start + 7 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "padding size exceeds payload boundary",
            ));
        }

        let (target, addr_len) = parse_socks5_target(&plain[body_start..])?;
        let payload = plain[body_start + addr_len..].to_vec();

        Ok(DecryptedClientPacket2022 {
            session_id,
            packet_id,
            target,
            payload,
        })
    } else {
        // ChaCha20-Poly1305 (prepended 12-byte nonce, PSK direct encryption)
        let min_len = 12 + tag_len + 8 + 8 + 1 + 8 + 2 + 7;
        if data.len() < min_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "packet too short for 2022 ChaCha20-Poly1305",
            ));
        }

        let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
        let unbound_aead = UnboundKey::new(cipher.algorithm(), key_bytes)
            .map_err(|_| std::io::Error::other("failed to initialize AEAD key"))?;
        let less_safe = LessSafeKey::new(unbound_aead);

        let mut ciphertext = data[12..].to_vec();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce"))?;

        let plain = less_safe
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "2022 ChaCha decrypt failed")
            })?;

        let session_id = u64::from_be_bytes(plain[0..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plain[8..16].try_into().unwrap());

        let socket_type = plain[16];
        if socket_type != TYPE_CLIENT_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid socket type: {socket_type}"),
            ));
        }

        let timestamp = u64::from_be_bytes(plain[17..25].try_into().unwrap());
        let now = get_now_unix();
        if now.abs_diff(timestamp) > MAX_TIMESTAMP_DIFF_SECS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "timestamp drift exceeded",
            ));
        }

        let padding_size = u16::from_be_bytes(plain[25..27].try_into().unwrap()) as usize;
        let body_start = 27 + padding_size;
        if plain.len() < body_start + 7 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "padding size exceeds payload boundary",
            ));
        }

        let (target, addr_len) = parse_socks5_target(&plain[body_start..])?;
        let payload = plain[body_start + addr_len..].to_vec();

        Ok(DecryptedClientPacket2022 {
            session_id,
            packet_id,
            target,
            payload,
        })
    }
}

/// Encrypt an outgoing SIP022 server UDP datagram to client.
pub fn encrypt_server_udp_packet_2022(
    server_session_id: u64,
    server_packet_id: u64,
    client_session_id: u64,
    target: &NetLocation,
    payload: &[u8],
    key_bytes: &[u8],
    cipher: ShadowsocksCipher,
) -> std::io::Result<Vec<u8>> {
    let is_aes = matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm");

    if is_aes {
        let mut header = [0u8; 16];
        header[0..8].copy_from_slice(&server_session_id.to_be_bytes());
        header[8..16].copy_from_slice(&server_packet_id.to_be_bytes());

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&header[4..16]);

        let session_key = derive_2022_udp_session_key(key_bytes, &header[0..8], cipher.key_len());
        let unbound_aead = UnboundKey::new(cipher.algorithm(), &session_key)
            .map_err(|_| std::io::Error::other("failed to initialize AEAD key"))?;
        let less_safe_aead = LessSafeKey::new(unbound_aead);

        let mut plaintext = Vec::with_capacity(1 + 8 + 8 + 2 + 19 + payload.len() + 16);
        plaintext.push(TYPE_SERVER_PAYLOAD);
        plaintext.extend_from_slice(&get_now_unix().to_be_bytes());
        plaintext.extend_from_slice(&client_session_id.to_be_bytes());
        plaintext.extend_from_slice(&0u16.to_be_bytes()); // padding size = 0
        write_socks5_target(target, &mut plaintext);
        plaintext.extend_from_slice(payload);

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce"))?;

        less_safe_aead
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
            .map_err(|_| std::io::Error::other("AEAD seal failed"))?;

        // Encrypt the 16-byte header with AES-ECB
        let algorithm = match key_bytes.len() {
            16 => &AES_128,
            32 => &AES_256,
            _ => return Err(std::io::Error::other("invalid key length for 2022 AES-GCM")),
        };
        let unbound_cipher = UnboundCipherKey::new(algorithm, key_bytes)
            .map_err(|_| std::io::Error::other("failed to initialize AES key"))?;
        let encrypting_key = EncryptingKey::ecb(unbound_cipher)
            .map_err(|_| std::io::Error::other("failed to create AES-ECB encryptor"))?;

        encrypting_key
            .less_safe_encrypt(&mut header, EncryptionContext::None)
            .map_err(|_| std::io::Error::other("failed to encrypt header"))?;

        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&plaintext);
        Ok(out)
    } else {
        // ChaCha20-Poly1305
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let unbound_aead = UnboundKey::new(cipher.algorithm(), key_bytes)
            .map_err(|_| std::io::Error::other("failed to initialize AEAD key"))?;
        let less_safe = LessSafeKey::new(unbound_aead);

        let mut plaintext = Vec::with_capacity(8 + 8 + 1 + 8 + 8 + 2 + 19 + payload.len() + 16);
        plaintext.extend_from_slice(&server_session_id.to_be_bytes());
        plaintext.extend_from_slice(&server_packet_id.to_be_bytes());
        plaintext.push(TYPE_SERVER_PAYLOAD);
        plaintext.extend_from_slice(&get_now_unix().to_be_bytes());
        plaintext.extend_from_slice(&client_session_id.to_be_bytes());
        plaintext.extend_from_slice(&0u16.to_be_bytes()); // padding size = 0
        write_socks5_target(target, &mut plaintext);
        plaintext.extend_from_slice(payload);

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce"))?;

        less_safe
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
            .map_err(|_| std::io::Error::other("AEAD seal failed"))?;

        let mut out = Vec::with_capacity(12 + plaintext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&plaintext);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_target_roundtrip() {
        let targets = vec![
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            NetLocation::new(
                Address::Ipv6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                853,
            ),
            NetLocation::new(Address::from("dns.google").unwrap(), 443),
        ];

        for target in targets {
            let mut buf = Vec::new();
            write_socks5_target(&target, &mut buf);
            let (parsed, len) = parse_socks5_target(&buf).unwrap();
            assert_eq!(len, buf.len());
            assert_eq!(parsed, target);
        }
    }

    #[test]
    fn test_legacy_aead_udp_roundtrip() {
        let password = "test-password-123";
        let ciphers = ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"];

        for cipher_name in ciphers {
            let cipher = ShadowsocksCipher::try_from(cipher_name).unwrap();
            let key = DefaultKey::new(password, cipher.key_len());

            let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 53);
            let payload = b"hello legacy udp shadowsocks";

            // Client encrypts request
            let mut request_salt = vec![0u8; cipher.salt_len()];
            rand::rng().fill_bytes(&mut request_salt);

            let session_key = key.create_session_key(&request_salt);
            let unbound = UnboundKey::new(cipher.algorithm(), &session_key).unwrap();
            let less_safe = LessSafeKey::new(unbound);

            let mut plain = Vec::new();
            write_socks5_target(&target, &mut plain);
            plain.extend_from_slice(payload);

            let nonce = Nonce::try_assume_unique_for_key(&[0u8; NONCE_LEN]).unwrap();
            less_safe
                .seal_in_place_append_tag(nonce, Aad::empty(), &mut plain)
                .unwrap();

            let mut request_data = request_salt;
            request_data.extend_from_slice(&plain);

            // Server decrypts request
            let (dec_target, dec_payload) =
                decrypt_client_udp_packet_legacy(&request_data, &key, cipher).unwrap();
            assert_eq!(dec_target, target);
            assert_eq!(dec_payload, payload);

            // Server encrypts response
            let response_payload = b"reply from 1.1.1.1";
            let response_packet =
                encrypt_server_udp_packet_legacy(&target, response_payload, &key, cipher).unwrap();

            // Client decrypts response
            let (dec_resp_target, dec_resp_payload) =
                decrypt_client_udp_packet_legacy(&response_packet, &key, cipher).unwrap();
            assert_eq!(dec_resp_target, target);
            assert_eq!(dec_resp_payload, response_payload);
        }
    }

    #[test]
    fn test_2022_aead_udp_roundtrip() {
        let ciphers = [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ];

        for (cipher_name, key_len) in ciphers {
            let stripped = cipher_name.strip_prefix("2022-blake3-").unwrap();
            let cipher = ShadowsocksCipher::try_from(stripped).unwrap();
            let key_bytes = vec![0x42u8; key_len].into_boxed_slice();

            let target = NetLocation::new(Address::from("example.com").unwrap(), 443);
            let payload = b"hello 2022 udp";
            let client_session_id: u64 = 0x123456789abcdef0;
            let client_packet_id: u64 = 1;

            // Simulate client packet creation
            let is_aes = matches!(stripped, "aes-128-gcm" | "aes-256-gcm");
            let client_packet = if is_aes {
                let mut header = [0u8; 16];
                header[0..8].copy_from_slice(&client_session_id.to_be_bytes());
                header[8..16].copy_from_slice(&client_packet_id.to_be_bytes());

                let mut nonce_bytes = [0u8; NONCE_LEN];
                nonce_bytes.copy_from_slice(&header[4..16]);

                let session_key =
                    derive_2022_udp_session_key(&key_bytes, &header[0..8], cipher.key_len());
                let unbound = UnboundKey::new(cipher.algorithm(), &session_key).unwrap();
                let less_safe = LessSafeKey::new(unbound);

                let mut plain = Vec::new();
                plain.push(TYPE_CLIENT_PAYLOAD);
                plain.extend_from_slice(&get_now_unix().to_be_bytes());
                plain.extend_from_slice(&0u16.to_be_bytes()); // padding size = 0
                write_socks5_target(&target, &mut plain);
                plain.extend_from_slice(payload);

                let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
                less_safe
                    .seal_in_place_append_tag(nonce, Aad::empty(), &mut plain)
                    .unwrap();

                let algorithm = match key_len {
                    16 => &AES_128,
                    32 => &AES_256,
                    _ => unreachable!(),
                };
                let unbound_cipher = UnboundCipherKey::new(algorithm, &key_bytes).unwrap();
                let encrypting_key = EncryptingKey::ecb(unbound_cipher).unwrap();
                encrypting_key
                    .less_safe_encrypt(&mut header, EncryptionContext::None)
                    .unwrap();

                let mut out = header.to_vec();
                out.extend_from_slice(&plain);
                out
            } else {
                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);

                let unbound = UnboundKey::new(cipher.algorithm(), &key_bytes).unwrap();
                let less_safe = LessSafeKey::new(unbound);

                let mut plain = Vec::new();
                plain.extend_from_slice(&client_session_id.to_be_bytes());
                plain.extend_from_slice(&client_packet_id.to_be_bytes());
                plain.push(TYPE_CLIENT_PAYLOAD);
                plain.extend_from_slice(&get_now_unix().to_be_bytes());
                plain.extend_from_slice(&0u16.to_be_bytes());
                write_socks5_target(&target, &mut plain);
                plain.extend_from_slice(payload);

                let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
                less_safe
                    .seal_in_place_append_tag(nonce, Aad::empty(), &mut plain)
                    .unwrap();

                let mut out = nonce_bytes.to_vec();
                out.extend_from_slice(&plain);
                out
            };

            // Server decrypts client packet
            let dec =
                decrypt_client_udp_packet_2022(&client_packet, &key_bytes, cipher).unwrap();
            assert_eq!(dec.session_id, client_session_id);
            assert_eq!(dec.packet_id, client_packet_id);
            assert_eq!(dec.target, target);
            assert_eq!(dec.payload, payload);

            // Server encrypts response
            let server_session_id: u64 = 0x9988776655443322;
            let server_packet_id: u64 = 1;
            let server_response = encrypt_server_udp_packet_2022(
                server_session_id,
                server_packet_id,
                client_session_id,
                &target,
                b"pong 2022",
                &key_bytes,
                cipher,
            )
            .unwrap();

            assert!(!server_response.is_empty());
        }
    }

    #[test]
    fn test_sliding_window_filter() {
        let mut filter = SlidingWindowFilter::new();
        assert!(filter.validate_and_update(1));
        assert!(filter.validate_and_update(2));
        assert!(!filter.validate_and_update(1)); // duplicate rejected
        assert!(!filter.validate_and_update(2)); // duplicate rejected
        assert!(filter.validate_and_update(10));
        assert!(filter.validate_and_update(5));
        assert!(!filter.validate_and_update(5)); // duplicate
        assert!(filter.validate_and_update(100)); // new far future
        assert!(!filter.validate_and_update(20)); // too old (diff 80 >= 64)
    }
}
