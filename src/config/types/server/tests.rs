use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[test]
fn sniff_config_defaults_and_round_trips() {
    fn check<T: serde::de::DeserializeOwned + serde::Serialize>(base: &str) {
        let config: T = serde_yaml::from_str(base).unwrap();
        let value = serde_yaml::to_value(config).unwrap();
        assert!(value.get("sniff").is_none());
        for enabled in [false, true] {
            let yaml = format!("{base}\nsniff: {enabled}\n");
            let config: T = serde_yaml::from_str(&yaml).unwrap();
            let value = serde_yaml::to_value(config).unwrap();
            assert_eq!(
                value.get("sniff").and_then(|v| v.as_bool()),
                enabled.then_some(true)
            );
            let round_trip: T = serde_yaml::from_value(value).unwrap();
            assert_eq!(
                serde_yaml::to_value(round_trip)
                    .unwrap()
                    .get("sniff")
                    .and_then(|v| v.as_bool()),
                enabled.then_some(true)
            );
        }
        for value in ["null", "1", "{}", "[tls]", "'true'"] {
            assert!(serde_yaml::from_str::<T>(&format!("{base}\nsniff: {value}\n")).is_err());
        }
        assert!(serde_yaml::from_str::<T>(&format!("{base}\nsnif: true\n")).is_err());
    }
    check::<ServerConfig>("address: '127.0.0.1:1080'\nprotocol: {type: socks}");
    check::<super::super::tun::TunConfig>("mtu: 1500");
    check::<ServerConfig>(
        "address: '127.0.0.1:51820'\nprotocol: {type: wireguard, private_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', addresses: [], peers: []}\nrules: []",
    );
    crate::config::create_server_configs(
        serde_yaml::from_str(include_str!("../../../../examples/sni_sniffing.yaml")).unwrap(),
    )
    .unwrap();
    crate::config::create_server_configs(
        serde_yaml::from_str(include_str!("../../../../examples/http_host_sniffing.yaml")).unwrap(),
    )
    .unwrap();
}

fn create_test_server_config_http() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
            .into(),
        protocol: ServerProxyConfig::Http {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        },
        transport: Transport::Tcp,
        tcp_settings: Some(TcpConfig { no_delay: true }),
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_socks() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1080)
            .into(),
        protocol: ServerProxyConfig::Socks {
            username: None,
            password: None,
            udp_enabled: false,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_shadowsocks() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: BindLocation::Path(PathBuf::from("/tmp/ss.sock")),
        protocol: ServerProxyConfig::Shadowsocks {
            config: ShadowsocksConfig::Legacy {
                cipher: "aes-256-gcm".try_into().unwrap(),
                password: "secret123".to_string(),
            },
            udp_enabled: true,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_vless() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            443,
        )
        .into(),
        protocol: ServerProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            decryption: Default::default(),
            _invalid_encryption: (),
            vision: false,
            encryption_limits: None,
            udp_enabled: true,
            fallback: None,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "server.crt".to_string(),
            key: "server.key".to_string(),
            alpn_protocols: NoneOrSome::Some(vec!["h3".to_string()]),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_trojan() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443)
            .into(),
        protocol: ServerProxyConfig::Trojan {
            password: "trojan_password".to_string(),
            shadowsocks: Some(ShadowsocksConfig::Legacy {
                cipher: "chacha20-poly1305".try_into().unwrap(),
                password: "ss_password".to_string(),
            }),
            udp_enabled: true,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_tls() -> ServerConfig {
    let mut tls_targets = HashMap::new();
    tls_targets.insert(
        "example.com".to_string(),
        TlsServerConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "example.crt".to_string(),
            key: "example.key".to_string(),
            alpn_protocols: NoneOrSome::Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            client_ca_certs: NoneOrSome::One("ca.crt".to_string()),
            client_fingerprints: NoneOrSome::One("abc123".to_string()),
            vision: false,
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            override_rules: NoneOrSome::None,
        },
    );

    ServerConfig {
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443)
            .into(),
        name: None,
        sniff: false,
        protocol: ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target: Some(Box::new(TlsServerConfig {
                certificate_source: None,
                certificate_binding: None,
                key_exchange_groups: Default::default(),
                cert: "default.crt".to_string(),
                key: "default.key".to_string(),
                alpn_protocols: NoneOrSome::None,
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                vision: false,
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                override_rules: NoneOrSome::None,
            })),
            shadowtls_targets: HashMap::new(),
            reality_targets: HashMap::new(),
            tls_buffer_size: Some(8192),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_vmess() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 10086)
            .into(),
        protocol: ServerProxyConfig::Vmess {
            cipher: "aes-128-gcm".to_string(),
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            udp_enabled: false,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_websocket() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
            .into(),
        protocol: ServerProxyConfig::Websocket {
            targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                max_early_data: 0,
                early_data_header_name: None,
                matching_path: Some("/ws".to_string()),
                matching_headers: None,
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                ping_type: WebsocketPingType::PingFrame,
                override_rules: NoneOrSome::None,
            })),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_port_forward() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090)
            .into(),
        protocol: ServerProxyConfig::PortForward {
            targets: OneOrSome::Some(vec![
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
            ]),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_hysteria2() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
            .into(),
        protocol: ServerProxyConfig::Hysteria2 {
            password: "hysteria_pass".to_string(),
            udp_enabled: true,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "hysteria.crt".to_string(),
            key: "hysteria.key".to_string(),
            alpn_protocols: NoneOrSome::One("hysteria".to_string()),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

fn create_test_server_config_tuic() -> ServerConfig {
    ServerConfig {
        name: None,
        sniff: false,
        bind_location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443)
            .into(),
        protocol: ServerProxyConfig::TuicV5 {
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            password: "tuic_password".to_string(),
            zero_rtt_handshake: false,
        },
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            certificate_source: None,
            certificate_binding: None,
            key_exchange_groups: Default::default(),
            cert: "tuic.crt".to_string(),
            key: "tuic.key".to_string(),
            alpn_protocols: NoneOrSome::None,
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: NoneOrSome::None,
        dns: None,
    }
}

// Test individual server config variants
#[test]
fn test_server_config_http() {
    let original = create_test_server_config_http();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    println!("HTTP config YAML:\n{yaml_str}");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Http { .. }
    ));
}

#[test]
fn test_server_config_socks() {
    let original = create_test_server_config_socks();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Socks { .. }
    ));
}

#[test]
fn test_server_config_shadowsocks() {
    let original = create_test_server_config_shadowsocks();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    println!("Shadowsocks YAML: {yaml_str}");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Shadowsocks { .. }
    ));
}

#[test]
fn test_server_config_vless() {
    let original = create_test_server_config_vless();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Vless { .. }
    ));
}

#[test]
fn test_server_config_trojan() {
    let original = create_test_server_config_trojan();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Trojan { .. }
    ));
}

#[test]
fn test_server_config_tls() {
    let original = create_test_server_config_tls();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Tls { .. }
    ));
}

#[test]
fn test_server_config_vmess() {
    let original = create_test_server_config_vmess();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Vmess { .. }
    ));
}

#[test]
fn test_server_config_websocket() {
    let original = create_test_server_config_websocket();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Websocket { .. }
    ));
}

#[test]
fn test_server_config_port_forward() {
    let original = create_test_server_config_port_forward();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::PortForward { .. }
    ));
}

#[test]
fn test_server_config_hysteria2() {
    let original = create_test_server_config_hysteria2();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::Hysteria2 { .. }
    ));
}

#[test]
fn test_server_config_tuic() {
    let original = create_test_server_config_tuic();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: ServerConfig =
        serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.protocol,
        ServerProxyConfig::TuicV5 { .. }
    ));
}

#[test]
fn test_rejects_invalid_upstream_field() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
upstream:
  address: "127.0.0.1:443"
  protocol:
    type: vless
    user_id: "test-uuid"
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "Should reject config with invalid 'upstream' field"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") && err.contains("upstream"),
        "Error should mention 'upstream' as unknown field, got: {err}"
    );
}

#[test]
fn test_rejects_typo_in_field_name() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocl:
  type: http
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err(), "Should reject config with typo 'protocl'");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") && err.contains("protocl"),
        "Error should mention 'protocl' as unknown field, got: {err}"
    );
}

#[test]
fn test_accepts_valid_server_config() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_ok(),
        "Should accept valid server config: {:?}",
        result.err()
    );
}

#[test]
fn test_scalar_bind_address_remains_scalar() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(matches!(
        &config.bind_location,
        BindLocation::Address(OneOrSome::One(_))
    ));

    let value = serde_yaml::to_value(&config).unwrap();
    let address = value
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::String("address".to_string()))
        .unwrap();
    assert_eq!(address.as_str(), Some("127.0.0.1:8080"));
}

#[test]
fn test_accepts_multiple_bind_addresses() {
    let yaml = r#"
address:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    let BindLocation::Address(addresses) = &config.bind_location else {
        panic!("expected address bind location");
    };
    let socket_addrs: Vec<String> = addresses
        .iter()
        .flat_map(|address| address.to_socket_addrs().unwrap())
        .map(|address| address.to_string())
        .collect();
    assert_eq!(
        socket_addrs,
        vec![
            "127.0.0.1:22223",
            "172.17.0.1:22223",
            "172.17.0.1:22224",
            "172.17.0.1:22225",
        ]
    );

    let serialized = serde_yaml::to_string(&config).unwrap();
    let round_tripped: ServerConfig = serde_yaml::from_str(&serialized).unwrap();
    assert_eq!(round_tripped.bind_location, config.bind_location);
}

#[test]
fn test_address_precedes_addresses_alias() {
    let yaml = r#"
address: "127.0.0.1:8080"
addresses:
  - "172.17.0.1:8080"
protocol:
  type: http
"#;

    let config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.bind_location.to_string(), "127.0.0.1:8080");
}

#[test]
fn test_rejects_empty_bind_address_list() {
    let yaml = r#"
address: []
protocol:
  type: http
"#;

    assert!(serde_yaml::from_str::<ServerConfig>(yaml).is_err());
}

#[test]
fn test_accepts_valid_server_config_with_all_fields() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
transport: tcp
tcp_settings:
  no_delay: true
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_ok(),
        "Should accept valid server config with all fields: {:?}",
        result.err()
    );
}

#[test]
fn test_rejects_unknown_field_in_vmess_server() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vmess
  cipher: aes-128-gcm
  user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
  typo_field: "should fail"
"#;
    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `typo_field`"),
        "Error should mention unknown field: {err}"
    );
}

// Note: This test was for reject unknown fields in Shadowsocks config.
// After adding udp_enabled with #[serde(flatten)] for ShadowsocksConfig,
// serde can no longer enforce deny_unknown_fields due to a serde limitation.
// See: https://github.com/serde-rs/serde/issues/1547
//
// The test is kept here but modified to verify that the known fields work correctly.
#[test]
fn test_shadowsocks_with_udp_enabled() {
    let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "secret"
  udp_enabled: false
"#;
    let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Valid Shadowsocks config should parse");
    let config = result.unwrap();
    if let ServerProxyConfig::Shadowsocks { udp_enabled, .. } = config.protocol {
        assert!(!udp_enabled, "udp_enabled should be false");
    } else {
        panic!("Expected Shadowsocks protocol");
    }
}

#[test]
fn test_shadowtls_handshake_serialization() {
    // Test local handshake with minimal fields
    let local = ShadowTlsLocalHandshake {
        cert: "server.crt".to_string(),
        key: "server.key".to_string(),
        alpn_protocols: NoneOrSome::Unspecified,
        client_ca_certs: NoneOrSome::Unspecified,
        client_fingerprints: NoneOrSome::Unspecified,
    };

    let yaml = serde_yaml::to_string(&local).unwrap();
    println!("Local handshake (minimal):\n{yaml}");

    // Should only contain cert and key
    assert!(yaml.contains("cert:"));
    assert!(yaml.contains("key:"));
    assert!(!yaml.contains("alpn_protocols:"));
    assert!(!yaml.contains("client_ca_certs:"));
    assert!(!yaml.contains("client_fingerprints:"));

    // Test remote handshake
    let remote = ShadowTlsRemoteHandshake {
        address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
        client_chain: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            super::super::client::ClientConfig::default(),
        ))),
    };

    let yaml = serde_yaml::to_string(&remote).unwrap();
    println!("Remote handshake (minimal):\n{yaml}");

    // Should contain address and client_chain
    assert!(yaml.contains("address:"));
    assert!(yaml.contains("client_chain:"));
}

#[test]
fn test_shadowtls_handshake_error_messages() {
    // Test invalid handshake config with cert but missing key
    let invalid_missing_key = r#"
cert: "server.crt"
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> =
        serde_yaml::from_str(invalid_missing_key);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    println!("Error for missing key: {error_msg}");
    assert!(error_msg.contains("Failed to parse local ShadowTLS handshake config"));
    assert!(error_msg.contains("missing field `key`"));
    assert!(error_msg.contains("Local handshake requires 'cert' and 'key' fields"));

    // Test invalid handshake config with mixed fields (cert + address)
    let invalid_mixed = r#"
cert: "server.crt"
address: "example.com:443"
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(invalid_mixed);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    println!("Error for mixed handshake fields: {error_msg}");
    // Since it has cert, it will try to parse as Local and reject the unknown 'address' field
    assert!(error_msg.contains("Failed to parse local ShadowTLS handshake config"));
    assert!(error_msg.contains("unknown field `address`"));

    // Test invalid handshake with unknown fields only
    let invalid_unknown = r#"
unknown_field: "value"
another_field: 123
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(invalid_unknown);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    println!("Error for unknown handshake fields: {error_msg}");
    assert!(error_msg.contains("Unable to determine ShadowTLS handshake type"));
    assert!(error_msg.contains("Found fields:"));
    assert!(error_msg.contains("unknown_field"));
    assert!(error_msg.contains("another_field"));

    // Test valid local handshake
    let valid_local = r#"
cert: "server.crt"
key: "server.key"
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(valid_local);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        ShadowTlsServerHandshakeConfig::Local(_)
    ));

    // Test valid remote handshake
    let valid_remote = r#"
address: "example.com:443"
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(valid_remote);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        ShadowTlsServerHandshakeConfig::Remote(_)
    ));

    // Test invalid remote with missing address value
    let invalid_remote_syntax = r#"
address:
"#;

    let result: Result<ShadowTlsServerHandshakeConfig, _> =
        serde_yaml::from_str(invalid_remote_syntax);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    println!("Error for invalid remote syntax: {error_msg}");
    // This will generate a parse error for NetLocation
    assert!(error_msg.contains("Failed to parse remote ShadowTLS handshake config"));
}

#[test]
fn test_rejects_unknown_field_in_shadowtls_local_handshake() {
    // Test ShadowTlsServerHandshakeConfig directly
    let yaml = r#"
cert: "server.crt"
key: "server.key"
bad_option: "value"
"#;
    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `bad_option`"),
        "Error should mention unknown field: {err}"
    );
}

#[test]
fn test_rejects_unknown_field_in_shadowtls_remote_handshake() {
    // Test ShadowTlsServerHandshakeConfig directly
    let yaml = r#"
address: "example.com:443"
misspelled: true
"#;
    let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `misspelled`"),
        "Error should mention unknown field: {err}"
    );
}

#[test]
fn test_shadowtls_remote_handshake_defaults_to_direct() {
    // When no client_chain or client_proxies is specified, should default to direct
    let yaml = r#"
address: "example.com:443"
"#;
    let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Should parse: {:?}", result.err());
    let handshake = result.unwrap();
    assert_eq!(handshake.client_chain.len(), 1);
    // Check it's a direct config
    if let super::super::rules::ClientChainHop::Single(
        super::super::selection::ConfigSelection::Config(config),
    ) = handshake.client_chain.iter().next().unwrap()
    {
        assert!(config.protocol.is_direct());
    } else {
        panic!("Expected Single hop with direct Config");
    }
}

#[test]
fn test_shadowtls_remote_handshake_with_client_chain() {
    let yaml = r#"
address: "example.com:443"
client_chain:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
    let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Should parse: {:?}", result.err());
    let handshake = result.unwrap();
    assert_eq!(handshake.client_chain.len(), 1);
}

#[test]
fn test_shadowtls_remote_handshake_with_deprecated_client_proxies() {
    // Should still work with deprecated client_proxies field
    let yaml = r#"
address: "example.com:443"
client_proxies:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
    let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Should parse: {:?}", result.err());
    let handshake = result.unwrap();
    assert_eq!(handshake.client_chain.len(), 1);
}

#[test]
fn test_shadowtls_remote_handshake_rejects_both_client_proxies_and_chain() {
    let yaml = r#"
address: "example.com:443"
client_proxies:
  - address: "proxy1.example.com:1080"
    protocol:
      type: socks
client_chain:
  - address: "proxy2.example.com:1080"
    protocol:
      type: socks
"#;
    let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("cannot specify both"),
        "Error should mention cannot specify both: {err}"
    );
}

#[test]
fn test_shadowtls_remote_handshake_serialization_roundtrip() {
    let yaml = r#"
address: "example.com:443"
client_chain:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
    let original: ShadowTlsRemoteHandshake = serde_yaml::from_str(yaml).unwrap();
    let serialized = serde_yaml::to_string(&original).unwrap();
    println!("Serialized:\n{serialized}");
    let deserialized: ShadowTlsRemoteHandshake = serde_yaml::from_str(&serialized).unwrap();
    assert_eq!(deserialized.client_chain.len(), original.client_chain.len());
}

#[test]
fn masque_config_deserialization_defaults_and_validation() {
    use crate::config::create_server_configs;
    use crate::config::resolved::ResolvedConfig;
    use crate::config::types::masque::{MasqueServerConfig, MasqueUserConfig};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let ca = rcgen::generate_simple_self_signed(vec!["client-ca".into()]).unwrap();
    let ca_pem = ca.cert.pem();

    // 1. Valid QUIC MASQUE with defaults + users (plaintext and $argon2id$)
    let quic_yaml = serde_json::json!([{
        "address": "0.0.0.0:443",
        "transport": "quic",
        "quic_settings": {
            "cert": cert_pem,
            "key": key_pem,
        },
        "protocol": {
            "type": "masque",
            "users": [
                {"username": "alice", "password": "secret-password"},
                {"username": "bob", "password": "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA"},
            ]
        }
    }]);
    let configs: Vec<crate::config::Config> =
        serde_yaml::from_str(&quic_yaml.to_string()).unwrap();
    let ServerConfig { protocol, .. } = match &configs[0] {
        crate::config::Config::Server(s) => s,
        _ => panic!("expected server"),
    };
    assert_eq!(protocol.to_string(), "MASQUE");
    let debug_str = format!("{protocol:?}");
    assert!(!debug_str.contains("secret-password"), "{debug_str}");
    assert!(!debug_str.contains("$argon2id$"), "{debug_str}");

    let validated = create_server_configs(configs).unwrap();
    let ResolvedConfig::Server(resolved_server) = &validated.configs[0] else {
        panic!("expected resolved server");
    };
    assert_eq!(resolved_server.protocol.to_string(), "MASQUE");
    let ResolvedServerProxyConfig::Masque(masque) = &resolved_server.protocol else {
        panic!("expected ResolvedServerProxyConfig::Masque");
    };
    assert!(masque.udp_enabled);
    assert_eq!(
        masque.udp_template,
        "/.well-known/masque/udp/{target_host}/{target_port}/"
    );
    assert!(!masque.ip_enabled);
    assert_eq!(
        masque.ip_template,
        "/.well-known/masque/ip/{target}/{ipproto}/"
    );
    assert!(masque.tunnel_addresses.is_empty());
    assert!(masque.advertise_routes.is_empty());
    assert_eq!(masque.mtu, 1280);
    assert!(masque.stealth_404);
    assert_eq!(masque.max_concurrent_requests, 1024);

    // 2. Valid QUIC MASQUE with explicit h3 ALPN, mTLS only (no users), and CONNECT-IP
    for quic_extra in [
        serde_json::json!({"alpn_protocols": ["h3"], "client_ca_certs": ca_pem}),
        serde_json::json!({"alpn_protocols": "h3", "client_fingerprints": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}),
    ] {
        let mut quic_settings = serde_json::json!({
            "cert": cert_pem,
            "key": key_pem,
        });
        for (k, v) in quic_extra.as_object().unwrap() {
            quic_settings[k] = v.clone();
        }
        let ip_yaml = serde_json::json!([{
            "address": "0.0.0.0:443",
            "transport": "quic",
            "quic_settings": quic_settings,
            "protocol": {
                "type": "masque",
                "ip_enabled": true,
                "tunnel_addresses": ["10.10.0.1/24", "fd00:10::1/64"],
                "mtu": 1400,
                "stealth_404": false,
                "max_concurrent_requests": 256,
            }
        }]);
        let configs: Vec<crate::config::Config> =
            serde_yaml::from_str(&ip_yaml.to_string()).unwrap();
        let validated = create_server_configs(configs).unwrap();
        let ResolvedConfig::Server(resolved_server) = &validated.configs[0] else {
            panic!("expected resolved server");
        };
        let ResolvedServerProxyConfig::Masque(masque) = &resolved_server.protocol else {
            panic!("expected MASQUE");
        };
        assert_eq!(
            masque.effective_advertise_routes(),
            vec![
                "0.0.0.0/0".parse::<ipnetwork::IpNetwork>().unwrap(),
                "::/0".parse::<ipnetwork::IpNetwork>().unwrap(),
            ]
        );
    }

    // 3. Valid TCP + TLS + MASQUE (HTTP/2 fallback) in both tls_targets and default_target
    for alpn in [
        None,
        Some(serde_json::json!(["h2"])),
        Some(serde_json::json!(["h2", "http/1.1"])),
    ] {
        let mut target = serde_json::json!({
            "cert": cert_pem,
            "key": key_pem,
            "protocol": {
                "type": "masque",
                "user": {"username": "alice", "password": "secret"}
            }
        });
        if let Some(alpn) = alpn {
            target["alpn_protocols"] = alpn;
        }
        let tls_yaml = serde_json::json!([{
            "address": "0.0.0.0:443",
            "protocol": {
                "type": "tls",
                "tls_targets": {
                    "masque.example": target
                },
                "default_target": {
                    "cert": cert_pem,
                    "key": key_pem,
                    "client_ca_certs": ca_pem,
                    "protocol": {"type": "masque"}
                }
            }
        }]);
        let configs: Vec<crate::config::Config> =
            serde_yaml::from_str(&tls_yaml.to_string()).unwrap();
        create_server_configs(configs).unwrap();
    }

    // 4. Reject unknown fields on MasqueServerConfig / MasqueUserConfig
    assert!(
        serde_yaml::from_str::<MasqueServerConfig>("unknown_field: true").is_err(),
        "unknown field on MasqueServerConfig must fail"
    );
    assert!(
        serde_yaml::from_str::<MasqueUserConfig>(
            "username: a\npassword: b\nextra: true"
        )
        .is_err(),
        "unknown field on MasqueUserConfig must fail"
    );

    // 5. Reject ip_enabled: true without tunnel_addresses or invalid tunnel_addresses
    for bad_ip_cfg in [
        serde_json::json!({"type": "masque", "ip_enabled": true, "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["10.0.0.1/24", "10.1.0.1/24"], "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["fd00::1/64", "fd01::1/64"], "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["10.0.0.1/32"], "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["10.0.0.0/31"], "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["fd00::1/128"], "users": [{"username": "u", "password": "p"}]}),
        serde_json::json!({"type": "masque", "ip_enabled": true, "tunnel_addresses": ["fd00::/127"], "users": [{"username": "u", "password": "p"}]}),
    ] {
        let cfg: ServerProxyConfig = serde_json::from_value(bad_ip_cfg.clone()).unwrap();
        let ServerProxyConfig::Masque(m) = cfg else {
            panic!();
        };
        assert!(m.validate().is_err(), "should reject {bad_ip_cfg}");
    }

    // 6. Reject mtu outside 1280..=1452, max_concurrent_requests == 0, invalid templates, bad users
    for bad_cfg in [
        serde_json::json!({"type": "masque", "mtu": 1279}),
        serde_json::json!({"type": "masque", "mtu": 0}),
        serde_json::json!({"type": "masque", "mtu": 1453}),
        serde_json::json!({"type": "masque", "max_concurrent_requests": 0}),
        serde_json::json!({"type": "masque", "udp_template": "relative/no-leading-slash/{target_host}/{target_port}"}),
        serde_json::json!({"type": "masque", "udp_template": "/udp/{target_host}/missing-port"}),
        serde_json::json!({"type": "masque", "udp_template": "/udp/{unknown_var}/{target_port}"}),
        serde_json::json!({"type": "masque", "ip_template": "/ip/{unknown}"}),
        serde_json::json!({"type": "masque", "ip_template": "no-slash"}),
        serde_json::json!({"type": "masque", "users": [{"username": "", "password": "p"}]}),
        serde_json::json!({"type": "masque", "users": [{"username": "u", "password": ""}]}),
        serde_json::json!({"type": "masque", "users": [{"username": "u", "password": "p1"}, {"username": "u", "password": "p2"}]}),
    ] {
        let cfg: ServerProxyConfig = serde_json::from_value(bad_cfg.clone()).unwrap();
        let ServerProxyConfig::Masque(m) = cfg else {
            panic!();
        };
        assert!(m.validate().is_err(), "should reject {bad_cfg}");
    }

    // 7. Reject masque with neither users nor client-cert auth (QUIC & TLS)
    let quic_no_auth = serde_json::json!([{
        "address": "0.0.0.0:443",
        "transport": "quic",
        "quic_settings": {"cert": cert_pem, "key": key_pem},
        "protocol": {"type": "masque"}
    }]);
    let configs: Vec<crate::config::Config> =
        serde_yaml::from_str(&quic_no_auth.to_string()).unwrap();
    assert!(
        create_server_configs(configs).is_err(),
        "QUIC masque without users or mTLS must fail"
    );

    let tls_no_auth = serde_json::json!([{
        "address": "0.0.0.0:443",
        "protocol": {
            "type": "tls",
            "default_target": {
                "cert": cert_pem,
                "key": key_pem,
                "protocol": {"type": "masque"}
            }
        }
    }]);
    let configs: Vec<crate::config::Config> =
        serde_yaml::from_str(&tls_no_auth.to_string()).unwrap();
    assert!(
        create_server_configs(configs).is_err(),
        "TLS masque without users or mTLS must fail"
    );

    // 8. Reject bare TCP without TLS, websocket/httpupgrade/grpc/shadowtls/sudoku_mask/reality
    let masque_with_user = serde_json::json!({
        "type": "masque",
        "users": [{"username": "alice", "password": "secret"}]
    });
    for invalid_server in [
        serde_json::json!({
            "address": "0.0.0.0:8080",
            "protocol": masque_with_user
        }),
        serde_json::json!({
            "address": "0.0.0.0:8080",
            "protocol": {"type": "websocket", "targets": [{"protocol": masque_with_user}]}
        }),
        serde_json::json!({
            "address": "0.0.0.0:8080",
            "protocol": {"type": "httpupgrade", "targets": [{"protocol": masque_with_user}]}
        }),
        serde_json::json!({
            "address": "0.0.0.0:8080",
            "protocol": {"type": "grpc", "targets": [{"protocol": masque_with_user}]}
        }),
        serde_json::json!({
            "address": "0.0.0.0:8080",
            "protocol": {"type": "sudoku_mask", "protocol": masque_with_user}
        }),
        serde_json::json!({
            "address": "0.0.0.0:443",
            "protocol": {
                "type": "tls",
                "shadowtls_targets": {
                    "cover.example": {
                        "password": "secret",
                        "handshake": {"cert": cert_pem, "key": key_pem},
                        "protocol": masque_with_user
                    }
                }
            }
        }),
        serde_json::json!({
            "address": "0.0.0.0:443",
            "protocol": {
                "type": "tls",
                "reality_targets": {
                    "cover.example": {
                        "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "dest": "example.com:443",
                        "protocol": masque_with_user
                    }
                }
            }
        }),
        // QUIC with non-h3 ALPN
        serde_json::json!({
            "address": "0.0.0.0:443",
            "transport": "quic",
            "quic_settings": {"cert": cert_pem, "key": key_pem, "alpn_protocols": ["h2"]},
            "protocol": masque_with_user
        }),
        // QUIC with explicit empty ALPN
        serde_json::json!({
            "address": "0.0.0.0:443",
            "transport": "quic",
            "quic_settings": {"cert": cert_pem, "key": key_pem, "alpn_protocols": []},
            "protocol": masque_with_user
        }),
        // TLS with ALPN missing h2
        serde_json::json!({
            "address": "0.0.0.0:443",
            "protocol": {
                "type": "tls",
                "default_target": {
                    "cert": cert_pem,
                    "key": key_pem,
                    "alpn_protocols": ["http/1.1"],
                    "protocol": masque_with_user
                }
            }
        }),
        // TLS with explicit empty ALPN
        serde_json::json!({
            "address": "0.0.0.0:443",
            "protocol": {
                "type": "tls",
                "default_target": {
                    "cert": cert_pem,
                    "key": key_pem,
                    "alpn_protocols": [],
                    "protocol": masque_with_user
                }
            }
        }),
    ] {
        let configs: Vec<crate::config::Config> =
            serde_yaml::from_str(&serde_json::json!([invalid_server]).to_string()).unwrap();
        assert!(
            create_server_configs(configs).is_err(),
            "should reject invalid placement/ALPN: {invalid_server}"
        );
    }
}
