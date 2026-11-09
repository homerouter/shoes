use serde_json::json;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::Socks5UdpAssociation;
use shoes_test_support::test_fixture::{
    SingBoxCapability, start_shoes_server, start_singbox_server_with,
};
use shoes_test_support::test_servers::{start_tcp_stream_echo_server, start_udp_echo_server};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";

async fn echo_round_trip(stream: &mut TcpStream, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(payload).await?;
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await?;
    assert_eq!(received, payload);
    Ok(())
}

#[tokio::test]
async fn singbox_client_with_shoes_grpc_server() -> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, shoes_port) = ports.get_localhost_listener_port();
        let (_, socks_port) = ports.get_localhost_listener_port();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let udp_echo = start_udp_echo_server("0.0.0.0", 0).await?;

        // Shoes server: gRPC transport wrapping VLESS
        let shoes_config = json!([{
            "address": format!("127.0.0.1:{shoes_port}"),
            "protocol": {
                "type": "grpc",
                "targets": [{
                    "service_name": "TunService",
                    "protocol": {
                        "type": "vless",
                        "user_id": TEST_UUID
                    }
                }]
            }
        }]);
        let (_shoes, _shoes_config) = start_shoes_server(&shoes_config.to_string())?;

        // sing-box client: socks inbound -> VLESS outbound with gRPC transport
        let singbox_config = json!({
            "log": {"level": "warn"},
            "inbounds": [{
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": socks_port
            }],
            "outbounds": [{
                "type": "vless",
                "server": "127.0.0.1",
                "server_port": shoes_port,
                "uuid": TEST_UUID,
                "packet_encoding": "xudp",
                "transport": {
                    "type": "grpc",
                    "service_name": "TunService"
                }
            }]
        });
        let (_singbox, _singbox_config) = start_singbox_server_with(
            &singbox_config.to_string(),
            SingBoxCapability::Standard,
            &[],
        )?;
        ports.wait_for_all_ports().await?;

        // TCP echo test
        let mut stream = super::h2mux::connect_tcp_via_socks5(
            "127.0.0.1",
            socks_port,
            "127.0.0.1",
            echo.local_addr().port(),
        )
        .await?;

        echo_round_trip(&mut stream, b"hello from singbox grpc client").await?;
        echo_round_trip(&mut stream, b"second round trip packet").await?;

        // UDP echo test via socks5
        let association = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
        let udp_target = (Ipv4Addr::LOCALHOST, udp_echo.local_addr().port()).into();
        let reply = association.send_to(udp_target, b"udp ping").await?;
        assert_eq!(reply, b"udp ping [ECHO]");

        Ok(())
    })
    .await?
}

#[tokio::test]
async fn shoes_client_with_singbox_grpc_server() -> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, singbox_port) = ports.get_localhost_listener_port();
        let (_, shoes_socks_port) = ports.get_localhost_listener_port();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let udp_echo = start_udp_echo_server("0.0.0.0", 0).await?;

        // sing-box server: VLESS inbound with gRPC transport -> direct outbound
        let singbox_config = json!({
            "log": {"level": "warn"},
            "inbounds": [{
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": singbox_port,
                "users": [{
                    "uuid": TEST_UUID
                }],
                "transport": {
                    "type": "grpc",
                    "service_name": "TunService"
                }
            }],
            "outbounds": [{
                "type": "direct"
            }]
        });
        let (_singbox, _singbox_config) = start_singbox_server_with(
            &singbox_config.to_string(),
            SingBoxCapability::Standard,
            &[],
        )?;

        // Shoes client: Socks5 listener routing through gRPC + VLESS outbound to sing-box
        let shoes_config = json!([{
            "address": format!("127.0.0.1:{shoes_socks_port}"),
            "protocol": {
                "type": "socks"
            },
            "rules": [{
                "mask": "0.0.0.0/0",
                "action": "allow",
                "client_chain": [{
                    "address": format!("127.0.0.1:{singbox_port}"),
                    "protocol": {
                        "type": "grpc",
                        "service_name": "TunService",
                        "protocol": {
                            "type": "vless",
                            "user_id": TEST_UUID
                        }
                    }
                }]
            }]
        }]);
        let (_shoes, _shoes_config) = start_shoes_server(&shoes_config.to_string())?;
        ports.wait_for_all_ports().await?;

        // TCP echo test
        let mut stream = super::h2mux::connect_tcp_via_socks5(
            "127.0.0.1",
            shoes_socks_port,
            "127.0.0.1",
            echo.local_addr().port(),
        )
        .await?;

        echo_round_trip(&mut stream, b"hello from shoes grpc client").await?;
        echo_round_trip(&mut stream, b"second packet from shoes client").await?;

        // UDP echo test via socks5
        let association = Socks5UdpAssociation::connect("127.0.0.1", shoes_socks_port).await?;
        let udp_target = (Ipv4Addr::LOCALHOST, udp_echo.local_addr().port()).into();
        let reply = association.send_to(udp_target, b"shoes udp ping").await?;
        assert_eq!(reply, b"shoes udp ping [ECHO]");

        Ok(())
    })
    .await?
}
