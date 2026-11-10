//! Snell interop with sing-snell, the reF1nd sing-box fork pinned in CI.
//! Ignored by default: set SHOES_TEST_SING_BOX_SNELL_BIN and pass `--ignored`.

use std::time::Duration;

use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper,
    process::{SingBoxCapability, start_singbox_server_with},
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server},
};
use tokio::time::timeout;

use crate::http_proxy_support as support;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PSK: &str = "snell-singbox-test";

/// sing-box `mixed` inbound on `entry` with a Snell outbound to a shoes server.
async fn singbox_client_to_shoes(
    outbound: Value,
    shoes_fields: Value,
    sessions: usize,
    udp: bool,
) -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let mut protocol = json!({"type": "snell", "cipher": "aes-128-gcm", "password": PSK});
        for (key, value) in shoes_fields.as_object().unwrap() {
            if value.is_null() {
                protocol.as_object_mut().unwrap().remove(key);
            } else {
                protocol[key] = value.clone();
            }
        }
        let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([
            {"address": format!("127.0.0.1:{server}"), "protocol": protocol}
        ]))?)?;
        let mut outbound = outbound;
        outbound["type"] = "snell".into();
        outbound["tag"] = "snell".into();
        outbound["server"] = "127.0.0.1".into();
        outbound["server_port"] = server.into();
        if outbound.get("psk").is_none() {
            outbound["psk"] = PSK.into();
        }
        let _peer = start_singbox_server_with(
            &json!({
                "log": {"level": "warn"},
                "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": entry}],
                "outbounds": [outbound]
            })
            .to_string(),
            SingBoxCapability::Snell,
            &[] as &[(&str, &str)],
        )?;
        ports.wait_for_all_ports().await?;

        let echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
        let target = format!("127.0.0.1:{}", echo.local_addr().port());
        // With `reuse`, later sessions ride a pooled connection.
        for _ in 0..sessions {
            let stream = support::connect(entry, &target).await?;
            // exchange() asserts; run it in a task so a refused session is an Err.
            tokio::spawn(support::exchange(stream)).await.map_err(|_| {
                std::io::Error::other("echo mismatch: the session was refused")
            })??;
        }
        if udp {
            let echo = start_udp_echo_server("127.0.0.1", 0).await?;
            let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
            for size in [1, 1200, 8192] {
                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                assert_eq!(
                    association.send_to(echo.local_addr(), &payload).await?,
                    [payload.as_slice(), b" [ECHO]"].concat()
                );
            }
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_v4_client() -> TestResult {
    for reuse in [false, true] {
        singbox_client_to_shoes(json!({"version": 4, "reuse": reuse}), json!({}), 3, false).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_v5_client() -> TestResult {
    singbox_client_to_shoes(json!({"version": 5}), json!({}), 3, true).await?;
    singbox_client_to_shoes(json!({"version": 5, "reuse": true}), json!({}), 3, false).await
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_v6_client_each_mode() -> TestResult {
    for mode in ["default", "unshaped", "unsafe-raw"] {
        singbox_client_to_shoes(
            json!({"version": 6, "mode": mode, "reuse": true}),
            json!({"version": "v6", "mode": mode}),
            3,
            mode == "default",
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn shoes_client_to_singbox_v5_server() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let _peer = start_singbox_server_with(
            &json!({
                "log": {"level": "warn"},
                "inbounds": [{"type": "snell", "version": 5, "listen": "127.0.0.1",
                    "listen_port": server, "psk": PSK}],
                "outbounds": [{"type": "direct"}]
            })
            .to_string(),
            SingBoxCapability::Snell,
            &[] as &[(&str, &str)],
        )?;
        let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([support::relay_config(
            entry,
            server,
            json!({"type": "snell", "cipher": "aes-128-gcm", "password": PSK}),
        )]))?)?;
        ports.wait_for_all_ports().await?;

        let echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
        let target = format!("127.0.0.1:{}", echo.local_addr().port());
        for _ in 0..2 {
            support::exchange(support::connect(entry, &target).await?).await?;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_userkey_client() -> TestResult {
    for (version, shoes_version) in [(5, "v5"), (6, "v6")] {
        singbox_client_to_shoes(
            json!({"version": version, "userkey": "alice-key", "reuse": true}),
            json!({
                "version": shoes_version,
                "multi_user_authentication": "userkey",
                "users": [{"name": "alice", "userkey": "alice-key"}],
            }),
            3,
            false,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_psk_users_client() -> TestResult {
    let users = json!([
        {"name": "alice", "password": "alice-psk-0001"},
        {"name": "bob", "password": "bob-psk-000002"},
    ]);
    for (outbound, shoes) in [
        (json!({"version": 5}), json!({"version": "v5"})),
        (json!({"version": 6, "mode": "default"}), json!({"version": "v6", "mode": "default"})),
        (json!({"version": 6, "mode": "unshaped"}), json!({"version": "v6", "mode": "unshaped"})),
    ] {
        let mut outbound = outbound;
        outbound["psk"] = "bob-psk-000002".into();
        outbound["reuse"] = true.into();
        let mut shoes = shoes;
        shoes["password"] = Value::Null;
        shoes["multi_user_authentication"] = "psk".into();
        shoes["users"] = users.clone();
        singbox_client_to_shoes(outbound, shoes, 2, false).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_wrong_userkey_is_refused() -> TestResult {
    let result = singbox_client_to_shoes(
        json!({"version": 5, "userkey": "mallory"}),
        json!({
            "version": "v5",
            "users": [{"name": "alice", "userkey": "alice-key"}],
        }),
        1,
        false,
    )
    .await;
    assert!(result.is_err(), "a wrong userkey must not reach the echo server");
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn shoes_client_to_singbox_v6_server_reuse() -> TestResult {
    for mode in ["default", "unshaped", "unsafe-raw"] {
        timeout(Duration::from_secs(30), async {
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let _peer = start_singbox_server_with(
                &json!({
                    "log": {"level": "warn"},
                    "inbounds": [{
                        "type": "snell",
                        "version": 6,
                        "mode": mode,
                        "listen": "127.0.0.1",
                        "listen_port": server,
                        "psk": PSK,
                    }],
                    "outbounds": [{"type": "direct"}],
                })
                .to_string(),
                SingBoxCapability::Snell,
                &[] as &[(&str, &str)],
            )?;
            let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([
                support::relay_config(
                    entry,
                    server,
                    json!({
                        "type": "snell",
                        "version": "v6",
                        "mode": mode,
                        "cipher": "aes-128-gcm",
                        "password": PSK,
                        "reuse": true,
                    }),
                )
            ]))?)?;
            ports.wait_for_all_ports().await?;

            let echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
            let target = format!("127.0.0.1:{}", echo.local_addr().port());
            for _ in 0..3 {
                support::exchange(support::connect(entry, &target).await?).await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn shoes_client_userkey_to_singbox_server() -> TestResult {
    for (version, shoes_version) in [(5, "v5"), (6, "v6")] {
        timeout(Duration::from_secs(30), async {
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let mut inbound = json!({
                "type": "snell",
                "version": version,
                "listen": "127.0.0.1",
                "listen_port": server,
                "psk": PSK,
                "users": [{"name": "alice", "userkey": "alice-key"}],
            });
            if version == 6 {
                inbound["mode"] = "default".into();
            }
            let _peer = start_singbox_server_with(
                &json!({
                    "log": {"level": "warn"},
                    "inbounds": [inbound],
                    "outbounds": [{"type": "direct"}],
                })
                .to_string(),
                SingBoxCapability::Snell,
                &[] as &[(&str, &str)],
            )?;
            let mut shoes_proto = json!({
                "type": "snell",
                "version": shoes_version,
                "cipher": "aes-128-gcm",
                "password": PSK,
                "userkey": "alice-key",
                "reuse": true,
            });
            if shoes_version == "v6" {
                shoes_proto["mode"] = "default".into();
            }
            let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([
                support::relay_config(entry, server, shoes_proto)
            ]))?)?;
            ports.wait_for_all_ports().await?;

            let echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
            let target = format!("127.0.0.1:{}", echo.local_addr().port());
            for _ in 0..2 {
                support::exchange(support::connect(entry, &target).await?).await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn singbox_client_to_shoes_v5_http_obfs() -> TestResult {
    singbox_client_to_shoes(
        json!({"version": 5, "obfs_mode": "http", "reuse": true}),
        json!({"version": "v5", "obfs_mode": "http"}),
        3,
        false,
    )
    .await
}

#[tokio::test]
#[ignore = "needs SHOES_TEST_SING_BOX_SNELL_BIN"]
async fn shoes_client_to_singbox_v5_http_obfs() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let _peer = start_singbox_server_with(
            &json!({
                "log": {"level": "warn"},
                "inbounds": [{
                    "type": "snell",
                    "version": 5,
                    "listen": "127.0.0.1",
                    "listen_port": server,
                    "psk": PSK,
                    "obfs_mode": "http",
                }],
                "outbounds": [{"type": "direct"}],
            })
            .to_string(),
            SingBoxCapability::Snell,
            &[] as &[(&str, &str)],
        )?;
        let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([support::relay_config(
            entry,
            server,
            json!({
                "type": "snell",
                "version": "v5",
                "cipher": "aes-128-gcm",
                "password": PSK,
                "obfs_mode": "http",
                "obfs_host": "bing.com",
            }),
        )]))?)?;
        ports.wait_for_all_ports().await?;

        let echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
        let target = format!("127.0.0.1:{}", echo.local_addr().port());
        for _ in 0..2 {
            support::exchange(support::connect(entry, &target).await?).await?;
        }
        Ok(())
    })
    .await?
}
