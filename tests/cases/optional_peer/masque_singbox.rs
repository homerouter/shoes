//! Live MASQUE interoperability tests against sing-box >= 1.15 (`http` outbound v2/v3 and
//! `masque-client` endpoint v2/v3).
//!
//! Discovers `sing-box` from `SING_BOX_BIN`, `SHOES_TEST_SING_BOX_BIN`, or `PATH` (`sing-box`),
//! and cleanly skips if no `sing-box >= 1.15.0` binary is available.

use std::error::Error;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use shoes_test_support::{
    process::ProcessGuard,
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server},
};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout};

use crate::http_proxy_support as support;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn parse_singbox_version(output: &str) -> Option<(u32, u32)> {
    let first_line = output.lines().find(|line| line.contains("sing-box version"))?;
    let ver_str = first_line.split_whitespace().last()?;
    let core = ver_str.split('-').next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

fn find_masque_singbox_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for env_var in ["SING_BOX_BIN", "SHOES_TEST_SING_BOX_BIN"] {
        if let Some(val) = std::env::var_os(env_var) {
            candidates.push(PathBuf::from(val));
        }
    }
    candidates.push(PathBuf::from("sing-box"));

    for candidate in candidates {
        let Ok(output) = Command::new(&candidate)
            .arg("version")
            .stdin(Stdio::null())
            .output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some((major, minor)) = parse_singbox_version(&combined)
            && (major > 1 || (major == 1 && minor >= 15))
        {
            eprintln!(
                "[MASQUE-SINGBOX] Using {} ({})",
                candidate.display(),
                combined.lines().next().unwrap_or("unknown")
            );
            return Some(candidate);
        }
    }
    None
}

fn is_windows_exe(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
}

struct TempConfigGuard {
    linux_path: PathBuf,
    cli_arg: String,
    _tempfile: Option<tempfile::NamedTempFile>,
}

impl Drop for TempConfigGuard {
    fn drop(&mut self) {
        if self._tempfile.is_none() {
            let _ = std::fs::remove_file(&self.linux_path);
        }
    }
}

fn write_singbox_config(bin: &Path, config: &str) -> io::Result<TempConfigGuard> {
    if !is_windows_exe(bin) {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(config.as_bytes())?;
        file.flush()?;
        let linux_path = file.path().to_path_buf();
        let cli_arg = linux_path.to_string_lossy().into_owned();
        return Ok(TempConfigGuard {
            linux_path,
            cli_arg,
            _tempfile: Some(file),
        });
    }

    let out = Command::new("/mnt/c/Windows/System32/cmd.exe")
        .args(["/c", "echo %TEMP%"])
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other("failed to query Windows %TEMP%"));
    }
    let win_temp = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let unix_temp_out = Command::new("wslpath")
        .args(["-u", &win_temp])
        .stdin(Stdio::null())
        .output()?;
    if !unix_temp_out.status.success() {
        return Err(io::Error::other("wslpath -u failed for %TEMP%"));
    }
    let unix_temp = PathBuf::from(String::from_utf8_lossy(&unix_temp_out.stdout).trim());
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let linux_path = unix_temp.join(format!("shoes-masque-sb-{}-{seq}.json", std::process::id()));
    std::fs::write(&linux_path, config)?;
    let win_cfg_out = Command::new("wslpath")
        .arg("-w")
        .arg(&linux_path)
        .stdin(Stdio::null())
        .output()?;
    if !win_cfg_out.status.success() {
        let _ = std::fs::remove_file(&linux_path);
        return Err(io::Error::other("wslpath -w failed for temp sing-box config"));
    }
    let cli_arg = String::from_utf8_lossy(&win_cfg_out.stdout)
        .trim()
        .to_string();
    Ok(TempConfigGuard {
        linux_path,
        cli_arg,
        _tempfile: None,
    })
}

fn wsl_eth0_ip() -> io::Result<IpAddr> {
    let out = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "eth0"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for token in text.split_whitespace() {
        if let Some((ip, _prefix)) = token.split_once('/')
            && let Ok(addr) = ip.parse::<IpAddr>()
        {
            return Ok(addr);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not determine WSL2 eth0 IPv4 address",
    ))
}

fn wsl_gateway_ip() -> io::Result<IpAddr> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "via"
            && let Some(gw) = parts.next()
            && let Ok(addr) = gw.parse::<IpAddr>()
        {
            return Ok(addr);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not determine WSL2 default gateway IP",
    ))
}

fn free_tcp_port() -> io::Result<u16> {
    Ok(TcpListener::bind("0.0.0.0:0")?.local_addr()?.port())
}

fn free_udp_port() -> io::Result<u16> {
    Ok(UdpSocket::bind("0.0.0.0:0")?.local_addr()?.port())
}

async fn wait_tcp_ready(addr: SocketAddr, wait: Duration) -> io::Result<()> {
    let deadline = Instant::now() + wait;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("address {addr} did not become ready"),
            ));
        }
        if timeout(Duration::from_millis(250), TcpStream::connect(addr))
            .await
            .is_ok_and(|res| res.is_ok())
        {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn socks5_tcp_connect(
    proxy_ip: &str,
    proxy_port: u16,
    target: &str,
) -> io::Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target_addr: SocketAddr = target
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stream = TcpStream::connect((proxy_ip, proxy_port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::other("SOCKS5 greeting rejected"));
    }

    let mut req = vec![5, 1, 0];
    match target_addr {
        SocketAddr::V4(v4) => {
            req.push(1);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(4);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT failed: code 0x{:02x}",
            hdr[1]
        )));
    }
    match hdr[3] {
        1 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        4 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut rest = vec![0u8; len + 2];
            stream.read_exact(&mut rest).await?;
        }
        atyp => {
            return Err(io::Error::other(format!("unexpected SOCKS5 atyp {atyp}")));
        }
    }
    Ok(stream)
}

async fn wait_and_exchange_tcp(
    proxy_ip: &str,
    proxy_port: u16,
    target: &str,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        match socks5_tcp_connect(proxy_ip, proxy_port, target).await {
            Ok(stream) => {
                if support::exchange(stream).await.is_ok() {
                    return Ok(());
                }
            }
            Err(_) if Instant::now() < deadline => {}
            Err(err) => return Err(err.into()),
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for sing-box MASQUE TCP tunnel".into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn verify_udp(
    proxy_ip: &str,
    proxy_port: u16,
    udp_target: SocketAddr,
    sizes: &[usize],
) -> TestResult {
    let association = Socks5UdpAssociation::connect(proxy_ip, proxy_port).await?;
    for &size in sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let expected = [payload.as_slice(), b" [ECHO]"].concat();
        assert_eq!(association.send_to(udp_target, &payload).await?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn singbox_1_15_http_and_masque_client_interop() -> TestResult {
    let Some(singbox_bin) = find_masque_singbox_binary() else {
        eprintln!("[SKIP] sing-box >= 1.15.0 not found in SING_BOX_BIN, SHOES_TEST_SING_BOX_BIN, or PATH");
        return Ok(());
    };

    timeout(Duration::from_secs(45), async {
        let win_exe = is_windows_exe(&singbox_bin);
        let (shoes_bind_ip, sb_listen_ip, sb_server_ip, client_ip) = if win_exe {
            (
                "0.0.0.0".to_string(),
                "0.0.0.0".to_string(),
                wsl_eth0_ip()?.to_string(),
                wsl_gateway_ip()?.to_string(),
            )
        } else {
            (
                "127.0.0.1".to_string(),
                "127.0.0.1".to_string(),
                "127.0.0.1".to_string(),
                "127.0.0.1".to_string(),
            )
        };

        let tcp_echo = start_tcp_stream_echo_server(&shoes_bind_ip, 0).await?;
        let udp_echo = start_udp_echo_server(&shoes_bind_ip, 0).await?;
        let tcp_target = format!("{sb_server_ip}:{}", tcp_echo.local_addr().port());
        let udp_target: SocketAddr = format!("{sb_server_ip}:{}", udp_echo.local_addr().port()).parse()?;

        let mut cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
        if let Ok(ip) = sb_server_ip.parse::<IpAddr>() {
            cert_params
                .subject_alt_names
                .push(rcgen::SanType::IpAddress(ip));
        }
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = cert_params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let h3_port = free_udp_port()?;
        let h2_port = free_tcp_port()?;

        let shoes_cfg = json!([
            {
                "address": format!("{shoes_bind_ip}:{h3_port}"),
                "transport": "quic",
                "quic_settings": {"cert": cert_pem, "key": key_pem},
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
                "address": format!("{shoes_bind_ip}:{h2_port}"),
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
        wait_tcp_ready(SocketAddr::from(([127, 0, 0, 1], h2_port)), Duration::from_secs(10)).await?;

        let p_http3 = free_tcp_port()?;
        let p_http2 = free_tcp_port()?;
        let p_masq3 = free_tcp_port()?;
        let p_masq2 = free_tcp_port()?;

        let tls_client = json!({
            "enabled": true,
            "server_name": "localhost",
            "certificate": cert_pem,
        });

        let sb_cfg = json!({
            "log": {"level": "warn"},
            "inbounds": [
                {"type": "socks", "tag": "in-http3", "listen": sb_listen_ip, "listen_port": p_http3},
                {"type": "socks", "tag": "in-http2", "listen": sb_listen_ip, "listen_port": p_http2},
                {"type": "socks", "tag": "in-masq3", "listen": sb_listen_ip, "listen_port": p_masq3},
                {"type": "socks", "tag": "in-masq2", "listen": sb_listen_ip, "listen_port": p_masq2},
            ],
            "outbounds": [
                {
                    "type": "http", "tag": "out-http3",
                    "server": sb_server_ip, "server_port": h3_port,
                    "username": "alice", "password": "secret",
                    "version": 3, "disable_version_fallback": true,
                    "tls": tls_client,
                },
                {
                    "type": "http", "tag": "out-http2",
                    "server": sb_server_ip, "server_port": h2_port,
                    "username": "alice", "password": "secret",
                    "version": 2, "disable_version_fallback": true,
                    "tls": tls_client,
                },
            ],
            "endpoints": [
                {
                    "type": "masque-client", "tag": "ep-masq3",
                    "server": sb_server_ip, "server_port": h3_port,
                    "username": "alice", "password": "secret",
                    "version": 3, "disable_version_fallback": true,
                    "system": false,
                    "tls": tls_client,
                },
                {
                    "type": "masque-client", "tag": "ep-masq2",
                    "server": sb_server_ip, "server_port": h2_port,
                    "username": "alice", "password": "secret",
                    "version": 2, "disable_version_fallback": true,
                    "system": false,
                    "tls": tls_client,
                },
            ],
            "route": {
                "rules": [
                    {"inbound": ["in-http3"], "action": "route", "outbound": "out-http3"},
                    {"inbound": ["in-http2"], "action": "route", "outbound": "out-http2"},
                    {"inbound": ["in-masq3"], "action": "route", "outbound": "ep-masq3"},
                    {"inbound": ["in-masq2"], "action": "route", "outbound": "ep-masq2"},
                ]
            }
        });

        let sb_cfg_guard = write_singbox_config(&singbox_bin, &sb_cfg.to_string())?;
        let child = Command::new(&singbox_bin)
            .args(["run", "-c", &sb_cfg_guard.cli_arg])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        let _sb_guard = ProcessGuard::new(child, "sing-box");

        let client_addr: IpAddr = client_ip.parse()?;
        for port in [p_http3, p_http2, p_masq3, p_masq2] {
            wait_tcp_ready(SocketAddr::new(client_addr, port), Duration::from_secs(10)).await?;
        }

        // Verify TCP + UDP across all 4 modes.
        let cases: &[(&str, u16, &[usize])] = &[
            ("http v3", p_http3, &[1, 1100]),
            ("http v2", p_http2, &[1, 1100, 4096]),
            ("masque-client v3", p_masq3, &[1, 1100]),
            ("masque-client v2", p_masq2, &[1, 1100]),
        ];
        for &(label, port, udp_sizes) in cases {
            wait_and_exchange_tcp(&client_ip, port, &tcp_target)
                .await
                .map_err(|e| format!("{label} TCP failed: {e}"))?;
            verify_udp(&client_ip, port, udp_target, udp_sizes)
                .await
                .map_err(|e| format!("{label} UDP failed: {e}"))?;
        }

        Ok(())
    })
    .await?
}
