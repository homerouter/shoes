use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, Bytes};
use h3::ConnectionState;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::config::{MasqueServerConfig, MasqueUserConfig, ResolvedRuleConfig};
use crate::option_util::NoneOrSome;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::create_test_selector;

use super::MasqueServer;
use super::auth::MasqueAuth;

fn basic_header(user: &str, pass: &str) -> HeaderValue {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    HeaderValue::from_str(&format!("Basic {encoded}")).unwrap()
}

fn direct_selector(resolver: &Arc<dyn Resolver>) -> Arc<crate::client_proxy_selector::ClientProxySelector> {
    Arc::new(create_test_selector(vec![ResolvedRuleConfig::default()], resolver.clone()).unwrap())
}

async fn spawn_tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    (addr, handle)
}

#[test]
fn auth_plaintext_proxy_authorization_and_non_connect_ip_rules() {
    let users = vec![MasqueUserConfig {
        username: "alice".into(),
        password: "secret:password".into(),
    }];
    let auth = MasqueAuth::from_users(&users, false).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::PROXY_AUTHORIZATION, basic_header("alice", "secret:password"));
    assert_eq!(
        auth.verify_headers(&headers, false, false),
        Ok(Some("alice".to_string()))
    );

    // Authorization header alone is rejected when allow_authorization == false.
    let mut auth_only = HeaderMap::new();
    auth_only.insert(header::AUTHORIZATION, basic_header("alice", "secret:password"));
    let err = auth.verify_headers(&auth_only, false, false).unwrap_err();
    assert_eq!(err.status_code(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    let resp = err.into_response();
    assert_eq!(
        resp.headers().get(header::PROXY_AUTHENTICATE).unwrap(),
        "Basic realm=\"shoes\""
    );
}

#[test]
fn auth_connect_ip_accepts_authorization_and_rejects_both_headers() {
    let users = vec![MasqueUserConfig {
        username: "alice".into(),
        password: "secret".into(),
    }];
    let auth = MasqueAuth::from_users(&users, false).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, basic_header("alice", "secret"));
    assert_eq!(
        auth.verify_headers(&headers, true, false),
        Ok(Some("alice".to_string()))
    );

    // RFC 9484 Section 11: both Proxy-Authorization and Authorization present must reject.
    headers.insert(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"));
    let err = auth.verify_headers(&headers, true, false).unwrap_err();
    assert_eq!(err.status_code(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
}

#[test]
fn auth_rejects_malformed_wrong_and_non_ascii_without_panicking() {
    let users = vec![MasqueUserConfig {
        username: "alice".into(),
        password: "secret".into(),
    }];

    for stealth in [true, false] {
        let auth = MasqueAuth::from_users(&users, stealth).unwrap();
        let expected_status = if stealth {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        };

        let cases = [
            HeaderMap::new(),
            {
                let mut h = HeaderMap::new();
                h.insert(header::PROXY_AUTHORIZATION, basic_header("alice", "wrong"));
                h
            },
            {
                let mut h = HeaderMap::new();
                h.insert(header::PROXY_AUTHORIZATION, basic_header("bob", "secret"));
                h
            },
            {
                let mut h = HeaderMap::new();
                h.insert(
                    header::PROXY_AUTHORIZATION,
                    HeaderValue::from_bytes(b"Basic \xff\xfe\xfd").unwrap(),
                );
                h
            },
            {
                let mut h = HeaderMap::new();
                h.insert(
                    header::PROXY_AUTHORIZATION,
                    HeaderValue::from_static("Basic !!!not_base64!!!"),
                );
                h
            },
            {
                let mut h = HeaderMap::new();
                let no_colon = base64::engine::general_purpose::STANDARD.encode("nocolon");
                h.insert(
                    header::PROXY_AUTHORIZATION,
                    HeaderValue::from_str(&format!("Basic {no_colon}")).unwrap(),
                );
                h
            },
            {
                let mut h = HeaderMap::new();
                h.insert(header::PROXY_AUTHORIZATION, HeaderValue::from_static("Bearer token"));
                h
            },
            {
                let mut h = HeaderMap::new();
                h.append(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"));
                h.append(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"));
                h
            },
        ];

        for headers in cases {
            let err = auth.verify_headers(&headers, false, false).unwrap_err();
            assert_eq!(err.status_code(), expected_status);
            let resp = err.into_response();
            assert_eq!(resp.status(), expected_status);
            if stealth {
                assert!(resp.headers().get(header::PROXY_AUTHENTICATE).is_none());
            } else {
                assert_eq!(
                    resp.headers().get(header::PROXY_AUTHENTICATE).unwrap(),
                    "Basic realm=\"shoes\""
                );
            }
        }
    }
}

#[test]
fn auth_argon2id_hash_verification() {
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        mem_cost: 1024,
        time_cost: 1,
        lanes: 1,
        ..Default::default()
    };
    let hash = argon2::hash_encoded(b"hunter2", b"saltsaltsalt1234", &config).unwrap();
    assert!(hash.starts_with("$argon2id$"));

    let users = vec![MasqueUserConfig {
        username: "alice".into(),
        password: hash,
    }];
    let auth = MasqueAuth::from_users(&users, true).unwrap();

    let mut ok_headers = HeaderMap::new();
    ok_headers.insert(header::PROXY_AUTHORIZATION, basic_header("alice", "hunter2"));
    assert_eq!(
        auth.verify_headers(&ok_headers, false, false),
        Ok(Some("alice".to_string()))
    );

    let mut bad_headers = HeaderMap::new();
    bad_headers.insert(header::PROXY_AUTHORIZATION, basic_header("alice", "wrong"));
    assert_eq!(
        auth.verify_headers(&bad_headers, false, false)
            .unwrap_err()
            .status_code(),
        StatusCode::NOT_FOUND
    );

    let invalid_phc = vec![MasqueUserConfig {
        username: "alice".into(),
        password: "$argon2id$invalid".into(),
    }];
    assert!(MasqueAuth::from_users(&invalid_phc, true).is_err());
}

#[test]
fn auth_mtls_only_mode() {
    let auth = MasqueAuth::from_users(&[], false).unwrap();
    let headers = HeaderMap::new();
    assert_eq!(auth.verify_headers(&headers, false, true), Ok(None));
    assert_eq!(
        auth.verify_headers(&headers, false, false)
            .unwrap_err()
            .status_code(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
}

#[tokio::test]
async fn h3_connect_relays_tcp_echo_and_advertises_settings() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (echo_addr, echo_handle) = spawn_tcp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let masque = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    stealth_404: false,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();

        let mut tls_server = crate::rustls_config_util::try_create_server_config(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
            vec![],
            &["h3".to_string()],
            &[],
            &Default::default(),
        )
        .unwrap();
        tls_server.max_early_data_size = u32::MAX;
        let mut quic_server_cfg = quinn::ServerConfig::with_crypto(
            crate::certificates::quic_config(Arc::new(tls_server), None).unwrap(),
        );
        crate::resources::configure_quic(&mut quic_server_cfg, 64, 16);
        let server_ep =
            quinn::Endpoint::server(quic_server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        let masque_srv = masque.clone();
        let accept_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let _ = masque_srv.serve_h3(conn).await;
        });

        let mut tls_client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_client.alpn_protocols = vec![b"h3".to_vec()];
        let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap(),
        ));
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(quic_client_cfg);
        let quic_conn = client_ep.connect(server_addr, "localhost").unwrap().await.unwrap();

        let (mut driver, mut send_req) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_quinn::Connection::new(quic_conn))
            .await
            .unwrap();
        let settings_check = tokio::spawn(async move {
            let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            let _ = err;
        });

        // 1. Unauthenticated CONNECT -> 407 with Proxy-Authenticate: Basic realm="shoes"
        let unauth_req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .body(())
            .unwrap();
        let mut unauth_stream = send_req.send_request(unauth_req).await.unwrap();
        unauth_stream.finish().await.unwrap();
        let unauth_resp = unauth_stream.recv_response().await.unwrap();
        assert_eq!(unauth_resp.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            unauth_resp.headers().get(header::PROXY_AUTHENTICATE).unwrap(),
            "Basic realm=\"shoes\""
        );

        // Verify peer SETTINGS received by client include extended_connect and datagram.
        assert!(send_req.settings().enable_extended_connect());
        assert!(send_req.settings().enable_datagram());

        // 2. Non-CONNECT request -> 404
        let get_req = Request::builder()
            .method(Method::GET)
            .uri("https://localhost/")
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut get_stream = send_req.send_request(get_req).await.unwrap();
        get_stream.finish().await.unwrap();
        let get_resp = get_stream.recv_response().await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

        // 3. Authenticated CONNECT -> 200 OK + TCP echo + half-close
        let connect_req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(connect_req).await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        stream.send_data(Bytes::from_static(b"hello masque h3")).await.unwrap();
        stream.finish().await.unwrap();

        let mut received = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            while chunk.has_remaining() {
                let s = chunk.chunk();
                received.extend_from_slice(s);
                let len = s.len();
                chunk.advance(len);
            }
        }
        assert_eq!(received, b"hello masque h3");

        drop(send_req);
        let _ = settings_check.await;
        accept_task.abort();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_connect_relays_tcp_echo_and_advertises_extended_connect() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (echo_addr, echo_handle) = spawn_tcp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let masque = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    stealth_404: true,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );

        let (client_io, server_io) = tokio::io::duplex(16384);
        let peer: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = masque.serve_h2_stream(server_io, peer, false).await;
        });

        let (mut send_req, mut conn) = h2::client::handshake(client_io).await.unwrap();
        let mut ping = conn.ping_pong().unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        ping.ping(h2::Ping::opaque()).await.unwrap();
        assert!(send_req.is_extended_connect_protocol_enabled());

        // 1. Unauthenticated CONNECT -> 404 (stealth_404 = true)
        let unauth = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .body(())
            .unwrap();
        let (unauth_resp_fut, _) = send_req.send_request(unauth, true).unwrap();
        let unauth_resp = unauth_resp_fut.await.unwrap();
        assert_eq!(unauth_resp.status(), StatusCode::NOT_FOUND);
        drop(unauth_resp);

        // 2. Authenticated CONNECT -> 200 OK + TCP echo + half-close
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = send_req.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        send_stream
            .send_data(Bytes::from_static(b"hello masque h2"), true)
            .unwrap();

        let mut recv_stream = resp.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = recv_stream.data().await {
            let bytes = chunk.unwrap();
            received.extend_from_slice(&bytes);
            recv_stream.flow_control().release_capacity(bytes.len()).unwrap();
        }
        assert_eq!(received, b"hello masque h2");

        drop(recv_stream);
        drop(send_stream);
        drop(ping);
        drop(send_req);
        let _ = driver.await;
        server_task.abort();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tls_masque_handler_supports_mtls_without_users() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (echo_addr, echo_handle) = spawn_tcp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);

        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();

        let protocol_json = serde_json::json!({
            "type": "tls",
            "default_target": {
                "cert": server_cert.cert.pem(),
                "key": server_cert.signing_key.serialize_pem(),
                "client_ca_certs": [client_cert.cert.pem()],
                "protocol": {
                    "type": "masque",
                    "stealth_404": false
                }
            }
        });
        let protocol = crate::config::test_support::from_json(protocol_json).unwrap();
        let handler =
            crate::tcp::tcp_server_handler_factory::create_tcp_server_handler(protocol, &selector, &resolver, None)
                .unwrap();

        let (client_io, server_io) = tokio::io::duplex(16384);
        let server_task = tokio::spawn(async move {
            let crate::tcp::tcp_handler::TcpServerSetupResult::Session(session) =
                handler.setup_server_stream(Box::new(server_io)).await.unwrap()
            else {
                panic!("expected Session");
            };
            session.await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert.cert.der().clone()).unwrap();
        let client_tls_cfg = crate::rustls_config_util::with_test_roots(roots, || {
            crate::rustls_config_util::try_create_client_config(
                true,
                vec![],
                vec!["h2".to_string()],
                true,
                Some((
                    client_cert.signing_key.serialize_pem().into_bytes(),
                    client_cert.cert.pem().into_bytes(),
                )),
                false,
                &Default::default(),
            )
            .unwrap()
        });
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_cfg));
        let tls_client = connector
            .connect("localhost".try_into().unwrap(), client_io)
            .await
            .unwrap();
        assert_eq!(tls_client.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let (mut send_req, conn) = h2::client::handshake(tls_client).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = send_req.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        send_stream
            .send_data(Bytes::from_static(b"mtls ok"), true)
            .unwrap();
        let mut recv_stream = resp.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = recv_stream.data().await {
            let bytes = chunk.unwrap();
            received.extend_from_slice(&bytes);
            recv_stream.flow_control().release_capacity(bytes.len()).unwrap();
        }
        assert_eq!(received, b"mtls ok");

        drop(recv_stream);
        drop(send_stream);
        drop(send_req);
        let _ = driver.await;
        server_task.abort();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_mtls_only_mode_accepts_verified_client_cert() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (echo_addr, echo_handle) = spawn_tcp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let masque = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::None,
                    stealth_404: false,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );

        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();

        let mut tls_server = crate::rustls_config_util::try_create_server_config(
            server_cert.cert.pem().as_bytes(),
            server_cert.signing_key.serialize_pem().as_bytes(),
            vec![client_cert.cert.pem().into_bytes()],
            &["h3".to_string()],
            &[],
            &Default::default(),
        )
        .unwrap();
        tls_server.max_early_data_size = u32::MAX;
        let mut quic_server_cfg = quinn::ServerConfig::with_crypto(
            crate::certificates::quic_config(Arc::new(tls_server), None).unwrap(),
        );
        crate::resources::configure_quic(&mut quic_server_cfg, 64, 16);
        let server_ep =
            quinn::Endpoint::server(quic_server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        let masque_srv = masque.clone();
        let accept_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let _ = masque_srv.serve_h3(conn).await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert.cert.der().clone()).unwrap();
        let client_tls = crate::rustls_config_util::with_test_roots(roots, || {
            crate::rustls_config_util::try_create_client_config(
                true,
                vec![],
                vec!["h3".to_string()],
                true,
                Some((
                    client_cert.signing_key.serialize_pem().into_bytes(),
                    client_cert.cert.pem().into_bytes(),
                )),
                false,
                &Default::default(),
            )
            .unwrap()
        });
        let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(quic_client_cfg);
        let quic_conn = client_ep.connect(server_addr, "localhost").unwrap().await.unwrap();

        let (mut driver, mut send_req) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_quinn::Connection::new(quic_conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(echo_addr.to_string())
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        stream.send_data(Bytes::from_static(b"h3 mtls ok")).await.unwrap();
        stream.finish().await.unwrap();
        let mut received = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            while chunk.has_remaining() {
                let s = chunk.chunk();
                received.extend_from_slice(s);
                let len = s.len();
                chunk.advance(len);
            }
        }
        assert_eq!(received, b"h3 mtls ok");

        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

async fn spawn_udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    (addr, handle)
}

async fn spawn_h3_masque_pair(
    config: MasqueServerConfig,
) -> (
    h3::client::Connection<h3_quinn::Connection, Bytes>,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let selector = direct_selector(&resolver);
    let masque = Arc::new(MasqueServer::new(config, selector, resolver).unwrap());

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();

    let mut tls_server = crate::rustls_config_util::try_create_server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
        vec![],
        &["h3".to_string()],
        &[],
        &Default::default(),
    )
    .unwrap();
    tls_server.max_early_data_size = u32::MAX;
    let mut quic_server_cfg = quinn::ServerConfig::with_crypto(
        crate::certificates::quic_config(Arc::new(tls_server), None).unwrap(),
    );
    crate::resources::configure_quic(&mut quic_server_cfg, 64, 16);
    let server_ep =
        quinn::Endpoint::server(quic_server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let _ = masque.serve_h3(conn).await;
    });

    let mut tls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_client.alpn_protocols = vec![b"h3".to_vec()];
    let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap(),
    ));
    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(quic_client_cfg);
    let quic_conn = client_ep.connect(server_addr, "localhost").unwrap().await.unwrap();

    let (driver, send_req) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(quic_conn))
        .await
        .unwrap();

    (driver, send_req, accept_task)
}

#[tokio::test]
async fn h3_connect_udp_relays_datagrams_and_capsules() {
    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use super::wire::{Capsule, decode_context0_datagram, encode_capsule, encode_context0_datagram};

    tokio::time::timeout(Duration::from_secs(10), async {
        let (udp_addr, udp_handle) = spawn_udp_echo().await;
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            stealth_404: false,
            ..Default::default()
        })
        .await;

        let mut dgram_reader = driver.get_datagram_reader();
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .uri(format!(
                "https://localhost/.well-known/masque/udp/{}/{}/",
                udp_addr.ip(),
                udp_addr.port()
            ))
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        let stream_id = stream.id();
        let mut dgram_sender = driver.get_datagram_sender(stream_id);
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("capsule-protocol").unwrap(), "?1");

        dgram_sender
            .send_datagram(encode_context0_datagram(b"hello h3 udp"))
            .unwrap();
        let reply = dgram_reader.read_datagram().await.unwrap();
        assert_eq!(reply.stream_id(), stream_id);
        assert_eq!(
            decode_context0_datagram(reply.into_payload()).unwrap(),
            Some(Bytes::from_static(b"hello h3 udp"))
        );

        // Also verify Capsule::Datagram on the H3 request stream works.
        stream
            .send_data(encode_capsule(&Capsule::Datagram(encode_context0_datagram(
                b"hello h3 capsule",
            ))))
            .await
            .unwrap();
        let reply = dgram_reader.read_datagram().await.unwrap();
        assert_eq!(reply.stream_id(), stream_id);
        assert_eq!(
            decode_context0_datagram(reply.into_payload()).unwrap(),
            Some(Bytes::from_static(b"hello h3 capsule"))
        );

        stream.finish().await.unwrap();
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();
        udp_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_connect_udp_relays_datagrams_via_capsules() {
    use super::wire::{
        Capsule, CapsuleDecoder, decode_context0_datagram, encode_capsule, encode_context0_datagram,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let (udp_addr, udp_handle) = spawn_udp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let masque = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    stealth_404: false,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );

        let (client_io, server_io) = tokio::io::duplex(16384);
        let peer: SocketAddr = "127.0.0.1:44445".parse().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = masque.serve_h2_stream(server_io, peer, false).await;
        });

        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-udp"))
            .uri(format!(
                "https://localhost/.well-known/masque/udp/{}/{}/",
                udp_addr.ip(),
                udp_addr.port()
            ))
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = send_req.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("capsule-protocol").unwrap(), "?1");

        let mut recv_stream = resp.into_body();
        let mut decoder = CapsuleDecoder::new();

        for msg in [b"hello h2 udp".as_slice(), b"second h2 udp".as_slice()] {
            send_stream
                .send_data(
                    encode_capsule(&Capsule::Datagram(encode_context0_datagram(msg))),
                    false,
                )
                .unwrap();

            let received = loop {
                if let Some(cap) = decoder.next_capsule().unwrap() {
                    if let Capsule::Datagram(payload) = cap {
                        if let Some(udp) = decode_context0_datagram(payload).unwrap() {
                            break udp;
                        }
                    }
                    continue;
                }
                let chunk = recv_stream.data().await.unwrap().unwrap();
                decoder.feed(&chunk);
                recv_stream.flow_control().release_capacity(chunk.len()).unwrap();
            };
            assert_eq!(received.as_ref(), msg);
        }

        send_stream.send_data(Bytes::new(), true).unwrap();
        while let Some(chunk) = recv_stream.data().await {
            assert!(chunk.unwrap().is_empty());
        }
        drop(recv_stream);
        drop(send_stream);
        drop(send_req);
        let _ = driver.await;
        server_task.abort();
        udp_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_unknown_stream_datagram_does_not_disrupt_sibling_streams() {
    use h3::quic::StreamId;
    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use super::wire::{decode_context0_datagram, encode_context0_datagram};

    tokio::time::timeout(Duration::from_secs(10), async {
        let (tcp_addr, tcp_handle) = spawn_tcp_echo().await;
        let (udp_addr, udp_handle) = spawn_udp_echo().await;
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            stealth_404: false,
            ..Default::default()
        })
        .await;

        let mut dgram_reader = driver.get_datagram_reader();
        let udp_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .uri(format!(
                "https://localhost/.well-known/masque/udp/{}/{}/",
                udp_addr.ip(),
                udp_addr.port()
            ))
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut udp_stream = send_req.send_request(udp_req).await.unwrap();
        let udp_stream_id = udp_stream.id();
        let mut udp_dgram_sender = driver.get_datagram_sender(udp_stream_id);
        let mut unknown_dgram_sender = driver.get_datagram_sender(StreamId::try_from(400).unwrap());

        let tcp_req = Request::builder()
            .method(Method::CONNECT)
            .uri(tcp_addr.to_string())
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut tcp_stream = send_req.send_request(tcp_req).await.unwrap();

        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        assert_eq!(udp_stream.recv_response().await.unwrap().status(), StatusCode::OK);
        assert_eq!(tcp_stream.recv_response().await.unwrap().status(), StatusCode::OK);

        // Send an orphan datagram for an unknown StreamId and a non-zero Context ID datagram.
        unknown_dgram_sender
            .send_datagram(encode_context0_datagram(b"orphan"))
            .unwrap();
        udp_dgram_sender
            .send_datagram(Bytes::from_static(&[0x01, 0xaa, 0xbb]))
            .unwrap();

        // Both healthy sibling streams must continue relaying without disruption.
        udp_dgram_sender
            .send_datagram(encode_context0_datagram(b"sibling udp ok"))
            .unwrap();
        let reply = dgram_reader.read_datagram().await.unwrap();
        assert_eq!(reply.stream_id(), udp_stream_id);
        assert_eq!(
            decode_context0_datagram(reply.into_payload()).unwrap(),
            Some(Bytes::from_static(b"sibling udp ok"))
        );

        tcp_stream
            .send_data(Bytes::from_static(b"sibling tcp ok"))
            .await
            .unwrap();
        tcp_stream.finish().await.unwrap();
        let mut tcp_received = Vec::new();
        while let Some(mut chunk) = tcp_stream.recv_data().await.unwrap() {
            while chunk.has_remaining() {
                let s = chunk.chunk();
                tcp_received.extend_from_slice(s);
                let len = s.len();
                chunk.advance(len);
            }
        }
        assert_eq!(tcp_received, b"sibling tcp ok");

        udp_stream.finish().await.unwrap();
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();
        tcp_handle.abort();
        udp_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_udp_rejects_disabled_malformed_and_non_matching_requests() {
    tokio::time::timeout(Duration::from_secs(10), async {
        // 1. udp_enabled = false with stealth_404 = false -> 403 on H3
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            udp_enabled: false,
            stealth_404: false,
            ..Default::default()
        })
        .await;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .uri("https://localhost/.well-known/masque/udp/127.0.0.1/53/")
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(
            stream.recv_response().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();

        // 2. udp_enabled = false with stealth_404 = true -> 404 on H2
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let masque_disabled = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    udp_enabled: false,
                    stealth_404: true,
                    ..Default::default()
                },
                selector.clone(),
                resolver.clone(),
            )
            .unwrap(),
        );
        let (client_io, server_io) = tokio::io::duplex(16384);
        let peer: SocketAddr = "127.0.0.1:44446".parse().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = masque_disabled.serve_h2_stream(server_io, peer, false).await;
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let h2_driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-udp"))
            .uri("https://localhost/.well-known/masque/udp/127.0.0.1/53/")
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::NOT_FOUND);
        drop(send_req);
        let _ = h2_driver.await;
        server_task.abort();

        // 3. udp_enabled = true: port 0 -> 400, non-matching path -> 404 (H3 & H2)
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            udp_enabled: true,
            stealth_404: false,
            ..Default::default()
        })
        .await;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        for (uri, expected) in [
            (
                "https://localhost/.well-known/masque/udp/127.0.0.1/0/",
                StatusCode::BAD_REQUEST,
            ),
            ("https://localhost/wrong/path", StatusCode::NOT_FOUND),
        ] {
            let req = Request::builder()
                .method(Method::CONNECT)
                .extension(h3::ext::Protocol::CONNECT_UDP)
                .uri(uri)
                .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();
            stream.finish().await.unwrap();
            assert_eq!(stream.recv_response().await.unwrap().status(), expected);
        }
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();

        let masque_enabled = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    udp_enabled: true,
                    stealth_404: false,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );
        let (client_io, server_io) = tokio::io::duplex(16384);
        let server_task = tokio::spawn(async move {
            let _ = masque_enabled.serve_h2_stream(server_io, peer, false).await;
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let h2_driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        for (uri, expected) in [
            (
                "https://localhost/.well-known/masque/udp/127.0.0.1/0/",
                StatusCode::BAD_REQUEST,
            ),
            ("https://localhost/wrong/path", StatusCode::NOT_FOUND),
        ] {
            let req = Request::builder()
                .method(Method::CONNECT)
                .extension(h2::ext::Protocol::from_static("connect-udp"))
                .uri(uri)
                .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
                .body(())
                .unwrap();
            let (resp_fut, _) = send_req.send_request(req, true).unwrap();
            assert_eq!(resp_fut.await.unwrap().status(), expected);
        }
        drop(send_req);
        let _ = h2_driver.await;
        server_task.abort();
    })
    .await
    .unwrap();
}

fn test_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn make_ipv4_udp_packet(
    src: std::net::Ipv4Addr,
    src_port: u16,
    dst: std::net::Ipv4Addr,
    dst_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = ttl;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_csum = test_checksum(&pkt[..20]);
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
    let mut udp_csum = test_checksum(&pseudo);
    if udp_csum == 0 {
        udp_csum = 0xffff;
    }
    pkt[26..28].copy_from_slice(&udp_csum.to_be_bytes());
    pkt
}

#[test]
fn address_pool_reserves_gateway_network_broadcast_rolls_back_and_reclaims() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use super::ip_pool::{AddressPool, IpRangeSet, IpSessionRegistry, ip_in_networks, routes_contain};
    use super::wire::AddressRange;

    let v4_net: ipnetwork::IpNetwork = "10.0.0.1/29".parse().unwrap();
    let v6_net: ipnetwork::IpNetwork = "fd00::1/126".parse().unwrap();
    let pool = AddressPool::new(&[v4_net, v6_net]).unwrap();
    assert_eq!(pool.prefixes(), &[v4_net, v6_net]);

    assert_eq!(
        pool.server_addresses(),
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
        ]
    );
    assert!(pool.contains_prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
    assert!(pool.contains_prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))));
    assert!(!pool.contains_prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
    assert!(ip_in_networks(
        IpAddr::V6("fd00::2".parse().unwrap()),
        &[v4_net, v6_net]
    ));

    let a1 = pool.allocate().unwrap();
    assert_eq!(
        a1,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V6("fd00::2".parse().unwrap()),
        ]
    );
    let a2 = pool.allocate().unwrap();
    assert_eq!(
        a2,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            IpAddr::V6("fd00::3".parse().unwrap()),
        ]
    );
    // v6 /126 only has ::2 and ::3; partial v4 (10.0.0.4) must roll back.
    assert!(pool.allocate().is_none());

    pool.release(&a1);
    let a3 = pool.allocate().unwrap();
    assert_eq!(a3, a1);
    assert!(pool.allocate().is_none());

    // Verify routes_contain, IpRangeSet, and IpSessionRegistry lookup/unregister.
    let range = vec![AddressRange {
        start: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 0)),
        end: IpAddr::V4(Ipv4Addr::new(192, 168, 10, 255)),
        ip_protocol: 17,
    }];
    let range_set = IpRangeSet::new(range.clone());
    assert_eq!(range_set.as_slice(), range.as_slice());
    assert!(range_set.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5)), 17));
    let net_range_set = IpRangeSet::from_networks(&[v4_net]);
    assert!(net_range_set.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 6));
    assert!(routes_contain(
        &range,
        IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5)),
        17
    ));
    assert!(!routes_contain(
        &range,
        IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5)),
        6
    ));

    let registry = IpSessionRegistry::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    registry.register(7, a3.clone(), tx);
    registry.set_peer_routes(7, range);
    assert_eq!(
        registry.lookup(a3[0], 6).map(|(id, _)| id),
        Some(7)
    );
    assert_eq!(
        registry
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 9)), 17)
            .map(|(id, _)| id),
        Some(7)
    );
    registry.unregister(7);
    assert!(registry.lookup(a3[0], 6).is_none());
    assert!(
        registry
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 9)), 17)
            .is_none()
    );
}

#[tokio::test]
async fn connect_ip_engine_spoofed_source_and_disallowed_route_emit_icmp_errors() {
    use std::net::{IpAddr, Ipv4Addr};
    use super::connect_ip::MasqueIpEngine;
    use super::wire::{AddressRange, inspect_ip_packet};

    tokio::time::timeout(Duration::from_secs(10), async {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let config = MasqueServerConfig {
            ip_enabled: true,
            tunnel_addresses: vec!["10.20.0.1/24".parse().unwrap()],
            advertise_routes: vec!["198.51.100.0/24".parse().unwrap()],
            ..Default::default()
        };
        let engine = MasqueIpEngine::new(&config, selector, resolver).unwrap();
        let allowed_routes = vec![
            AddressRange {
                start: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                end: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 255)),
                ip_protocol: 0,
            },
            AddressRange {
                start: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 255)),
                ip_protocol: 0,
            },
        ];
        let mut lease = engine.open_session(allowed_routes).unwrap();
        let assigned_v4 = match lease.assigned_ips()[0] {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4"),
        };

        // 1. Spoofed source -> ICMP SourcePolicy (type 3, code 13)
        let spoofed = make_ipv4_udp_packet(
            Ipv4Addr::new(10, 20, 0, 99),
            40000,
            Ipv4Addr::new(198, 51, 100, 10),
            53,
            64,
            b"spoof",
        );
        engine.handle_inbound_packet(&lease, &spoofed).await;
        let icmp = lease.recv().await.unwrap();
        let meta = inspect_ip_packet(&icmp).unwrap();
        assert_eq!(meta.src, IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1)));
        assert_eq!(meta.dst, IpAddr::V4(Ipv4Addr::new(10, 20, 0, 99)));
        assert_eq!(meta.proto, 1);
        assert_eq!(icmp[20], 3);
        assert_eq!(icmp[21], 13);

        // 2. Disallowed destination outside advertised_routes -> ICMP NoRoute (type 3, code 0)
        let disallowed = make_ipv4_udp_packet(
            assigned_v4,
            40000,
            Ipv4Addr::new(203, 0, 113, 10),
            53,
            64,
            b"noroute",
        );
        engine.handle_inbound_packet(&lease, &disallowed).await;
        let icmp = lease.recv().await.unwrap();
        let meta = inspect_ip_packet(&icmp).unwrap();
        assert_eq!(meta.dst, IpAddr::V4(assigned_v4));
        assert_eq!(meta.proto, 1);
        assert_eq!(icmp[20], 3);
        assert_eq!(icmp[21], 0);

        // 3. Unassigned non-gateway address inside tunnel prefix -> ICMP AddressUnreachable (type 3, code 1)
        let unreach = make_ipv4_udp_packet(
            assigned_v4,
            40000,
            Ipv4Addr::new(10, 20, 0, 50),
            53,
            64,
            b"unreach",
        );
        engine.handle_inbound_packet(&lease, &unreach).await;
        let icmp = lease.recv().await.unwrap();
        let meta = inspect_ip_packet(&icmp).unwrap();
        assert_eq!(meta.dst, IpAddr::V4(assigned_v4));
        assert_eq!(meta.proto, 1);
        assert_eq!(icmp[20], 3);
        assert_eq!(icmp[21], 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_ip_lease_drop_reclaims_ip_and_removes_registry_route() {
    use super::connect_ip::MasqueIpEngine;

    tokio::time::timeout(Duration::from_secs(10), async {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let config = MasqueServerConfig {
            ip_enabled: true,
            tunnel_addresses: vec!["10.21.0.1/30".parse().unwrap()],
            ..Default::default()
        };
        let engine = MasqueIpEngine::new(&config, selector, resolver).unwrap();
        let routes = engine.default_advertised_routes().to_vec();

        let lease1 = engine.open_session(routes.clone()).unwrap();
        let ip1 = lease1.assigned_ips()[0];
        assert!(engine.registry().lookup(ip1, 17).is_some());
        assert!(engine.open_session(routes.clone()).is_err());

        drop(lease1);
        assert!(engine.registry().lookup(ip1, 17).is_none());

        let lease2 = engine.open_session(routes).unwrap();
        assert_eq!(lease2.assigned_ips()[0], ip1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_ip_peer_to_peer_routing_and_ttl_expiry() {
    use std::net::{IpAddr, Ipv4Addr};
    use super::connect_ip::MasqueIpEngine;
    use super::wire::inspect_ip_packet;

    tokio::time::timeout(Duration::from_secs(10), async {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let config = MasqueServerConfig {
            ip_enabled: true,
            tunnel_addresses: vec!["10.22.0.1/24".parse().unwrap()],
            ..Default::default()
        };
        let engine = MasqueIpEngine::new(&config, selector, resolver).unwrap();
        let routes = engine.default_advertised_routes().to_vec();

        let mut lease_a = engine.open_session(routes.clone()).unwrap();
        let mut lease_b = engine.open_session(routes).unwrap();
        assert_ne!(lease_a.session_id(), lease_b.session_id());
        assert_eq!(engine.mtu(), 1280);
        assert!(engine.pool().is_server_address(IpAddr::V4(Ipv4Addr::new(10, 22, 0, 1))));
        assert!(!lease_a.advertised_routes().is_empty());

        // Exercise peer_routes on lease_a and take_receiver on lease_b.
        let extra_src_range = vec![super::wire::AddressRange {
            start: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 0)),
            end: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 255)),
            ip_protocol: 17,
        }];
        lease_a.set_peer_routes(extra_src_range.clone());
        assert_eq!(lease_a.peer_routes(), extra_src_range);
        assert!(!lease_a.tx().is_closed());
        let mut rx_b = lease_b.take_receiver().unwrap();

        let ip_a = match lease_a.assigned_ips()[0] {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4"),
        };
        let ip_b = match lease_b.assigned_ips()[0] {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4"),
        };

        let pkt = make_ipv4_udp_packet(ip_a, 1111, ip_b, 2222, 64, b"p2p-ok");
        engine.handle_inbound_packet(&lease_a, &pkt).await;
        let forwarded = rx_b.recv().await.unwrap();
        let meta = inspect_ip_packet(&forwarded).unwrap();
        assert_eq!(meta.src, IpAddr::V4(ip_a));
        assert_eq!(meta.dst, IpAddr::V4(ip_b));
        assert_eq!(meta.ttl, 63);
        assert_eq!(&forwarded[28..], b"p2p-ok");

        let expired = make_ipv4_udp_packet(ip_a, 1111, ip_b, 2222, 1, b"p2p-ttl1");
        engine.handle_inbound_packet(&lease_a, &expired).await;
        let icmp = lease_a.recv().await.unwrap();
        let meta = inspect_ip_packet(&icmp).unwrap();
        assert_eq!(meta.src, IpAddr::V4(Ipv4Addr::new(10, 22, 0, 1)));
        assert_eq!(meta.dst, IpAddr::V4(ip_a));
        assert_eq!(meta.proto, 1);
        assert_eq!(icmp[20], 11); // Time Exceeded
        assert_eq!(icmp[21], 0);  // Hop Limit / TTL Exceeded
        assert!(rx_b.try_recv().is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_ip_udp_echo_via_packet_stack_and_tun_udp_manager() {
    use std::net::IpAddr;
    use super::wire::inspect_ip_packet;

    tokio::time::timeout(Duration::from_secs(10), async {
        let (udp_addr, udp_handle) = spawn_udp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);

        let disabled_server = MasqueServer::new(
            MasqueServerConfig::default(),
            selector.clone(),
            resolver.clone(),
        )
        .unwrap();
        assert!(disabled_server.ip_engine().is_none());

        let server = MasqueServer::new(
            MasqueServerConfig {
                ip_enabled: true,
                tunnel_addresses: vec!["10.30.0.1/24".parse().unwrap()],
                ..Default::default()
            },
            selector,
            resolver,
        )
        .unwrap();
        let engine = server.ip_engine().expect("ip_enabled must initialize ip_engine");
        let mut lease = engine
            .open_session(engine.default_advertised_routes().to_vec())
            .unwrap();
        let client_ip = match lease.assigned_ips()[0] {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4"),
        };
        let target_ip = match udp_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4 echo addr"),
        };

        let pkt = make_ipv4_udp_packet(
            client_ip,
            40001,
            target_ip,
            udp_addr.port(),
            64,
            b"hello connect-ip",
        );
        engine.handle_inbound_packet(&lease, &pkt).await;

        let reply = lease.recv().await.unwrap();
        let meta = inspect_ip_packet(&reply).unwrap();
        assert_eq!(meta.src, IpAddr::V4(target_ip));
        assert_eq!(meta.dst, IpAddr::V4(client_ip));
        assert_eq!(meta.proto, 17);
        let ihl = usize::from(reply[0] & 0x0f) * 4;
        let src_port = u16::from_be_bytes([reply[ihl], reply[ihl + 1]]);
        let dst_port = u16::from_be_bytes([reply[ihl + 2], reply[ihl + 3]]);
        assert_eq!(src_port, udp_addr.port());
        assert_eq!(dst_port, 40001);
        assert_eq!(&reply[ihl + 8..], b"hello connect-ip");

        udp_handle.abort();
    })
    .await
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn make_ipv4_tcp_packet(
    src: std::net::Ipv4Addr,
    src_port: u16,
    dst: std::net::Ipv4Addr,
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
    let ip_csum = test_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5 (20 bytes)
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + usize::from(tcp_len));
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(&pkt[20..]);
    let tcp_csum = test_checksum(&pseudo);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

#[tokio::test]
async fn h3_connect_ip_handshake_and_udp_roundtrip() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use super::wire::{
        AssignedAddress, Capsule, CapsuleDecoder, decode_context0_datagram, encode_capsule,
        encode_context0_datagram, inspect_ip_packet,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let (udp_addr, udp_handle) = spawn_udp_echo().await;
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            ip_enabled: true,
            tunnel_addresses: vec!["10.40.0.1/24".parse().unwrap()],
            stealth_404: false,
            ..Default::default()
        })
        .await;

        let mut dgram_reader = driver.get_datagram_reader();
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h3::ext::Protocol::CONNECT_IP)
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        let stream_id = stream.id();
        let mut dgram_sender = driver.get_datagram_sender(stream_id);
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("capsule-protocol").unwrap(), "?1");

        let (mut send_stream, mut recv_stream) = stream.split();
        let mut decoder = CapsuleDecoder::new();
        let mut read_capsule = async || loop {
            if let Some(cap) = decoder.next_capsule().unwrap() {
                return cap;
            }
            let mut chunk = recv_stream.recv_data().await.unwrap().unwrap();
            while chunk.has_remaining() {
                let bytes = chunk.chunk();
                decoder.feed(bytes);
                let len = bytes.len();
                chunk.advance(len);
            }
        };

        let assigned = match read_capsule().await {
            Capsule::AddressAssign(addrs) => addrs,
            other => panic!("expected AddressAssign, got {other:?}"),
        };
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].request_id, 0);
        assert_eq!(assigned[0].prefix_len, 32);
        let client_ip = match assigned[0].ip {
            IpAddr::V4(v4) => v4,
            other => panic!("expected IPv4 assignment, got {other:?}"),
        };
        assert_eq!(client_ip, Ipv4Addr::new(10, 40, 0, 2));

        let routes = match read_capsule().await {
            Capsule::RouteAdvertisement(routes) => routes,
            other => panic!("expected RouteAdvertisement, got {other:?}"),
        };
        assert!(!routes.is_empty());

        // Exercise ADDRESS_REQUEST (v4 available + v6 unavailable -> ::/128)
        let req_capsule = Capsule::AddressRequest(vec![
            AssignedAddress {
                request_id: 5,
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 32,
            },
            AssignedAddress {
                request_id: 6,
                ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_len: 128,
            },
        ]);
        send_stream
            .send_data(encode_capsule(&req_capsule))
            .await
            .unwrap();
        let reply_assign = match read_capsule().await {
            Capsule::AddressAssign(addrs) => addrs,
            other => panic!("expected AddressAssign reply, got {other:?}"),
        };
        assert_eq!(
            reply_assign,
            vec![
                AssignedAddress {
                    request_id: 5,
                    ip: IpAddr::V4(client_ip),
                    prefix_len: 32,
                },
                AssignedAddress {
                    request_id: 6,
                    ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_len: 128,
                },
            ]
        );

        let target_ip = match udp_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4 echo addr"),
        };
        let pkt = make_ipv4_udp_packet(
            client_ip,
            41001,
            target_ip,
            udp_addr.port(),
            64,
            b"hello h3 connect-ip",
        );
        dgram_sender
            .send_datagram(encode_context0_datagram(&pkt))
            .unwrap();

        let reply = dgram_reader.read_datagram().await.unwrap();
        assert_eq!(reply.stream_id(), stream_id);
        let reply_pkt = decode_context0_datagram(reply.into_payload()).unwrap().unwrap();
        let meta = inspect_ip_packet(&reply_pkt).unwrap();
        assert_eq!(meta.src, IpAddr::V4(target_ip));
        assert_eq!(meta.dst, IpAddr::V4(client_ip));
        assert_eq!(meta.proto, 17);
        let ihl = usize::from(reply_pkt[0] & 0x0f) * 4;
        assert_eq!(&reply_pkt[ihl + 8..], b"hello h3 connect-ip");

        send_stream.finish().await.unwrap();
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();
        udp_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_connect_ip_handshake_and_tcp_roundtrip() {
    use std::net::{IpAddr, Ipv4Addr};
    use super::wire::{
        AssignedAddress, Capsule, CapsuleDecoder, decode_context0_datagram, encode_capsule,
        encode_context0_datagram, inspect_ip_packet,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let (echo_addr, echo_handle) = spawn_tcp_echo().await;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = direct_selector(&resolver);
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();

        let protocol_json = serde_json::json!({
            "type": "tls",
            "default_target": {
                "cert": server_cert.cert.pem(),
                "key": server_cert.signing_key.serialize_pem(),
                "protocol": {
                    "type": "masque",
                    "users": [{"username": "alice", "password": "secret"}],
                    "ip_enabled": true,
                    "tunnel_addresses": ["10.41.0.1/30"],
                    "stealth_404": false
                }
            }
        });
        let protocol = crate::config::test_support::from_json(protocol_json).unwrap();
        let handler = crate::tcp::tcp_server_handler_factory::create_tcp_server_handler(
            protocol,
            &selector,
            &resolver,
            None,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(65536);
        let server_task = tokio::spawn(async move {
            let crate::tcp::tcp_handler::TcpServerSetupResult::Session(session) =
                handler.setup_server_stream(Box::new(server_io)).await.unwrap()
            else {
                panic!("expected Session");
            };
            session.await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert.cert.der().clone()).unwrap();
        let client_tls_cfg = crate::rustls_config_util::with_test_roots(roots, || {
            crate::rustls_config_util::try_create_client_config(
                true,
                vec![],
                vec!["h2".to_string()],
                true,
                None,
                false,
                &Default::default(),
            )
            .unwrap()
        });
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_cfg));
        let tls_client = connector
            .connect("localhost".try_into().unwrap(), client_io)
            .await
            .unwrap();
        assert_eq!(tls_client.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let (mut send_req, conn) = h2::client::handshake(tls_client).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = send_req.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("capsule-protocol").unwrap(), "?1");

        let mut recv_stream = resp.into_body();
        let mut decoder = CapsuleDecoder::new();

        async fn next_h2_capsule(
            recv: &mut h2::RecvStream,
            decoder: &mut CapsuleDecoder,
        ) -> Capsule {
            loop {
                if let Some(cap) = decoder.next_capsule().unwrap() {
                    return cap;
                }
                let chunk = recv.data().await.unwrap().unwrap();
                decoder.feed(&chunk);
                recv.flow_control().release_capacity(chunk.len()).unwrap();
            }
        }

        let assigned = match next_h2_capsule(&mut recv_stream, &mut decoder).await {
            Capsule::AddressAssign(addrs) => addrs,
            other => panic!("expected AddressAssign, got {other:?}"),
        };
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].request_id, 0);
        let client_ip = match assigned[0].ip {
            IpAddr::V4(v4) => v4,
            other => panic!("expected ipv4, got {other:?}"),
        };
        assert_eq!(client_ip, Ipv4Addr::new(10, 41, 0, 2));

        let routes = match next_h2_capsule(&mut recv_stream, &mut decoder).await {
            Capsule::RouteAdvertisement(routes) => routes,
            other => panic!("expected RouteAdvertisement, got {other:?}"),
        };
        assert!(!routes.is_empty());

        // Verify ADDRESS_REQUEST roundtrip.
        send_stream
            .send_data(
                encode_capsule(&Capsule::AddressRequest(vec![AssignedAddress {
                    request_id: 7,
                    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 32,
                }])),
                false,
            )
            .unwrap();
        let reply_assign = match next_h2_capsule(&mut recv_stream, &mut decoder).await {
            Capsule::AddressAssign(addrs) => addrs,
            other => panic!("expected AddressAssign reply, got {other:?}"),
        };
        assert_eq!(
            reply_assign,
            vec![AssignedAddress {
                request_id: 7,
                ip: IpAddr::V4(client_ip),
                prefix_len: 32,
            }]
        );

        // Run a real TCP 3-way handshake + payload echo over Capsule::Datagram.
        let target_ip = match echo_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected ipv4 echo addr"),
        };
        let client_port = 42001u16;
        let client_isn = 0x1000_0000u32;

        let syn = make_ipv4_tcp_packet(
            client_ip,
            client_port,
            target_ip,
            echo_addr.port(),
            client_isn,
            0,
            0x02, // SYN
            &[],
        );
        send_stream
            .send_data(
                encode_capsule(&Capsule::Datagram(encode_context0_datagram(&syn))),
                false,
            )
            .unwrap();

        let syn_ack = loop {
            if let Capsule::Datagram(payload) = next_h2_capsule(&mut recv_stream, &mut decoder).await
            {
                if let Some(pkt) = decode_context0_datagram(payload).unwrap() {
                    let meta = inspect_ip_packet(&pkt).unwrap();
                    if meta.proto == 6 && (pkt[33] & 0x12) == 0x12 {
                        break pkt;
                    }
                }
            }
        };
        let server_isn = u32::from_be_bytes(syn_ack[24..28].try_into().unwrap());
        let server_ack = u32::from_be_bytes(syn_ack[28..32].try_into().unwrap());
        assert_eq!(server_ack, client_isn + 1);

        // Send ACK + data payload.
        let msg = b"hello h2 connect-ip tcp";
        let ack_data = make_ipv4_tcp_packet(
            client_ip,
            client_port,
            target_ip,
            echo_addr.port(),
            client_isn + 1,
            server_isn + 1,
            0x18, // PSH | ACK
            msg,
        );
        send_stream
            .send_data(
                encode_capsule(&Capsule::Datagram(encode_context0_datagram(&ack_data))),
                false,
            )
            .unwrap();

        let mut echoed = Vec::new();
        while echoed.len() < msg.len() {
            if let Capsule::Datagram(payload) = next_h2_capsule(&mut recv_stream, &mut decoder).await
            {
                if let Some(pkt) = decode_context0_datagram(payload).unwrap() {
                    let meta = inspect_ip_packet(&pkt).unwrap();
                    if meta.proto == 6 {
                        let ihl = usize::from(pkt[0] & 0x0f) * 4;
                        let tcp_hdr_len = usize::from(pkt[ihl + 12] >> 4) * 4;
                        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
                        let data = &pkt[ihl + tcp_hdr_len..total_len];
                        echoed.extend_from_slice(data);
                    }
                }
            }
        }
        assert_eq!(echoed, msg);

        // Close first stream and verify IP lease is reclaimed back to the /30 pool.
        send_stream.send_data(Bytes::new(), true).unwrap();
        while let Some(chunk) = recv_stream.data().await {
            if chunk.unwrap().is_empty() {
                break;
            }
        }
        drop(recv_stream);
        drop(send_stream);

        let req2 = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut2, mut send_stream2) = send_req.send_request(req2, false).unwrap();
        let resp2 = resp_fut2.await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let mut recv_stream2 = resp2.into_body();
        let mut decoder2 = CapsuleDecoder::new();
        let assigned2 = match next_h2_capsule(&mut recv_stream2, &mut decoder2).await {
            Capsule::AddressAssign(addrs) => addrs,
            other => panic!("expected AddressAssign on 2nd session, got {other:?}"),
        };
        assert_eq!(assigned2[0].ip, IpAddr::V4(Ipv4Addr::new(10, 41, 0, 2)));

        send_stream2.send_data(Bytes::new(), true).unwrap();
        drop(recv_stream2);
        drop(send_stream2);
        drop(send_req);
        let _ = driver.await;
        server_task.abort();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_ip_rejects_disabled_exhausted_and_unroutable_targets() {
    #[derive(Debug)]
    struct TestDnsResolver;

    impl Resolver for TestDnsResolver {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            let host = location.address().hostname().map(str::to_owned);
            let port = location.port();
            Box::pin(async move {
                match host.as_deref() {
                    Some("routable.test") => Ok(vec![SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 42)),
                        port,
                    )]),
                    Some("unroutable.test") => Ok(vec![SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 42)),
                        port,
                    )]),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "nxdomain",
                    )),
                }
            })
        }
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        let resolver: Arc<dyn Resolver> = Arc::new(TestDnsResolver);
        let selector = direct_selector(&resolver);
        let peer: SocketAddr = "127.0.0.1:44451".parse().unwrap();

        // 1. ip_enabled = false with stealth_404 = false -> 403 on H3
        let (mut driver, mut send_req, accept_task) = spawn_h3_masque_pair(MasqueServerConfig {
            users: NoneOrSome::One(MasqueUserConfig {
                username: "alice".into(),
                password: "secret".into(),
            }),
            ip_enabled: false,
            stealth_404: false,
            ..Default::default()
        })
        .await;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h3::ext::Protocol::CONNECT_IP)
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(
            stream.recv_response().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        drop(send_req);
        let _ = driver_task.await;
        accept_task.abort();

        // 2. ip_enabled = false with stealth_404 = true -> 404 on H2
        let masque_disabled = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    ip_enabled: false,
                    stealth_404: true,
                    ..Default::default()
                },
                selector.clone(),
                resolver.clone(),
            )
            .unwrap(),
        );
        let (client_io, server_io) = tokio::io::duplex(16384);
        let server_task = tokio::spawn(async move {
            let _ = masque_disabled.serve_h2_stream(server_io, peer, false).await;
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let h2_driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::NOT_FOUND);
        drop(send_req);
        let _ = h2_driver.await;
        server_task.abort();

        // 3. Enabled server with /30 pool (1 client IP) and restricted advertise_routes
        let masque = Arc::new(
            MasqueServer::new(
                MasqueServerConfig {
                    users: NoneOrSome::One(MasqueUserConfig {
                        username: "alice".into(),
                        password: "secret".into(),
                    }),
                    ip_enabled: true,
                    tunnel_addresses: vec!["10.42.0.1/30".parse().unwrap()],
                    advertise_routes: vec!["198.51.100.0/24".parse().unwrap()],
                    stealth_404: false,
                    ..Default::default()
                },
                selector,
                resolver,
            )
            .unwrap(),
        );
        let (client_io, server_io) = tokio::io::duplex(32768);
        let server_task = tokio::spawn(async move {
            let _ = masque.serve_h2_stream(server_io, peer, false).await;
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let h2_driver = tokio::spawn(async move {
            let _ = conn.await;
        });

        // 3a. Dual Authorization + Proxy-Authorization rejected -> 407
        let dual_auth_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .header(header::PROXY_AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(dual_auth_req, true).unwrap();
        assert_eq!(
            resp_fut.await.unwrap().status(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        // 3b. Unroutable target CIDR and unroutable resolved hostname -> 403
        let unroutable_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/192.0.2.0%2F24/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(unroutable_req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::FORBIDDEN);

        let unroutable_host_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/unroutable.test/17/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(unroutable_host_req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::FORBIDDEN);

        // 3c. Non-matching path -> 404; invalid ipproto -> 400
        let wrong_path_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/not-masque/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(wrong_path_req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::NOT_FOUND);

        let bad_proto_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/999/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(bad_proto_req, true).unwrap();
        assert_eq!(resp_fut.await.unwrap().status(), StatusCode::BAD_REQUEST);

        // 3d. DNS resolution failure -> 502 with Proxy-Status: shoes; error=dns_error
        let bad_dns_req = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/nonexistent.invalid/17/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_fut, _) = send_req.send_request(bad_dns_req, true).unwrap();
        let bad_dns_resp = resp_fut.await.unwrap();
        assert_eq!(bad_dns_resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            bad_dns_resp.headers().get("proxy-status").unwrap(),
            "shoes; error=dns_error"
        );
        drop(bad_dns_resp);

        // 3e. Hold 1 active session (resolved hostname) on /30 pool, then 2nd session -> 503 Service Unavailable
        let req_ok = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/routable.test/17/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_ok_fut, mut hold_send) = send_req.send_request(req_ok, false).unwrap();
        let resp_ok = resp_ok_fut.await.unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);

        let req_exhausted = Request::builder()
            .method(Method::CONNECT)
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .uri("https://localhost/.well-known/masque/ip/*/*/")
            .header(header::AUTHORIZATION, basic_header("alice", "secret"))
            .body(())
            .unwrap();
        let (resp_exhausted_fut, _) = send_req.send_request(req_exhausted, true).unwrap();
        assert_eq!(
            resp_exhausted_fut.await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        hold_send.send_data(Bytes::new(), true).unwrap();
        let mut hold_recv = resp_ok.into_body();
        while let Some(chunk) = hold_recv.data().await {
            let bytes = chunk.unwrap();
            hold_recv
                .flow_control()
                .release_capacity(bytes.len())
                .unwrap();
        }
        drop(hold_recv);
        drop(hold_send);
        drop(send_req);
        let _ = h2_driver.await;
        server_task.abort();
    })
    .await
    .unwrap();
}
