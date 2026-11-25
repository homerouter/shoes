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

        let ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client.local".into()]).unwrap();
        drop(ca_params);

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
                vec!["h2".to_string()],
                vec![],
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
                vec!["h3".to_string()],
                vec![],
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
