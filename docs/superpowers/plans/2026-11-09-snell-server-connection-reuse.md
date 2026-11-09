# Snell Server Connection Reuse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A shoes Snell server on v4/v5/v6 framing serves reused connections (cmd 5) and sends tunnel replies, error replies, zero chunks, and closes exactly as sing-snell does.

**Architecture:** A new `TcpServerSetupResult::ReusableTcpForward` carries a `Box<dyn ReusableTcpStream>`; `tcp_server` forwards one session at a time through an extracted `forward_tcp` and asks the stream for its `next_request`. Snell's `SnellTunnelStream` wraps the v4/v6 framed stream, defers the `0x00` reply to the first remote payload, turns write shutdown into a zero chunk or an error reply, and drains client data after its own zero chunk. The shoes client reads the reply lazily.

**Tech Stack:** Rust 2024 (rustc 1.99.1), tokio, async-trait. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-09-snell-server-connection-reuse-design.md` (sub-project A of `docs/superpowers/specs/2026-11-09-snell-sing-snell-parity-roadmap.md`).

## Global Constraints

- Toolchain: `export PATH=$HOME/.cargo/bin:$PATH` before any `cargo` command.
- Do NOT run `cargo fmt` or `rustfmt`: this rustfmt reorders imports across the whole crate (e.g. `{ready, Context, Poll}` → `{Context, Poll, ready}`). Hand-format to match surrounding code.
- No new dependencies.
- Wire constants, verbatim from the spec:
  - tunnel reply `0x00`; pong `0x01`; error reply `[0x02, code, msg-len, msg...]`
  - Remote EOF reply: `[0x02, 0x65, 10, b"Remote EOF"]`
  - end-of-file reply (v4/v5, cmd 1): `[0x02, 0xff, 11, b"end of file"]`
  - drain limit: `0x80001` bytes (error when discarded bytes `>=` the limit)
- No idle timeout between sessions.
- v3 framing, h2mux, and first-request UDP/ping behavior stay as they are, except the v6 UDP same-record check.
- Commit after each task; end every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Pipelined next request** — a client that sends its next request right behind its zero chunk, before reading the server's reply, must get the next session served, not lose the bytes. Test: Task 6 `pipelined_request_is_served`.
2. **Payload larger than one record** (> 16 KiB, so the first inner write is capped) — the `0x00` reply must appear once and every byte must arrive in order. Test: Task 6 `large_payload_round_trips`.
3. **Many sessions on one connection** — nonces and state must keep working across dozens of sessions. Test: Task 6 `fifty_sessions_on_one_connection`.
4. **Client disconnects mid-session** — the server task must finish, not hang. Test: Task 6 `client_disconnect_ends_connection`.
5. **Policy-blocked or refused connect on a reused session** — the client must see `Remote EOF` and then a closed connection. Test: Task 6 `refused_connect_replies_remote_eof`.

## File Structure

- `src/tcp/tcp_handler.rs` — `TcpSession`, `ReusableTcpStream`, `ReusableTcpForward` variant.
- `src/tcp/tcp_server.rs` — `forward_tcp` (moved `TcpForward` body) and the reuse loop.
- `src/snell/snell_handler.rs` — `read_request`, `udp_relay`, `SnellTunnelStream`, `SnellReplyStream` (client), dispatch, unit tests, end-to-end tests.
- `README.md`, `docs/src/content/docs/protocols/snell.md`, `docs/src/content/docs/zh-cn/protocols/snell.md` — remove the "no reuse" claims.

---

### Task 1: Client reads the tunnel reply lazily

**Files:**
- Modify: `src/snell/snell_handler.rs` (`SnellClientHandler::setup_client_tcp_stream`, new `SnellReplyStream`; tests module)

**Interfaces:**
- Consumes: `SnellFramedStream<Box<dyn AsyncStream>>` (existing).
- Produces: `struct SnellReplyStream` (private) — later tasks do not use it directly.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/snell/snell_handler.rs`:

```rust
    #[tokio::test]
    async fn snell_client_returns_before_reply() {
        let client = test_client(Some("v4"), None);
        let (client_io, _server_io) = duplex(65536);
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.setup_client_tcp_stream(Box::new(client_io), target),
        )
        .await
        .expect("setup must not wait for the reply")
        .unwrap();
    }

    #[tokio::test]
    async fn snell_client_surfaces_error_reply() {
        let server = test_server(None, None);
        let client = test_client(Some("v4"), None);
        let (client_io, server_io) = duplex(65536);
        // The server side runs concurrently so a client that waits for the
        // reply during setup fails instead of hanging.
        let server_task = tokio::spawn(async move {
            let mut framed = server
                .detect_and_frame_stream(Box::new(server_io))
                .await
                .unwrap();
            let mut request = [0u8; 64];
            let _ = framed.read(&mut request).await.unwrap();
            write_all(&mut framed, b"\x02\x65\x0aRemote EOF").await.unwrap();
            framed.flush().await.unwrap();
            framed
        });
        let target: ResolvedLocation =
            NetLocation::from_str("example.com:443", None).unwrap().into();
        let mut result = client
            .setup_client_tcp_stream(Box::new(client_io), target)
            .await
            .unwrap();
        let err = result.client_stream.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.to_string(), "snell error 0x65: Remote EOF");
        drop(server_task.await.unwrap());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib snell_client_ -- --nocapture`
Expected: `snell_client_returns_before_reply` FAILS with "setup must not wait for the reply"; `snell_client_surfaces_error_reply` FAILS (setup returns an error "Got non-tunnel response (2)").

- [ ] **Step 3: Implement**

In `setup_client_tcp_stream`, delete everything from `let mut response = [0u8; 1];` through the `if response[0] != 0 { ... }` block, and return:

```rust
        Ok(TcpClientSetupResult {
            client_stream: Box::new(SnellReplyStream {
                inner: client_stream,
                reply: Some(Vec::new()),
            }),
            early_data: None,
        })
```

Add above `#[derive(Debug)] pub struct SnellClientHandler`:

```rust
/// Client tunnel stream that consumes the server's reply on first read:
/// sing-snell and snell-server send it with the first remote payload.
struct SnellReplyStream {
    inner: SnellFramedStream<Box<dyn AsyncStream>>,
    /// Reply bytes read so far; `None` once the tunnel reply is consumed.
    reply: Option<Vec<u8>>,
}

impl SnellReplyStream {
    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while let Some(head) = &mut self.reply {
            let need = match head.as_slice() {
                [] => 1,
                [0x00] => {
                    self.reply = None;
                    break;
                }
                [0x02] | [0x02, _] => 3,
                [0x02, code, len, msg @ ..] if msg.len() == *len as usize => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "snell error 0x{code:02x}: {}",
                        String::from_utf8_lossy(msg)
                    ))));
                }
                [0x02, _, len, ..] => 3 + *len as usize,
                [other, ..] => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "Got non-tunnel response ({other})"
                    ))));
                }
            };
            let mut tmp = [0u8; 258];
            let mut buf = ReadBuf::new(&mut tmp[..need - head.len()]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF when reading tunnel response",
                )));
            }
            head.extend_from_slice(buf.filled());
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SnellReplyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_reply(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SnellReplyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncPing for SnellReplyStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl AsyncStream for SnellReplyStream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        AsyncStream::flow(&self.inner)
    }
}
```

Change the import `use std::task::{Context, Poll};` to `use std::task::{ready, Context, Poll};`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib snell`
Expected: all pass, including the existing `run_tcp_echo` tests (the server still replies immediately at this point).

- [ ] **Step 5: Commit**

```bash
git add src/snell/snell_handler.rs
git commit -m "fix(snell): read the client tunnel reply lazily

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Reusable forward in the TCP server

**Files:**
- Modify: `src/tcp/tcp_handler.rs` (new struct, trait, variant; `set_need_initial_flush`)
- Modify: `src/tcp/tcp_server.rs:27-41` (`send_connect_failure`), `:190-312` (`TcpForward` arm), the setup-result `match`

**Interfaces:**
- Produces:
  ```rust
  pub struct TcpSession {
      pub remote_location: NetLocation,
      pub need_initial_flush: bool,
      pub connection_success_response: Option<Box<[u8]>>,
      pub connection_failure_response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
      pub initial_remote_data: Option<Box<[u8]>>,
      pub proxy_selector: Arc<ClientProxySelector>,
  }
  #[async_trait]
  pub trait ReusableTcpStream: AsyncStream {
      async fn next_request(self: Box<Self>) -> std::io::Result<Option<TcpServerSetupResult>>;
  }
  TcpServerSetupResult::ReusableTcpForward { stream: Box<dyn ReusableTcpStream>, session: TcpSession }
  ```

This task is a refactor plus a new variant with no producer yet; its behavior is tested end to end in Task 6. The gate here is that every existing test still passes.

- [ ] **Step 1: Add the types in `src/tcp/tcp_handler.rs`**

Add the variant at the end of `pub enum TcpServerSetupResult`, after `Session(...)`:

```rust
    /// A TCP forward whose stream can carry further requests after a clean
    /// session; see [`ReusableTcpStream`].
    ReusableTcpForward {
        stream: Box<dyn ReusableTcpStream>,
        session: TcpSession,
    },
```

In `set_need_initial_flush`, add an arm before `TcpServerSetupResult::Session(_) => {}`:

```rust
            TcpServerSetupResult::ReusableTcpForward { session, .. } => {
                session.need_initial_flush = need_initial_flush;
            }
```

Add after the `impl TcpServerSetupResult` block:

```rust
/// Per-session forward parameters: the `TcpForward` fields minus the stream.
pub struct TcpSession {
    pub remote_location: NetLocation,
    pub need_initial_flush: bool,
    /// Response to write to the server stream after connection to remote location succeeds
    pub connection_success_response: Option<Box<[u8]>>,
    pub connection_failure_response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
    /// Initial data to send to the remote location
    pub initial_remote_data: Option<Box<[u8]>>,
    /// The proxy selector to use for routing this session
    pub proxy_selector: Arc<ClientProxySelector>,
}

/// A server stream that can carry another request after a clean session.
#[async_trait]
pub trait ReusableTcpStream: AsyncStream {
    /// Reads the next request on this stream. `None` closes the connection.
    async fn next_request(self: Box<Self>) -> std::io::Result<Option<TcpServerSetupResult>>;
}
```

- [ ] **Step 2: Make `send_connect_failure` generic (`src/tcp/tcp_server.rs:27`)**

```rust
async fn send_connect_failure<S: AsyncStream + ?Sized>(
    stream: &mut S,
    response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
    kind: std::io::ErrorKind,
) {
```

(body unchanged).

- [ ] **Step 3: Move the `TcpForward` arm body into `forward_tcp`**

Add this function to `src/tcp/tcp_server.rs` right after `process_stream_with_permit`. Its body is the current `TcpForward` arm body with these changes only: it destructures `TcpSession`, the policy-block `return Ok(())` becomes `return Ok(false)`, local DNS borrows the stream, and the final shutdown depends on `reuse`.

```rust
/// Forwards one TCP session from `server_stream` to its routed destination.
/// Returns `Ok(false)` when routing blocked the session. With `reuse`, only
/// the remote stream is shut down, so `server_stream` can carry the next
/// request.
async fn forward_tcp(
    server_stream: &mut dyn AsyncStream,
    session: TcpSession,
    source: Option<SocketAddr>,
    resolver: Arc<dyn Resolver>,
    setup_timeout: Duration,
    reuse: bool,
) -> std::io::Result<bool> {
    let TcpSession {
        remote_location,
        need_initial_flush: server_need_initial_flush,
        proxy_selector,
        mut connection_success_response,
        mut connection_failure_response,
        initial_remote_data,
    } = session;
    let mut server_stream = server_stream;
    let setup_client_stream_future = async {
        let route = timeout(setup_timeout, async {
            let prepared = super::ingress::PreparedTcp::new(
                &proxy_selector,
                remote_location.clone(),
                initial_remote_data.map_or_else(Vec::new, |data| data.into_vec()),
            )?
            .with_source(source);
            if prepared.needs_sniff_read() {
                crate::util::timeout_stream_setup(async {
                    let response = connection_success_response.take();
                    connection_failure_response = None;
                    let flush = response.is_some() || server_need_initial_flush;
                    if let Some(data) = response {
                        write_all(&mut server_stream, &data).await?;
                    }
                    if flush {
                        server_stream.flush().await?;
                    }
                    Ok(())
                })
                .await?;
            }
            prepared
                .route(&mut server_stream, &proxy_selector, &resolver)
                .await
        })
        .await?;
        match route {
            Ok(route) => timeout(setup_timeout, route.connect(&resolver)).await,
            Err(error) => Ok(Err(error)),
        }
    };

    let routed = match setup_client_stream_future.await {
        Ok(Ok(routed)) => routed,
        Ok(Err(e)) => {
            send_connect_failure(&mut server_stream, connection_failure_response, e.kind())
                .await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            send_connect_failure(
                &mut server_stream,
                connection_failure_response,
                std::io::ErrorKind::TimedOut,
            )
            .await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };
    drop(proxy_selector);
    drop(resolver);
    let Some(TcpClientSetupResult {
        mut client_stream,
        early_data,
    }) = routed.setup
    else {
        send_connect_failure(
            &mut server_stream,
            connection_failure_response,
            std::io::ErrorKind::PermissionDenied,
        )
        .await;
        return Ok(false);
    };
    log::debug!("TCP setup completed for {}", routed.wire_destination);

    let flow = client_stream.flow().cloned();
    crate::control::tracked_stream::during_flow(
        flow.as_deref(),
        crate::util::timeout_stream_setup(async {
            let flush_server = server_need_initial_flush || early_data.is_some();
            if let Some(data) = connection_success_response {
                write_all(&mut server_stream, &data).await?;
            }
            if let Some(data) = early_data {
                write_all(&mut server_stream, &data).await?;
            }
            if flush_server {
                server_stream.flush().await?;
            }
            if !routed.is_local_dns && !routed.prefix.is_empty() {
                write_all(&mut client_stream, &routed.prefix).await?;
                client_stream.flush().await?;
            }
            Ok(())
        }),
    )
    .await?;
    // Local DNS can produce replies before it consumes a pipelined prefix.
    let mut prepended;
    let server_stream: &mut dyn AsyncStream = if routed.is_local_dns {
        prepended = crate::prepend_stream::PrependStream::new(
            server_stream,
            Some(routed.prefix.into_boxed_slice()),
        );
        &mut prepended
    } else {
        drop(routed.prefix);
        server_stream
    };

    let copy_result = copy_bidirectional(server_stream, &mut client_stream, false, false).await;

    if reuse {
        crate::util::shutdown_stream(&mut client_stream).await;
    } else {
        crate::util::shutdown_stream_pair(server_stream, &mut client_stream).await;
    }

    copy_result?;
    Ok(true)
}
```

Before deleting the old arm body, diff it against this function to confirm nothing else changed.

Replace the whole `TcpServerSetupResult::TcpForward { ... } => { ... }` arm in `process_stream_with_permit` with:

```rust
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush,
            proxy_selector,
            connection_success_response,
            connection_failure_response,
            initial_remote_data,
        } => {
            let session = TcpSession {
                remote_location,
                need_initial_flush,
                connection_success_response,
                connection_failure_response,
                initial_remote_data,
                proxy_selector,
            };
            forward_tcp(&mut *server_stream, session, source, resolver, setup_timeout, false)
                .await?;
            Ok(())
        }
```

- [ ] **Step 4: Add the reuse loop**

Directly before `match setup_result {` in `process_stream_with_permit`, insert:

```rust
    let mut setup_result = setup_result;
    while let TcpServerSetupResult::ReusableTcpForward { mut stream, session } = setup_result {
        if !forward_tcp(&mut *stream, session, source, resolver.clone(), setup_timeout, true)
            .await?
        {
            return Ok(());
        }
        let Some(next) = stream.next_request().await? else {
            return Ok(());
        };
        setup_result = next;
    }
```

Add a final arm to the `match setup_result`:

```rust
        TcpServerSetupResult::ReusableTcpForward { .. } => {
            unreachable!("handled by the reuse loop")
        }
```

Update the import: `use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult, TcpSession};`

- [ ] **Step 5: Build and run the regression tests**

Run: `cargo build && cargo test --lib tcp_server && cargo test --lib snell`
Expected: build succeeds with no new warnings; all tests pass. If the compiler reports another non-exhaustive `match` on `TcpServerSetupResult`, add a `ReusableTcpForward { .. }` arm with the same handling as that match's `TcpForward` arm.

- [ ] **Step 6: Commit**

```bash
git add src/tcp/tcp_handler.rs src/tcp/tcp_server.rs
git commit -m "feat(tcp): add reusable TCP forward with a per-session loop

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Shared Snell request parser, UDP helper, v6 UDP same-record check

**Files:**
- Modify: `src/snell/snell_handler.rs` (`setup_server_stream`; new `read_request`, `udp_relay`, constants; tests)

**Interfaces:**
- Produces:
  ```rust
  const CMD_PING: u8 = 0; const CMD_CONNECT: u8 = 1; const CMD_CONNECT_V2: u8 = 5; const CMD_UDP: u8 = 6;
  struct SnellRequest { command: u8, client_id: Box<[u8]>, location: Option<NetLocation> }
  async fn read_request<R: AsyncRead + Unpin>(reader: &mut StreamReader, stream: &mut R) -> std::io::Result<SnellRequest>
  async fn udp_relay(stream: SnellFramedStream<Box<dyn AsyncStream>>, leftover: &[u8], udp_enabled: bool, proxy_selector: &Arc<ClientProxySelector>) -> std::io::Result<TcpServerSetupResult>
  ```

- [ ] **Step 1: Write the failing test**

Add to `mod tests`:

```rust
    #[tokio::test]
    async fn snell_v6_udp_rejects_datagram_in_request_record() {
        let server = test_server(None, None);
        let client = test_client(Some("v6"), None);
        let (client_io, server_io) = duplex(65536);
        let mut framed = client.frame_stream(Box::new(client_io));
        // Request and first datagram in one write, so one v6 record.
        write_all(&mut framed, &[1, 6, 0, 0xde, 0xad]).await.unwrap();
        framed.flush().await.unwrap();
        let err = server
            .setup_server_stream(Box::new(server_io))
            .await
            .err()
            .expect("v6 UDP with a datagram in the request record must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib snell_v6_udp_rejects`
Expected: FAIL with "v6 UDP with a datagram in the request record must fail".

- [ ] **Step 3: Implement**

Add near `TCP_TUNNEL_RESPONSE`:

```rust
const CMD_PING: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_CONNECT_V2: u8 = 5;
const CMD_UDP: u8 = 6;

/// A parsed Snell request header.
struct SnellRequest {
    command: u8,
    /// Checked per request by the authentication sub-project (roadmap B).
    #[allow(dead_code)]
    client_id: Box<[u8]>,
    /// Destination of a connect request.
    location: Option<NetLocation>,
}

/// Reads one request header. Ping stops after the command byte, without
/// consuming its client-id bytes (snell-server v5.0.1, per sing-snell).
async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut StreamReader,
    stream: &mut R,
) -> std::io::Result<SnellRequest> {
    let version = reader.read_u8(stream).await?;
    if version != 1 {
        return Err(std::io::Error::other(format!(
            "unexpected snell version: {version}"
        )));
    }
    let command = reader.read_u8(stream).await?;
    if command == CMD_PING {
        return Ok(SnellRequest {
            command,
            client_id: Box::default(),
            location: None,
        });
    }
    if !matches!(command, CMD_CONNECT | CMD_CONNECT_V2 | CMD_UDP) {
        return Err(std::io::Error::other(format!(
            "Got unknown command: {command}"
        )));
    }
    let client_id_len = reader.read_u8(stream).await? as usize;
    let client_id: Box<[u8]> = reader.read_slice(stream, client_id_len).await?.into();
    if command == CMD_UDP {
        return Ok(SnellRequest {
            command,
            client_id,
            location: None,
        });
    }
    let hostname_len = reader.read_u8(stream).await? as usize;
    let hostname_and_port_bytes = reader.read_slice(stream, hostname_len + 2).await?;
    let hostname_str = match std::str::from_utf8(&hostname_and_port_bytes[0..hostname_len]) {
        Ok(s) => s,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode hostname: {e}"),
            ));
        }
    };
    let port = u16::from_be_bytes(hostname_and_port_bytes[hostname_len..].try_into().unwrap());
    Ok(SnellRequest {
        command,
        client_id,
        location: Some(NetLocation::new(Address::from(hostname_str)?, port)),
    })
}

/// Starts a UDP relay after a cmd 6 request. `leftover` holds bytes read
/// past the request header.
async fn udp_relay(
    mut stream: SnellFramedStream<Box<dyn AsyncStream>>,
    leftover: &[u8],
    udp_enabled: bool,
    proxy_selector: &Arc<ClientProxySelector>,
) -> std::io::Result<TcpServerSetupResult> {
    if !udp_enabled {
        return Err(std::io::Error::other("snell UDP requested but not enabled"));
    }
    // snell-server v6.0.0b4 (per sing-snell): the first datagram must not
    // share the request's record.
    if matches!(stream, SnellFramedStream::V6(_)) && !leftover.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UDP tunnel request",
        ));
    }
    let max_payload_len = stream.max_payload_len();
    write_all(&mut stream, UDP_READY_RESPONSE).await?;
    let peer = stream.peer_addr();
    let udp_stream = SnellUdpStream::new(Box::new(stream), max_payload_len).with_peer(peer);
    Ok(TcpServerSetupResult::MultiDirectionalUdp {
        stream: Box::new(udp_stream),
        need_initial_flush: true,
        proxy_selector: proxy_selector.clone(),
    })
}
```

In `setup_server_stream`, replace everything from `let max_payload_len = server_stream.max_payload_len();` through the end of the hostname/port parsing (`let remote_location = NetLocation::new(...)?;`) with:

```rust
        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let request =
            read_request(&mut stream_reader, &mut HeaderReader(&mut server_stream)).await?;
        let remote_location = match request.command {
            CMD_PING => {
                write_all(&mut server_stream, &[0x01]).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::other("responded to ping"));
            }
            CMD_UDP => {
                return udp_relay(
                    server_stream,
                    stream_reader.unparsed_data(),
                    self.udp_enabled,
                    &self.proxy_selector,
                )
                .await;
            }
            _ => request
                .location
                .expect("connect requests carry a location"),
        };
```

Delete the old `if !is_udp { ... } else { ... UDP_READY_RESPONSE ... }` structure: the h2mux check and the final `Ok(TcpServerSetupResult::TcpForward { ... })` stay, unindented one level, after the code above. Delete the now-unused `max_payload_len` local.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib snell`
Expected: all pass, including `snell_udp_relay_v4_client_auto_detect_server`, `snell_udp_relay_v6_client_auto_detect_server`, and the new test.

- [ ] **Step 5: Commit**

```bash
git add src/snell/snell_handler.rs
git commit -m "refactor(snell): share request parsing and reject v6 UDP datagrams in the request record

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `SnellTunnelStream`: deferred reply, session end, drain

**Files:**
- Modify: `src/snell/snell_handler.rs` (new constants, `TunnelWrite`, `SnellTunnelStream`; tests)

**Interfaces:**
- Consumes: `SnellFramedStream`, `UDP_READY_RESPONSE` (existing).
- Produces:
  ```rust
  const REMOTE_EOF_REPLY: &[u8]; const END_OF_FILE_REPLY: &[u8]; const DRAIN_LIMIT: usize;
  enum TunnelWrite { ReplyPending, ReplyStaged, Open, Ending { record: &'static [u8], close: bool }, Flushing { close: bool }, Draining, Closed }
  struct SnellTunnelStream { inner, reuse, write, read_eof, drained, scratch, udp_enabled, proxy_selector }
  impl SnellTunnelStream { fn new(inner: SnellFramedStream<Box<dyn AsyncStream>>, reuse: bool, udp_enabled: bool, proxy_selector: Arc<ClientProxySelector>) -> Self }
  impl AsyncRead, AsyncWrite, AsyncPing, AsyncStream for SnellTunnelStream
  ```

- [ ] **Step 1: Write the failing tests**

Add test helpers and tests to `mod tests`:

```rust
    const PSK: &[u8] = b"test-psk-12345";
    type Framed = SnellFramedStream<Box<dyn AsyncStream>>;

    fn framed_pair(v6: bool) -> (Framed, Framed) {
        let (a, b) = duplex(1 << 20);
        let frame = |io: tokio::io::DuplexStream| -> Framed {
            let io: Box<dyn AsyncStream> = Box::new(io);
            if v6 {
                SnellFramedStream::V6(V6Conn::new(
                    io,
                    Arc::from(PSK),
                    V6Codec::new(SnellV6Mode::Default, PSK),
                ))
            } else {
                SnellFramedStream::V4(V4Conn::new(io, Arc::from(PSK)))
            }
        };
        (frame(a), frame(b))
    }

    fn tunnel_pair(v6: bool, reuse: bool) -> (SnellTunnelStream, Framed) {
        let (server, peer) = framed_pair(v6);
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        (SnellTunnelStream::new(server, reuse, true, selector), peer)
    }

    async fn send_zero_chunk(conn: &mut Framed) {
        poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, &[]))
            .await
            .unwrap();
        conn.flush().await.unwrap();
    }

    async fn read_to_eof<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                return got;
            }
            got.extend_from_slice(&buf[..n]);
        }
    }

    /// True when a further read stays pending: a zero chunk, not a closed connection.
    async fn still_open(conn: &mut Framed) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            conn.read(&mut [0u8; 1]),
        )
        .await
        .is_err()
    }

    #[tokio::test]
    async fn tunnel_reply_rides_with_first_payload() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"data").await.unwrap();
            server.flush().await.unwrap();
            let mut record = [0u8; 64];
            let mut buf = ReadBuf::new(&mut record);
            poll_fn(|cx| Pin::new(&mut peer).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), b"\x00data", "v6={v6}");
        }
    }

    #[tokio::test]
    async fn tunnel_reply_survives_pending_inner_write() {
        for v6 in [false, true] {
            let (a, b) = duplex(64);
            let frame = |io: tokio::io::DuplexStream| -> Framed {
                let io: Box<dyn AsyncStream> = Box::new(io);
                if v6 {
                    SnellFramedStream::V6(V6Conn::new(
                        io,
                        Arc::from(PSK),
                        V6Codec::new(SnellV6Mode::Default, PSK),
                    ))
                } else {
                    SnellFramedStream::V4(V4Conn::new(io, Arc::from(PSK)))
                }
            };
            let selector = Arc::new(ClientProxySelector::new(Vec::new()));
            let mut server = SnellTunnelStream::new(frame(a), true, true, selector);
            let mut peer = frame(b);
            let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            let expected = [&[0u8][..], &payload].concat();
            let reader = tokio::spawn(async move {
                let mut got = vec![0u8; expected.len()];
                peer.read_exact(&mut got).await.unwrap();
                assert!(got == expected, "v6={v6}");
            });
            server.write_all(&payload).await.unwrap();
            server.flush().await.unwrap();
            reader.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reuse_shutdown_after_data_sends_zero_chunk() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"x").await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(read_to_eof(&mut peer).await, b"\x00x", "v6={v6}");
            assert!(still_open(&mut peer).await, "zero chunk, not close: v6={v6}");
        }
    }

    #[tokio::test]
    async fn reuse_shutdown_before_data_replies_remote_eof_and_closes() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.shutdown().await.unwrap();
            let got = read_to_eof(&mut peer).await;
            assert_eq!(got, REMOTE_EOF_REPLY, "v6={v6}");
            assert!(!still_open(&mut peer).await, "closed: v6={v6}");
            assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn single_shutdown_before_data() {
        let (mut server, mut peer) = tunnel_pair(false, false);
        server.shutdown().await.unwrap();
        assert_eq!(read_to_eof(&mut peer).await, END_OF_FILE_REPLY);
        let (mut server, mut peer) = tunnel_pair(true, false);
        server.shutdown().await.unwrap();
        assert!(read_to_eof(&mut peer).await.is_empty());
    }

    #[tokio::test]
    async fn single_shutdown_after_data_closes_without_zero_chunk() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, false);
            server.write_all(b"x").await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(read_to_eof(&mut peer).await, b"\x00x", "v6={v6}");
            assert!(!still_open(&mut peer).await, "closed: v6={v6}");
            assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn drain_discards_until_client_zero_chunk() {
        for v6 in [false, true] {
            let (mut server, mut peer) = tunnel_pair(v6, true);
            server.write_all(b"x").await.unwrap();
            server.shutdown().await.unwrap();
            peer.write_all(&[7u8; 1000]).await.unwrap();
            send_zero_chunk(&mut peer).await;
            assert_eq!(server.read(&mut [0u8; 64]).await.unwrap(), 0, "v6={v6}");
        }
    }

    #[tokio::test]
    async fn drain_errors_past_limit() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        server.write_all(b"x").await.unwrap();
        server.shutdown().await.unwrap();
        let writer = tokio::spawn(async move {
            let chunk = [7u8; 16 * 1024];
            for _ in 0..(DRAIN_LIMIT / chunk.len() + 1) {
                if peer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = peer.flush().await;
            peer
        });
        let err = server.read(&mut [0u8; 64]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        drop(server);
        let _ = writer.await;
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib snell`
Expected: compile errors — `SnellTunnelStream`, `REMOTE_EOF_REPLY`, `END_OF_FILE_REPLY`, `DRAIN_LIMIT` not found.

- [ ] **Step 3: Implement**

Add after `udp_relay`:

```rust
/// Reply when the remote ends a reusable session before sending anything.
const REMOTE_EOF_REPLY: &[u8] = b"\x02\x65\x0aRemote EOF";
/// v4/v5 reply when the remote ends a cmd 1 tunnel before sending anything.
const END_OF_FILE_REPLY: &[u8] = b"\x02\xff\x0bend of file";
/// Client bytes discarded after the server's zero chunk before giving up
/// (sing-snell `reuse.WaitingDiscardLimit`).
const DRAIN_LIMIT: usize = 0x80001;

/// Write side of one tunnel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelWrite {
    /// Nothing sent yet: the first payload carries the `0x00` reply.
    ReplyPending,
    /// `0x00 ++ payload` is staged in the inner stream; its count is owed.
    ReplyStaged,
    Open,
    /// Writing the session's last record: a zero chunk (`b""`) or an error reply.
    Ending { record: &'static [u8], close: bool },
    Flushing { close: bool },
    /// Zero chunk sent: client data is discarded until its zero chunk.
    Draining,
    /// The connection is closed.
    Closed,
}

/// A v4/v5/v6 server tunnel that replies and ends sessions as sing-snell
/// does. With `reuse` (cmd 5) the connection carries further requests.
struct SnellTunnelStream {
    inner: SnellFramedStream<Box<dyn AsyncStream>>,
    reuse: bool,
    write: TunnelWrite,
    read_eof: bool,
    drained: usize,
    scratch: Vec<u8>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
}

impl SnellTunnelStream {
    fn new(
        inner: SnellFramedStream<Box<dyn AsyncStream>>,
        reuse: bool,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
    ) -> Self {
        Self {
            inner,
            reuse,
            write: TunnelWrite::ReplyPending,
            read_eof: false,
            drained: 0,
            scratch: Vec::new(),
            udp_enabled,
            proxy_selector,
        }
    }
}

impl AsyncRead for SnellTunnelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write == TunnelWrite::Closed || this.read_eof || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.write == TunnelWrite::Draining {
            let mut tmp = [0u8; 4096];
            loop {
                let mut discard = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut discard))?;
                let n = discard.filled().len();
                if n == 0 {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.drained += n;
                if this.drained >= DRAIN_LIMIT {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snell: read too much data after request end",
                    )));
                }
            }
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.read_eof = buf.filled().len() == before;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SnellTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.write {
            TunnelWrite::ReplyPending => {
                this.scratch.clear();
                this.scratch.push(0x00);
                this.scratch.extend_from_slice(buf);
                this.write = TunnelWrite::ReplyStaged;
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                this.write = TunnelWrite::Open;
                Poll::Ready(Ok(n.saturating_sub(1)))
            }
            // The inner stream finishes the staged frame first and reports its count.
            TunnelWrite::ReplyStaged => {
                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                this.write = TunnelWrite::Open;
                Poll::Ready(Ok(n.saturating_sub(1)))
            }
            TunnelWrite::Open => Pin::new(&mut this.inner).poll_write(cx, buf),
            _ => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "snell session write side closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write == TunnelWrite::Closed {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    /// Ends the session's write side: a zero chunk after data (reuse), else
    /// an error reply or a close, per sing-snell.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            this.write = match this.write {
                TunnelWrite::ReplyPending if this.reuse => TunnelWrite::Ending {
                    record: REMOTE_EOF_REPLY,
                    close: true,
                },
                TunnelWrite::ReplyPending if matches!(this.inner, SnellFramedStream::V4(_)) => {
                    TunnelWrite::Ending {
                        record: END_OF_FILE_REPLY,
                        close: true,
                    }
                }
                TunnelWrite::ReplyPending => TunnelWrite::Flushing { close: true },
                TunnelWrite::ReplyStaged => {
                    ready!(Pin::new(&mut this.inner).poll_write(cx, &this.scratch))?;
                    TunnelWrite::Open
                }
                TunnelWrite::Open if this.reuse => TunnelWrite::Ending {
                    record: b"",
                    close: false,
                },
                TunnelWrite::Open => TunnelWrite::Flushing { close: true },
                TunnelWrite::Ending { record, close } => {
                    ready!(Pin::new(&mut this.inner).poll_write(cx, record))?;
                    TunnelWrite::Flushing { close }
                }
                TunnelWrite::Flushing { close: false } => {
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    TunnelWrite::Draining
                }
                TunnelWrite::Flushing { close: true } => {
                    ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                    ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
                    TunnelWrite::Closed
                }
                TunnelWrite::Draining | TunnelWrite::Closed => return Poll::Ready(Ok(())),
            };
        }
    }
}

impl AsyncPing for SnellTunnelStream {
    // A ping record could precede the deferred reply.
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for SnellTunnelStream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        AsyncStream::flow(&self.inner)
    }
}
```

Note: `SnellTunnelStream` is not constructed outside tests until Task 5; if the build warns `struct SnellTunnelStream is never constructed`, that warning disappears in Task 5 — do not add `allow`s.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib snell`
Expected: all pass. If `tunnel_reply_survives_pending_inner_write` fails for v6, the V6 inner write is not reporting the staged count on the follow-up call; stop and report rather than changing `V6Conn`.

- [ ] **Step 5: Commit**

```bash
git add src/snell/snell_handler.rs
git commit -m "feat(snell): add tunnel stream with deferred reply and session end

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Dispatch first requests and serve next requests

**Files:**
- Modify: `src/snell/snell_handler.rs` (`setup_server_stream` tail; `impl ReusableTcpStream for SnellTunnelStream`; `run_tcp_echo`; tests)

**Interfaces:**
- Consumes: `TcpSession`, `ReusableTcpStream`, `TcpServerSetupResult::ReusableTcpForward` (Task 2); `read_request`, `udp_relay`, `CMD_*` (Task 3); `SnellTunnelStream`, `TunnelWrite` (Task 4).
- Produces: `impl ReusableTcpStream for SnellTunnelStream`.

- [ ] **Step 1: Write the failing tests**

Replace the `let TcpServerSetupResult::TcpForward { ... } = result else { panic!(...) };` block in `run_tcp_echo` with:

```rust
            let reusable = matches!(result, TcpServerSetupResult::ReusableTcpForward { .. });
            let (remote_location, mut stream, connection_success_response) = match result {
                TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream,
                    connection_success_response,
                    ..
                } => (remote_location, stream, connection_success_response),
                TcpServerSetupResult::ReusableTcpForward { stream, session } => (
                    session.remote_location,
                    stream as Box<dyn AsyncStream>,
                    session.connection_success_response,
                ),
                _ => panic!("expected a TCP forward"),
            };
            assert_eq!(reusable, expect_reusable);
```

and give `run_tcp_echo` a final parameter `expect_reusable: bool`, moved into the server task. Update its callers: `snell_v3_client_auto_detect_server` passes `false`; every v4/v5/v6 caller passes `true` (the shoes client sends cmd 5 on v4+).

Add helpers and tests:

```rust
    fn request(cmd: u8) -> Vec<u8> {
        let mut r = vec![1, cmd, 0];
        if cmd == CMD_CONNECT || cmd == CMD_CONNECT_V2 {
            let host = b"example.com";
            r.push(host.len() as u8);
            r.extend_from_slice(host);
            r.extend_from_slice(&443u16.to_be_bytes());
        }
        r
    }

    /// Runs one data session to completion: reply, zero chunks both ways.
    async fn end_session(server: &mut SnellTunnelStream, peer: &mut Framed) {
        server.write_all(b"x").await.unwrap();
        server.shutdown().await.unwrap();
        assert_eq!(read_to_eof(peer).await, b"\x00x");
        send_zero_chunk(peer).await;
        assert_eq!(server.read(&mut [0u8; 8]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn next_request_connect_commands_continue() {
        for v6 in [false, true] {
            for cmd in [CMD_CONNECT_V2, CMD_CONNECT] {
                let (mut server, mut peer) = tunnel_pair(v6, true);
                end_session(&mut server, &mut peer).await;
                write_all(&mut peer, &request(cmd)).await.unwrap();
                peer.flush().await.unwrap();
                let next = Box::new(server).next_request().await.unwrap();
                let Some(TcpServerSetupResult::ReusableTcpForward { session, .. }) = next else {
                    panic!("expected another session: v6={v6} cmd={cmd}");
                };
                assert_eq!(session.remote_location.to_string(), "example.com:443");
                assert!(session.connection_success_response.is_none());
            }
        }
    }

    #[tokio::test]
    async fn next_request_udp_becomes_relay() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &request(CMD_UDP)).await.unwrap();
        peer.flush().await.unwrap();
        let next = Box::new(server).next_request().await.unwrap();
        assert!(matches!(next, Some(TcpServerSetupResult::MultiDirectionalUdp { .. })));
        let mut reply = [0u8; 1];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x00]);
    }

    #[tokio::test]
    async fn next_request_v6_udp_rejects_datagram_in_request_record() {
        let (mut server, mut peer) = tunnel_pair(true, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &[1, CMD_UDP, 0, 0xde, 0xad]).await.unwrap();
        peer.flush().await.unwrap();
        let err = Box::new(server).next_request().await.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn next_request_ping_pongs_and_closes() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &request(CMD_PING)).await.unwrap();
        peer.flush().await.unwrap();
        assert!(Box::new(server).next_request().await.unwrap().is_none());
        let mut pong = [0u8; 1];
        peer.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [0x01]);
    }

    #[tokio::test]
    async fn next_request_client_close_ends_quietly() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        drop(peer);
        assert!(Box::new(server).next_request().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn next_request_unknown_command_errors() {
        let (mut server, mut peer) = tunnel_pair(false, true);
        end_session(&mut server, &mut peer).await;
        write_all(&mut peer, &[1, 9, 0]).await.unwrap();
        peer.flush().await.unwrap();
        assert!(Box::new(server).next_request().await.is_err());
    }

    #[tokio::test]
    async fn first_cmd1_is_single_tunnel() {
        let server = test_server(None, None);
        let (client_io, server_io) = duplex(65536);
        let mut framed = test_client(Some("v4"), None).frame_stream(Box::new(client_io));
        write_all(&mut framed, &request(CMD_CONNECT)).await.unwrap();
        framed.flush().await.unwrap();
        let result = server.setup_server_stream(Box::new(server_io)).await.unwrap();
        let TcpServerSetupResult::TcpForward {
            connection_success_response,
            ..
        } = result
        else {
            panic!("cmd 1 must be a single TcpForward");
        };
        assert!(connection_success_response.is_none(), "reply is deferred");
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib snell`
Expected: compile error — `next_request` not found for `Box<SnellTunnelStream>`.

- [ ] **Step 3: Implement**

Replace the final `Ok(TcpServerSetupResult::TcpForward { ... })` of `setup_server_stream` (after the h2mux check) with:

```rust
        let initial_remote_data = stream_reader.unparsed_data_owned();
        if matches!(server_stream, SnellFramedStream::V3(_)) {
            return Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                connection_failure_response: None,
                initial_remote_data,
                proxy_selector: self.proxy_selector.clone(),
            });
        }

        // v4+: the tunnel stream sends the reply with the first remote payload.
        let reuse = request.command == CMD_CONNECT_V2;
        let stream = SnellTunnelStream::new(
            server_stream,
            reuse,
            self.udp_enabled,
            self.proxy_selector.clone(),
        );
        if reuse {
            return Ok(TcpServerSetupResult::ReusableTcpForward {
                stream: Box::new(stream),
                session: TcpSession {
                    remote_location,
                    need_initial_flush: true,
                    connection_success_response: None,
                    connection_failure_response: None,
                    initial_remote_data,
                    proxy_selector: self.proxy_selector.clone(),
                },
            });
        }
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(stream),
            need_initial_flush: true,
            connection_success_response: None,
            connection_failure_response: None,
            initial_remote_data,
            proxy_selector: self.proxy_selector.clone(),
        })
```

Add after the `impl AsyncStream for SnellTunnelStream` block:

```rust
#[async_trait]
impl ReusableTcpStream for SnellTunnelStream {
    /// Serves the next request after a clean session, as sing-snell's reuse
    /// loop does: connect (cmd 1 or 5) continues, UDP becomes the final
    /// session, ping pongs and closes, TCP EOF closes quietly.
    async fn next_request(
        mut self: Box<Self>,
    ) -> std::io::Result<Option<TcpServerSetupResult>> {
        if self.write == TunnelWrite::Closed {
            return Ok(None);
        }
        let mut stream_reader = StreamReader::new_with_buffer_size(400);
        let mut header = HeaderReader(&mut self.inner);
        match stream_reader.peek_u8(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let request = read_request(&mut stream_reader, &mut header).await?;
        match request.command {
            CMD_PING => {
                write_all(&mut self.inner, &[0x01]).await?;
                self.inner.flush().await?;
                Ok(None)
            }
            CMD_UDP => {
                let this = *self;
                udp_relay(
                    this.inner,
                    stream_reader.unparsed_data(),
                    this.udp_enabled,
                    &this.proxy_selector,
                )
                .await
                .map(Some)
            }
            _ => {
                let remote_location = request
                    .location
                    .expect("connect requests carry a location");
                if let Address::Hostname(host) = remote_location.address()
                    && host == MUX_DESTINATION_HOST
                    && remote_location.port() == MUX_DESTINATION_PORT
                {
                    return Err(std::io::Error::other("snell: h2mux on a reused connection"));
                }
                self.write = TunnelWrite::ReplyPending;
                self.read_eof = false;
                self.drained = 0;
                let session = TcpSession {
                    remote_location,
                    need_initial_flush: true,
                    connection_success_response: None,
                    connection_failure_response: None,
                    initial_remote_data: stream_reader.unparsed_data_owned(),
                    proxy_selector: self.proxy_selector.clone(),
                };
                Ok(Some(TcpServerSetupResult::ReusableTcpForward {
                    stream: self,
                    session,
                }))
            }
        }
    }
}
```

Update the import: `use crate::tcp::tcp_handler::{ReusableTcpStream, TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult, TcpSession};`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib snell && cargo build`
Expected: all pass; no warnings about unused `SnellTunnelStream`.

- [ ] **Step 5: Commit**

```bash
git add src/snell/snell_handler.rs
git commit -m "feat(snell): serve reused connections and defer v4+ tunnel replies

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: End-to-end reuse through `process_stream`

**Files:**
- Modify: `src/snell/snell_handler.rs` (`mod tests`: echo connector, selector, e2e tests)

**Interfaces:**
- Consumes: `crate::tcp::tcp_server::process_stream(stream, Arc<dyn TcpServerHandler>, Arc<dyn Resolver>)`; `SocketConnector`, `ClientProxyChain`, `ClientChainGroup`, `InitialHopEntry`, `ConnectRule`, `ConnectAction`, `NetLocationMask::ANY`; Task 4/5 test helpers (`Framed`, `request`, `send_zero_chunk`, `read_to_eof`).

- [ ] **Step 1: Write the tests**

Add to `mod tests`:

```rust
    /// Serves every connect from a fresh echo task (or refuses it).
    struct EchoConnector {
        refuse: bool,
    }

    #[async_trait]
    impl crate::tcp::socket_connector::SocketConnector for EchoConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            if self.refuse {
                return Err(std::io::ErrorKind::ConnectionRefused.into());
            }
            let (ours, mut theirs) = duplex(1 << 20);
            tokio::spawn(async move {
                let mut data = Vec::new();
                if theirs.read_to_end(&mut data).await.is_ok() {
                    let _ = theirs.write_all(&data).await;
                    let _ = theirs.shutdown().await;
                }
            });
            Ok(Box::new(ours))
        }

        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// A raw client connection to a Snell server running in `process_stream`.
    fn connect_e2e(
        version: &str,
        mode: Option<&str>,
        refuse: bool,
    ) -> (Framed, tokio::task::JoinHandle<std::io::Result<()>>) {
        use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
        use crate::client_proxy_selector::{ConnectAction, ConnectRule};
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(EchoConnector { refuse }))],
            vec![],
        );
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::ANY],
            ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
        )]));
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let server = SnellServerHandler::new(
            cipher,
            "test-psk-12345",
            true,
            selector,
            resolver.clone(),
            None,
            mode,
        );
        let (client_io, server_io) = duplex(1 << 20);
        let task = tokio::spawn(crate::tcp::tcp_server::process_stream(
            server_io,
            Arc::new(server),
            resolver,
        ));
        let framed = test_client(Some(version), mode).frame_stream(Box::new(client_io));
        (framed, task)
    }

    /// One session: request + payload, zero chunk, everything until EOF.
    async fn e2e_session(conn: &mut Framed, cmd: u8, payload: &[u8]) -> Vec<u8> {
        write_all(conn, &[request(cmd), payload.to_vec()].concat()).await.unwrap();
        send_zero_chunk(conn).await;
        read_to_eof(conn).await
    }

    fn e2e_cases() -> [(&'static str, Option<&'static str>); 5] {
        [
            ("v4", None),
            ("v5", None),
            ("v6", None),
            ("v6", Some("unshaped")),
            ("v6", Some("unsafe-raw")),
        ]
    }

    #[tokio::test]
    async fn reuse_serves_mixed_sessions_then_ping() {
        for (version, mode) in e2e_cases() {
            let (mut conn, task) = connect_e2e(version, mode, false);
            for (i, cmd) in [CMD_CONNECT_V2, CMD_CONNECT, CMD_CONNECT_V2].into_iter().enumerate() {
                let payload = format!("session {i}");
                let got = e2e_session(&mut conn, cmd, payload.as_bytes()).await;
                assert_eq!(got, [b"\x00", payload.as_bytes()].concat(), "{version} {mode:?} #{i}");
            }
            write_all(&mut conn, &request(CMD_PING)).await.unwrap();
            conn.flush().await.unwrap();
            assert_eq!(read_to_eof(&mut conn).await, [0x01], "{version} {mode:?} pong");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pipelined_request_is_served() {
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            write_all(&mut conn, &[request(CMD_CONNECT_V2), b"one".to_vec()].concat())
                .await
                .unwrap();
            send_zero_chunk(&mut conn).await;
            // Second request goes out before the first reply is read.
            write_all(&mut conn, &[request(CMD_CONNECT_V2), b"two".to_vec()].concat())
                .await
                .unwrap();
            send_zero_chunk(&mut conn).await;
            assert_eq!(read_to_eof(&mut conn).await, b"\x00one", "{version} {mode:?}");
            assert_eq!(read_to_eof(&mut conn).await, b"\x00two", "{version} {mode:?}");
        }
    }

    #[tokio::test]
    async fn large_payload_round_trips() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            let got = e2e_session(&mut conn, CMD_CONNECT_V2, &payload).await;
            assert_eq!(got[0], 0x00, "{version} {mode:?}");
            assert!(got[1..] == payload[..], "{version} {mode:?}");
        }
    }

    #[tokio::test]
    async fn fifty_sessions_on_one_connection() {
        for (version, mode) in e2e_cases() {
            let (mut conn, _task) = connect_e2e(version, mode, false);
            for i in 0..50u32 {
                let payload = i.to_be_bytes();
                let got = e2e_session(&mut conn, CMD_CONNECT_V2, &payload).await;
                assert_eq!(got, [&[0u8][..], &payload].concat(), "{version} {mode:?} #{i}");
            }
        }
    }

    #[tokio::test]
    async fn refused_connect_replies_remote_eof() {
        for (version, mode) in e2e_cases() {
            let (mut conn, task) = connect_e2e(version, mode, true);
            let got = e2e_session(&mut conn, CMD_CONNECT_V2, b"x").await;
            assert_eq!(got, REMOTE_EOF_REPLY, "{version} {mode:?}");
            assert!(task.await.unwrap().is_err(), "connect failure is reported");
        }
    }

    #[tokio::test]
    async fn client_disconnect_ends_connection() {
        let (mut conn, task) = connect_e2e("v4", None, false);
        write_all(&mut conn, &[request(CMD_CONNECT_V2), b"half".to_vec()].concat())
            .await
            .unwrap();
        conn.flush().await.unwrap();
        drop(conn);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("server task must finish after the client disconnects")
            .unwrap()
            .ok();
    }
```

- [ ] **Step 2: Run them**

Run: `cargo test --lib snell -- --nocapture`
Expected: all pass. A hang means a session did not end: check that `forward_tcp` was called with `reuse: true` and that the echo task saw EOF.

- [ ] **Step 3: Run the wider regression set**

Run: `cargo test --lib tcp_server && cargo test --test integration snell`
Expected: all pass (`tests/cases/integration/snell_integration.rs`, including `test_snell_multiple_requests`).

- [ ] **Step 4: Commit**

```bash
git add src/snell/snell_handler.rs
git commit -m "test(snell): end-to-end connection reuse through process_stream

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Docs

**Files:**
- Modify: `README.md` (Snell compatibility bullets)
- Modify: `docs/src/content/docs/protocols/snell.md`, `docs/src/content/docs/zh-cn/protocols/snell.md`
- Modify: `docs/superpowers/specs/2026-11-09-snell-sing-snell-parity-roadmap.md` (row A status)

- [ ] **Step 1: README**

Replace the bullet starting `- **Snell v4, v5, and v6 (server)**:` with:

```markdown
- **Snell v4, v5, and v6 (server)**: Connection reuse (Connect v2) and UDP-over-TCP, with tunnel and error replies matching sing-snell / snell-server. Auto-detection only considers v4+ when the cipher is `aes-128-gcm`; other ciphers are served as v3.
```

Replace the bullet starting `- **shoes Snell client**:` with:

```markdown
- **shoes Snell client**: Speaks v4 with `aes-128-gcm` and v3 with other ciphers; the version cannot be chosen and connections are not pooled. A v4 client cannot reach shoes servers older than v0.3.8 or real Snell v3 servers, so use another cipher there.
```

- [ ] **Step 2: Snell docs pages**

In `docs/src/content/docs/protocols/snell.md` replace `Each connection serves one request; reused connections are not supported.` with `Connect v2 (reuse) is supported: one connection can carry many requests, as with sing-snell.`

In `docs/src/content/docs/zh-cn/protocols/snell.md` replace `每个连接只处理一个请求，不支持连接复用。` with `支持 Connect v2（连接复用）：一个连接可承载多个请求，与 sing-snell 一致。`

- [ ] **Step 3: Roadmap**

In row A of the roadmap table, change the last cell to `` `2026-11-09-snell-server-connection-reuse-design.md` (done) ``.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/src/content/docs/protocols/snell.md docs/src/content/docs/zh-cn/protocols/snell.md docs/superpowers/specs/2026-11-09-snell-sing-snell-parity-roadmap.md
git commit -m "docs(snell): document server connection reuse

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
