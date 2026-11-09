# Snell server: native connection reuse (Connect v2)

Date: 2026-11-09
Status: revised to match sing-snell; awaiting re-review

## Goal

A shoes Snell server on v4/v5/v6 framing behaves like the sing-snell server
for connection reuse and tunnel replies, so Surge and sing-box clients that
pool connections work against shoes exactly as they do against sing-snell.

Reference: `reF1nd/sing-snell@e056cb336137` (pinned by
`reF1nd/sing-box@e7c5f20`): `snellv5/server.go`, `snellv5/reuse.go` (v4/v5),
`snellv6/server.go`, `snellv6/reuse.go`, `internal/reuse/reuse.go`. Its
comments map each behavior to snell-server v5.0.1 / v6.0.0b4. meow-rs
`crates/meow-proxy/src/snell/protocol.rs` confirms the client side.

Success: a client runs several sessions over one connection, mixing cmd 5
and cmd 1, and ending with UDP or ping, and every byte on the wire —
reply placement, zero chunks, error replies, closes — matches what
sing-snell does for the same input.

## Scope

This is sub-project A of the sing-snell parity roadmap
(`docs/superpowers/specs/2026-11-09-snell-sing-snell-parity-roadmap.md`).

In (v4, v5, v6 framing only):
- server reuse loop started by cmd 5;
- tunnel reply deferred to the first remote payload, for cmd 1 and cmd 5;
- error replies and close behavior on remote EOF;
- client-data drain after the server's zero chunk;
- shoes client reads the reply lazily (required by the deferred reply).

Out, each a separate follow-up:
- **Authentication** (`users`, `multi_user_authentication` userkey/psk, salt
  replay cache, v6 PSK length 12..255) — next spec. This spec only keeps the
  request's client ID so that spec can check it per request.
- Client connection pool; v3 framing (Snell v1–v3) behavior; h2mux (shoes
  only; unchanged).

## Wire behavior to match

Records, salts, and nonces are unchanged: the server writes its salt on its
first write and its AEAD stream continues across sessions.

Request: `[0x01 version, cmd, client-id-len, client-id..., host-len, host...,
port u16]`. Ping (cmd 0) ends after the 3-byte prefix; its client-id bytes
are not consumed.

Replies: tunnel `0x00`; pong `0x01`; error `[0x02, code, msg-len, msg...]`.

### First request

| cmd | Behavior |
|---|---|
| 0 ping | write pong `0x01`, close (unchanged) |
| 1 connect | single session, reply deferred (below); on remote EOF close the connection — no zero chunk. If nothing was sent yet: v4/v5 reply `[0x02, 0xff, 11, "end of file"]` then close; v6 just closes |
| 5 connect v2 | reuse session loop (below) |
| 6 UDP | immediate `0x00`, UDP relay (unchanged), except v6: if the first datagram starts in the same decrypted record as the request, close (`invalid UDP tunnel request`) |
| h2mux destination | unchanged |

### Deferred tunnel reply (cmd 1 and cmd 5)

Nothing is written on connect. The first remote payload is written as one
record containing `0x00` followed by the payload. Connect failure is
reported like a remote EOF with nothing sent (the handler closes, which
triggers the EOF path).

### Reuse session (cmd 5)

Per session:
1. Forward with the deferred reply.
2. Remote EOF (or connect failure):
   - reply already sent → write a zero chunk; the session's write side is
     done;
   - nothing sent → write `[0x02, 0x65, 10, "Remote EOF"]` and close the
     connection (no further sessions).
3. Client zero chunk → client→remote direction ends (remote write half
   closed).
4. If the server's zero chunk went first, client records are discarded
   until the client's zero chunk; more than `0x80001` bytes discarded closes
   the connection ("read too much data after request end").
5. When both directions are done, read the next request on the same stream:
   - TCP EOF before a request → close quietly;
   - cmd 1 or cmd 5 → next session (cmd 1 here is reusable too, as in Go);
   - cmd 6 → same v6 same-record check as a first request, then write
     `0x00`; the connection becomes a UDP relay (final);
   - cmd 0 → write pong, close;
   - an h2mux destination, anything else, bad version, or decode error →
     close.

No idle timeout between sessions (Go has none; the connection lives until
the client closes it or an error occurs).

## Components

### `src/tcp/tcp_handler.rs`

```rust
/// Per-session forward parameters: the `TcpForward` fields minus the stream.
pub struct TcpSession {
    pub remote_location: NetLocation,
    pub need_initial_flush: bool,
    pub connection_success_response: Option<Box<[u8]>>,
    pub connection_failure_response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
    pub initial_remote_data: Option<Box<[u8]>>,
    pub proxy_selector: Arc<ClientProxySelector>,
}

/// A server stream that can carry another request after a clean session.
#[async_trait]
pub trait ReusableTcpStream: AsyncStream {
    /// Read the next request. `None` closes the connection.
    async fn next_request(self: Box<Self>) -> std::io::Result<Option<TcpServerSetupResult>>;
}

// New variant:
ReusableTcpForward { stream: Box<dyn ReusableTcpStream>, session: TcpSession },
```

`set_need_initial_flush` sets `session.need_initial_flush` for the new
variant. `TcpForward` and its 34 construction sites are unchanged.

### `src/tcp/tcp_server.rs`

- Move the `TcpForward` arm body unchanged into
  `forward_tcp(server_stream: &mut dyn AsyncStream, session: TcpSession,
  source, resolver, setup_timeout, reuse: bool) -> io::Result<bool>`.
  It returns `Ok(true)` when the copy finished cleanly. With `reuse`, only
  the remote stream is shut down afterwards; otherwise both, as today.
  Local DNS wraps `&mut *server_stream` in `PrependStream` (borrowed, so the
  server stream survives the session). `send_connect_failure` takes
  `&mut dyn AsyncStream`.
- The setup-result `match` becomes a loop. `ReusableTcpForward`: call
  `forward_tcp(.., reuse: true)`; on `Ok(true)` call
  `stream.next_request()`; `Some(result)` → loop on that result (which may
  be another `ReusableTcpForward` or a UDP result); `None` or `Ok(false)` →
  return.

### `src/snell/snell_handler.rs`

- `read_request(reader, stream, version: u8) -> io::Result<SnellRequest>`:
  the existing parser, shared by first and later requests.
  `SnellRequest { command: u8, client_id: Box<[u8]>, location:
  Option<NetLocation> }`. Ping returns after the prefix.
- `SnellTunnelStream`: owns the framed stream (V4 or V6 only) plus
  `proxy_selector`, `udp_enabled`, `max_payload_len`, and a mode
  (`Single` for cmd 1, `Reuse` for cmd 5). It implements `AsyncStream`
  and, in `Reuse` mode, `ReusableTcpStream`. Per-session state:
  - reply: `Pending` → first non-empty write sends `0x00 ++ payload` as one
    inner write (returns consumed − 1; if the inner write pends, the staged
    frame finishes on the next call) → `Sent`;
  - shutdown: `Reuse` + `Sent` → zero chunk + flush, start draining;
    `Reuse` + `Pending` → `Remote EOF` error reply, flush, close inner,
    `Aborted`; `Single` → (v4/v5 + `Pending`: `end of file` error reply,
    flush) then close inner, `Closed`;
  - read: `Aborted`/`Closed` → EOF; draining → discard until EOF, erroring
    past `0x80001` bytes; otherwise delegate, remembering EOF.
  - `next_request` (state is reset first): read the first byte (EOF →
    `None`), then `read_request` via message reads like the first request;
    dispatch per the table above. The session's
    `connection_success_response` is `None` — the stream writes the reply.
- First request on V4/V6 framing: cmd 5 → `ReusableTcpForward`; cmd 1 →
  `TcpForward` with a `Single` `SnellTunnelStream` and no success response.
  UDP on V6 framing: if the header read left unparsed bytes from the
  request's record, return an `InvalidData` error ("invalid UDP tunnel
  request"). V3 framing, other UDP, ping, and h2mux keep today's code.

### `SnellClientHandler`

`setup_client_tcp_stream` no longer waits for the reply. It returns the
framed stream wrapped so the first `poll_read` consumes the reply: `0x00`
→ continue; `0x02` → read `[code, len, msg]` and fail with
`io::Error::other("snell error 0x<code>: <msg>")`; other → error. This
also stops v4+ shoes clients deadlocking against sing-snell and
snell-server, which already defer the reply.

## Error handling

Every error closes the connection; nothing is retried.

| Case | Result |
|---|---|
| Connect failure (cmd 5) | `Remote EOF` error reply, close |
| Connect failure (cmd 1) | v4/v5 `end of file` error reply, close; v6 close |
| Policy block | same as connect failure (shutdown with no reply sent) |
| Copy error | close |
| > `0x80001` bytes drained | close |
| Bad next request | close |

## Testing

Unit (`snell_handler.rs` tests, duplex + `V4Conn`/`V6Conn` peers):
- reply and first payload arrive in one record; pending inner write path
  (tiny duplex) still reports correct counts;
- cmd 5: shutdown after data → zero chunk, peer reads EOF, connection
  usable; shutdown before data → `Remote EOF` reply, later reads EOF;
- cmd 1: shutdown before data → `end of file` reply (v4) / plain close
  (v6); after data → close with no zero chunk;
- drain discards until the client's zero chunk; errors past the cap;
- `next_request`: cmd 5 and cmd 1 → `ReusableTcpForward`; cmd 6 → UDP
  result after `0x00`; cmd 0 → pong then `None`; TCP EOF → `None`;
  unknown cmd → error; v6 UDP with a datagram in the request record →
  error, first request and reused;
- client: stream returned before any reply; `Remote EOF` reply surfaces as
  an error on first read;
- existing `run_tcp_echo` tests accept either forward variant and assert
  v3 → `TcpForward`, v4+ cmd 5 → `ReusableTcpForward`.

End to end (in crate): `process_stream` on a `tokio::io::duplex` end with a
real `SnellServerHandler` and a test `SocketConnector` that serves each
connect from a fresh echo task. A raw `V4Conn` client (and `V6Conn` in each
mode) runs cmd 5, cmd 1, cmd 5 on one connection, then ping; each session
checks reply, echo, and EOF. Plus: connect refused → `Remote EOF`.

Regression: `cargo test --lib snell`, `tcp_server` lifetime tests, and
`tests/integration.rs` Snell cases.

Not covered: live Surge / sing-box interop (none in CI).
