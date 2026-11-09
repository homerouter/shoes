# Snell: sing-snell parity roadmap

Date: 2026-11-09

Goal: shoes' Snell server and client behave like sing-snell
(`reF1nd/sing-snell@e056cb336137`, used by `reF1nd/sing-box@e7c5f20`), whose
comments map behavior to snell-server v5.0.1 and v6.0.0b4. Each sub-project
gets its own spec, plan, and review.

Order: A, G, B, D, F, E, C. The interop test (G) comes second so every
later sub-project is checked against real sing-snell; D closes an open
security gap.

| # | Sub-project | sing-snell reference | shoes today | Spec |
|---|---|---|---|---|
| A | Server connection reuse, deferred replies, error replies, drain, v6 UDP same-record check | `snellv5/server.go`, `snellv5/reuse.go`, `snellv6/server.go`, `snellv6/reuse.go`, `internal/reuse` | one request per connection, immediate reply | `2026-11-09-snell-server-connection-reuse-design.md` (done) |
| B | Authentication: `users`, `multi_user_authentication` (`userkey` per-request client ID; `psk` per-user PSK by ranked trial decryption), salt replay cache (2 × 500k bloom, fp 1e-10), v6 PSK length 12..255 | `internal/multiuser`, `MultiService` in `snellv5`/`snellv6`, `option/snell.go` | single PSK, no replay check | to write |
| C | Obfuscation: HTTP simple-obfs on the v5 server (TLS obfs rejected, ShadowTLS recommended); HTTP/TLS obfs on the client | `obfs.go`, sing-box `transport/simple-obfs` | none | to write |
| D | QUIC proxy: authenticated init, NAT with idle timeout, v6 inbound accepting the v5 QUIC proxy wire format | `quic_proxy.go`, sing-box `protocol/snell/quic_auth.go`, `quic_nat.go` | `quic_proxy.rs` forwards by source address only | to write |
| E | Client: version choice v1–v6 (`legacy/` for v1–v3), `reuse` pool (180 s max age, 20 s timer), obfs, QUIC proxy client, lazy reply | `legacy/`, `snellv4/client.go`, `snellv4/reuse.go`, `snellv6/client.go`, sing-box `protocol/snell/outbound.go` | v3/v4 fixed by cipher, no pool | to write |
| F | v6 wire parity: handshake, mixing, shaping profile, salt | `snellv6/handshake.go`, `mixing.go`, `profile.go`, `shaped.go`, `salt.go` | ported from meow-rs, never compared | to write |
| G | Interop verification: optional-peer tests running sing-box (fork) as Snell server and client against shoes | sing-box `test/snell_test.go` | Mihomo v3 peer test only | to write |

Notes:
- The sing-box inbound serves versions 5 and 6 (v4 clients use the v5
  server). sing-snell has no v1–v3 server, so shoes' v3 server has no
  parity target and stays as is.
- G is the only way to show behavior matches rather than matching on paper;
  this machine has no Go or Docker, so G runs where a sing-box binary is
  provided (like the Mihomo peer test).
