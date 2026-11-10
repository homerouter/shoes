---
title: "Snell"
description: shoes snell v3–v6 configuration.
---

**Complete example:** [snell.yaml](/examples/snell/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string             # Shared PSK; omit with multi_user_authentication: psk
  udp_enabled: true            # Default: true
  version: string              # Optional: v3, v4, v5, v6. Unset or unrecognized: auto-detect
  mode: string                 # Optional, v6 only: default, unshaped, unsafe-raw
  multi_user_authentication: string  # Optional with users: userkey (default) or psk
  users:                       # Optional; requires version v4/v5/v6 and aes-128-gcm
    - name: string             # Optional, shown in logs
      userkey: string          # userkey mode: 1-255 bytes, sent by the client per request
      password: string         # psk mode: this user's PSK
```

v4, v5, and v6 always use `aes-128-gcm`; auto-detection only considers them when `cipher` is `aes-128-gcm`. Connect v2 (reuse) is supported: one connection can carry many requests, as with sing-snell.

With `udp_enabled`, the server also opens a QUIC proxy listener on the same UDP port for Surge clients with `block-quic=off`. It always uses `aes-128-gcm`. Set `udp_enabled: false` to turn it off.

QUIC proxy sessions end 60 seconds after the client's last packet. A repeated init on a live session keeps the session's original target, as in sing-box.

### Users

With `users`, set an explicit `version`. In `userkey` mode every client shares `password` and sends its `userkey` with each request; requests without a known key are closed. In `psk` mode each user has their own `password` (no shared one); the server finds the user by trying each key. `psk` mode does not support v6 `unsafe-raw`. The QUIC proxy listener authenticates users the same way.

v4/v5 servers refuse a connection whose salt was seen recently (replay protection), as snell-server does. With `version: v6`, every PSK must be 12 to 255 bytes.

## Client

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

The client cannot choose a version: it speaks v4 with `aes-128-gcm` and v3 with other ciphers.
