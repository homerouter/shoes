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
  password: string
  udp_enabled: true            # Default: true
  version: string              # Optional: v3, v4, v5, v6. Unset or unrecognized: auto-detect
  mode: string                 # Optional, v6 only: default, unshaped, unsafe-raw
```

v4, v5, and v6 always use `aes-128-gcm`; auto-detection only considers them when `cipher` is `aes-128-gcm`. Each connection serves one request; reused connections are not supported.

With `udp_enabled`, the server also opens a QUIC proxy listener on the same UDP port for Surge clients with `block-quic=off`. It always uses `aes-128-gcm`. Set `udp_enabled: false` to turn it off.

## Client

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

The client cannot choose a version: it speaks v4 with `aes-128-gcm` and v3 with other ciphers.
