---
title: "Tips"
description: shoes tips configuration.
---

### Generate Keys

**Reality keypair:**
```bash
shoes generate-reality-keypair
```

**Optional Reality post-quantum authentication keys:**
```bash
shoes generate-reality-mldsa65-keypair
```
Keep `mldsa65_seed` on the server; distribute only `mldsa65_verify` to clients.

**Shadowsocks 2022 password:**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID:**
```bash
uuidgen
```

**TLS certificate fingerprint:**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### Security Best Practices

- Use strong, random passwords
- Keep private keys secure
- Use `127.0.0.1` instead of `0.0.0.0` for local-only access
- Use firewall rules to restrict access
- Enable client certificate authentication for sensitive services
- Use Vision with Reality for maximum privacy

### Performance Tips

- Enable `vision: true` for TLS-in-TLS scenarios
- Use `tcp_settings.no_delay: true` for low latency
- Set `quic_settings.num_endpoints` to match worker threads
- Use QUIC transport for high-latency or lossy networks

### Linux Memory and Connection Tuning

On Linux, the `shoes` binary configures process memory and socket timeouts at
startup without changing host sysctl or sysfs settings:

- **Process THP disabled:** A startup constructor calls
  `prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)` so hosts with
  `transparent_hugepage/enabled=always` do not back sparse allocator extents or
  thread stacks with 2 MiB anonymous huge pages (`THP_enabled: 0` in
  `/proc/<pid>/status`).
- **Small-VPS jemalloc defaults:** Linux builds export
  `_rjem_malloc_conf` with
  `background_thread:true,narenas:2,dirty_decay_ms:1000,thp:never` to cap arena
  overhead and return freed pages promptly.
- **TCP user timeout:** On Linux and Android, keepalive-enabled inbound and
  outbound TCP sockets set `TCP_USER_TIMEOUT` to 120 seconds so connections with
  unacknowledged data close promptly when a peer disappears.

On higher-core or multi-tenant hosts, override jemalloc options through
`_RJEM_MALLOC_CONF` (`MALLOC_CONF` is ignored because `tikv-jemallocator` builds
with the `_rjem_` prefix). Use `-t` to match worker threads to available CPU and
memory; see [global settings](/config/global-settings/) and the
[small-VPS Snell example](/examples/small_vps_snell/) for admission caps:

```bash
# Restore automatic CPU-scaled arena count (`narenas:0`) and limit workers to 2 threads
_RJEM_MALLOC_CONF=narenas:0 shoes -t 2 config.yaml
```

### Common Issues

- **"Address already in use"**: Change port or stop conflicting service
- **"Permission denied"**: Ports < 1024 require root/admin
- **Reality connection fails**: Verify keys match, UUID matches, SNI matches server's reality_targets key
- **Vision not working**: Ensure inner protocol is VLESS
- **Config validation fails**: Run with `--dry-run` for detailed errors
