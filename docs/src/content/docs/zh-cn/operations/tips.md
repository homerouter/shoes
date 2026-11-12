---
title: "使用技巧"
description: "shoes提示配置。"
---

### 生成密钥

**Reality 密钥对：**
```bash
shoes generate-reality-keypair
```

**可选的 Reality 后量子身份验证密钥：**
```bash
shoes generate-reality-mldsa65-keypair
```
在服务器上保留`mldsa65_seed`；仅向客户端分发 `mldsa65_verify`。

**Shadowsocks 2022 密码：**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID：**
```bash
uuidgen
```

**TLS 证书指纹：**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### 安全最佳实践

- 使用强随机密码
- 确保私钥安全
- 使用 `127.0.0.1` 而不是 `0.0.0.0` 进行仅限本地访问
- 使用防火墙规则来限制访问
- 为敏感服务启用客户端证书身份验证
- 将 Vision 与 Reality 结合使用可实现最大程度的隐私保护

### 性能技巧

- 对 TLS-in-TLS 场景启用 `vision: true`
- 使用 `tcp_settings.no_delay: true` 实现低延迟
- 设置 `quic_settings.num_endpoints` 以匹配工作线程
- 对高延迟或有损网络使用 QUIC 传输

### Linux 内存与连接调优

在 Linux 上，`shoes` 二进制文件会在启动时配置进程内存与套接字超时默认值，无需修改宿主机的 sysctl 或 sysfs 设置：

- **进程级禁用 THP：** 启动构造函数会调用 `prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)`，防止开启了 `transparent_hugepage/enabled=always` 的宿主机为稀疏分配器区段或线程栈分配 2 MiB 匿名大页（`/proc/<pid>/status` 中显示 `THP_enabled: 0`）。
- **低内存 VPS 的 jemalloc 默认配置：** Linux 构建导出 `_rjem_malloc_conf`，默认设为 `background_thread:true,narenas:2,dirty_decay_ms:1000,thp:never`，以控制 arena 开销并及时归还空闲页。
- **TCP 用户超时：** 在 Linux 和 Android 上，启用了 keepalive 的入站和出站 TCP 套接字会将 `TCP_USER_TIMEOUT` 设为 120 秒，确保携带未确认数据的连接在对端失联后及时关闭。

在多核或高并发主机上，可通过 `_RJEM_MALLOC_CONF` 覆盖 jemalloc 参数（由于 `tikv-jemallocator` 使用 `_rjem_` 前缀构建，`MALLOC_CONF` 会被忽略）。可通过 `-t` 按可用 CPU 和内存调整工作线程数；准入上限配置请参阅[全局设置](/zh-cn/config/global-settings/)和[低内存 VPS Snell 示例](/zh-cn/examples/small_vps_snell/)：

```bash
# Restore automatic CPU-scaled arena count (`narenas:0`) and limit workers to 2 threads
_RJEM_MALLOC_CONF=narenas:0 shoes -t 2 config.yaml
```

### 常见问题

- **“地址已在使用中”**：更改端口或停止冲突服务
- **“权限被拒绝”**：端口 < 1024 需要 root/admin
- **Reality 连接失败**：验证密钥匹配、UUID 匹配、SNI 匹配服务器的 real_targets 密钥
- **Vision 不起作用**：确保内部协议为 VLESS
- **配置验证失败**：使用 `--dry-run` 运行以获取详细错误
