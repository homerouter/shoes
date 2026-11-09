---
title: "Snell"
description: "shoes snell v3–v6 配置。"
---

**完整示例：** [snell.yaml](/zh-cn/examples/snell/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
  version: string              # 可选：v3、v4、v5、v6。未设置或无法识别：自动检测
  mode: string                 # 可选，仅 v6：default、unshaped、unsafe-raw
```

v4、v5 和 v6 始终使用 `aes-128-gcm`；只有当 `cipher` 为 `aes-128-gcm` 时自动检测才会考虑它们。每个连接只处理一个请求，不支持连接复用。

启用 `udp_enabled` 时，服务端还会在同一 UDP 端口上为设置了 `block-quic=off` 的 Surge 客户端开启 QUIC 代理监听。它始终使用 `aes-128-gcm`。设置 `udp_enabled: false` 可将其关闭。

<a id="client"></a>
## 客户端

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

客户端无法选择版本：使用 `aes-128-gcm` 时为 v4，使用其他加密方式时为 v3。
