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
  password: string             # 共享 PSK；multi_user_authentication: psk 时省略
  udp_enabled: true            # Default: true
  version: string              # 可选：v3、v4、v5、v6。未设置或无法识别：自动检测
  mode: string                 # 可选，仅 v6：default、unshaped、unsafe-raw
  multi_user_authentication: string  # 可选，需配合 users：userkey（默认）或 psk
  users:                       # 可选；需要 version v4/v5/v6 且 cipher 为 aes-128-gcm
    - name: string             # 可选，用于日志
      userkey: string          # userkey 模式：1-255 字节，客户端每个请求都会发送
      password: string         # psk 模式：该用户的 PSK
```

v4、v5 和 v6 始终使用 `aes-128-gcm`；只有当 `cipher` 为 `aes-128-gcm` 时自动检测才会考虑它们。支持 Connect v2（连接复用）：一个连接可承载多个请求，与 sing-snell 一致。

启用 `udp_enabled` 时，服务端还会在同一 UDP 端口上为设置了 `block-quic=off` 的 Surge 客户端开启 QUIC 代理监听。它始终使用 `aes-128-gcm`。设置 `udp_enabled: false` 可将其关闭。

QUIC 代理会话在客户端最后一个包之后 60 秒结束。存活会话上重复的 init 沿用会话原来的目标，与 sing-box 一致。

### 用户

配置 `users` 时必须显式设置 `version`。`userkey` 模式下所有客户端共用 `password`，并在每个请求中发送自己的 `userkey`；未知的 key 会被断开。`psk` 模式下每个用户有自己的 `password`（不设共享密码），服务器逐个尝试密钥来识别用户。`psk` 模式不支持 v6 `unsafe-raw`。QUIC 代理监听以同样方式认证用户。

v4/v5 服务器会拒绝近期出现过的 salt（防重放），与 snell-server 一致。设置 `version: v6` 时，所有 PSK 必须为 12 到 255 字节。

<a id="client"></a>
## 客户端

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

客户端无法选择版本：使用 `aes-128-gcm` 时为 v4，使用其他加密方式时为 v3。
