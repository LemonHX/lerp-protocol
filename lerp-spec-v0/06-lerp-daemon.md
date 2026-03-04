# 06 · lerp-daemon

## 概述

lerp-daemon 是 lerp 协议的系统守护进程实现，设计为长期稳定运行于服务器、开发机、k8s sidecar 等环境。对本机应用**完全透明**——应用只认 localhost，不需要任何改造。

---

## 运行环境

- Linux（systemd service）
- macOS（launchd）
- Windows（Windows Service）
- k8s sidecar container
- Docker 容器

---

## 多 Endpoint 管理

lerp-daemon 可同时持有任意多个 endpoint_id，每个 endpoint_id 独立管理：

```
~/.lerp/keys/
  ├── <eid1_base32>.key    ← endpoint 1 私钥
  ├── <eid2_base32>.key    ← endpoint 2 私钥
  └── ...
```

每个 endpoint_id 可同时：
- **接受**来自其他 endpoint 的连接
- **发起**到其他 endpoint 的连接

不同 endpoint_id 之间完全隔离，共享同一个进程及 relay 的底层 QUIC 连接。

---

## 内嵌 WebTransport 服务器

lerp-daemon 在本机启动一个 **WebTransport 服务器**（基于 QUIC），监听外部 UDP 端口，供其他 lerp-daemon 在打洞成功后直接建立 P2P 连接，完全绕过 relay。

### 为什么需要内嵌服务器

- P2P 打洞的本质是「让对端的 UDP 包能穿透本机 NAT 并到达本机某个端口」
- 打洞成功后，连接双方需要各自有一个能够接受 QUIC 握手的服务器端
- lerp-client（浏览器）没有监听能力，因此只有 lerp-daemon 可以做直连

### 监听地址

```
0.0.0.0:<quic_port>    ← IPv4
[::]:<quic_port>       ← IPv6（双栈）
```

`quic_port` 默认随机分配，也可在配置文件中固定：

```toml
[daemon]
quic_port = 51820    # 可选，不填则自动选择
```

### TLS 证书

直连路径使用自签名证书，证书公钥由 **endpoint 的 Ed25519 私钥派生**（转换为 X25519 后生成 TLS 密钥对）：

- 证书内容对任何第三方毫无意义
- 对端通过 E2E 握手（Ed25519 签名验证）确认身份，不依赖证书链
- 证书有效期可设置较长（如 1 年），私钥不变则证书固定不变

### 候选地址广播

打洞阶段，lerp-daemon 将以下地址作为「直连候选」发送给对端：

```json
{
  "addrs": [
    "<本机内网 IP>:<quic_port>",
    "<NAT 外网 IP>:<quic_port>",
    "<IPv6 地址>:<quic_port>"
  ]
}
```

外网 IP 通过 relay 的 QUIC Address Discovery（QAD）获取。

### 直连握手

打洞成功后，发起方向接收方的 WebTransport 服务器发起连接，复用**相同的 E2E 握手流程**（见 [05-connection.md](05-connection.md)），不需要任何新密钥协商。原有 relay 信道上协商好的会话可以迁移，也可以在直连上重新握手。

---

## 本地 API（IPC）

lerp-daemon 通过本地 Unix socket（Linux/macOS）或 Named Pipe（Windows）暴露控制 API，供 CLI 工具和应用进行管理操作。

API 使用 MessagePack over Unix socket。

### 主要操作

```
// 生成新 endpoint
lerp-daemon new-endpoint
→ { "eid": "<base32>" }

// 列出所有 endpoint
lerp-daemon list-endpoints
→ [{ "eid": "...", "created_at": ... }, ...]

// 生成 ticket
lerp-daemon ticket --eid <eid> [--relay <url>] [--dir <addr>...]
→ { "ticket": "<base64url>" }

// 发布本机服务（接受连接并转发到 localhost）
lerp-daemon serve --eid <eid> --forward localhost:<port>

// 连接远端服务（发起连接并在本地监听）
lerp-daemon connect --ticket <ticket> --local-port <port>

// 查看当前连接状态
lerp-daemon status
```

---

## 发布模式（Serve）

lerp-daemon 监听来自 relay 的连接，建立 E2E 加密信道后，将流量透明转发到 `localhost:<port>`：

```
[远端 lerp-daemon/lerp-client]
        ↓ E2E 加密流
      relay
        ↓ E2E 加密流
  lerp-daemon (本机)
        ↓ 明文 TCP
  localhost:<port>（本机应用）
```

配置示例（将本机 8080 端口发布到 endpoint E1）：

```toml
# ~/.lerp/config.toml

[[serve]]
eid     = "a3f9b2c1..."
forward = "localhost:8080"
```

### on_connect 回调与 meta

收到连接时，lerp-daemon 在建立转发之前触发 `on_connect` 回调，应用可据此决定是否接受本次连接：

```toml
[[serve]]
eid     = "a3f9b2c1..."
forward = "localhost:8080"
# 可选：连接接入时执行的鉴权脚本（stdin 收到 JSON，stdout 返回 {"accept": true/false}）
on_connect_hook = "/usr/local/bin/lerp-auth"
```

hook 进程的 stdin 收到：

```json
{
  "peer_eid": "<base32>",
  "meta": { ...ticket 中的 app_fields... }
}
```

stdout 应返回：

```json
{ "accept": true }
// 或
{ "accept": false, "reason": "unauthorized" }
```

`accept: false` 时 lerp-daemon 发送 `Close(reason="rejected")` 并断开连接，不建立转发。

---

## 连接模式（Connect）

lerp-daemon 持有 ticket，主动连接目标 endpoint，并在本地开一个 TCP 监听端口，供本机应用连接：

```
本机应用
  └─ localhost:<local_port>（TCP）
       └─ lerp-daemon（本机）
            └─ E2E 加密流
                 └─ relay
                      └─ E2E 加密流
                           └─ lerp-daemon（对端）
                                └─ localhost:<remote_port>（对端应用）
```

配置示例：

```toml
[[connect]]
ticket     = "<base64url>"
local_port = 5678
```

---

## P2P 打洞

连接建立后，lerp-daemon 自动尝试 P2P 打洞（见 [05-connection.md](05-connection.md)）：

1. 收集本机所有网卡地址（结合内嵌 WebTransport 服务器的 `quic_port`）
2. 向 relay 发送 QAD 请求获取外网 IP
3. 通过 E2E 信道与对端交换候选地址列表
4. 双向 UDP 探测，协商直连路径
5. 打洞成功 → 发起方向对端内嵌 WebTransport 服务器发起直连
6. 直连建立后，relay 路径作兜底保留

直连建立后的连接延迟通常大幅降低。若网络条件变化（NAT 重置、IP 变更），自动回落到 relay 并重新尝试打洞。
