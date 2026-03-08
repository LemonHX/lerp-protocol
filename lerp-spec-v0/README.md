# lerp Specification v0

> 线性插值（Linear Interpolation）—— 在两点之间找路。

lerp 是一个点对点加密通信协议，目标是让任意两个节点之间建立端到端加密的双向流，同时对现有网络基础设施（防火墙、NAT、CDN、DPI）完全透明。

---

## 文档结构

| 文件 | 内容 |
|---|---|
| [01-overview.md](01-overview.md) | 设计哲学、职责边界、术语定义 |
| [02-identity.md](02-identity.md) | Endpoint 身份、密钥体系 |
| [03-ticket.md](03-ticket.md) | Ticket 格式完整规范 |
| [04-relay.md](04-relay.md) | Relay 协议、盲化路由令牌、WebTransport |
| [05-connection.md](05-connection.md) | 连接建立流程、E2E 加密握手、打洞 |
| [06-lerp-daemon.md](06-lerp-daemon.md) | lerp-daemon 规范（系统守护进程） |
| [07-lerp-client.md](07-lerp-client.md) | lerp-client 规范（浏览器） |
| [08-security.md](08-security.md) | 安全分析、威胁模型 |
| [09-internal-protocol.md](09-internal-protocol.md) | LPP 内部协议、消息定义、状态机 |
| [10-hrelay.md](10-hrelay.md) | hrelay-server：HTTP 反向代理 Relay，浏览器直接访问 lerp 后端服务 |

---

## 核心原则

1. **Ticket 即一切** —— 持有 ticket 即持有连接能力，无需知道对方 IP/端口
2. **Relay 零状态** —— Relay 是纯函数，无存储，无注册，可水平扩展
3. **E2E 加密** —— Relay 只做盲转发，无法解密任何内容
4. **对现有基建透明** —— 流量外观为标准 HTTPS，通过任何防火墙/CDN
5. **管道而非框架** —— lerp 只建流，管道里跑什么由应用自己决定

---

## 统一术语约定

| 术语 | 统一含义 |
|---|---|
| endpoint | 一个身份实例（Ed25519 密钥对），由 endpoint_id 唯一标识 |
| connection | 两端点之间的一条 WebTransport 连接（可经 relay 或直连） |
| session | LPP/E2E 握手建立后的加密会话上下文（含协商版本与会话密钥） |
| stream | WebTransport 流；`open_uni()` 用于控制消息，`open_bi()` 用于应用数据 |
| relay path | 经 relay 转发的连接路径，始终可作为兜底 |
| direct path | daemon↔daemon 打洞成功后的直连路径 |
| daemon profile | 支持 `AO/PS/DU/DA`，可进入 `PROBING/UPGRADING/DIRECT` |
| client profile | relay-only，不发送 `AO/PS/DU/DA` |

---

## v0 Normative Checklist

以下清单用于实现自测。关键词含义：
- **MUST**：必须满足，否则不兼容 v0
- **SHOULD**：强烈建议，若不满足需有明确理由

### MUST

- MUST 使用 `Ed25519` 作为 endpoint 身份密钥，`endpoint_id = Ed25519 公钥`（见 [02-identity.md](02-identity.md)）
- MUST 按 `routing_token = endpoint_id XOR BLAKE3(relay_secret || time_bucket)[:32]` 生成 SNI 令牌（见 [04-relay.md](04-relay.md)）
- MUST 在 relay 端同时接受 `current/previous time_bucket`，并以 `endpoint_id` 作为配对键（见 [04-relay.md](04-relay.md)）
- MUST 执行 E2E 握手（Hello/HelloAck + Ed25519 签名验证 + X25519 ECDH）后才允许传输应用数据（见 [05-connection.md](05-connection.md), [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 在 `Hello/HelloAck` 中协商 `ver`，版本不兼容时关闭连接（见 [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 将 `Close` 作为最高优先级事件处理；`Close` 之后忽略 AO/PS/DU/DA/PI/PO（见 [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 在 daemon↔daemon 双方 `ProbeSuccess` 后按 `endpoint_id` 字典序选主发 `DU`（见 [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 采用 v0 迁移语义：直连建立后仅新 `open_bi()` 走直连，旧流不迁移（见 [05-connection.md](05-connection.md), [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 在重连后重新握手；v0 不恢复旧流与旧会话密钥（见 [05-connection.md](05-connection.md), [09-internal-protocol.md](09-internal-protocol.md)）
- MUST 将 ticket 视为敏感凭证；`BLAKE3[:4]` 仅做损坏检测，不作为防篡改机制（见 [03-ticket.md](03-ticket.md)）

### SHOULD

- SHOULD 对 Relay 配对实现原子“取等待连接 + 配对”以避免竞态双配对（见 [04-relay.md](04-relay.md)）
- SHOULD 使用“连续丢失 + 静默窗口”联合判定断连，降低 datagram 误判（见 [09-internal-protocol.md](09-internal-protocol.md), [08-security.md](08-security.md)）
- SHOULD 在应用层对 ticket 实施 `exp/nbf/jti` 校验和撤销列表（见 [03-ticket.md](03-ticket.md)）
- SHOULD 预置多张 ticket（不同 relay）作为 v0 的应用层 failover（见 [05-connection.md](05-connection.md), [08-security.md](08-security.md)）

---

## 版本

本文档描述 lerp 协议 **v0**（`lerp_ver: "0.1.0-dev"`）。
