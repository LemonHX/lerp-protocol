# 05 · Connection Establishment

## 概述

lerp 连接建立分为两个阶段：

1. **Relay 阶段**：通过 relay 建立初始连接，保证可达性
2. **直连阶段**（仅 lerp-daemon）：通过 relay 信道交换地址，尝试 P2P 打洞，迁移到直连

lerp-client（浏览器）只执行阶段 1，永远走 relay。

---

## 阶段 1：通过 Relay 建立连接

```
发起方 (A)                    Relay                    接收方 (B)
   │                             │                          │
   │  ① 计算 routing_token       │                          │
   │  ② WebTransport 连接        │                          │
   │ ──────────────────────────► │                          │
   │                             │  Relay 解密 SNI          │
   │                             │  得到 endpoint_id        │
   │                             │                          │
   │                             │ ◄──────────────────────  │
   │                             │  B 已连接，等待配对       │
   │                             │                          │
   │                             │  Relay 配对两个连接       │
   │                             │  建立双向字节管道         │
   │                             │                          │
   │  ③ E2E 握手（经 relay 传输） │                          │
   │ ◄──────────────────────────────────────────────────── │
   │   [双方验证对方 endpoint_id] │                          │
   │                             │                          │
   │  ④ 连接建立，可传输应用数据   │                          │
   │ ◄──────────────────────────────────────────────────── │
```

### E2E 加密握手

lerp 在 relay 建立的字节管道之上，执行**基于 Ed25519 的端对端加密握手**，与 relay 的 TLS 独立：

1. 双方各自生成临时 ECDH 密钥对（X25519）
2. 使用各自的 Ed25519 私钥对 ECDH 公钥签名
3. 交换签名后的 ECDH 公钥
4. 双方验证对方的签名，确认对方持有与 `endpoint_id` 对应的私钥
5. 用 ECDH 协商出会话密钥（ChaCha20-Poly1305）
6. 后续所有数据在此会话密钥保护下传输

这一步保证：
- Relay 无法解密任何应用层内容
- 连接只能建立在持有正确私钥的 endpoint 之间
- 即使 Relay 被攻击者控制，也无法中间人攻击（MITM）

> 发起方使用 ticket 中的 `lerp_eid` 验证接收方身份；接收方可选择是否验证发起方身份（应用层决定）。

---

## 阶段 2：P2P 打洞（仅 lerp-daemon）

在 E2E 加密连接建立后，双方通过已建立的加密信道交换各自的直连候选地址：

```
// 在 E2E 加密信道内发送（Relay 看不到内容）
{
  "addrs": ["1.2.3.4:51820", "192.168.1.5:51820", "[2001:db8::1]:51820"]
}
```

### 打洞流程

```
1. A 通过 relay 信道发送自己的地址列表给 B
2. B 通过 relay 信道发送自己的地址列表给 A
3. 双方同时向对方的所有候选地址发送 UDP 探测包（打洞）
4. 某条路径探测成功（双向 UDP 可达）
5. A 向 B 的内嵌 WebTransport 服务器发起 QUIC 连接
6. 复用 E2E 握手验证对端身份（Ed25519 签名），确认是同一 endpoint
7. 直连路径建立 → Relay 连接保留作兜底，直连断开时自动回退
```

### 候选地址来源

- 本机所有网卡 IP，端口为 lerp-daemon 内嵌 WebTransport 服务器的 `quic_port`
- 通过 relay 的 QAD（QUIC Address Discovery）获得的外网 IP（端口同上）
- ticket `lerp_dir` 中指定的静态直连地址

> 每个候选地址指向对端的 lerp-daemon 内嵌 WebTransport 服务器，打洞成功后发起方直接向该服务器建立 QUIC 连接。

### 打洞成功率

- 锥形 NAT（Full Cone / Restricted Cone）：成功率极高
- 对称 NAT（Symmetric NAT）：两端均为对称 NAT 时，打洞不可能，回落relay

---

## 连接状态机

```
INIT
  │
  ▼
CONNECTING_RELAY        ← 计算 routing_token，发起 WebTransport 连接
  │
  ▼
HANDSHAKING             ← Hello/HelloAck，ver 协商 + E2E 密钥协商
  │
  ▼
ESTABLISHED             ← 连接建立，可传输数据（relay 路径）
  │       │
  │       ▼
  │    PROBING           ← （仅 daemon）交换 AddrOffer，UDP 探测
  │       │
  │       ▼
  │    UPGRADING         ← DirectUpgrade + 直连握手
  │       │
  │       ▼
  │    DIRECT            ← 直连为主路径，relay 作兜底
  │
  ▼
RECONNECTING            ← Ping 连续超时，重连 relay
  │
  ▼
CLOSED
```

> 详细消息级状态机见 [09-internal-protocol.md](09-internal-protocol.md)。

---

## 连接复用

同一对 endpoint 之间，多次调用 `lerp.connect()` 默认**复用已有连接**，在其上开新的双向流（`open_bi()`），而非建立新的 WebTransport 连接。

- 减少握手次数
- 减少 relay 上的连接数
- 直连优化路径自动共享

---

## 路径迁移与流一致性（v0）

v0 采用 **make-before-break** 迁移语义：

- `DIRECT` 建立后，仅**新创建**的 `open_bi()` 数据流走直连路径
- 已在 relay 路径上的 in-flight 流**不迁移**，保持原路径直到自然结束
- 不做“半开流强制搬迁”，避免重复、乱序和应用层语义破坏

一致性保证：
- **单条流内有序**（由底层传输保证）
- **跨流不保证全局顺序**（应用若需要全局顺序，需自行编号）

---

## 重连与状态恢复（v0）

`RECONNECTING → CONNECTING_RELAY` 成功后，v0 **不提供会话恢复/流恢复**：

- 断链前的 `open_bi()` 视为失效，统一以连接中断错误返回给应用
- 应用需重新建立逻辑会话并按需重开流
- 建议应用协议具备幂等、重放去重或断点续传能力

---

## 单 Relay 可用性边界（v0）

- v0 的 ticket 仅支持单个 `lerp_rly`
- 该 relay 故障时，新连接无法建立（已建立直连可继续，直连断开后仍会受影响）
- 实践上建议应用分发多张 ticket（每张指向不同 relay）作为手动/应用层 failover
