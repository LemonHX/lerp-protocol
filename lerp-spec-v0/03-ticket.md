# 03 · Ticket

## 概述

ticket 是 lerp 的**能力凭证**。持有 ticket 即持有连接目标 endpoint 的全部必要信息。ticket out-of-band 分发（二维码、链接、文件等），不经过任何 lerp 网络协议传输。

---

## 编码格式

```
msgpack_payload = msgpack(fields)
wire            = blake3(msgpack_payload)[:4] || msgpack_payload
ticket          = base64url(wire)
```

1. 将所有字段用 **MessagePack** 序列化
2. 对 msgpack 字节序列计算 **BLAKE3**，取前 **4 字节**作为校验前缀（用于快速检测损坏）
3. `4字节校验 || msgpack_payload` 整体做 **base64url**（RFC 4648，无 padding）编码，得到最终字符串

---

## MessagePack 字段结构

使用短字符串 key（仿 JWT 风格），所有 `lerp_` 前缀字段为保留字段。

```
{
  // ── 必填 ────────────────────────────────────────
  "lerp_ver": <str>,       // lerp 协议版本，当前为 "0.1.0-dev"
  "lerp_eid": <str>,       // endpoint_id，base32 编码的 Ed25519 公钥（52字符）

  // ── 可选（至少提供其中一个用于寻址） ─────────────
  "lerp_rly": <str>,       // relay URL，如 "relay.example.com"
  "lerp_sec": <bytes 32>,  // relay_secret，32字节随机数
  "lerp_dir": <str[]>,     // 直连地址列表，如 ["1.2.3.4:7777", "[::1]:7777"]

  // ── 应用自定义字段（不使用 lerp_ 前缀） ──────────
  // 任意 key-value，lerp 协议栈完全忽略，由应用自行解析
  // 例如：
  // "user_id": "alice",
  // "app_ver": "2.0.0",
  // "invite_code": "XXXX"
}
```

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `lerp_ver` | `str` | ✅ | lerp 协议版本号，实现方应校验兼容性 |
| `lerp_eid` | `str` | ✅ | 目标 endpoint 的 Ed25519 公钥，base32 编码 |
| `lerp_rly` | `str` | 可选 | relay 服务器地址，用于中继连接 |
| `lerp_sec` | `bytes` | 可选 | relay_secret，与 `lerp_rly` 配合使用 |
| `lerp_dir` | `str[]` | 可选 | 直连候选地址列表，用于 P2P 打洞 |

- `lerp_rly` 和 `lerp_sec` 必须同时存在或同时缺失
- `lerp_dir` 缺失时仅通过 relay 连接，不尝试直连
- 应用自定义字段使用非 `lerp_` 前缀的任意 key

---

## 解析流程

```
输入: ticket_string (base64url)

1. base64url_decode(ticket_string) → wire
2. checksum = wire[:4]
   payload  = wire[4:]
3. if blake3(payload)[:4] != checksum → 拒绝，ticket 损坏
4. fields = msgpack_decode(payload)
5. 校验 fields["lerp_ver"] 兼容性
6. 校验 fields["lerp_eid"] 为合法 base32 Ed25519 公钥
7. 返回解析结果
```

---

## Ticket 扩展性

ticket 是**应用级凭证**，不仅仅是 lerp 的路由信息载体。应用可以在 ticket 中携带任意业务数据, **请注意安全**，不要在 ticket 中放置敏感信息（如用户密码、私钥等），因为 ticket 可能被日志记录或泄露。

```json
{
  "lerp_ver": "0.1.0-dev",
  "lerp_eid": "a3f9b2c1...",
  "lerp_rly": "relay.example.com",
  "lerp_sec": "<bytes>",

  "app_info1": "value1",
  "app_info2": "value2",
}
```

Relay 和 lerp 协议栈只读取 `lerp_*` 字段，其余字段透明传递，由应用自行解释。

### app_fields 的生命周期与转发

ticket 中的应用自定义字段（非 `lerp_` 前缀）不仅供发起方本地使用，**lerp 协议栈会在发起连接时自动将其填入 `Hello.meta` 字段转发给接收方**，接收方通过 `on_connect` 回调获取：

```
发起方 ticket.app_fields
    └─→ Hello.meta（经 relay TLS 保护传输）
             └─→ 接收方 on_connect(peer_eid, meta)
```

这使得接收方无需额外握手即可获得连接上下文（如邀请码、用户标识、应用版本等），常见用途：

- 接入鉴权：校验 `meta` 中的邀请码或 token，决定是否接受连接
- 路由分发：根据 `meta` 中的应用标识将连接分配给不同处理逻辑
- 审计日志：记录连接发起时携带的业务元数据

**约束：**
- `meta` 在 E2E 加密建立**之前**传输（受 relay TLS 保护，不受端到端密钥保护）
- 不应在 `meta` / `app_fields` 中放置需要端到端机密性的数据
- lerp 对 `meta` 内容无格式限制，接收方负责全部校验

---

## 安全注意事项

- ticket 包含 `relay_secret`，**相当于连接凭证**，泄露即意味着任何人都可以向目标 endpoint 发起连接
- ticket 应视为敏感数据，不应明文记录日志、不应用于 URL query string（建议用 fragment `#`）
- ticket 本身不含过期时间，应用如需有效期控制，可在自定义字段中加入 `expires` 并在应用层校验
- BLAKE3 校验前缀（4字节）仅用于检测意外损坏，不提供防篡改保证——ticket 的真实安全由 E2E 加密握手保证

---

## 生命周期与撤销（v0 约定）

v0 不内建协议级过期/撤销；推荐应用在自定义字段中实现：

```json
{
  "exp": 1712345678,      // 过期时间（Unix 秒）
  "nbf": 1712340000,      // 生效时间（Unix 秒）
  "jti": "invite-uuid"   // 唯一票据 ID（可用于撤销列表）
}
```

推荐策略：
- 连接建立后先做应用层鉴权：校验 `nbf/exp/jti`
- 服务端维护 `jti` 撤销列表（deny-list）
- 发生泄露时轮换 `relay_secret`，使旧 ticket 全部失效

> 以上为 v0 兼容做法，不改变 ticket 基础编码格式。
