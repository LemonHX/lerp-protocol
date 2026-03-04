# 07 · lerp-client（浏览器）

## 概述

lerp-client 是 lerp 协议的浏览器实现，以 JavaScript/WebAssembly 库的形式分发，无需用户安装任何软件。

核心差异（对比 lerp-daemon）：
- 不转发本机端口，暴露**双向流 API**给网页应用
- **永远走 relay**，不支持 P2P 打洞
- endpoint_id 私钥存储于浏览器 **IndexedDB**（持久化）或 **sessionStorage**（会话级）

---

## 安装

```html
<script type="module">
  import { lerp } from 'https://cdn.lerp.dev/v0/lerp.js'
</script>
```

或通过 npm：

```
npm install @lerp/client
```

---

## Endpoint 管理

```js
import { lerp } from '@lerp/client'

// 生成新的 endpoint（首次调用，持久化存储到 IndexedDB）
const endpoint = await lerp.newEndpoint()
console.log(endpoint.id)  // base32 编码的 endpoint_id

// 加载已有 endpoint（通过 endpoint_id 查找）
const endpoint = await lerp.loadEndpoint(endpointId)

// 列出所有本地 endpoint
const endpoints = await lerp.listEndpoints()

// 删除 endpoint（连同私钥）
await lerp.deleteEndpoint(endpointId)
```

---

## 发起连接

```js
// 从 ticket 字符串解析并连接
const conn = await endpoint.connect(ticketString)

// conn 是一个 WebTransport 双向流，暴露 Web Streams API
conn.readable  // ReadableStream<Uint8Array>
conn.writable  // WritableStream<Uint8Array>

// 读取数据
const reader = conn.readable.getReader()
const { value, done } = await reader.read()

// 写入数据
const writer = conn.writable.getWriter()
await writer.write(new TextEncoder().encode('hello'))
await writer.close()

// 关闭连接
await conn.close()
```

---

## 接受连接

lerp-client 也可以接受来自其他 endpoint 的连接：

```js
// 生成自己的 ticket（供对端使用）
const ticket = await endpoint.ticket({
  relay: 'relay.example.com',
  // relaySecret 由本地 endpoint 生成（或应用层预置）并写入 ticket
})

// 监听传入连接
// incoming() 产出的对象包含 conn、peerEid 以及对端 ticket 中的 app_fields（meta）
for await (const { conn, peerEid, meta } of endpoint.incoming()) {
  // meta 是对端 ticket 中的应用自定义字段，lerp 透明转发，应用自行校验
  if (!isAuthorized(meta)) {
    await conn.close()
    continue
  }
  handleConnection(conn)
}
```

### connect() 返回值补充

发起方连接成功后同样可拿到接收方的 endpoint_id：

```js
const { conn, peerEid } = await endpoint.connect(ticketString)
// peerEid 与 ticket 中的 lerp_eid 一致（经 E2E 握手验证）
```

---

## 多 Endpoint 并发

```js
// 同一页面可持有多个 endpoint
const e1 = await lerp.loadEndpoint(id1)
const e2 = await lerp.loadEndpoint(id2)

// 各自独立连接/接受，互不影响
const conn1 = await e1.connect(ticket1)
const conn2 = await e2.connect(ticket2)
```

---

## 私钥存储

| 存储方式 | 生命周期 | 适用场景 |
|---|---|---|
| IndexedDB（默认） | 持久化，跨会话 | 长期身份，Local-first App |
| sessionStorage | 当前标签页会话 | 临时身份，一次性用途 |
| 内存（不持久化） | 当前页面生命周期 | 纯临时，测试 |

私钥使用 Web Crypto API 的 `SubtleCrypto.importKey()` 以 non-extractable 模式存储，防止 JS 代码直接读取原始私钥字节。

---

## 为什么不支持 P2P 打洞

浏览器沙箱限制：

1. **无法监听 UDP 端口**：WebTransport 只支持浏览器作为 QUIC client，无法作为 server
2. **无法发送原始 UDP 包**：打洞需要向多个候选地址同时发包，浏览器不支持
3. **WebRTC 虽有 ICE**：但引入信令服务器、STUN、TURN 等完整基础设施，且对称 NAT 下成功率仅约 70-80%，剩余流量仍需 TURN 中转

结论：relay 的可预期延迟优于引入 WebRTC 的复杂度。lerp-client 永远走 relay。

---

## Local-first Web App 模式

lerp-client 天然适合构建 local-first 应用：

```js
// 数据存 IndexedDB，完全 offline 可用
const db = await openDB('my-app', 1)

// 需要同步时，通过 lerp 建立加密流
const conn = await endpoint.connect(peerTicket)

// 在流上跑任意同步协议（CRDT、自定义协议等）
const sync = new MyCRDTSyncProtocol(conn)
await sync.run()
```

特性：
- **Offline first**：数据在本地，断网正常工作
- **无中心化后端**：对端可以是另一个浏览器或 lerp-daemon
- **ticket 即权限**：无账号体系，无服务器存储用户数据
- **对端可信验证**：E2E 握手确认对端 endpoint_id，无法中间人伪造
