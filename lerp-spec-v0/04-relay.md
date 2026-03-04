# 04 · Relay Protocol

## Relay 的角色

Relay 是 lerp 网络中的**无状态中继节点**，职责极其有限：

```
收到连接 → 解密 SNI 得到 endpoint_id → 转发到目标 endpoint → 结束
```

Relay 的三个不：
- **不存储**任何连接状态
- **不解密**任何应用层内容（E2E 加密，Relay 无密钥）
- **不要求** endpoint 提前注册或心跳

---

## 传输层：WebTransport over HTTP/3

```
Relay 监听: 0.0.0.0:443
协议:        HTTP/3 (QUIC over UDP)
外观:        对 DPI 和防火墙来说是普通 HTTPS 流量
```

两个 endpoint 均**作为 WebTransport client** 连接到 Relay，Relay 作为 WebTransport server。Relay 在两个连接之间建立双向字节管道。

连接 URL 格式：

```
https://<routing_token>.relay.example.com/<任意path>
                ↑
         Relay 只看这个子域名
```

Relay 只解析 SNI（从 TLS ClientHello 的 SNI 扩展字段提取子域名），**不解析 URL path**，path 对 Relay 完全透明。

---

## 盲化路由令牌（Blind Routing Token）

### 问题

若将 `endpoint_id` 明文放入 SNI 子域名，观察者可直接读取，得知通信目标。

### 解法

对 `endpoint_id` 用 `relay_secret` 派生的密钥流做一次性加密（OTP），使 SNI 对观察者不可解读，但 Relay 可直接解密还原。

### 算法

**发送方生成 routing_token：**

```
keystream     = BLAKE3(relay_secret || time_bucket)[:32]
routing_token = endpoint_id XOR keystream          // 32 字节
SNI           = base32(routing_token) + "." + relay_host
```

**Relay 解密还原 endpoint_id：**

```
token_bytes   = base32_decode(SNI 子域名部分)
keystream     = BLAKE3(relay_secret || time_bucket)[:32]
endpoint_id   = token_bytes XOR keystream
```

Relay 是纯函数，无需任何查表或存储。

### time_bucket

```
time_bucket = floor(unix_timestamp_seconds / window_seconds)
```

- `window_seconds` 默认为 **600**（10 分钟）
- Relay 应同时接受当前窗口和前一个窗口的令牌（容忍时钟偏差和窗口边界）
- 令牌在窗口过期后自动失效，抗重放攻击

### SNI 子域名长度

- `endpoint_id`：32 字节 → base32 编码：**52 字符**
- DNS label 上限：63 字符 ✅

### 观察者视角

```
// 观察者看到的 TLS ClientHello SNI:
x7k2m9p1q4r8nj5a...52chars....relay.example.com

// 完全随机，无法反推 endpoint_id
// 10 分钟后这个 token 自动失效
```

---

## Relay 的 relay_secret 管理

- 每个 Relay 实例持有自己的 `relay_secret`，在部署时生成，不对外公开
- `relay_secret` 通过 ticket 的 `lerp_sec` 字段 out-of-band 传递给 endpoint，**Relay 本身不在线分发**
- 不同 relay 实例使用不同的 `relay_secret`，互不影响

---

## Relay 路由流程（详细）

```
1. 收到新的 WebTransport 连接请求
2. 读取 TLS ClientHello 中的 SNI 字段
3. 从 SNI 子域名部分提取 routing_token（base32 解码，32字节）
4. 分别用 current_time_bucket 和 previous_time_bucket 解密，得到候选 endpoint_id_cur / endpoint_id_prev
5. 按以下优先级选择 endpoint_id：
   - 若某候选 endpoint_id 已有等待中的配对连接，优先选它
   - 否则优先 current_time_bucket 对应的 endpoint_id_cur
   - 再否则选 endpoint_id_prev
6. 查找是否有已连接的、等待连接的 endpoint_id 对应的连接
   - 若无：将当前连接挂起，等待对端连接（设置超时，默认 30 秒）
   - 若有：将两个连接配对，建立双向字节管道
7. 双向透明转发，直到任意一端断开
8. 清理，无状态残留
```

> Relay 的"等待配对"是短暂的内存状态，超时后自动清除，不视为持久状态。

### 配对竞态与窗口边界规则

- Relay 的配对键是 `endpoint_id`，而不是 `time_bucket`
- 即使双方跨 time_bucket 边界到达（一个用 current，一个用 previous），只要都能解到同一 `endpoint_id`，仍可配对
- 若双方几乎同时到达，Relay 需以原子方式完成“取等待连接 + 配对”，避免双重配对
- 默认挂起超时 30 秒；超时后必须返回可识别错误（如 408/配对超时），由端点重试

---

## Wildcard TLS 证书

Relay 需要 `*.relay.example.com` 的通配符 TLS 证书，以支持任意 routing_token 子域名的 TLS 握手。

证书申请和续期使用标准 ACME 协议（如 Let's Encrypt）。
