# 08 · Security Analysis

## 威胁模型

lerp 假设以下攻击者存在：

| 攻击者 | 能力 |
|---|---|
| 网络被动监听者 | 能捕获所有网络流量，读取包头和 SNI |
| 网络主动攻击者 | 能修改/注入/重放网络包 |
| 恶意 Relay | Relay 被攻击者完全控制 |
| 票据泄露者 | 获得了一张 ticket |

lerp **不保护**对抗：

- 攻击者控制了 endpoint 本机（私钥泄露）
- 攻击者控制了 DNS 基础设施（可将 relay.example.com 劫持到其他服务器）

---

## 各层安全分析

### 1. 流量内容（E2E 加密）

**保护**：应用层数据被 Ed25519 + X25519 ECDH + ChaCha20-Poly1305 保护。

- Relay 只看到密文字节流，无法解密
- 即使 Relay 被完全控制，无法中间人攻击（MITM）——攻击者无法伪造持有目标私钥的 endpoint
- 前向保密（Forward Secrecy）：每次连接生成新的 X25519 临时密钥对，历史会话密钥不可推导

### 2. 路由信息（SNI 盲化）

**保护**：观察者无法从 SNI 中读取 `endpoint_id`。

- `routing_token = endpoint_id XOR BLAKE3(relay_secret || time_bucket)[:32]`
- 观察者看到的是伪随机字符串
- 没有 `relay_secret` 无法还原 `endpoint_id`
- `time_bucket` 每 10 分钟轮换，令牌自动失效

**局限**：
- 观察者能看到你在连接 `*.relay.example.com`，即知道你在使用 lerp
- 观察者能看到流量大小和时序（流量分析攻击）

### 3. 重放攻击

**保护**：`time_bucket` 机制限制令牌有效期最长 20 分钟（跨窗口容忍）。

- 攻击者抓到某次 SNI 中的 routing_token，最多 20 分钟后自动失效
- 即使在有效期内回放，Relay 建立的是新连接，E2E 握手会产生新的临时密钥，无法复用旧会话

### 4. Ticket 泄露

**风险**：ticket 泄露意味着攻击者可以向目标 endpoint 发起连接。

- lerp 不在协议层防止这种情况——这是应用层的责任
- 应用层应在 E2E 握手建立后，通过自定义字段（如 `expires`、`nonce` 等）做应用层鉴权
- ticket 应视为敏感数据，同等于 API key 或 SSH 私钥

### 5. Relay 被攻击者控制

**保护**：即使 Relay 完全被攻击者控制，攻击者只能：
- 看到双方的 `endpoint_id`（解密 routing_token 后）
- 看到流量大小和时序
- 中断连接

攻击者**不能**：
- 解密任何应用层数据
- 伪造来自任意 endpoint 的数据（无私钥）
- 进行中间人攻击（MITM）——E2E 握手的签名验证会失败

### 6. DNS 劫持

**风险**：若 `relay.example.com` 的 DNS 被劫持，连接会到达攻击者控制的服务器。

- 攻击者无法伪造 `relay_secret`（在 ticket 中，out-of-band 分发）
- routing_token 解密失败，攻击者无法将流量路由到目标
- 但攻击者可以**拒绝服务**（丢弃所有连接）
- 若 `lerp_dir` 有直连地址，可绕过受损 relay

**缓解（v0）**：分发多张 ticket（每张指向不同 relay）作为应用层 failover。

---

## 可用性边界（v0）

### 1. 单 Relay 单点故障

- v0 ticket 仅支持单个 `lerp_rly`
- 该 relay 故障时，新连接不可建立
- 缓解：应用侧预置多张 ticket / 多 relay 候选

### 2. Ping/Pong 误判风险

- datagram 在移动网络切换、高丢包链路上可能连续丢失
- 建议采用“连续超时 + 连接静默窗口”联合判定，而非仅凭 3 次丢包

### 3. 重连后无会话恢复

- v0 不恢复旧流，不恢复旧会话密钥
- 重连成功后需重新握手，应用需自行恢复业务状态

---

## 流量分析（Traffic Analysis）

lerp **不提供**对流量分析攻击的保护：

- 观察者能看到包大小、时序、频率
- 观察者能关联"谁在什么时候访问了哪个 relay"

这超出了 lerp v0 的设计范围。需要更强隐匿性的场景应在 lerp 之上叠加 traffic padding / timing obfuscation 等技术。

---

## 安全参数汇总

| 参数 | 值 | 备注 |
|---|---|---|
| 身份密钥算法 | Ed25519 | 256-bit 安全强度 |
| ECDH 临时密钥 | X25519 | 前向保密 |
| 对称加密 | ChaCha20-Poly1305 | AEAD，256-bit key |
| PRF（密钥流派生） | BLAKE3 | 取前 32 字节作为密钥流输出 |
| Ticket 校验 | BLAKE3 前 4 字节 | 错误检测，非密码学保证 |
| relay_secret 长度 | 32 字节（256 bit） | 随机生成 |
| time_bucket 窗口 | 600 秒（10 分钟） | 可配置 |
| 最大令牌有效期 | 1200 秒（20 分钟） | 当前 + 前一窗口 |
