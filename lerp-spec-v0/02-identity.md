# 02 · Identity

## 密钥体系

lerp 使用 **Ed25519** 作为唯一的密钥算法。

```
SecretKey  (Ed25519 私钥，32 字节)
    └── PublicKey  (Ed25519 公钥，32 字节)
            └── endpoint_id  (类型别名，节点的全局唯一标识)
```

- `endpoint_id` 即公钥本身，无需向任何中心机构注册，全局唯一
- `SecretKey` 本地持久化，**绝不离开本机**
- 所有 E2E 加密握手使用对应的密钥对完成，Relay 无法参与

---

## Endpoint 身份生成

每个 lerp-daemon / lerp-client 实例可同时持有**任意多个 endpoint_id**。

### 生成规则

- 首次使用某个 endpoint 时，自动生成新的 Ed25519 密钥对
- 私钥存储在本地持久化存储中（文件系统 / 浏览器 IndexedDB）
- 不同 endpoint_id 之间完全隔离，互不影响

### 身份与行为正交

`endpoint_id` 是身份，发起连接 / 接受连接是行为，两者完全正交：

- 任意 endpoint 可同时发起连接（作为 client）
- 任意 endpoint 可同时接受连接（作为 server）
- 同一个进程内多个 endpoint_id 共享与 relay 的底层连接

### 存储格式

私钥以原始 32 字节二进制存储，文件权限应为 `0600`（仅所有者可读写）。

```
~/.lerp/keys/<endpoint_id_base32>.key   ← 私钥文件
```

---

## endpoint_id 的文本表示

`endpoint_id`（32 字节公钥）的标准文本表示为 **base32**（RFC 4648，无 padding），共 **52 个字符**。

```
例：a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

52 字符正好在 DNS label 长度上限（63 字符）以内，可作为子域名使用。

---

## Relay Secret

每张 ticket 携带一个 `relay_secret`（32 字节随机数），是 endpoint 与某个特定 relay 之间的共享密钥。

- `relay_secret` 由 ticket 创建方生成（`crypto_random_bytes(32)`）
- 通过 ticket out-of-band 分发给持有方，**Relay 本身不参与分发过程**
- Relay 持有自身的 `relay_secret` 用于路由令牌的解密（见 [04-relay.md](04-relay.md)）

> **注意：** `relay_secret` 与 relay 的 TLS 私钥是两个不同的密钥，前者用于路由令牌派生，后者用于 TLS 握手。

---

## 密码学原语汇总

| 用途 | 算法 |
|---|---|
| 节点身份 / E2E 认证 | Ed25519 |
| 路由令牌派生（密钥流） | BLAKE3（用作 PRF） |
| Ticket 完整性校验 | BLAKE3 |
| Ticket 序列化 | MessagePack |
| Ticket 文本编码 | base64url（RFC 4648） |
| routing_token 文本编码 | base32（RFC 4648，无 padding） |
