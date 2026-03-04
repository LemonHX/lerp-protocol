# the lerp protocol

## 本地 / 局域网部署 Relay 的 DNS 要求

lerp relay 使用 **通配符子域名**来路由连接：客户端会拨号到形如

```
https://<bucket-token>.<relay-host>/lerp
```

的 URL，其中 `<bucket-token>` 是一个随机 Base32 标识符。这意味着 relay
所在的域名必须有 **通配符 A/AAAA 记录**（`*.<relay-host> → relay IP`），
否则客户端无法解析该主机名，连接会直接超时。

> **注意**：`*.localhost` 在绝大多数操作系统上 **不会** 自动解析，
> 即使 `localhost` 本身可以使用，子域形式也会失败。

### 推荐方案

| 场景 | 推荐工具 | 说明 |
|------|----------|------|
| 本机开发 | [**dnsmasq**](https://thekelleys.org.uk/dnsmasq/doc.html) | 在本机监听 53 端口，配置 `address=/<relay-host>/<relay-ip>`，一条规则覆盖所有子域。macOS / Linux 均可用；Windows 可在 WSL2 内运行。 |
| 局域网内网 | [**Pi-hole**](https://pi-hole.net/) + Custom DNS | 在路由器或树莓派上运行 Pi-hole，在 *Local DNS Records* 中添加 `*.<relay-host>` 的通配符记录，让局域网内所有设备自动解析。 |
| 局域网内网（轻量）| [**CoreDNS**](https://coredns.io/) | 配置 `file` 或 `hosts` 插件，写一条通配符 zone 记录，部署成本极低，适合容器化环境。 |
| 公网 / VPS | 任意权威 DNS（Cloudflare、DNSPod 等）| 在域名面板添加 `* IN A <relay-ip>` 记录即可，TTL 设为 60s 方便调试。 |

### dnsmasq 快速示例（本机开发）

```ini
# /etc/dnsmasq.conf 或 ~/.config/dnsmasq.conf
# 将 *.relay.local 全部指向本机
address=/relay.local/127.0.0.1
```

```toml
# server.config.toml
relay = "relay.local"   # 与 dnsmasq 中的域名一致

# client.config.toml（ticket 中已含 relay 字段，无需额外配置）
```

启动 dnsmasq 后，将系统 DNS 服务器改为 `127.0.0.1`，即可在本机解析
`*.relay.local` 到 loopback 地址。