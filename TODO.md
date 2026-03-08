- [ ] daemon 没有 webapi


- [ ] 看到这个config我才想起来，你能不能这样，就是你顺便改一下 lerp-spec-v0, daemon 当收到如 --connect <ticket> , 会直接从系统挑选一个端口，并返回端口，毕竟让用户配置网络端口是否有点没有解决任何问题...
- [ ] daemon 应该得有一个 known_tickets 文件，这个文件可以是简单的 JSON 数组(从ticket序列化到serde_json)，记录所有 --connect 或者 webapi 接收到的 ticket，以便后续查询和管理（比如查看当前有哪些连接是基于哪些 ticket 发起的，或者实现撤销功能）。这个文件可以放在 ~/.lerp/known_tickets.json。

----

高风险问题

P0: ticket 的 app_fields 没有自动进入 Hello.meta：connect 配置固定 meta: None（main.rs:299-306），握手发送的是 cfg.meta（connect.rs:125，handshake.rs:67-72），这违背 spec 的自动转发语义。
P0: IPC 可生成无效 ticket（有 lerp_rly 无 lerp_sec）：IPC 路径会直接设置 lerp_rly（ipc.rs:260-263）；而 Ticket::encode 不校验该组合（ticket.rs:156），decode 才拒绝（ticket.rs:204-207）。
P1: connect 模式缺少断线重连触发：进入本地监听死循环后仅在每次 open_bi 失败时打日志，不会因 relay 关闭退出 connect_once（connect.rs:158-179；文件内也没有 closed() 监听）。
P1: TLS 证书校验被关闭：relay/direct 拨号都用了 with_no_cert_validation（connect.rs:238，serve.rs:226，holepunch.rs:300）。
P1: relay 配对存在并发竞态：remove 与 insert 分离，非原子（router.rs:93-112），并发到达时可能双超时/误删 pending。
中风险与规范偏差

LPP 控制面未做 E2E 二次加密：AO/PS/DU/DA/CL 直接 msgpack 发 uni（holepunch.rs:585-601），PI/PO 直接 datagram（keepalive.rs:127-133），relay 透明转发 uni/datagram（pipe.rs:77-99）。
lerp_dir 未被 daemon 使用：ticket 解码后未消费 lerp_dir（connect.rs:77），打洞入口也没有该参数（holepunch.rs:49-54）。
直连服务端与 spec 偏差：证书是随机 self_signed、非 endpoint 派生（holepunch.rs:407），且只绑 IPv4 0.0.0.0（holepunch.rs:410）。
ticket 版本兼容策略过宽：版本不匹配仅 warning 不拒绝（ticket.rs:192-196）。
已确认符合规范的点

routing_token 派生与 current/previous bucket 处理已实现（routing.rs:54-75，main.rs:108-124）。

Hello/HelloAck + Ed25519 签名校验 + X25519 握手链路完整（handshake.rs:60-120，handshake.rs:168-204）。

DU 发起方按 endpoint_id 字典序判定已做（holepunch.rs:211，holepunch.rs:239）。

基线验证：cargo test -p lerp-proto（72 通过），cargo test -p lerp-daemon -p lerp-relay（可编译，无单测）。

要不要我直接按优先级先修 P0/P1（meta 透传、IPC ticket 校验、connect 重连、relay 配对竞态）并给你一版补丁？