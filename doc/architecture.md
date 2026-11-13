# lzh-hole 架构与打洞原理

## 1. 定位

两台 Apple Silicon Mac 之间的 IPv4-over-UDP 直连：在固定虚拟 IPv4（VIP）之间透明承载 TCP、UDP 和 ICMP。数据面是明文 IPv4 + HMAC-SHA256，不做隧道加密、业务中继、出口节点或多节点 mesh。UDP 直连失败时如实离线，不退回 SSH/TCP/TURN/DERP。

## 2. crate 分层

```text
crates/
├── lzh-hole-types/      最小共享领域类型：身份、Endpoint、配对结果、秘密包装
├── lzh-hole-store/      身份初始化、配对、私密持久化、durable seq、peer 高水位、单 writer 锁
├── lzh-hole-protocol/   sans-I/O 协议：wire、session、握手、crypto、replay、health、path、PeerEngine
├── lzh-hole-discovery/  ntfy transport/message/exchange/pacing、签名联系记录、候选、STUN 事务
├── lzh-hole-net/        macOS 接口与路由枚举、绑定物理接口的 UDP socket、utun、精确 /32 route
├── lzh-hole-control/    私有 Unix socket doctor：DTO、权限、有界帧
├── lzh-hole-service/    配置、daemon、lifecycle 与组件编排
└── lzh-hole/            极薄 CLI：init / pair / daemon / doctor
```

有向依赖（箭头指向被依赖方）：

```text
types       无内部依赖
store       → types
protocol    → types
discovery   → protocol, types
net         无内部依赖
control     → store
service     → types, store, protocol, discovery, net, control
CLI         → service, control, store, types
```

边界规则：

- `protocol` 没有业务 I/O，不直接依赖 Tokio/HTTP/socket/libc。
- `discovery` 不创建业务 UDP socket，STUN 事务只编解码，由 service 在共享 socket 上收发。
- `net` 不依赖 protocol/discovery/service。
- `control` 不直接操作 net。
- `unsafe` 仅允许出现在 net、store、control、service 四个 crate，且每处须有 `// SAFETY:` 说明。

### daemon 模块

- `daemon/mod.rs`：组件构造、事件循环、生命周期输入。
- `daemon/dataplane.rs`：共享 UDP socket 与 TUN 之间的认证 IPv4 转发。
- `daemon/stun.rs`：STUN 调度、映射和状态。
- `daemon/signaling.rs`：签名记录、请求/回复、durable seq 与候选提交。
- `daemon/lifecycle.rs`：自动恢复、物理接口选择与检查、资源清理。
- `daemon/status.rs`：doctor 快照与有界 drop 计数。

## 3. 打洞流程

```text
绑定一个物理接口 UDP socket（IP_BOUND_IF）
→ 在同一 socket 上查询 STUN 公网映射
→ 经 ntfy 交换有界 Ed25519 签名联系记录
→ 双方从同一 socket 向对方候选发 UDP
→ 认证握手、当前路径 PING/PONG、1024-bit replay window
→ 只有验证过的 endpoint 才承载明文 IPv4 + HMAC 的 DATA
```

必须复用同一 socket：在一个 socket 上测到的 NAT 映射，换另一个 socket 发数据通常会失效。STUN 回复必须来自所查询的服务器、事务号匹配、完整消费，并给出合法公网映射。STUN seeds 只接受数值公网 IPv4，拒绝 Fake-IP、私网、loopback、组播等特殊地址。

通信角色由两份公钥的字节序决定，与 `pair offer` 的角色无关。PONG 必须先校验 nonce、实际来源和路径上下文，再提交 replay window；错误来源或未知 nonce 不推进 replay 或健康状态。只有 engine 中当前 session/endpoint/epoch 匹配的 PONG 才能形成 direct/healthy 状态。

## 4. 透明数据路径

```text
应用 → 内核 IPv4 → 专用 utun → DATA 封装
     → UDP 直连 → 对端认证 / 防重放 / VIP 校验 → 对端 utun → 对端应用
```

每个 IPv4 包或分片都检查总长度、header checksum 和双方 VIP。错误 VIP、错误方向、过期 session/epoch、错误来源和重放均 fail closed。

只使用专用 utun 和对端 VIP 的一条 `/32` host route。utun destination 保持 unset，避免 macOS 抢先创建路由；route 只精确清理自己安装且仍匹配的条目。不改默认路由、DNS、PF 或现有 VPN。

## 5. 身份、配对与信令

- 身份为 Ed25519 seed 与 z-base-32 公钥；配对使用 pairing-v2 三步格式（offer / accept / finalize）。
- VIP、双方公钥与 relationship ID 只来自 finalized 配对状态；配置文件中重复填写 VIP 或 PSK 会被拒绝。PSK 只存放于私有 state 目录（目录 0700、文件 0600）。
- ntfy 只承载有界、签名的 `ContactRecord + kind + RequestId`，不承载业务包、PSK 或私钥。topic 必须为 `lzh-hole-v1-<relationship_id 小写 hex>`，它不是认证机制，HTTP 200 也不代表对端在线。
- 联系记录 sequence 在构造/发布前 durable 预留，重启不倒退、不复用。新记录的 peer 高水位原子持久化成功后才使用其候选。
- 缓存消息只作候选线索：不自动回复、不完成本地请求、不标记在线。

### ntfy 限流

- 每 host 的 subscribe、reconnect、publish 串行，间隔至少 30 秒；遵守 `Retry-After`（缺省 429 退避 5 分钟）和滚动 24 小时 128 次预算。
- 收到合法 NDJSON open/keepalive/message 才算订阅就绪。持续健康 1 小时才重置重连退避；反复断流按 30 秒至 15 分钟指数退避。
- 重连保留已发布请求的关联 ID 和签名过期时间，不重放旧签名。成功 live reply 后 45 分钟再刷新；失败按 30 秒至 30 分钟指数退避。健康直连时不额外请求。
- 预算或 `Retry-After` 阻塞期间不生成新 request/reply；doctor 保留原始阻塞原因和 `not_before_unix_ms`，后续现象不覆盖它。
- `state_dir/ntfy-pacing.json`（0600，原子替换）持久化操作时间与等待边界，跨重启继承；读写失败则停止 HTTP。
- ntfy 断开不影响已建立的 UDP；PONG 健康独立于 ntfy。

## 6. 自动恢复

- engine 在健康失效、确认超时或 sequence 耗尽时自动重建 session。
- 接口、bind IP 和自动模式下的出口路由每 5 秒复查。自动模式只选择有同接口公网路由（unicast、非 loopback/tunnel）的物理候选，按失败计数再按 index 排序轮换；显式配置 `interface`/`bind_ip` 时严格限定候选。
- 路由或 IPv4 消失、UDP 错误、全部 STUN 服务器连续超时都会调度 socket/STUN/engine 恢复，socket 重建间隔 5 秒。
- 没有手动 reconnect 命令；离线测试通过测试专用组件注入。

## 7. 控制接口

私有 Unix socket，一行一个 JSON、每连接一个请求、最大 16 KiB，只接受 `{"command":"doctor"}`。目录 0700、socket 0600，属主为管理 UID，连接后再经 `peer_cred()` 只允许 root 或管理 UID。bind 时路径已存在即失败；正常退出只删除 device/inode 与本次 bind 相符的 socket。

doctor 返回 `daemon`、`ntfy`、`stun`、`session`、`tun`、`routes`、`bytes`、带原因的 `drops`，以及独立的 `overlay.direct_reachable` / `currently_healthy`；未检测项为 `unknown` / `null`。它不包含 `functional_pass` 或 `p0_qualified`，这些由外部验收判断。

## 8. 离线测试范围

固定 wire/auth/握手向量（`tests/fixtures/wire-v1.json`，格式见[协议](protocol.md)）、PONG 来源与 replay 提交顺序、IPv4 分片与错误 VIP、配对与 ntfy 签名字节、私密持久化、STUN 严格解码、两个真实 loopback UDP engine + 内存 TUN、doctor socket 清理。离线测试不访问公网或对端主机、不创建 OS utun、不执行 sudo，不能替代真实双机验收。
