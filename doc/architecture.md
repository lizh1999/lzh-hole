# lzh-hole 架构与打洞原理

## 1. 定位

两台 Apple Silicon Mac 之间的 IPv4-over-UDP 直连：在固定虚拟 IPv4（VIP）之间透明承载 TCP、UDP 和 ICMP。数据面是明文 IPv4 + HMAC-SHA256，不做隧道加密、业务中继、出口节点或多节点 mesh。UDP 直连失败时如实离线，不退回 SSH/TCP/TURN/DERP。

## 2. crate 分层

```text
crates/
├── lzh-hole-types/      最小共享领域类型：身份、Endpoint、配对结果、秘密包装
├── lzh-hole-store/      身份初始化、配对、私密持久化、durable seq、peer 高水位、单 writer 锁
├── lzh-hole-protocol/   sans-I/O 协议：wire、session、握手、crypto、replay、health、path、PeerEngine
├── lzh-hole-discovery/  LAN/Public 两个具体发现模型、公共候选更新、ntfy、签名记录、STUN 事务
├── lzh-hole-net/        macOS 接口/路由、原生 Bonjour、物理 UDP socket、utun、精确 /32 route
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
- `discovery` 不创建业务 UDP socket；两个具体模型负责 LAN 观察规范化、过期，以及各 transport 的 STUN/公网候选/请求时序，由 service 执行 I/O。没有统一 backend trait 或泛型 daemon。
- `net` 不依赖 protocol/discovery/service。
- `control` 不直接操作 net。
- `unsafe` 仅允许出现在 net、store、control、service 四个 crate，且每处须有 `// SAFETY:` 说明。

### daemon 模块

- `daemon/mod.rs`：组件构造、事件循环、生命周期输入。
- `daemon/discovery.rs`：Bonjour/公网模型接线、签名记录、durable seq、请求/回复与 native operation 生命周期。
- `daemon/candidates.rs`：按 discovery `ObservationId` 合并线索、来源独立撤回、接口世代及 transport 作用域投影；不依赖 control DTO。
- `daemon/transport.rs`：最多 8 个真实绑定 socket、永不复用的 transport ID、单个持久接收 buffer、轮转 poll。
- `daemon/dataplane.rs`：按实际 transport 收发，与 TUN 之间转发认证 IPv4。
- `daemon/lifecycle.rs`：物理接口/所有 IPv4 alias 的选择、5 秒拓扑复查、局部失效与资源清理。
- `daemon/status.rs`：doctor 快照与有界 drop 计数。

## 3. 打洞流程

```text
绑定物理接口＋IPv4 的保留 UDP sockets（IP_BOUND_IF）
├─ LAN：Bonjour 发现版本/公钥/实际地址，校验 A 记录交集及接口世代/子网/直连路由
└─ 公网：各 socket 独立测 STUN → ntfy 交换有界 Ed25519 签名联系记录
→ 合并为 transport-bound 候选，LAN 优先但不抢占已有健康路径
→ 认证握手决定唯一双向路径，再以当前路径 PING/PONG 验证，1024-bit replay window
→ 只有当前 session/endpoint/transport/epoch 匹配的路径承载 DATA
```

必须复用同一 socket：在一个 socket 上测到的 NAT 映射，换另一个 socket 发数据通常会失效。STUN 回复必须来自所查询的服务器、事务号匹配、完整消费，并给出合法公网映射。STUN seeds 只接受数值公网 IPv4，拒绝 Fake-IP、私网、loopback、组播等特殊地址。

通信角色由两份公钥的字节序决定，与 `pair offer` 的角色无关。PONG 必须先校验 nonce、实际来源和路径上下文，再提交 replay window；错误来源或未知 nonce 不推进 replay 或健康状态。只有 engine 中当前 session/endpoint/epoch 匹配的 PONG 才能形成 direct/healthy 状态。

Bonjour 使用 `_lzh-hole._udp.local.`，TXT 为 `v=1`、`pk`、`addr`，SRV port 来自成功绑定的 socket。只接受 pinned peer 公钥且 `addr` 出现在同接口 A 记录的 RFC1918 地址；必须属于该 socket 自己的真实子网，并存在非 gateway/reject/default 的同接口直连路由。每个 alias 单独绑定/通告；LAN 不要求 WAN 路由。Public 候选另要求实际同接口公网路由。接口世代、观察时 socket ID 和 native operation ID 隔离迟到事件；TTL/重试使用进程单调时间，wire 时间戳使用 UNIX 时间。

候选刷新保留未变路径的定时器。记录过期只撤销后续尝试资格，不终止健康会话；socket 消失才失效其路径。一侧发现可由认证 PROBE/入站握手完成连接；PROBE nonce 在有效期内有界去重，学习候选有效 120 秒。主动 HELLO/重传、PROBE、路径 PING 共用每关系 10/s、每路径 2/s 的滑动预算；正常健康、DATA 和有独立边界的认证即时回复不占主动探测预算。

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
- 重连保留已发布请求的关联 ID 和签名过期时间，不重放旧签名。成功 live reply 后 45 分钟刷新；失败按 30 秒至 30 分钟指数退避。实际 mapping/transport 变化提前刷新并取消旧请求关联，完全相同的 STUN 刷新不加速请求；健康 LAN/公网路径抑制主动 request 而保留待刷新时序，回复仍可发送，始终受既有持久化 ntfy pacing 约束。发布至多 8 个去重映射，先覆盖各 transport 最新映射，再轮转补足历史映射。
- 预算或 `Retry-After` 阻塞期间不生成新 request/reply；doctor 保留原始阻塞原因和 `not_before_unix_ms`，后续现象不覆盖它。
- `state_dir/ntfy-pacing.json`（0600，原子替换）持久化操作时间与等待边界，跨重启继承；读写失败则停止 HTTP。
- ntfy 断开不影响已建立的 UDP；PONG 健康独立于 ntfy。

## 6. 自动恢复

- engine 在健康失效、确认超时或 sequence 耗尽时自动重建 session。
- 接口、所有 IPv4 alias/真实掩码和路由每 5 秒复查。自动模式优先同接口公网路由，然后失败计数/index；LAN 开启时保留无 WAN 路由的物理接口。显式 `interface`/`bind_ip` 严格限定候选，最多成功绑定 8 个 sockets。
- 只移除实际消失或接收失败的 transport，其他 sockets/session 不全局重建。STUN/ntfy/Bonjour 故障独立退避，不作为 socket 消失证据。启动时没有可用物理接口也保留 daemon/control，等待后续拓扑恢复。
- Bonjour native refs/events、候选、重试和队列都有上限；接口撤销立即取消相应注册/浏览。native 扫描期限跨 select 取消保留，单条坏记录不取消其他服务；持续 PTR 存在时有界重解析补充 TTL。
- 没有手动 reconnect 命令；离线测试通过测试专用组件注入。

## 7. 控制接口

私有 Unix socket，一行一个 JSON、每连接一个请求、最大 16 KiB，只接受 `{"command":"doctor"}`。目录 0700、socket 0600，属主为管理 UID，连接后再经 `peer_cred()` 只允许 root 或管理 UID。bind 时路径已存在即失败；正常退出只删除 device/inode 与本次 bind 相符的 socket。

doctor 返回 `daemon`、`lan`、`ntfy`、`stun`、`session`、`tun`、`routes`、`bytes`、带原因的 `drops`，以及独立的 `overlay.direct_reachable` / `currently_healthy`。`current_path` 给出实际 transport ID、物理接口、本地/远端 endpoint 与 LAN/Public 类别；`candidates` 有界且不代表在线，`discovery` 计数独立于认证健康。未检测项为 `unknown` / `null`。严格未知字段校验要求 daemon 与 doctor 客户端一起升级。它不包含 `functional_pass` 或 `p0_qualified`，这些由外部验收判断。

## 8. 离线测试范围

固定 wire/auth/握手向量（`tests/fixtures/wire-v1.json`，格式见[协议](protocol.md)）、PONG 来源/transport/replay、双路径握手唯一赢家、IPv4 分片/VIP、配对与 ntfy 签名字节、私密持久化、STUN 严格解码、LAN 规范化及来源独立撤回/世代隔离、单进程离线 LAN 冷启动/公网故障隔离模拟、真实 loopback socket set/engine + 内存 TUN、doctor 清理。测试不发布组播/公网记录，不访问对端主机、不创建 OS utun、不执行 sudo；原生 Bonjour 双机发现、真实 TCP/UDP/ICMP 和 P0 仍须另行授权验收。
