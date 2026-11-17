# lzh-hole 架构与打洞原理

## 1. 定位

多台 Apple Silicon Mac 之间的全互联 IPv4-over-UDP mesh：在固定虚拟 IPv4（VIP）之间透明承载 TCP、UDP 和 ICMP。数据面是明文 IPv4 + HMAC-SHA256，不做隧道加密、业务中继或出口节点。UDP 直连失败时如实离线，不退回 SSH/TCP/TURN/DERP。

拓扑是**全互联、逐对独立**：每两台机器之间一条独立关系，各自持有 PSK、握手 session、replay window、durable sequence、peer 高水位、anti-rollback 缓存、请求关联表和协调 topic。共享的只有节点级资源：身份密钥、自己的 VIP、物理 socket 池、STUN 测量、Bonjour 作用域和一条 utun。一个节点最多 8 个 peer（`MAX_PEERS`）。

**不做转发或中继**：A 与 B 不通时不会借道 C。节点级聚合只用于诊断，绝不把部分健康报成健康。

## 2. crate 分层

```text
crates/
├── lzh-hole-types/      最小共享领域类型：身份、Endpoint、配对结果、秘密包装
├── lzh-hole-store/      身份初始化、配对、私密持久化、durable seq、peer 高水位、单 writer 锁
├── lzh-hole-protocol/   sans-I/O 协议：wire、session、握手、crypto、replay、health、path、punch、PeerEngine
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

- `daemon/mod.rs`：组件构造、事件循环、生命周期输入；持有 `peers`、一个 `PeerSet`、一个 ntfy actor 和一条 `OverlayRoutes`。
- `daemon/peer.rs`：一条关系的全部运行时状态（协调、anti-rollback 缓存、sequence 流、请求关联、候选、计数），以及构建该关系签名记录所需的 `NodeFacts` 视图。
- `daemon/discovery.rs`：节点级 Bonjour/STUN 接线，加上按 ntfy 事件携带的 relationship 分发的签名记录处理；一个 payload 只对一条关系验证。
- `daemon/candidates.rs`：按 `(RelationshipId, ObservationId)` 合并线索、来源独立撤回、接口世代及 transport 作用域投影；观察与投影上限都按关系计算；不依赖 control DTO。
- `daemon/transport.rs`：最多 8 个真实绑定 socket、永不复用的 transport ID（与打洞池共用同一分配器）、单个持久接收 buffer、轮转 poll；`adopt` 让打洞获胜 socket 保留原 ID 加入数据面。
- `daemon/punch.rs`：临时打洞 socket 池（独立临时端口、有界、`Drop` 兜底）、独立令牌桶（默认 400 pps）、触发与角色判定、成功晋升与失败退避；socket 池是节点级但每个 slot 记住属于哪条关系。
- `daemon/dataplane.rs`：入向按 wire header 的 relationship 分流，出向按目的 VIP 选引擎；计数归到真正产生或消费流量的 peer，本层自己拒收的字节算节点级。
- `daemon/lifecycle.rs`：物理接口/所有 IPv4 alias 的选择、5 秒拓扑复查、局部失效与资源清理；每次重投影为**每条**关系写入路径集（含空集）。
- `daemon/status.rs`：逐 peer 观测 + 真正节点级的子系统；节点级 `current_path`/`candidates` 恒为空。

## 3. 打洞流程

```text
绑定物理接口＋IPv4 的保留 UDP sockets（IP_BOUND_IF）
├─ LAN：Bonjour 发现版本/公钥/实际地址，校验 A 记录交集及接口世代/子网/直连路由
└─ 公网：各 socket 独立测 STUN → ntfy 交换有界 Ed25519 签名联系记录
→ 合并为 transport-bound 候选，LAN 优先但不抢占已有健康路径
→ 无健康路径且角色可判定时进入打洞：硬侧（EDM）开 256 个临时 socket 向对端候选发 PUNCH，易侧（EIM）用数据 socket 按步长 128 扫对端 IP 的连续端口块；命中后硬侧获胜 socket 保留原 transport ID 晋升为数据面 socket，易侧把命中端口学成 peer-reflexive 候选
→ 认证握手决定唯一双向路径，再以当前路径 PING/PONG 验证，1024-bit replay window
→ 只有当前 session/endpoint/transport/epoch 匹配的路径承载 DATA
```

必须复用同一 socket：在一个 socket 上测到的 NAT 映射，换另一个 socket 发数据通常会失效。STUN 回复必须来自所查询的服务器、事务号匹配、完整消费，并给出合法公网映射。STUN seeds 只接受数值公网 IPv4，拒绝 Fake-IP、私网、loopback、组播等特殊地址。

通信角色由两份公钥的字节序决定，与 `pair offer` 的角色无关。PONG 必须先校验 nonce、实际来源和路径上下文，再提交 replay window；错误来源或未知 nonce 不推进 replay 或健康状态。只有 engine 中当前 session/endpoint/epoch 匹配的 PONG 才能形成 direct/healthy 状态。

Bonjour 使用 `_lzh-hole._udp.local.`，TXT 为 `v=1`、`pk`、`addr`，SRV port 来自成功绑定的 socket。只接受 pinned peer 公钥且 `addr` 出现在同接口 A 记录的 RFC1918 地址；必须属于该 socket 自己的真实子网，并存在非 gateway/reject/default 的同接口直连路由。每个 alias 单独绑定/通告；LAN 不要求 WAN 路由。Public 候选另要求实际同接口公网路由。接口世代、观察时 socket ID 和 native operation ID 隔离迟到事件；TTL/重试使用进程单调时间，wire 时间戳使用 UNIX 时间。

打洞与数据面完全隔离：PUNCH 用独立帧型与独立静态密钥 `k_punch`，有独立 outbox（512 帧）、独立速率预算（令牌桶，默认 400 pps、burst 100）和独立 socket 池；既不占 `ProbeBudget`，也不占 `MAX_UDP_OUTBOX`，不进 transcript、replay window 或任何序号空间。硬侧 socket 数（256）与易侧网格步长（128）是必须成对的协议常量——块宽不足步长两倍时网格会整块跨过，因此不暴露为配置项。PUNCH 绝不写入 `seen_probes`。

全 mesh **同时最多一个打洞尝试**：socket 池是节点级描述符预算，一次扫描也只对一台对端的 NAT 有意义。其他想打洞的 peer 排队，`peer_punch_status` 如实报告排队原因而不是谎称在跑；退避、失败原因和队列原因都按关系独立保存，一条关系反复失败不会拖住另一条。

打洞只在**该关系没有健康路径**时启动，由 `start_punch` 单点强制；EDM↔EDM、任一侧映射行为未知、无公网候选、ntfy 阻塞期或退避期内均不启动，并在 doctor 中如实给出原因。硬侧窗口最多 180 秒以容纳限流发布和传播；开窗/关窗及映射分类变化都会刷新签名记录但不绕过 ntfy pacing。开窗记录过期时间不晚于实际窗口结束，易侧仅在收到仍有完整 30 秒扫描时间的有效 offer 后启动，网格发完后继续等待在途确认直至截止。发送端要求 offer 剩余时间严格大于 60 秒（30 秒扫描、25 秒 POST 上限、5 秒处理余量），这不是传播时延保证；构造时不足则改发普通 TTL 的无 offer 记录。可用 offer 同时预留独立更高序号并签好无 offer 替代项，排队过时或窗口关闭时选择替代项，仍只占一次 POST，绝不修改签名或延长实际窗口。命中时丢弃旧扫描队列，硬侧 slot 0 与易侧数据 slot 0 按角色分别解析；晋升 socket 有 30 秒握手宽限，未建链或失效后自动回收。失败一律如实离线，不降级、不兜底。

候选刷新保留未变路径的定时器。记录过期只撤销后续尝试资格，不终止健康会话；socket 消失才失效其路径。一侧发现可由认证 PROBE/入站握手完成连接；PROBE nonce 在有效期内有界去重，学习候选有效 120 秒。尚未进入 FINISH 的 HELLO attempt 耗尽 8 次发送后，保留最后一次发送起 2 秒响应宽限再释放路径，允许新 nonce 重试；FINISH 唯一赢家仍遵循原有会话清理边界。主动 HELLO/重传、PROBE、路径 PING 共用每关系 10/s、每路径 2/s 的滑动预算；正常健康、DATA 和有独立边界的认证即时回复不占主动探测预算。

## 4. 透明数据路径

```text
应用 → 内核 IPv4 → 专用 utun → DATA 封装
     → UDP 直连 → 对端认证 / 防重放 / VIP 校验 → 对端 utun → 对端应用
```

每个 IPv4 包或分片都检查总长度、header checksum 和双方 VIP。错误 VIP、错误方向、过期 session/epoch、错误来源和重放均 fail closed。

只使用一条专用 utun，以及**每个 peer 一条** `/32` host route。utun destination 保持 unset，避免 macOS 抢先创建路由；route 只精确清理自己安装且仍匹配的条目，从不安装前缀或默认路由。不改默认路由、DNS、PF 或现有 VPN。关闭时先清 route 再销毁 utun。

## 5. 身份、配对与信令

- 身份为 Ed25519 seed 与 z-base-32 公钥；配对使用 pairing-v2 三步格式（offer / accept / finalize）。
- VIP、双方公钥与 relationship ID 只来自 finalized 配对状态；配置文件中重复填写 VIP 或 PSK 会被拒绝。PSK 只存放于私有 state 目录（目录 0700、文件 0600）。
- ntfy 只承载有界、签名的 `ContactRecord + kind + RequestId`，不承载业务包、PSK 或私钥。每条关系的 topic 恒为 `lzh-hole-v1-<relationship_id 小写 hex>`，**由代码从配对状态推导，配置文件里没有 topic 字段**（旧配置带 topic 会被 `deny_unknown_fields` 直接拒绝）。它不是认证机制，HTTP 200 也不代表对端在线。
- 一个节点持有 N 条关系就有 N 份待完成 offer，按 pairing_id 分别存放（上限 8），因此并行的 `pair offer` 不会互相覆盖 PSK；finalize 按 acceptance/offer 里的 pairing_id 取回并删除对应 offer。
- 同一节点内 peer key 与 peer VIP 各只能被一条关系占用，self VIP 在所有关系中必须一致，self 公钥必须与身份密钥一致；违反者在 `pair offer` 阶段就报错，`finalise` 再校验一次。
- 联系记录 sequence 在构造/发布前 durable 预留，重启不倒退、不复用。新记录的 peer 高水位原子持久化成功后才使用其候选。
- 缓存消息只作候选线索：不自动回复、不完成本地请求、不标记在线。

### ntfy 主机名解析

- ntfy 主机名**不经过系统解析器**。系统解析器可能返回 198.18.0.0/15 的 Fake-IP，这类地址只有在代理隧道正常时才可达，而信令通道不允许依赖一个可能随时失效的第三方隧道状态。
- 解析由 `lzh-hole-net::dns` 完成：在绑定到选定物理接口（`IP_BOUND_IF`）的独立短期 UDP socket 上，向选定的解析器发一个递归 IN/A 问题。该 socket 与保留的物理 socket 池无关，源端口不同即映射不同，不会干扰已测得的 STUN 映射。
- **解析器是一条链，不是一个猜测。** 配置了 `[ntfy].dns_server` 时它是唯一会被问的服务器：那是运维决定，不允许被悄悄替换成别人。未配置时，每个候选接口先贡献自己 DHCP 租约 option 6 里的解析器，再贡献自己的 IPv4 默认网关。网关不跑 DNS 是常见的企业网形态，不是放弃解析的理由。
- DHCP 租约从 SystemConfiguration 只读获取：用 `Setup:/Network/Service/*/Interface` 的 `DeviceName` 定位该接口对应的网络服务，再读 `State:/Network/Service/<id>/DHCP` 的 `Option_6`。只读该接口自己的租约、只取 DNS 选项；loopback、组播、广播、未指定地址和 198.18.0.0/15 一律丢弃，每份租约最多贡献 4 个解析器。系统解析器配置（`State:/Network/Global/DNS`）仍然不读——它正是会被 Fake-IP 代理改写的那个。
- 源地址按**路由表**判定可达性，而不是「与服务器同链路」的猜测：跨网段的解析器经本接口自己的路由可达，因此可用；没有任何路由的别名仍然被拒绝，同一适配器上不相关的第二个别名不会被借用。位于服务器同链路的地址优先，其次才是有路由的地址。路由表只读，不增删改任何路由。
- 一个服务器不应答就换下一个：解析链上每个服务器 2 次尝试 ×1.5 秒、单服务器上限 4 秒，整个解析仍 ≤15 秒。接口未在配置中指定时，按内核快照顺序遍历所有可用物理适配器；只有 link-local 地址的适配器（awdl0/llw0 等）不参与候选。
- `[ntfy].dns_server` 显式指定的解析器**不要求与本机同网段**，只要求该接口有路由可达它；除此之外没有任何写死的第三方地址。
- 编解码与查询全程受界：单问题、无 EDNS0、无 TCP 回退、不追 CNAME 链；响应 ≤512 字节，答案 ≤16 条，返回地址 ≤8 个，名字压缩指针只允许向后跳且 ≤8 次，单次尝试 ≤2 秒、`query_a` 默认 3 次尝试，确定性失败（NXDOMAIN、问题不匹配、截断）不重试。
- 解析结果在**建连之前**逐个校验：任何落入 `path::classify` 拒绝范围的地址（Fake-IP、私网、loopback、CGNAT、组播等）都会让整次解析失败，不会建立任何 TCP 连接，因此不会消耗签名记录、sequence 或 24 小时操作预算。诊断串会展平错误来源链，doctor 能直接看到具体拒绝原因。
- HTTP 客户端禁用系统代理（`no_proxy`）：一次 host 操作不能悄悄变成另一台主机的操作。

### ntfy 限流

- **DNS 解析失败不是 host 操作。** subscribe 与 publish 都先做一次 preflight 名字解析，成功后才预留预算并发请求。解析失败既不消耗滚动 24 小时预算、不写 pacing 状态，也不升级每关系的指数退避，只按 30 秒固定间隔重试——否则一个网关不提供 DNS 的网络会把有限预算烧在根本不可能成功的请求上。
- 每 host 只有一个 ntfy actor，订阅全部关系的 topic；subscribe、reconnect、publish 全部串行，间隔至少 30 秒。关系数量不会提高操作速率：无论多少条关系排队，每 30 秒只放行一次 host 操作，订阅与发布交替以防饿死。遵守 `Retry-After`（缺省 429 退避 5 分钟）和滚动 24 小时 128 次预算。
- 收到合法 NDJSON open/keepalive/message 才算订阅就绪。持续健康 1 小时才重置重连退避；反复断流按 30 秒至 15 分钟指数退避。
- 重连保留已发布请求的关联 ID 和签名过期时间，不重放旧签名。成功 live reply 后 45 分钟刷新；失败按 30 秒至 30 分钟指数退避。实际 mapping/transport 或协调 flags 变化提前刷新并撤销旧待发布 request；同关系 request 只保留最新项，reply 保留各自关联 ID、不参与合并。撤销覆盖尚未开始 POST 的排队项，不虚构撤回已发送的 HTTP，不退还已持久预留的 host 操作预算。完全相同的 STUN 刷新不加速请求；健康 LAN/公网路径抑制主动 request 而保留待刷新时序，回复仍可发送，始终受既有持久化 ntfy pacing 约束。发布至多 8 个去重映射，先覆盖各 transport 最新映射，再轮转补足历史映射。
- 预算或 `Retry-After` 阻塞期间不生成新 request/reply；doctor 保留原始阻塞原因和 `not_before_unix_ms`，后续现象不覆盖它。
- `state_dir/ntfy-pacing.json`（0600，原子替换）持久化操作时间与等待边界，跨重启继承；读写失败则停止 HTTP。
- ntfy 断开不影响已建立的 UDP；PONG 健康独立于 ntfy。

## 6. 自动恢复

- engine 在健康失效、确认超时或 sequence 耗尽时自动重建 session。
- 接口、所有 IPv4 alias/真实掩码和路由每 5 秒复查。自动模式优先同接口公网路由，然后失败计数/index；LAN 开启时保留无 WAN 路由的物理接口。显式 `interface`/`bind_ip` 严格限定候选，最多成功绑定 8 个 sockets。
- 只移除实际消失或接收失败的 transport，其他 sockets/session 不全局重建。STUN/ntfy/Bonjour 故障独立退避，不作为 socket 消失证据。启动时没有可用物理接口也保留 daemon/control，等待后续拓扑恢复。
- Bonjour native refs/events、候选、重试和队列都有上限；接口撤销立即取消相应注册/浏览。native 扫描期限跨 select 取消保留，单条坏记录不取消其他服务；持续 PTR 存在时有界重解析补充 TTL。
- 打洞失败后按 30 秒起、指数至 15 分钟退避重试；接口消失立即关闭该接口上的全部打洞 socket 并取消进行中的尝试。晋升失败（如 8 个 transport 已满）时关闭打洞 socket 并如实报告，绝不驱逐正在工作的数据面 socket。
- 没有手动 reconnect 命令；离线测试通过测试专用组件注入。

## 7. 控制接口

私有 Unix socket，一行一个 JSON、每连接一个请求、最大 128 KiB，只接受 `{"command":"doctor"}`。上限按饱和快照实测（8 peer × 32 候选 × 满长度 drop reason = 71022 字节）留余量确定，并由 `dto::tests::a_saturated_snapshot_fits_one_control_line` 钉住：调小帧上限而不调小那些边界会直接构建失败，而不是让 doctor 退化成一句 internal error。目录 0700、socket 0600，属主为管理 UID，连接后再经 `peer_cred()` 只允许 root 或管理 UID。bind 时路径已存在即失败；正常退出只删除 device/inode 与本次 bind 相符的 socket。

doctor 返回逐 peer 的 `peers[]`（每条关系一份 `relationship_id`、`peer_vip`、`peer_key`、`role`、`session`、`overlay`、`ntfy`、`current_path`、`candidates`、`punch`、`bytes`、`drops`），以及节点级的 `daemon`、`lan`、`ntfy`、`stun`、`session`、`tun`、`routes`、`bytes`、带原因的 `drops`，聚合的 `overlay.direct_reachable` / `currently_healthy`，以及 `punch`（`state`、`role`、`local_mapping`、`peer_mapping`、`blocked_by`、`last_failure`、`probes_sent`、`sockets_open`、`hit_port`、`started_unix_ms`；全部是观测值，不代表打洞会成功）。节点级 `current_path` 恒为 `null`、`candidates` 恒为空：一条路径只属于一个 peer，节点级取值只会有歧义。逐 peer 的 `current_path` 给出实际 transport ID、物理接口、本地/远端 endpoint 与 LAN/Public 类别；`candidates` 有界且不代表在线，`discovery` 计数独立于认证健康。未检测项为 `unknown` / `null`。聚合规则集中在 `ServiceSnapshot::set_peers`：布尔三态取 AND（任一 `false` 即 `false`，有未测即 `null`，全 `true` 才 `true`），session 取最差且 `unknown` 排在 `healthy` 之前，时间戳取最大；空列表被拒绝，调用全有或全无。严格未知字段校验要求 daemon 与 doctor 客户端一起升级。它不包含 `functional_pass` 或 `p0_qualified`，这些由外部验收判断。

## 8. 构建与离线分发

开发机从项目根目录执行：

~~~sh
cargo xtask check
cargo xtask dist
./dist/install.sh --dry-run
./dist/install.sh
~~~

`xtask` 是独立的开发工具 crate，不进入部署包。Cargo alias 固定使用 `--locked --offline`；`check` 执行 release build、fmt、clippy、workspace tests 与四组 CLI help，`dist` 先完整检查，再构建 Apple Silicon macOS 二进制、拒绝非系统动态库依赖，并从 Mach-O 记录最低 macOS 版本。最低版本是构建元数据，不表示已通过跨版本实测。

`dist/` 被 Git 忽略，包含可执行的 `install.sh`、`lzh-hole`、配置与 launchd 模板、当前构建的 `manifest.json`、`SHA256SUMS`，以及只含上述载荷的 tar.gz 和归档校验和。未提交的构建明确标记 `dirty`；不含源码、生产配置或秘密。所有检查与归档成功后才替换上一份 dist；安装端不需要 Rust、Homebrew、Python、jq 或下载依赖。SHA256 只用于完整性检查，不代替可信来源或代码签名。

安装器默认交互确认；非交互执行必须显式传 `--yes`。首次默认只安装二进制与 `/etc/lzh-hole/config.toml.example`，不创建身份、不配对、不安装/启动系统服务、不创建 TUN。按现有运维流程完成身份、配对和生产配置后，首次服务注册/启动必须显式执行并确认：

~~~sh
./dist/install.sh --enable-service --allow-tun
~~~

已有且已加载的服务在升级时会短暂重启；未加载的服务保持未加载。已有配置、定制 plist、身份、PSK、durable seq、peer 高水位与 ntfy pacing 不覆盖、不删除。定制的服务路径或参数不符合受支持布局时拒绝自动升级，不静默改写。按当前管理用户实际 UID 配置 `management_uid`。配置里没有 topic：每条关系的 topic 由 daemon 从 finalized 配对状态推导，因此示例配置可以直接用于任意节点，只需替换 `state_dir`、`control_socket` 和 `management_uid`。

升级先暂存并校验新文件，以 `doctor --preflight --config /etc/lzh-hole/config.toml` 只读检查配置、现有私密目录/文件、身份，以及**每一条**关系的 PSK 可读性与推导 topic 可用性。该模式不创建目录、不取 publisher writer 锁、不预留 sequence、不联网，也不输出私钥/PSK。停止旧服务后有界等待旧 PID、control socket、旧 utun 与 peer /32 route 清理，再替换二进制、核对哈希、恢复原服务运行状态。就绪检查要求 daemon/TUN/routes 已初始化，不要求对端在线；安装成功不等于功能或 P0 通过。

失败时自动恢复旧二进制与原服务状态，但不回滚私密状态；清理或回滚失败则明确失败并保留 `/usr/local/libexec/.lzh-hole-install.lock` 内的备份，供人工恢复，不盲删网络资源或绕过 pacing。正常成功/回滚后删除临时备份。并发安装或上次遗留恢复目录会被拒绝。

home4 仍只接收本机生成的二进制，经 `ssh home4` 或 `ssh home-local` 按现有流程部署；本打包工具不包含 SSH 自动部署，不授权上传源码或脚本。

## 9. 离线测试范围

固定 wire/auth/握手向量（`tests/fixtures/wire-v1.json`，格式见[协议](protocol.md)）、PONG 来源/transport/replay、双路径握手唯一赢家、IPv4 分片/VIP、配对与 ntfy 签名字节、私密持久化、STUN 严格解码、LAN 规范化及来源独立撤回/世代隔离、单进程离线 LAN 冷启动/公网故障隔离模拟、真实 loopback socket set/engine + 内存 TUN、doctor 清理。

mesh 专项：三节点真实双握手与双向数据面（`protocol::mesh`）、多关系并行配对与 offer 按 pairing_id 隔离（`store`）、单 actor 多 topic 下「关系数不提高操作速率」与「一条流失败不抬高另一条关系退避」（`discovery`）、按关系隔离的候选容量与投影（`daemon::candidates`）、全 mesh 单打洞窗口与按关系排队/退避（`daemon::punch`）、聚合绝不上调健康与饱和快照帧大小（`control`）、一条 utun 多条 /32 的安装与回滚（`net::overlay`）。测试不发布组播/公网记录，不访问对端主机、不创建 OS utun、不执行 sudo；原生 Bonjour 双机发现、真实 TCP/UDP/ICMP 和 P0 仍须另行授权验收。
