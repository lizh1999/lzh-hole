# wire v1 协议

本文描述 `lzh-hole-protocol`（帧、握手、会话）与 `lzh-hole-discovery`（联系记录）实现的线上格式。字节级测试向量见 `tests/fixtures/wire-v1.json`，由 `crates/lzh-hole-discovery/tests/fixture_vectors.rs` 逐字节比对；任何格式改动都会改变向量。所有整数为大端序。

## 1. 密码学原语

- MAC：HMAC-SHA256，完整 32 字节标签，常数时间比较。
- KDF：HKDF-SHA256（RFC 5869）。
- 联系记录签名：Ed25519，覆盖 ntfy 域分隔的 `kind`、`request_id` 与规范记录体。

## 2. 角色与方向

- `lo_pub` 为两把已固定公钥中字典序较小者，`hi_pub` 为另一把。
- 持有 `lo_pub` 的一端是 initiator，发送 HELLO；持有 `hi_pub` 的一端是 responder，发送 PROBE 与 CHALLENGE。
- 方向字节：`0` = lo→hi，`1` = hi→lo。

## 3. 密钥派生

标签前缀均为 `lzh-hole/v1/`，`||` 表示拼接：

| 量 | 定义 |
|---|---|
| PRK | `HKDF-Extract(salt = relationship_id, ikm = PSK)` |
| k_hello | `Expand(PRK, kdf/hello ‖ lo_pub ‖ hi_pub ‖ nonce_i, 32)` |
| k_chal | `Expand(PRK, kdf/challenge ‖ lo_pub ‖ hi_pub ‖ nonce_i ‖ nonce_r ‖ th1, 32)` |
| k_fin | `Expand(PRK, kdf/finish ‖ lo_pub ‖ hi_pub ‖ nonce_i ‖ nonce_r ‖ th1 ‖ th2, 32)` |
| k_probe | `Expand(PRK, kdf/probe ‖ lo_pub ‖ hi_pub, 32)`（静态，无 nonce/session） |
| k_punch | `Expand(PRK, kdf/punch ‖ lo_pub ‖ hi_pub, 32)`（静态，无 nonce/session；与 k_probe 标签不同，不共用 MAC 密钥） |
| session_id | `Expand(PRK, kdf/session-id ‖ lo_pub ‖ hi_pub ‖ nonce_i ‖ nonce_r ‖ th3, 8)` 作 u64 |
| k_i2r / k_r2i | `Expand(PRK, kdf/key/i2r 或 kdf/key/r2i ‖ lo_pub ‖ hi_pub ‖ nonce_i ‖ nonce_r ‖ th3, 32)` |
| th1 | `SHA256(transcript ‖ HELLO 完整帧)` |
| th2 | `SHA256(transcript ‖ HELLO ‖ CHALLENGE)` |
| th3 | `SHA256(transcript ‖ HELLO ‖ CHALLENGE ‖ FINISH)` |
| 帧 MAC | `HMAC-SHA256(K, frame-mac ‖ header[0..42] ‖ payload)` |

各帧 MAC 密钥：HELLO→k_hello，CHALLENGE→k_chal，FINISH→k_fin，ACK→k_r2i，PROBE→k_probe，PUNCH→k_punch，lo→hi 的 PING/PONG/DATA→k_i2r，hi→lo→k_r2i。

## 4. 帧格式

帧 = 42 字节头 + payload + 32 字节 MAC，`payload_len` 必须等于帧长 − 74，payload 最大 1400。

| 偏移 | 长度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 4 | magic | `0x4C5A4831` |
| 4 | 1 | version | `1` |
| 5 | 1 | frame_type | 见下 |
| 6 | 1 | direction | 0 = lo→hi，1 = hi→lo |
| 7 | 1 | flags | v1 必须为 0 |
| 8 | 16 | relationship_id | |
| 24 | 8 | session_id | 0 表示无会话帧，此时 sequence 必须为 0 |
| 32 | 8 | sequence | 每会话每方向独立，从 1 开始 |
| 40 | 2 | payload_len | |

帧类型：`0x01` HELLO、`0x02` CHALLENGE、`0x03` FINISH、`0x04` ACK、`0x05` PROBE、`0x10` DATA、`0x20` CTRL_PING、`0x21` CTRL_PONG、`0x22` PUNCH。

PUNCH 与 PROBE 一样是 sessionless（session_id 与 sequence 均为 0）、永不应答、不分配会话状态，但有两点关键差异：**方向不固定**（两个方向都合法，因为硬侧可能是任意一方），且**不写入 `seen_probes` 去重表**（网格扫描会产生数百个 nonce，改由打洞状态机内部的有界 nonce 环去重）。方向合法性由 payload 的 sender 公钥推出：sender 为 lo 时 header direction 必须是 `0`，为 hi 时必须是 `1`。

### 握手 payload（均为 240 字节，帧长 314）

| 帧 | 字段（偏移:名称(长度)） |
|---|---|
| HELLO | 0:lo_pub(32) 32:hi_pub(32) 64:nonce_i(32) 96:initiator_boot_id(16) 112:initiator_generation(8) 120:issued_at_ms(8) 128:零填充(112) |
| CHALLENGE | 0:hi_pub(32) 32:lo_pub(32) 64:nonce_i(32) 96:nonce_r(32) 128:th1(32) 160:responder_boot_id(16) 176:responder_generation(8) 184:issued_at_ms(8) 192:零填充(48) |
| FINISH | 0:lo_pub(32) 32:hi_pub(32) 64:nonce_i(32) 96:nonce_r(32) 128:th1(32) 160:th2(32) 192:initiator_boot_id(16) 208:initiator_generation(8) 216:issued_at_ms(8) 224:零填充(16) |
| ACK | 0:hi_pub(32) 32:lo_pub(32) 64:th3(32) 96:responder_boot_id(16) 112:responder_generation(8) 120:issued_at_ms(8) 128:零填充(112) |

四种握手帧等长，响应不大于请求，放大比恰为 1。零填充位于 MAC 覆盖范围内，接收方仍须逐字节检查为 0，MAC 正确也要拒绝非零填充。

### PROBE payload（128 字节，帧长 202）

0:sender_pubkey(32) 32:receiver_pubkey(32) 64:sender_boot_id(16) 80:sender_generation(8) 88:issued_at_ms(8) 96:probe_nonce(32)。

只由 hi 发往 lo；从不应答、不分配会话状态、不刷新健康、不改变选中路径。`issued_at` 偏离本地时钟超过 120 秒即丢弃。

### PUNCH payload（128 字节，帧长 202，与 PROBE 等长，放大比恰为 1）

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 32 | sender_pubkey |
| 32 | 32 | receiver_pubkey |
| 64 | 16 | sender_boot_id |
| 80 | 8 | sender_generation |
| 88 | 8 | issued_at_ms |
| 96 | 32 | punch_nonce |

无零填充，128 字节正好用满。`issued_at` 偏离本地时钟超过 120 秒即丢弃。MAC 用 k_punch 覆盖完整 header 与 payload。

### PING / PONG payload（136 字节，帧长 210）

0:sender_pubkey(32) 32:receiver_pubkey(32) 64:nonce(32) 96:sender_boot_id(16) 112:sender_generation(8) 120:issued_at_ms(8) 128:flags(1) 129:保留(7，必须为 0)。

flags：bit0 = 发送方 local_confirmed；bit1 = path_probe（PONG 回显）；bit2 = rekey_request（仅 PING，PONG 置位即拒绝）；bit3–7 必须为 0。PING 的 nonce 为新鲜挑战，PONG 回显所答 PING 的 nonce。

### DATA payload

1..1400 字节，原样承载从 TUN 读出的明文 IPv4 包。

## 5. 会话规则

- 无会话帧（HELLO/CHALLENGE/FINISH/ACK/PROBE）session_id 与 sequence 均为 0；ACK 用 k_r2i 计算 MAC 但不占用 r2i 序号空间。CTRL 与 DATA 携带派生 session_id，sequence ≥ 1。
- 派生出 session_id 为 0，或与已安装但 transcript 不同的会话冲突时，放弃本次尝试，用新 nonce 重来。
- 重传有界：重复的有效 HELLO 让 responder 重发**相同**的 CHALLENGE（同 nonce_r），间隔 ≥1 秒、最多 8 次；重复 CHALLENGE 重发相同 FINISH；派生出相同 session_id 的重复 FINISH 重发相同 ACK，视为幂等而非冲突。一次尝试内不重新生成 nonce；尝试 TTL 为 90 秒，超时或用尽重传预算才可用新 nonce 开新尝试。无效或 MAC 未知的输入只忽略，不清除待定状态。
- 接收窗口为 1024-bit replay window；DATA 与 CTRL 共享序号空间。序号永不回绕，距 u64::MAX 不足 1024 即视为耗尽并重建会话。

## 6. 健康与路径

- 已建立但未确认的会话不算 Direct。只有满足双边确认才报告 Direct / currently_healthy：本端在当前会话完成至少一次 nonce 唯一的 PING→匹配 PONG，并收到对端在该会话置位 local_confirmed 的 PING 或 PONG。local_confirmed 按当前会话和当前已验证 endpoint 动态计算，首次成功后不粘滞。
- 双边确认前每 1 秒 PING，之后每 5 秒；PING 期限 10 秒，每次新 nonce、不重传；每方向最多 4 个待定 nonce，每个绑定 (endpoint, 本端 boot_id, 本端 generation, session_id)，代际或会话不符的结果整体丢弃。只计同一 nonce 的首次到达；DATA、旧 nonce 或其他来源的流量不刷新健康。20 秒无有效回复为 Suspect，30 秒为 Offline。PONG 发送队列容量 8，满时丢弃最旧者并计数。
- 来自非选中路径的正确会话 MAC 只能启动回程挑战：endpoint 经 Observed → Challenged → Verified，需在同一本端代际内、10 秒内从该确切来源收到回显 nonce 与 path_probe 位的 PONG。只有 Verified endpoint 可被选中，切换先建后断。
- rekey：PING bit2 表示请求。只有在当前活动会话下 MAC 正确、序号被 replay window 接受、epoch 为当前、且来自当前选中 endpoint 的 rekey PING 才建立 rekey 意图，有效期 90 秒。总是由 lo 发送 HELLO：lo 想 rekey 时先发 bit2 PING，收到匹配 PONG 后开始 HELLO；hi 想 rekey 时发 bit2 PING，lo 回 PONG 后开始 HELLO。新会话双边确认后才切换，先建后断。没有有效意图的握手不得抢占健康会话。

## 7. 内存上限

| 项 | 上限 |
|---|---|
| 待定握手尝试 | 每关系 32 个，每个 ≤4 KiB，总计 ≤128 KiB |
| responder HELLO 表 | 每来源 16 项 |
| shadow 会话 | 2 |
| 待定 endpoint / 候选 | 各 16 |
| UDP 发送 outbox | 64 帧 |
| 待写入 TUN 的 IPv4 包 | 32 |
| 每 endpoint 路径探测 | 8 |

## 8. 联系记录

记录体固定部分 134 字节，后接 N 个 8 字节候选（1 ≤ N ≤ 8）：

| 偏移 | 长度 | 字段 | 约束 |
|---:|---:|---|---|
| 0 | 2 | magic | `0x4C5A` |
| 2 | 1 | schema_version | `1` |
| 3 | 1 | record_type | `1`（contact） |
| 4 | 16 | relationship_id | |
| 20 | 32 | sender_pubkey | 必须等于 ntfy 签名公钥且为已固定的对端公钥 |
| 52 | 32 | receiver_pubkey | 必须等于本端公钥 |
| 84 | 8 | record_seq | 微秒值，durable、严格递增 |
| 92 | 8 | issued_at_ms | |
| 100 | 8 | expires_at_ms | 默认 issued_at + 600 000，最长 1 小时，读取缓存不延长 |
| 108 | 16 | boot_id | 每次进程启动的 128-bit 随机值 |
| 124 | 8 | generation | 同一 boot_id 内单调 |
| 132 | 1 | candidate_count | 1..=8 |
| 133 | 1 | flags | 见下 |
| 134 | 8N | candidates | |

候选：0:ipv4(4) 4:port(2) 6:source_class(1) 7:保留(1，为 0)。v1 只允许两类来源：`0` STUN 实测映射、`1` 已通过当前代际回程挑战的认证 peer-reflexive；没有人工配置类，STUN 服务器地址永远不是候选。候选两两不同。

flags 位（其余位保留，必须为 0，否则整条记录被拒）：

| 位 | 名称 | 含义 |
|---|---|---|
| bit0 | `FLAG_MAPPING_EDM` | 发布者 NAT 为 endpoint-dependent mapping，只能当硬侧 |
| bit1 | `FLAG_MAPPING_UNKNOWN` | 发布者未能分类自己的映射行为，不得为其分配打洞角色 |
| bit2 | `FLAG_PUNCH_OFFER` | 发布者已开启硬侧打洞窗口；记录 expires_at 不晚于该窗口结束 |

映射位或开窗状态变化需要刷新签名记录，仍遵守公共 HTTP/发布限流。硬侧窗口最多 180 秒，易侧只在有效 offer 剩余时间大于 30 秒时扫描；网格发完不代表响应已经收齐，须继续接收至扫描截止。

两个映射位都不置（`flags` 为 0）表示 endpoint-independent，这也是不支持这些位的旧版本二进制的样子。签名覆盖 flags，篡改即验签失败。

记录规则：

- `record_seq = max(max(本地 durable, 对端最高有效 seq) + 1, now_us)`，checked 运算且不超过 i64::MAX；在单 writer 锁下 fsync 预留后才签名或排队发布。
- 读取时**先**检查过期；同 seq 且字节相同为幂等（不刷新任何时间），同 seq 字节不同为 equivocation，seq 更小为回滚，均拒绝。
- 同一 boot_id 内 generation 不得回退；新 boot_id 可重置 generation，但 record_seq 仍须严格递增。
- 发布与选为目标是两套检查：发布时只拒绝结构上不可用的地址与 STUN 服务器地址；选目标时另外拒绝本端的确切 endpoint 与整体禁止的地址（信令网关、overlay）。同公网 IP 不同端口是合法的对端映射，不得整体屏蔽。
