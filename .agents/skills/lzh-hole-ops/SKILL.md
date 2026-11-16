---
name: lzh-hole 运维
description: lzh-hole 多机 UDP 直连 mesh 的部署、升级、逐对配对、launchd 服务管理、doctor 排障与逐对验收。当需要安装/升级/卸载 lzh-hole 服务、向 home4 或 kuma 部署二进制、首次配对或新增一个 peer、查看 doctor、排查某一对不通、或做 TCP/UDP/ICMP 验收时使用。
---

# lzh-hole 运维

## 环境

| 项 | 本机（公司） | home4 | kuma |
|---|---|---|---|
| VIP | `10.203.0.1` | `10.203.0.2` | `10.203.0.3` |
| 访问 | 本地 | `ssh home4`（经跳板，只用于部署、配对、启动和事后取证） | `ssh kuma`（同上） |
| 远端工作目录 | — | `~/Workspace/hole`，不改名 | 同 home4 布局 |

拓扑是**全互联**：三台机器两两之间各一条独立关系，共 3 条关系（mac–home、mac–kuma、home–kuma）。每条关系有自己的 PSK 和协调 topic；**不做转发**，mac 与 kuma 不通时不会借道 home。

在家中同一局域网时，管理连接使用 `ssh home-local`（SSH 配置通过 mDNS 解析）；下文部署命令中的 `home4` 相应替换为 `home-local`。`ssh home` 指向隧道 VIP `10.203.0.2`，不用于需要重启隧道的部署操作。远端目录仍为 `~/Workspace/hole`。运行时发现、候选交换和恢复不依赖 SSH。

两端安装位置相同：

| 路径 | 用途 |
|---|---|
| `/usr/local/libexec/lzh-hole` | 二进制（root:wheel 0755） |
| `/etc/lzh-hole/config.toml` | 非秘密配置（root 持有，不可 group/world 写） |
| `/var/db/lzh-hole/` | 身份、PSK、durable seq、高水位、`ntfy-pacing.json`（0700/0600） |
| `/var/run/lzh-hole/control.sock` | doctor socket（管理 UID 持有，0600） |
| `/Library/LaunchDaemons/com.lzhhole.daemon.plist` | launchd 服务，label `com.lzhhole.daemon` |

模板：[`templates/com.lzhhole.daemon.plist`](templates/com.lzhhole.daemon.plist)、[`templates/config.toml.example`](templates/config.toml.example)。

下文命令中的 `lzh-hole` 指 `/usr/local/libexec/lzh-hole`，它不在 PATH 中，执行时写全路径。

## 硬性规则

- 只在本机构建；只向 home4 传本机生成的二进制，不传源码/测试/脚本，不在 home4 执行 cargo。
- 运行时发现、候选交换和恢复不得依赖 SSH；不得手填本次公网端口冒充发现；不增加 SSH/TCP/TURN/DERP 业务兜底。
- 不改默认路由、DNS、PF 或现有 VPN，不开放家庭 LAN。
- **禁止删除 `ntfy-pacing.json`** 或 state 目录来绕限流；不得换 key/IP/topic 绕限流。
- 卸载时默认不删 `/var/db/lzh-hole` 与 `/etc/lzh-hole/config.toml`（身份、PSK、durable seq 不可恢复）。
- PSK、私钥、offer 文件内容不得进入 argv、环境变量、日志、对话输出或任何附件。
- 以下操作每次都需要用户明确确认，不能从“继续”推定：首次安装/卸载系统服务、创建 TUN、特权 helper、真实休眠/换网/系统重启测试。常规升级也要先告知将重启两端服务。
- 不把服务进程重启当作系统重启验收。
- 测试和验收结果只在对话中报告，工作区不保存运行记录；临时文件放会话临时目录并在结束时删除。

## 首次配对

1. 两端各自初始化身份（state 目录自动建为 0700）：
   ```sh
   sudo lzh-hole init --state /var/db/lzh-hole
   ```
2. A 生成 offer（含 PSK，文件 0600）：
   ```sh
   sudo lzh-hole pair offer --state /var/db/lzh-hole --peer-key '<B_PUBLIC_KEY>' \
     --self-vip 10.203.0.1 --peer-vip 10.203.0.2 --out <offer 文件>
   ```
3. offer 经管理 SSH 传给 B（已授权的唯一文件交换用途），B 接受：
   ```sh
   sudo lzh-hole pair accept --state /var/db/lzh-hole --offer <offer 文件> --out <accept 文件>
   ```
4. accept 传回 A 后双方 finalize：
   ```sh
   # A
   sudo lzh-hole pair finalize --state /var/db/lzh-hole --role initiator \
     --expect-peer-key '<B_PUBLIC_KEY>' --accept <accept 文件>
   # B
   sudo lzh-hole pair finalize --state /var/db/lzh-hole --role responder \
     --expect-peer-key '<A_PUBLIC_KEY>' --offer <offer 文件>
   ```
5. finalize 后删除两端所有 offer/accept 中转副本。参数以 `lzh-hole pair <sub> --help` 为准。

### 多机 mesh：逐对配对

每新增一个 peer 就重复一次上面的三步，**每对之间一条独立关系**。三台机器需要 3 条关系：

- mac–home：mac `--self-vip 10.203.0.1 --peer-vip 10.203.0.2`，home 反之。
- mac–kuma：mac `--self-vip 10.203.0.1 --peer-vip 10.203.0.3`，kuma 反之。
- home–kuma：home `--self-vip 10.203.0.2 --peer-vip 10.203.0.3`，kuma 反之。

要点：

- 同一个节点的 `--self-vip` 在所有关系中必须一致；peer key 与 peer VIP 各只能被一条关系占用。违反时 `pair offer` 当场报错并指出是哪条关系占用了它。
- 同一节点可以**同时**持有多个未完成 offer（上限 8），各自按 pairing_id 存放，互不覆盖 PSK。finalize 时按 acceptance/offer 里的 pairing_id 取回对应 offer，完成后自动删除。
- `pair offer`/`finalize` 会打印当前已 finalized 的关系数，用它核对进度。
- 已配过的节点再对同一个 peer key 发起 offer 会被拒绝；要重新配对必须先移除该关系目录。

## 配置

从模板生成 `/etc/lzh-hole/config.toml`，按实际环境修改：

- `management_uid`：管理员 `id -u`。
- `interface` / `bind_ip`：默认省略，由 daemon 保留有界物理接口/IPv4 socket 集合；LAN 可使用没有公网路由的接口，公网候选按真实出口路由筛选。仅在必须限制接口或地址时填写。
- `[lan].enabled`：默认 `true`，通过 Bonjour 发现同网段 RFC1918 候选；仍须认证握手和当前路径 PONG 才能上线。旧配置无需增加此节。
- `stun_seeds`：1 个以上数值公网 IPv4:port，部署前确认可用。
- `[ntfy]` **没有 topic 字段**：每条关系的 topic 由 daemon 从 finalized 配对状态推导。带 `topic` 的旧配置会被直接拒绝，必须删掉该行。
- `[ntfy].dns_server`：仅在网关本身不提供 DNS 时指定解析器。主机名默认不经过系统解析器，而是在绑定到选定物理接口的 UDP socket 上向该接口的 IPv4 默认网关查询，因此系统解析器返回 Fake-IP 不再影响信令。
- `[ntfy].resolve_ip`：最后手段，把 base_url 的 hostname 钉死到某个公网 IPv4；服务端换 IP 后必须手工更新。
- 限制：文件 ≤64 KiB，不跟随最终 symlink，属主为 daemon effective UID 且不可 group/world 写；`udp_port` 非零；`mtu` 576–1200；路径必须是绝对路径，socket 位于专用目录。VIP/PSK 不得写入配置。

## 服务管理

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.lzhhole.daemon.plist   # 启动
sudo launchctl bootout system/com.lzhhole.daemon                                 # 停止
sudo launchctl print system/com.lzhhole.daemon                                   # 查看状态/PID
lzh-hole doctor --socket /var/run/lzh-hole/control.sock                         # 健康快照
```

plist 参数固定为 `daemon --config /etc/lzh-hole/config.toml --allow-tun`，`RunAtLoad`/`KeepAlive`、`ThrottleInterval=30`、`Umask=077`、以 root 运行。

`bootout` 返回不代表清理完成。再次 bootstrap 前须有界等待（如最多 30 秒，每秒检查）：

- `/var/run/lzh-hole/control.sock` 已消失；
- `ifconfig` 中不再有该实例的 utun；
- `netstat -rn -f inet` 中不再有对端 VIP 的 `/32` 路由。

超时未清理时先确认进程确已退出、路径确属本程序，再报告用户决定，不盲删。

## 升级流程

1. 本机构建与离线检查（命令见项目 `AGENTS.md`），记录 `shasum -a 256 target/release/lzh-hole`。
2. 传输到 home4：`scp target/release/lzh-hole home4:~/Workspace/hole/lzh-hole.new`。
3. **独立核对**远端 SHA256（传输工具退出码不可信，SCP 可能传完后超时）：
   `ssh home4 'shasum -a 256 ~/Workspace/hole/lzh-hole.new'`。
4. 先升级 home4（bootout → 等待清理 → `sudo install -m 0755 -o root -g wheel` 覆盖 `/usr/local/libexec/lzh-hole` → bootstrap），再升级本机，便于确认新旧互通。删除远端 `.new` 临时文件。
5. 两端核对 `/usr/local/libexec/lzh-hole` 的 SHA256 与本机构建一致。
6. 等待双方 doctor 显示 healthy 后执行验收。ntfy 限流已持久化，重启后可能需等待 `not_before_unix_ms`；不要为加速而删除 pacing 文件。

## 卸载

```sh
sudo launchctl bootout system/com.lzhhole.daemon
# 等待清理（见上）
sudo rm /Library/LaunchDaemons/com.lzhhole.daemon.plist
sudo rm /usr/local/libexec/lzh-hole   # 仅在确认不再需要时
```

## doctor 解读

- `overlay.direct_reachable` / `overlay.currently_healthy`：只有当前 session/endpoint/transport/epoch 匹配的 PONG 才会为 true。
- `lan`：Bonjour 发现状态，不等于对端健康；`current_path.kind` 区分 `lan` / `public`，并展示实际接口和双方 endpoint。
- `stun`：本端公网映射与服务器状态；STUN 超时不重建健康 LAN 连接，物理接口或 socket 失效按 transport 局部处理。
- `ntfy`：订阅状态、`pacing_reason`、`not_before_unix_ms`。阻塞原因优先于后续 idle/发布失败等现象，等待期间不会发请求。
- `peers[]`：**逐 peer** 的 `relationship_id`、`peer_vip`、`peer_key`、`role`、`session`、`overlay`、`ntfy`、`current_path`、`candidates`、`punch`、`bytes`、`drops`。判断某一对通不通只看这里。
- 节点级 `session`/`overlay` 是**跨 peer 聚合**，只会比最差的 peer 更差，不会更好；`unknown` 排在 `healthy` 之前。节点级 `current_path` 恒为 `null`、`candidates` 恒为空。
- `session`、`tun`、`routes`、`bytes`、`drops`（带原因计数）；未检测项为 `unknown`/`null`。
- doctor 不含 `functional_pass` 和 `p0_qualified`，必须靠下方外部验收判断。

## 排障

| 症状 | 检查 |
|---|---|
| STUN 发送失败或无映射 | 检查 `route -n get -ifscope <ifname> <STUN IP>`；区分公网发现故障和当前 LAN 路径健康状态 |
| 0 个对端候选 / 信令不通 | LAN 检查 Bonjour、同网段地址和接口限制；公网检查 ntfy 状态与限流。解析失败时 doctor 的 detail 会给出 dns error 的具体原因（网关不可达、答案被拒或超时），据此判断是网关 DNS 还是网络出口问题 |
| 有候选但不 healthy | 区分 LAN / 公网候选；同出口公网路径可能受 NAT 回环限制，LAN 检查实际接口和对端地址。需要抓包时 `sudo tcpdump -ni <ifname> udp port 51000`，须用户确认，取证后停止 |
| ping 不通但 healthy | utun 是否存在、对端 VIP `/32` 路由是否指向本程序 utun、`drops` 原因 |

## 逐对验收

**每一对关系单独验收并单独报告**，不能用节点级聚合健康代替，也不能用其中一对通推断其余对通。
三台机器就要报 3 组结果（mac–home、mac–kuma、home–kuma）。

每组分别报告以下四项，不以握手成功代替透明组网验收：

- `direct_reachable`、`currently_healthy`：来自该对**两端** doctor 的 `peers[]` 中对应 `relationship_id` 的那一项。
- `functional_pass`：双向 ICMP、TCP、UDP 全部通过。
- P0 资格：每端至少 5 次记录更新、传播 p95 ≤120 秒、3 次独立冷启动各 ≤180 秒；未测即为未通过。

方法：

- ICMP：`/sbin/ping -n -c 20 -t 30 -S <本端VIP> <对端VIP>`，两个方向各一次，看丢包与退出码。
- TCP：在 VIP 上用 `nc` 双向各传约 64 KiB 随机数据，比较收发长度与 SHA256。
- UDP：双向各传 512 字节并比较 SHA256。macOS `nc` 会把超过 1024 字节的 UDP 报文截断，不要用大报文判断隧道丢包。
- 验收前后对比默认路由、DNS（`scutil --dns`）和 plist/config 哈希，确认未变；结束后确认临时监听端口已关闭（`lsof -nP -i :<port>` 无输出）。
- 区分单进程模拟、双进程 mock、真实多机 LAN 和真实多机公网测试；LAN 功能通过不等于公网 P0 通过，自有记录读回不等于对端传播时间。
- 验收前确认三端的 `peers[]` 条数与预期一致（mac 应为 2，home 与 kuma 各为 2），且每条的 `peer_vip`/`peer_key` 与配对时一致。
