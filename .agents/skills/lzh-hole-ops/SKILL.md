---
name: lzh-hole 运维
description: lzh-hole 双机 UDP 直连的部署、升级、配对、launchd 服务管理、doctor 排障与双端验收。当需要安装/升级/卸载 lzh-hole 服务、向 home4 部署二进制、首次配对、查看 doctor、排查连不通或做 TCP/UDP/ICMP 验收时使用。
---

# lzh-hole 运维

## 环境

| 项 | 本机（公司） | home4 |
|---|---|---|
| VIP | `10.203.0.1` | `10.203.0.2` |
| 访问 | 本地 | `ssh home4`（经跳板，只用于部署、配对、启动和事后取证） |
| 远端工作目录 | — | `~/Workspace/hole`，不改名 |

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

## 配置

从模板生成 `/etc/lzh-hole/config.toml`，按实际环境修改：

- `management_uid`：管理员 `id -u`。
- `interface` / `bind_ip`：默认省略，由 daemon 自动选择有公网路由的物理接口并失败轮换；仅在必须固定时填写，填写后不会自动改选。
- `stun_seeds`：1 个以上数值公网 IPv4:port，部署前确认可用。
- `[ntfy].topic`：严格为 `lzh-hole-v1-<relationship_id 的 32 个小写 hex>`。
- `[ntfy].resolve_ip`：仅在 DNS 把 ntfy 解析成 Fake-IP 时设置一个公网 IPv4。
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

- `overlay.direct_reachable` / `overlay.currently_healthy`：只有当前 session/endpoint/epoch 匹配的 PONG 才会为 true。
- `stun`：本端公网映射与服务器状态；全部服务器连续超时会触发 socket 重建。
- `ntfy`：订阅状态、`pacing_reason`、`not_before_unix_ms`。阻塞原因优先于后续 idle/发布失败等现象，等待期间不会发请求。
- `session`、`tun`、`routes`、`bytes`、`drops`（带原因计数）；未检测项为 `unknown`/`null`。
- doctor 不含 `functional_pass` 和 `p0_qualified`，必须靠下方外部验收判断。

## 排障

| 症状 | 检查 |
|---|---|
| STUN 发送失败或无映射 | `route -n get -ifscope <ifname> <STUN IP>` 是否有路由；自动模式会轮换候选，固定 `interface` 不会；只剩一个有路由接口时只能 degraded |
| 0 个对端候选 / 信令不通 | doctor 的 ntfy 状态与 `pacing_reason`；是否在等待限流；DNS 是否返回 Fake-IP（需 `resolve_ip`） |
| 有候选但不 healthy | 双方 STUN 映射是否同一公网 IP（同出口 NAT 回环未解决，见 `doc/status.md`）；需要抓包时 `sudo tcpdump -ni <ifname> udp port 51000`，须用户确认，取证后停止 |
| ping 不通但 healthy | utun 是否存在、对端 VIP `/32` 路由是否指向本程序 utun、`drops` 原因 |

## 双端验收

分别报告以下四项，不以握手成功代替透明组网验收：

- `direct_reachable`、`currently_healthy`：来自双端 doctor。
- `functional_pass`：双向 ICMP、TCP、UDP 全部通过。
- P0 资格：每端至少 5 次记录更新、传播 p95 ≤120 秒、3 次独立冷启动各 ≤180 秒；未测即为未通过。

方法：

- ICMP：`/sbin/ping -n -c 20 -t 30 -S <本端VIP> <对端VIP>`，两个方向各一次，看丢包与退出码。
- TCP：在 VIP 上用 `nc` 双向各传约 64 KiB 随机数据，比较收发长度与 SHA256。
- UDP：双向各传 512 字节并比较 SHA256。macOS `nc` 会把超过 1024 字节的 UDP 报文截断，不要用大报文判断隧道丢包。
- 验收前后对比默认路由、DNS（`scutil --dns`）和 plist/config 哈希，确认未变；结束后确认临时监听端口已关闭（`lsof -nP -i :<port>` 无输出）。
- 区分单进程模拟、双进程 mock 和真实双机公网测试；自有记录读回不等于对端传播时间。
