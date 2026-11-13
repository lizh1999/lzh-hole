# AGENTS.md

## 项目目标

lzh-hole 是面向两台 Apple Silicon macOS 的 Rust 双机 IPv4-over-UDP 组网项目，仅允许 UDP 直连。
目标是固定虚拟 IPv4 下透明承载 TCP、UDP、ICMP；不是代理、出口节点或多节点 mesh。
已知问题见 `doc/status.md`，架构见 `doc/architecture.md`。
优先跑通实际功能，只修必要阻塞；不要把无止境重构或审查当作推进功能的替代品。

## 目录结构

- `Cargo.toml` / `Cargo.lock` / `rust-toolchain.toml`：Rust workspace、锁定依赖与固定工具链 1.99.1；edition 2024。`.gitignore` 排除 `target/`。
- `crates/lzh-hole-types/`：最小身份、Endpoint、公开配对结果与必要秘密类型。
- `crates/lzh-hole-store/`：身份初始化、配对、私密持久化、durable seq、peer 高水位与单 writer 锁。
- `crates/lzh-hole-protocol/`：sans-I/O wire/session/handshake/crypto/replay/health/path/PeerEngine。
- `crates/lzh-hole-discovery/`：ntfy transport/message/exchange/pacing、签名记录与 STUN 事务。
- `crates/lzh-hole-net/`：macOS 接口、绑定 UDP socket、utun 与精确 routes；不依赖上层协议。
- `crates/lzh-hole-control/`：私有 Unix socket doctor、DTO、权限、有界帧与 channel。
- `crates/lzh-hole-service/`：配置、daemon/runtime/lifecycle 与组件编排。
- `crates/lzh-hole/`：极薄 CLI，仅 `init`/`pair`/`daemon`/`doctor`。
- `tests/fixtures/wire-v1.json`：wire v1 字节级测试向量（仅合成输入与期望输出），改动即改变线上格式。
- `doc/`：`architecture.md` 架构说明，`protocol.md` wire v1 线上格式，`status.md` 只记录当前已知问题。
- `.agents/skills/lzh-hole-ops/`：部署、配对、服务管理、排障与验收的运维 skill 及 launchd/config 模板。

## 本地构建与验证

所有命令从项目根目录执行，编译只在本机进行：

~~~sh
cargo build --release --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo run --locked --offline --bin lzh-hole -- --help
cargo run --locked --offline --bin lzh-hole -- daemon --help
cargo run --locked --offline --bin lzh-hole -- doctor --help
cargo run --locked --offline --bin lzh-hole -- pair --help
~~~

离线缓存缺依赖时先说明，不擅自升级 Cargo.lock 或悄悄改变依赖版本。
新增行为补针对性回归测试；使用 rustfmt 和已有 Rust 命名、错误处理风格。
lint 统一在 `[workspace.lints]`：`unsafe` 只允许出现在 net/store/control/service，每处须有 `// SAFETY:` 注释。
不得用 `| tail` 等管道掩盖构建或测试退出码；报告实际命令、退出码与测试结果。
默认测试不得发布公网记录、访问 home4 或执行特权操作；网络实验必须显式启用。

## 协作与改动边界

保持一个 writer；修改前读取当前文件，局部修改优先精确编辑；禁止基于片段读取覆盖完整文件或绕过权限检查。
代码托管于私有仓库 `lizh1999/lzh-hole`（分支 `main`）。只提交源码、文档与模板，不提交构建产物、二进制、运行记录或任何秘密；提交前运行完整本地验证。
不保留历史文档：版本历史只存在于 Git 提交中，不写变更日志、版本哈希表、实验报告或运行记录；`doc/status.md` 只写当前仍存在的问题，问题解决即删除条目。
部署、配对、服务管理、排障与验收按 `lzh-hole-ops` skill 执行。
本地工作区为 `/Users/minimax/Workspace/lzh-hole`，home4 仍使用 `~/Workspace/hole`，不改远端目录名。
只向 home4 部署本地生成的二进制，不上传源码、测试或构建脚本，不在 home4 执行 cargo。
首次配对文件通过管理 SSH 交换已获明确授权；这不授权无关文件传输或把秘密放入诊断包。
SSH 仅可用于部署、配对、启动和事后取证；运行时发现、候选交换和恢复不得依赖它。

## 网络与安全契约

- 数据面是明文 IPv4-over-UDP + HMAC-SHA256，不加隧道加密；不得引入 WireGuard、HPKE 或业务中继。
- 公共信令（ntfy）只能承载有界签名协调记录，不能承载业务 IP 包、PSK 或私钥。
- 使用成熟密码库；验证身份、关系、MAC、方向、session、sequence、epoch 与实际 endpoint，拒绝重放。
- 私密目录 0700、文件 0600；秘密不得进入 argv、环境变量、日志、工具输出或交付附件。
- 联系记录 sequence 必须构造/发布前 durable 预留；同一 key 单 writer，重启不得倒退或复用。
- 公共 HTTP 每 host 操作及每 key 发布至少间隔 30 秒，遵守更严格的限流和 Retry-After；不得换 key/IP 绕限流，不得删除 `ntfy-pacing.json`。
- STUN 与数据必须复用保留的物理接口 socket；保留多个真实出口候选，拒绝 Fake-IP，禁止手填本次公网端口冒充发现。
- 不改默认路由、DNS、PF 或现有 VPN，不开放家庭 LAN；仅使用专用 utun 与双方 /32 host route。
- 创建 TUN、特权 helper、系统服务安装、真实休眠/换网/重启必须另行明确确认，不从普通“继续”推定授权。
- UDP 直连失败必须如实离线，不增加 SSH/TCP/TURN/DERP 等业务兜底；队列、重试和取消清理都必须有界。

## 实测与交付

区分单进程模拟、双进程 mock、真实双机公网测试；自有记录读回不等于对端传播时间。
P0 门槛包括每端至少 5 次记录更新、传播 p95 ≤120 秒及 3 次独立冷启动均 ≤180 秒；未测项目不得填通过。
分别报告 direct_reachable、currently_healthy、functional_pass 与 P0 资格，不能以握手成功代替透明组网验收。
实验结果只在对话中报告，工作区不落盘运行记录；临时文件放会话临时目录，结束时删除。
部署核对双端二进制 SHA256；不得把服务进程重启冒充为系统重启验收。
