# lzh-hole

面向两台 Apple Silicon macOS 的双机 IPv4-over-UDP 直连。在固定虚拟 IPv4（VIP）之间透明承载 TCP、UDP 和 ICMP；不是代理、互联网出口或多节点 mesh，UDP 直连失败时如实离线，不退回 SSH/TCP/TURN/DERP 中继。

- [架构与打洞原理](doc/architecture.md)
- [wire v1 协议](doc/protocol.md)
- [已知问题](doc/status.md)
- 部署、配对、服务管理、排障与验收：项目 skill [`lzh-hole-ops`](.agents/skills/lzh-hole-ops/SKILL.md)

## 安全约束

- 业务面是明文 IPv4-over-UDP + HMAC-SHA256，不做隧道加密或业务中继。
- ntfy 只承载有界、Ed25519 签名的联系记录，不承载业务 IP 包、PSK 或私钥。
- VIP、双方公钥和 relationship ID 只来自 finalized 配对状态；PSK 只存放在私有 state 目录（目录 0700、文件 0600）。
- 只使用专用 utun 和对端 VIP 的一条 `/32` host route，不改默认路由、DNS、PF 或现有 VPN。
- 最多保留 8 个绑定真实物理接口＋IPv4 的 socket；每个 socket 的 STUN、握手、健康检查和业务 UDP 复用同一描述符。

## 自动发现

默认开启 `[lan] enabled = true`（旧配置可直接加载）。同网段通过接口隔离的 Bonjour `_lzh-hole._udp.local.` 发现对端，仅广播版本、公钥和实际绑定地址；候选必须匹配已配对公钥、A 记录及真实 RFC1918 子网/直连路由。LAN 冷启动不依赖默认路由、STUN 或 ntfy。

公网仍使用 STUN＋ntfy。新候选优先尝试 LAN，已有健康公网路径保持稳定；最终只使用认证握手及当前路径 PONG 确认的一条路径。Bonjour、公网信令或 STUN 故障不重建其他健康 transport。真实换网与公网 P0 仍待验收，当前限制见 [已知问题](doc/status.md)。

## 结构

```text
crates/
├── lzh-hole-types/      共享领域类型
├── lzh-hole-store/      身份、配对、私密持久化、durable seq
├── lzh-hole-protocol/   sans-I/O 协议与 PeerEngine
├── lzh-hole-discovery/  LAN/Public 发现模型、签名记录、STUN、ntfy、限流
├── lzh-hole-net/        macOS 接口、Bonjour、UDP socket、utun、routes
├── lzh-hole-control/    私有 Unix socket doctor
├── lzh-hole-service/    配置、daemon、lifecycle、组件编排
└── lzh-hole/            CLI：init / pair / daemon / doctor
tests/fixtures/          wire v1 测试向量
doc/                     架构、协议与已知问题
.agents/skills/          运维 skill 与部署模板
```

## 构建与测试

工具链由 `rust-toolchain.toml` 固定为 1.99.1。在项目根目录执行：

```sh
cargo build --release --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo run --locked --offline --bin lzh-hole -- --help
cargo run --locked --offline --bin lzh-hole -- daemon --help
cargo run --locked --offline --bin lzh-hole -- doctor --help
cargo run --locked --offline --bin lzh-hole -- pair --help
```

离线测试不访问公网或对端主机、不创建 OS utun、不执行 sudo，不能替代真实双机验收。
