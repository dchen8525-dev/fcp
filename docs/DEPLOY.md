# FCP 部署与运维指南

> 面向部署者与运维；设计与验收依据见 `FCP_PROTOCOL_V6.md`、`FCP_V6_DETAILED_DESIGN.md`、
> `FCP_M2_PROXY.md`（代理）、`FCP_M3_CONTROL.md`（控制器）、`FCP_M4_EVAL.md`（评估）。
> 本文全部参数以 `apps/fcp-proxy/cli.cc` 的 Usage 为准。

## 1. 构建矩阵

| 产物 | 平台 | 命令 |
|---|---|---|
| 代理 CLI（client/server） | Windows | `cmake -B build/proxy -S . -DCMAKE_BUILD_TYPE=Release -DFCP_BUILD_PROXY=ON` + `cmake --build build/proxy --config Release` |
| 代理 CLI | Linux | `cmake -B build/rel -S . -DCMAKE_BUILD_TYPE=Release -DFCP_BUILD_PROXY=ON && cmake --build build/rel -j$(nproc)` |
| Qt 桌面客户端 | Windows | `build_app.bat [Debug\|Release]`（需要 vcpkg 的 qtbase：`vcpkg install qtbase:x64-windows`；脚本自动在 VS 内置 vcpkg 与 `D:\work\vcpkg` 间切换） |
| 工具（fcp_bench / fcp_replay） | 双端 | 默认随 `FCP_BUILD_TOOLS=ON` 构建，无需额外开关 |
| 全部单测（27 项） | 双端 | `build.bat [Debug\|Release]`（Windows）/ `ctest --preset linux-x64-debug`（Linux） |

- 门禁标准：**Windows × Debug/Release + Linux × Debug/Release 四套 ctest 27/27**。
- Linux 没有 release 构建预设：手动 `-DCMAKE_BUILD_TYPE=Release` 配第二棵构建树。
- Qt 客户端只链 `fcp_proxy_core`（引擎库，默认随 tests/apps 构建），不依赖 CLI 的两个可执行文件。

### 1.1 版本兼容（v7 硬断 v6，R3-1）

**v7 与 v6 不能互通，升级必须两端同时替换。** 这不是"协商降级"，两端各自拒绝对方：

| 层 | v6 | v7 | 表现 |
|---|---|---|---|
| 握手 magic | `FCP_HELLO_V3` | `FCP_HELLO_V4` | magic 兼作握手版本号；旧 magic 一律不识别 → 3 次重试后 `V4 no ACK after 3 tries` |
| HELLO 长度 | 20 | 36（多 16B 发送方 nonce） | 长度门限不符，直接丢弃 |
| HELLO_ACK 长度 | 20 | 52（回显 c_nonce + s_nonce） | 同上 |
| 会话密钥 | `AES_psk(salt‖0^8)` | `AES_psk(AES_psk(AES_psk(salt‖0^8) ⊕ c_nonce) ⊕ s_nonce)` | 密钥不同 → 数据面全丢（`auth_fail` 陡增） |
| 数据密文 | 同一把密钥 | 与握手密钥分离（双 envelope） | 旧版本用握手密钥解数据 → 全丢 |

升级步骤（**不能滚动升级**）：
1. 窗口期停服务端 → 换 `fcp-proxy-server` → 换全部 `fcp-proxy-client`/Qt 客户端 → 起服务端。
2. 若误混版本，症状是**握手失败**（日志 `V4 no ACK`）或**握手成功但 0 吞吐**（`auth_fail` 持续增长）。
   两者都不是网络/防火墙问题，先核对版本。
3. `fcp_bench` 的会合格式未变（salt 交换仍在会合包里），但两端都必须是 v7 才有意义。
4. PSK 与 salt 宽度未变（16B / 8B）：**不需要改任何配网或密钥材料**。


## 2. 二进制与角色

| 文件 | 角色 |
|---|---|
| `fcp-proxy-server` | 服务端：监听一个 UDP 端口，按 SOKS5/HTTP-CONNECT 语义代理客户端拨号 |
| `fcp-proxy-client` | 客户端：本地 SOCKS5(:1080)/HTTP(:1080 同端口自适应) 入口，流量经 FCP 到服务端 |
| `fcp_client.exe` | Qt GUI：测速页 + 代理页（与 CLI 同引擎） |
| `fcp_bench` | 无交付义务的吞吐标定（对照"天花板"用） |
| `fcp_replay` | 控制器轨迹回放（`--trace` 录制文件的离线分析） |

## 3. 密钥与端口规划

- **PSK**：16 字节，两端一致；CLI 用 `--key=HEX32`（32 位十六进制）。生成：
  `openssl rand -hex 16`。会话密钥按 salt 派生（§6.0），PSK 轮换归运维。
  仓库不内置任何默认 PSK。Qt GUI 每次启动用 CSPRNG 生成随机 PSK 且**不写入 QSettings**；
  连已有服务端时把服务端 `--key` 填进界面（脚本化用 `--proxy-psk` 覆盖），两端一致才可通。
  会话 salt 由程序每连接随机生成，GUI 不提供配置项。
- **UDP 端口**：默认 4460。**部署前实测云商防火墙**——部分云商只放行特定 UDP 端口
  （#22 实测：UDP/40001 报文到网卡但不进 socket，最终只能用 UDP/40000）。端口试探：
  服务端起在候选端口 → 本地 `ss -uln` 确认监听 → 客户端小流量实测。
- **PMTU**：`--mtu`（默认 1400）必须 ≤ 路径最小 MTU，否则触发黑洞故障模式
  （握手可过、data/parity 全丢、表现为吞吐骤降；§14.12）。

## 4. 服务端部署（Linux）

```bash
# 最小参数
fcp-proxy-server --key=HEX32 --bind=0.0.0.0 --port=40000
# 生产推荐（可观测）
fcp-proxy-server --key=HEX32 --bind=0.0.0.0 --port=40000 \
  -v --stats=10000 --trace=/var/log/fcp/srv --idle=300000
```

| 参数 | 说明 |
|---|---|
| `--bind/--port` | UDP 监听（默认 0.0.0.0:4460） |
| `--k=N` | 钉死 parity（-1 自适应；短连接密集用 `--k=2`，§14.16） |
| `--fec-budget=R` | 冗余字节比上限（默认 0.50，0 = 不限；深队列/按流量计费链路收紧） |
| `--d=N --p=N` | 集合几何（默认 10/3；两端一致才生效，协商取小） |
| `--max-sessions=N` | 并发会话上限（默认 256） |
| `--idle=ms` | 会话静默拆除（默认 300000；**应用响应慢于该值会被误拆**，见 §7） |
| `-v` | 协议级日志（FECSTAT/ledger/capped/销毁诊断）；不开则只有 stats 行 |
| `--stats=ms` | 周期 stats 行（缺省仅退出时） |
| `--trace=PREFIX` | 每会话控制器轨迹 `<PREFIX>.<cid>.jsonl`（目录自动创建；#35 起 GUI 同款） |

守护化：`systemd`（`Restart=on-failure`）或
`setsid nohup ... >/var/log/fcp/server.log 2>&1 </dev/null &`（注意：远端 shell 里
`pkill -f` 会匹配命令行自身，用 `pkill -x fcp-proxy-server`）。

## 5. 客户端

### 5.1 CLI

```bash
fcp-proxy-client --key=HEX32 --host=<服务器IP> --port=40000 --local-port=1080
# 验收
curl --socks5-hostname 127.0.0.1:1080 http://<目标>/
curl --socks5-hostname 127.0.0.1:1080 https://<目标>/   # CONNECT + TLS，证书端到端校验
```

客户端专属：`--host/--port/--listen/--local-port`；其余与服务端同名同义
（`--k/--fec-budget/--trace/--idle/--d/--p/--mtu/--window/--rcv-buf/--no-prewarm`）。

### 5.2 Qt GUI

- 代理页字段：服务器 / PSK（每次启动随机、不落盘） / 本地监听 / MTU / 钉 k / 预热 /
  **FEC 预算** / **轨迹前缀**（QSettings 键 `proxy/fec_budget`、`proxy/trace_prefix`）。
  测速页同规则：PSK 随机生成、不持久化；连固定服务端时手工填入其 `--key`。
- 脚本化验收参数：`--proxy-host/--proxy-port/--proxy-listen/--proxy-psk/
  --proxy-fec-budget/--proxy-trace/--proxy-autostart`。
- 分发：`build_app.bat` 末尾的 windeployqt 部署 Qt 运行时；拷贝整个输出目录即可。

## 6. 观测与排障

### 6.1 stats 行（两端同格式）

```text
stats  220.2s live=0 up=42 tunnels=37 tx=6472895B rx=173696566B bad_entry=0 refused=5
       hs_failed=0 reset=0 idle=0 clash=0 over=0 unknown=0 tomb=50 duprec=0
```

| 字段 | 解读 |
|---|---|
| `live/up/tunnels` | 存活会话 / 已协商 / 已通隧道；**收尾应全部归零**（否则泄漏） |
| `refused` | 服务端拨号被拒（目标端口未开）——正常业务事件 |
| `hs_failed/clash/over` | 握手失败 / salt 冲突（第四方重放）/ 超会话上限 |
| `unknown` | 无主 salt 报文（应为 0；#29a 后死会话尾巴不再计入此项） |
| `tomb` | 墓碑吸收的死会话尾段重传（#29a；有值 = 对端尾巴被静默消化，正常） |
| `duprec` | FEC 先修复、重传后到（M4 触发器；持续 >0 才考虑延迟重传，见 M4_EVAL §1.1） |

### 6.2 控制器日志（需 `-v`）

```text
FECSTAT sets=219 expect=2189 rx=1976 rec=123 ... pre=97304ppm usable=41114ppm -> k=2 state=ON
FEC ledger: groups=200 fail=220000ppm k=2 peff=0.1369 (binomial 0.1380) kl=1.60 applied=2 skipped=0
FEC capped: parity/data=52.3% > budget=50.0% (k=5)      ← 触发字节预算
FEC ledger: ... skipped=N                               ← 账本被门拒（样本不足/主导 k 错位）
conn N ... closed: idle timeout [stream queued=... acked=... delivered=... rwnd=... rto=...]
```

- `pre`（修复前丢包）是策略输入；`usable`（FEC 没救回来的）决定 KCP/流层重传量。
- `peff > binomial` = 账本经验校正在上调（突发链路）；`kl` 是突发检测距离（≥1 nat 明显突发）。
- **销毁诊断行**：`acked < queued` = 发送方被确认卡死（看 rwnd/rto）；
  `delivered < acked` = 接收方应用不读——一眼定位停滞在哪一侧（#33③ 方法论）。

### 6.3 轨迹回放

```bash
fcp_replay --trace=srv.101.jsonl                 # 汇总：k 轨迹/CAPPED/峰值冗余比/agree
fcp_replay --trace=srv.101.jsonl --dump          # 逐报告轨迹（含录制对照）
fcp_replay --trace=srv.101.jsonl --budget=0.10   # what-if：候选参数重放
```

`agree=N/M` 是重放与录制的逐决策一致率——恒等（阈值标定的基线）。

### 6.4 吞吐标定（`fcp_bench`）

```bash
fcp_bench server --port=47123 [--key=HEX32] [--mbps=M] [--seg=N] [--k=K]
fcp_bench client --host=<服务端IP> --port=47123 [--key=HEX32] ...
```

两端 PSK 必须一致（缺省为工具内置测试键，生产标定请显式给 `--key`）。客户端每轮生成
随机 salt 并经会合包交给服务端，**新旧版本会合格式不同，不能混跑**。RESULT 的吞吐只计
`send()` 成功的报文，失败单独计入 `tx_fail`（对抗审查 A2/A20）。

## 7. 已知部署坑（全部实测过）

1. **云商 UDP 端口白名单**：报文"到网卡不进 socket"= 防火墙没放行该 UDP 端口；换端口实测。
2. **hairpin 拨号**：服务端代理目标是"自己的公网 IP"时走出云防火墙再回来——小流量可用，
   大流量稳定性未保证；服务端目标尽量写内网/回环地址。
3. **idle 拆除 vs 慢响应应用**：会话静默 `--idle` 毫秒后拆除，正在等慢应用响应的隧道会被
   误拆（curl exit 52 empty reply）。应用响应可能慢时放大 `--idle`；FCP 层有数据在飞不算静默。
4. **小内存云主机**：2 核/2GB 实测 10 并发 8MiB 下载可触发重启；`--max-sessions` 与
   并发规模按内存预算。
5. **短连接自适应盲区**：活不过 2~3 个报告周期的连接全程 k=0（或 pinned）——短连接密集
   部署用 `--k=2`（或预热 `--no-prewarm` 反向）。
6. **trace 前缀目录**：#35 起自动创建；旧版本会静默不录制——升级到当前版。

## 8. 发布物清单

- Windows：`fcp-proxy-client.exe` + `fcp-proxy-server.exe`（CLI，零依赖）；
  GUI 目录（`fcp_client.exe` + windeployqt 输出）。
- Linux：`fcp-proxy-server` + `fcp-proxy-client` + `fcp_replay`（glibc 静态可用性视目标；
  同发行版构建最稳）。
- 配套：`docs/DEPLOY.md`（本文）+ `docs/FCP_PROTOCOL_V6.md`（协议）+ `docs/FCP_M3_CONTROL.md`（控制器行为）。
