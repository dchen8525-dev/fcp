# FCP

**FEC Control Protocol**：跑在 UDP 上的隧道，把 TCP 应用（SOCKS5 / HTTP CONNECT）
送过丢包、高 RTT 的链路。基于 KCP，叠加 Reed–Solomon 纠删与闭环自适应冗余——
默认不发 parity，接收端回传实测丢包率，发送端按需加冗余；拥塞控制用 BBR v2，
路径 MTU 自动上探。

> 线上协议版本 **v7**。v7 与 v6 不互通，**两端必须同时升级**。

## 特性

- **自适应 FEC**：默认 `10:3` 集合几何，冗余随丢包率与字节预算闭环调整
- **BBR v2**（默认，可切 v1 或退回 epoch 控制器），ACK 合并、亚节拍 pacing
- **向上 PMTUD**：从 `--mtu` 探到 1500 或 `--pmtu-max`，依赖 DF
- **免安装客户端**：Windows 单文件 exe、Linux AppImage；服务端是 deb + systemd
- **可观测**：`--log=stats`、`--trace` 每会话控制器轨迹、桌面端实时曲线与链路测速

## 下载

| 平台 | 文件 | 用法 |
|---|---|---|
| Ubuntu 服务端 | `fcp-server-<版本>-linux-amd64.deb` | `sudo dpkg -i …`；同包带 `fcp-client` |
| Windows 客户端 | `fcp-client-gui-<版本>-windows-amd64.exe` | 双击运行，无需安装 |
| Linux 客户端 | `fcp-client-gui-<版本>-linux-amd64.AppImage` | `chmod +x` 后双击 |

见 [Releases](https://github.com/dchen8525-dev/fcp/releases)。

## 快速开始（CLI）

```bash
# 服务端（PSK 是 32 位十六进制；-k 只把路径放进命令行）
fcp-server -k /etc/fcp/psk -b :40000 --log=verbose

# 客户端：本地 127.0.0.1:1080 起一个 SOCKS5 入口
fcp-client -H <服务器IP>:40000 -k /etc/fcp/psk
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

参数以 `apps/cli/cli.cc` 的 Usage 为准，说明见 `docs/部署运维指南.md` §4–§5。

## 从源码构建

要求 CMake ≥ 3.20、C++20 编译器与 [vcpkg](https://github.com/microsoft/vcpkg)（manifest 模式）：

```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics
export VCPKG_ROOT=~/vcpkg          # Windows: setx VCPKG_ROOT D:\vcpkg
```

```bash
# Windows：构建 + ctest（Debug / Release）
build.bat
build.bat Release

# Linux：构建 CLI（FCP_BUILD_PROXY 默认 OFF）并跑测试
cmake -B build/rel -S . -DCMAKE_BUILD_TYPE=Release -DFCP_BUILD_PROXY=ON
cmake --build build/rel -j"$(nproc)"
ctest --test-dir build/rel --output-on-failure
```

桌面客户端是 Qt 6 Widgets 壳，隧道由 `fcp-client` 以 sidecar 承载。构建需要
Qt 6.2+ Widgets 开发包（Windows 打包另需 Rust，用于单文件引导器）：

```bash
# Linux（qt6-base-dev 即可；脚本同时构建 CLI 与 AppImage）
bash scripts/desktop/build_linux.sh

# Windows（Qt 6 前缀由 -QtPrefix 指定）
pwsh -File scripts/desktop/build_windows.ps1 `
  -ProxyBin build\release-win\apps\cli\Release\fcp-client.exe `
  -QtPrefix D:\work\vcpkg\installed\x64-windows
```

只想要 GUI 可执行文件时，可以单独构建 `apps/desktop`（见其 README）。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `src/fcp` | 协议核心：信封、握手、FEC、流层与拥塞控制 |
| `src/proxy` | 代理引擎（无 socket，宿主回调注入，可脱机测试） |
| `apps/cli` | `fcp-server` / `fcp-client`、select 反应堆、`fcp-bench` 基准、`fcp-replay` 轨迹重放 |
| `apps/desktop` | Qt 6 桌面客户端（GUI 壳 + Windows 单文件引导器） |
| `scripts` | 构建与打包脚本（`desktop/` 下是 Qt GUI / AppImage / 引导器流水线） |
| `tests` | ctest 用例（含链路模拟与对抗用例） |
| `packaging` | deb / systemd / Windows 打包输入与安装落点（`FCPPackaging.cmake`） |
| `docs` | 规格、设计、决策与运维文档 |

## 文档

从 `docs/文档索引.md` 开始。常用的几份：

- `docs/部署运维指南.md` — 构建矩阵、密钥与端口、部署、排障
- `docs/协议规格.md` — 线格式、握手、不变量（对外契约）
- `docs/决策记录.md` — 每个设计选择的原因
- `docs/发布流程.md` — tag 与 release 工作流
