# Tauri 2 客户端（Windows / Linux 便携交付）

这是唯一的图形客户端：Tauri 2 壳（Rust + 系统 WebView），真正跑隧道的仍是
`apps/cli` 的 `fcp-client`（以 sidecar 子进程方式启动，密钥走环境
变量，不进 argv）。传输层、FEC、信封、策略一行未改。原 Qt 客户端
（`apps/fcp-client`）已于 2026-11-03 移除，不再构建也不再发布。

```
apps/desktop/
├── launcher/                # 单文件引导器（Rust）：解压载荷到本地缓存并启动 FCP.exe
├── src-ui/                  # 静态前端（无打包器，Tauri 直接吃这个目录）
├── src-tauri/               # Rust 壳
│   ├── src/main.rs          # 启动/停止 sidecar、解析 stats、转发事件
│   ├── tauri.conf.json      # externalBin、图标、窗口、CSP
│   └── binaries/            # sidecar 输入（带目标三元组后缀，构建前放入）
├── scripts/
│   ├── build_windows.ps1    # Windows：CMake 构建 → tauri build → 单文件 exe
│   ├── build_linux.sh       # Linux：同上，产出 AppImage
│   ├── prepare_sidecar.ps1  # 单独把 fcp-client.exe 放进 binaries/
│   └── bundle_windows_portable.ps1  # 引导器 + zip 载荷 + 尾部 → 单文件 exe
└── icons/                   # 由 scripts/make_icons.mjs 生成（npm run icons）
```

## 界面与行为

左栏四个菜单对应四块内容，同一时刻只显示一块（启动/停止会自动切到对应页）：

- **连接**：只露 4 个参数——服务器地址、UDP 端口、本地代理端口、预共享密钥
  （实时校验 32 位 hex，可显示/隐藏）。本地监听地址、MTU、FEC 预算、固定 k 收进
  「高级设置」，不展开时按 sidecar 默认值（127.0.0.1 / 1400 / 0.5 / -1）提交。
- **运行状态**：每 500ms 解析 sidecar 的 `stats` 行，展示活动会话、已建立、隧道
  数、上下行字节，并把速率画成最近 60 秒折线；非零诊断计数单独列出（坏入口/
  拒绝/握手失败/reset/空闲回收/salt 冲突/超会话/错配置/无熵/限速建连/未知 salt）。
- **链路测速**：另起一个 `fcp-client --speedtest` 直连服务端同一个 UDP 端口，两端
  直接向 FCP 帧/FEC 层灌数据符号，先下载后上传，显示两向 Mbps、传输字节数与测速
  期间的原始丢包率。不经过代理的 TCP 流窗口，也不打 HTTP 靶子，所以结果是隧道本身
  的裸吞吐；代理未启动也能测。单程默认 8 秒（5/8/12/20 秒可选）。服务端需以
  `--speedtest` 启动，否则提示“服务端没有响应测速”。
- **日志**：sidecar 的 stdout 非 stats 行与全部 stderr，带行数统计与清空。

界面启动 sidecar 时固定带 `--window=:4096`（自适应上限 4 MiB，即向服务端通告
4 MiB 接收容量）。空的 START 表示不显式设置起点：默认的 BBRv2 会把窗口和 pacing
收敛到链路工作点（200 ms 级跨洲链路，50 MB 下载实测 2.15–2.21 MB/s，见部署运维指南
§4）。服务端下载方向同样配 `--window=:4096` 即可；要固定窗口做对照才用
`--window=START:MAX` 并加 `--no-auto-window`，要对照 BBRv1 或旧 epoch 控制器需用 CLI
（`--bbr-version=1` / `--no-bbr`）。

设置保存在 WebView 的 localStorage；"记住设置"关闭时不落盘。`?panel=conn|status|speed|log`
可直接打开某一页（排障/截图用）。

## Windows 构建（便携单文件）

```powershell
# 0) vcpkg 一次性准备（manifest 模式；之后新终端会继承 VCPKG_ROOT）
git clone https://github.com/microsoft/vcpkg.git D:\vcpkg
D:\vcpkg\bootstrap-vcpkg.bat
setx VCPKG_ROOT D:\vcpkg

# 1) 先构建 sidecar（build.bat 默认不开 FCP_BUILD_PROXY，必须显式打开）
cmake -S . -B build/release-win `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DFCP_BUILD_PROXY=ON -DFCP_BUILD_TESTS=OFF -DFCP_BUILD_TOOLS=OFF
cmake --build build/release-win --config Release --parallel

# 2) 一键打包
pwsh -File apps/desktop/scripts/build_windows.ps1 `
  -ProxyBin build\release-win\apps\cli\Release\fcp-client.exe
```

产物：`dist/FCP-<版本>-win64.exe`。首次双击时引导器把 `FCP.exe` +
`fcp-client.exe` 解到 `%LOCALAPPDATA%\FCP\bin\<载荷哈希>\`，之后直接启动缓存；
换新版本会解到新目录，旧目录 7 天未用后清理。不写系统目录、不建卸载项、
不需要管理员权限。删除 exe 即卸载（缓存目录可手动删除）。

配置存在 WebView 的 localStorage（按 `com.fcp.client` 标识），与版本缓存目录
无关，升级不需要重输；前提是不要改 `src-tauri/tauri.conf.json` 的 `identifier`。

依赖：Rust（`cargo` 在 PATH，构建 Tauri 壳与引导器）、Node/npm。
Windows 10/11 自带 WebView2 运行时。排障：`--fcp-launcher-selftest`，
失败日志在 `%LOCALAPPDATA%\FCP\launcher.log`。

测速的无界面自检（服务端先以 `--speedtest` 启动；不需要本地代理）：

```powershell
$env:FCP_SPEEDTEST_HOST="198.51.100.7"   # 默认 127.0.0.1
$env:FCP_SPEEDTEST_PORT="4460"           # 默认 4460
$env:FCP_SPEEDTEST_SECONDS="5"           # 默认 8，范围 3..30
$env:FCP_SPEEDTEST_KEY="<32 位 hex>"     # 或复用 FCP_PSK
.\FCP.exe --fcp-speedtest-selftest   # 结果同时写到 %TEMP%\fcp-speedtest.txt
```

它直接拉起 `fcp-client --speedtest` sidecar，与界面走同一条命令；release 是
GUI 子系统，所以别指望在控制台看到 JSON，读文件或看退出码（0 = 两向都完成）。

## Linux 构建（AppImage）

在 Linux（或 VPS）上：

```bash
bash apps/desktop/scripts/build_linux.sh
# 产物：apps/desktop/src-tauri/target/x86_64-unknown-linux-gnu/release/bundle/appimage/*.AppImage
```

依赖（Debian/Ubuntu）：

```bash
apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
  libayatana-appindicator3-dev patchelf cmake build-essential pkg-config libssl-dev
curl -sSf https://sh.rustup.rs | sh -s -- -y
# 脚本里的 CMake 需要 vcpkg toolchain
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics
export VCPKG_ROOT=~/vcpkg
```

AppImage 是单文件、`chmod +x` 后双击即用，不需要安装。运行时不需要用户系统预装
WebKit（AppImage 内含 webkit2gtk 相关库）。

## 调试

```bash
cd apps/desktop
npm install
FCP_PROXY_BIN=/path/to/fcp-client npm run dev   # 开发模式
```

`FCP_PROXY_BIN` 覆盖 sidecar 路径，便于在开发机上直接跑 dev 模式。

## 图标

`npm run icons` 重新生成 `src-tauri/icons/`（纯 Node，无图形库依赖）：深色圆角
底 + 冰白 F + 右下角品牌蓝圆点。
