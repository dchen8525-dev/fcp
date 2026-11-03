# Tauri 2 客户端（Windows / Linux 便携交付）

这是唯一的图形客户端：Tauri 2 壳（Rust + 系统 WebView），真正跑隧道的仍是
`apps/cli` 的 `fcp-client`（以 sidecar 子进程方式启动，密钥走环境
变量，不进 argv）。传输层、FEC、信封、策略一行未改。原 Qt 客户端
（`apps/fcp-client`）已于 2026-11-03 移除，不再构建也不再发布。

```
apps/desktop/
├── src-ui/                  # 静态前端（无打包器，Tauri 直接吃这个目录）
├── src-tauri/               # Rust 壳
│   ├── src/main.rs          # 启动/停止 sidecar、解析 stats、转发事件
│   ├── tauri.conf.json      # externalBin、图标、窗口、CSP
│   └── binaries/            # sidecar 输入（带目标三元组后缀，构建前放入）
├── scripts/
│   ├── build_windows.ps1    # Windows：CMake 构建 → tauri build → 单文件 exe
│   ├── build_linux.sh       # Linux：同上，产出 AppImage
│   ├── prepare_sidecar.ps1  # 单独把 fcp-client.exe 放进 binaries/
│   └── bundle_windows_portable.ps1  # 7zSD 自解压单文件封装
└── icons/                   # 由 scripts/make_icons.mjs 生成（npm run icons）
```

## 界面与行为

左栏三个菜单对应三块内容，同一时刻只显示一块（启动/停止会自动切到对应页）：

- **连接**：只露 4 个参数——服务器地址、UDP 端口、本地代理端口、预共享密钥
  （实时校验 32 位 hex，可显示/隐藏）。本地监听地址、MTU、FEC 预算、固定 k 收进
  「高级设置」，不展开时按 sidecar 默认值（127.0.0.1 / 1400 / 0.5 / -1）提交。
- **运行状态**：每 500ms 解析 sidecar 的 `stats` 行，展示活动会话、已建立、隧道
  数、上下行字节，并把速率画成最近 60 秒折线；非零诊断计数单独列出（坏入口/
  拒绝/握手失败/reset/空闲回收/salt 冲突/超会话/错配置/无熵/限速建连/未知 salt）。
- **日志**：sidecar 的 stdout 非 stats 行与全部 stderr，带行数统计与清空。

设置保存在 WebView 的 localStorage；"记住设置"关闭时不落盘。`?panel=conn|status|log`
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

产物：`dist/FCP-<版本>-win64.exe`。双击后 7zSD 把 `FCP.exe` +
`fcp-client.exe` 解到临时目录并启动，退出后清理——不写系统目录、不建
卸载项、不需要管理员权限。删除文件即卸载。

依赖：Rust（`cargo` 在 PATH）、Node/npm、7-Zip（`winget install 7zip.7zip`）。
Windows 10/11 自带 WebView2 运行时。

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
