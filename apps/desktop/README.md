# FCP 桌面客户端（Qt 6 Widgets）

一个很薄的 GUI 壳：**协议和隧道都不在这里**。真正的代理进程是同一仓库
`apps/cli` 的 `fcp-client`，GUI 只负责：

* 按界面参数启动/停止 `fcp-client`（sidecar）；
* 读它的 `stats` 行，画吞吐、会话数与诊断计数；
* 另起一个 `fcp-client --speedtest` 进程跑链路测速；
* 托盘、关窗/最小化只隐藏窗口（隧道继续跑）。

Qt 只用到 **Widgets**（没有 WebView、没有 QML、没有 QtCharts）。图标、折线图
和复选框的勾都是 `QPainter`/QSS 画的，运行库由 `windeployqt` 收集。

## 为什么是 Qt

旧版是 Tauri 2 + WebView：Windows 依赖系统 WebView2，Linux AppImage 得把
WebKitGTK 整套打进去（77 MiB，其中 WebKit/JSC/ICU 约 160 MiB 解压后）。
Qt Widgets 的 AppImage 只带 Qt 运行库，体积和启动都小一个量级，也没有
"系统 WebView 版本不一致"这一类问题。决策记录见 `docs/决策记录.md` #73。

## 目录

```
CMakeLists.txt        独立可构建的 Qt 项目（也可由根 CMake 的 FCP_BUILD_GUI=ON 引入）
src/main.cpp          QApplication、样式表、--fcp-speedtest-selftest
src/mainwindow.*      左栏 + 连接 / 运行状态 / 链路测速 / 日志 四页
src/sidecar.*          fcp-client 子进程管理、stats / @speedtest 解析
src/sparkline.*       最近 60 秒上下行折线（QPainter）
assets/               fcp.png、fcp.ico、check.png、app.qss、fcp.desktop、fcp.rc
launcher/             Windows 单文件引导器（Rust，仅打包用）
```

## 构建

需要 Qt 6.2+ 的 Widgets 开发包。Windows 上本仓库的习惯是用 vcpkg 的经典树
（`D:\work\vcpkg\installed\x64-windows`，其中带 `tools/Qt6/bin/windeployqt.exe`）：

```powershell
cmake -S apps/desktop -B build/gui -DCMAKE_PREFIX_PATH=D:\work\vcpkg\installed\x64-windows
cmake --build build/gui --config Release
```

Linux（Ubuntu 22.04+）：

```bash
sudo apt install qt6-base-dev cmake ninja-build
cmake -S apps/desktop -B build/linux-gui -DCMAKE_BUILD_TYPE=Release
cmake --build build/linux-gui --parallel
```

`FCP.exe` / `FCP` 需要和 `fcp-client` 放在同一目录（开发时把构建出来的
`fcp-client` 拷过去，或设 `FCP_PROXY_BIN` 指向它）。sidecar 解析顺序是
**环境变量 → 主程序同目录**，从不回落到 `PATH`。

Windows 上构建完就能直接双击：`FCP_GUI_AUTO_DEPLOY`（默认开）会在
POST_BUILD 自动跑 `windeployqt` 并把 Qt bin 里剩余的第三方 DLL
（zlib/pcre2/icu 等）收进输出目录。关掉用 `-DFCP_GUI_AUTO_DEPLOY=OFF`；
关掉后需自行把 Qt bin 加入 `PATH` 才能运行。发布的完整打包（递归依赖
清点 + 单文件封装）仍走 `scripts/desktop/build_windows.ps1`。

也可以从仓库根一起构建：

```bash
cmake -S . -B build -DFCP_BUILD_PROXY=ON -DFCP_BUILD_GUI=ON \
  -DCMAKE_PREFIX_PATH=<Qt6 前缀>
```

## 行为约定

* **参数**：`--host --port --listen --local-port --mtu --fec-budget --window=:4096
  --key-env=FCP_PSK --log=stats:500`，`k >= 0` 时再加 `--k`。PSK 走环境变量
  `FCP_PSK`，不出现在命令行。
* **校验顺序**（与旧版一致）：密钥 32 位十六进制 → UDP 端口 → 本地端口 →
  MTU 576..9000 → k -1..7 → FEC 0..1 → 监听地址非空 → 服务器地址非空。
  高级设置折叠时按默认值提交（127.0.0.1 / 1400 / -1 / 0.5）。
* **设置**：`QSettings`（Windows 注册表 `HKCU\Software\FCP\FCP Client`，
  Linux `~/.config/FCP/FCP Client.conf`）。取消"记住设置"会清空已存配置。
* **托盘**：关窗和最小化只 `hide()`，sidecar 继续跑；真正退出走托盘菜单。
  没有系统托盘时关窗即退出。
* **子进程随 GUI 一起死**：Windows 用 `KILL_ON_JOB_CLOSE` 的 Job Object，
  Linux 用 `PR_SET_PDEATHSIG`。任务管理器强杀 GUI 后不会留下占着 1080 的
  `fcp-client`。
* **日志**：stdout 灰色、stderr 沙色，最多保留 4000 行；只有视图在底部时才
  自动滚动。

## 测速自检

无界面跑一次测速（服务端需以 `--speedtest` 启动）：

```bash
FCP_SPEEDTEST_HOST=127.0.0.1 FCP_SPEEDTEST_PORT=4460 \
FCP_SPEEDTEST_KEY=<32 位十六进制> FCP_SPEEDTEST_SECONDS=8 \
  ./FCP --fcp-speedtest-selftest
```

结果 JSON 同时写到 `%TEMP%\fcp-speedtest.txt`（release 是 GUI 子系统，没有
控制台）；含 `"mbps"` 时退出码为 0。

## 打包

* Windows：`scripts/desktop/build_windows.ps1` 构建 GUI + 收集 Qt 运行库 +
  `fcp-client`，`scripts/desktop/bundle_windows_portable.ps1` 用
  `launcher/` 打成单文件便携 exe（载荷是整棵目录树）。
* Linux：`scripts/desktop/build_linux.sh` 构造 AppDir，用 linuxdeploy 的 Qt
  插件生成 AppImage。
* 图标：`node scripts/desktop/make_icons.mjs`（产物进仓库）。

发布流水线与排障见 `docs/发布流程.md`。
