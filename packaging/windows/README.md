# Windows 打包素材

`7zSD.sfx` 是 7-Zip 的 **静默自解压模块**（silent SFX for installers），取自
LZMA SDK（7-Zip 官方发布，public domain）：

- 来源：<https://www.7-zip.org/sdk.html>（`lzma2501.7z` 的 `bin/7zSD.sfx`）
- 用途：`apps/desktop/scripts/bundle_windows_portable.ps1` 把 Tauri 构建目录
  （`FCP.exe` + `fcp-client.exe`）打成 7z 载荷，再按
  `7zSD.sfx + 配置 + 载荷` 拼成单文件 `FCP-<版本>-win64.exe`。
- 行为：双击后把载荷解到临时目录、运行 `FCP.exe`，程序退出后清理临时
  目录；不写 Program Files、不建卸载项、不需要管理员权限。
- 配置格式：

  ```
  ;!@Install@!UTF-8!
  Title="FCP <版本>"
  RunProgram="FCP.exe"
  ;!@InstallEnd@!
  ```

该文件是二进制素材，升级 7-Zip/LZMA SDK 时整体替换即可；脚本会校验它存在，
缺失时直接失败，不会悄悄退回其他打包方式。
