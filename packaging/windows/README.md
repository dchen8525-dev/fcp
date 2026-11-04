# Windows 打包素材

Windows 客户端是**单文件免安装 exe**，由三部分拼接而成：

```text
[fcp-launcher.exe][payload.zip][64 字节尾部]
```

引导器源码在 `apps/desktop/launcher/`，拼接脚本是
`apps/desktop/scripts/bundle_windows_portable.ps1`。仓库不再携带 7-Zip 的
`7zSD.sfx` 自解压模块。

## 尾部格式（小端）

| 偏移 | 长度 | 内容 |
|---|---|---|
| 0 | 8 | `FCPBOOT1` |
| 8 | 4 | u32 格式版本（当前为 1） |
| 12 | 4 | u32 保留（0） |
| 16 | 8 | u64 载荷偏移 |
| 24 | 8 | u64 载荷长度 |
| 32 | 32 | 载荷的 SHA-256 |

脚本把载荷的 SHA-256 前 8 字节（16 个十六进制字符）作为缓存目录名。

## 运行时行为

- 首次双击：把 `payload.zip` 解压到
  `%LOCALAPPDATA%\FCP\bin\<哈希>\`，然后启动其中的 `FCP.exe`。
- 之后双击：缓存命中，直接启动，不再解压。首次运行时杀毒软件可能扫描刚解
  压出的 exe，启动会稍慢；缓存命中后没有这个开销。
- 换新版本：新 exe 的内容哈希不同，会解到新目录；旧版本可以继续运行。
  7 天没有启动过的旧版本目录会被自动清理（正在运行的文件删不掉，留到下次）。
- 用户配置存在 WebView 的 localStorage（按 `com.fcp.client` 标识），
  与版本缓存目录无关，升级不需要重输。
- 不写 Program Files、不建卸载项、不需要管理员权限；删除 exe 即卸载
  （缓存目录 `%LOCALAPPDATA%\FCP\bin` 可手动删除）。

## 排障

- 自检（解压并确认 `FCP.exe` / `fcp-client.exe` 就位，不启动 GUI）：

  ```powershell
  Start-Process -Wait -FilePath .\fcp-client-0.0.1-windows-x64.exe `
    -ArgumentList "--fcp-launcher-selftest" -PassThru | Select-Object ExitCode
  ```

  结果同时写到 `%LOCALAPPDATA%\FCP\selftest.txt`。
- 启动失败会弹消息框，并追加到 `%LOCALAPPDATA%\FCP\launcher.log`。
- 手动查看载荷：`7z l fcp-client-<版本>-windows-x64.exe`（载荷是标准 zip）。
