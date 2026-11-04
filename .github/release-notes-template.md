## 下载与运行

| 平台 | 文件 | 用法 |
|---|---|---|
| Ubuntu 服务端 | `fcp-server-VERSION-linux-ARCH.deb` | `sudo dpkg -i` 安装（见下）；同包带命令行客户端 |
| Windows 客户端 | `fcp-client-gui-VERSION-windows-amd64.exe` | 单文件，双击即运行；**无需安装** |
| Linux 客户端 | `fcp-client-gui-VERSION-linux-amd64.AppImage` | `chmod +x` 后双击；**无需安装** |

Windows 客户端是单文件便携版：首次双击时解压到
`%LOCALAPPDATA%\FCP\bin` 缓存，之后直接启动；换新版本会自动使用新缓存目录，
旧目录一周后清理。不写 Program Files、不建卸载项、不需要管理员权限；
设置会保留，升级不需要重输。首次运行可能被 SmartScreen
提示"未知发布者"（本版本没有代码签名），点"更多信息 → 仍要运行"即可。

Linux AppImage 自带 WebKitGTK 运行时。浏览器下载会丢掉可执行位，先
`chmod +x fcp-client-gui-VERSION-linux-amd64.AppImage`，再在文件管理器里双击运行。
如果系统提示缺 libfuse2：`sudo apt install libfuse2`，或设
`APPIMAGE_EXTRACT_AND_RUN=1` 直接解包运行。不需要安装，删除这一个文件就是卸载。

**Ubuntu 服务端**（22.04+，amd64）

```bash
sudo dpkg -i fcp-server-VERSION-linux-ARCH.deb   # 依赖缺失时改用：sudo apt install ./fcp-server-VERSION-linux-ARCH.deb
sudo editor /etc/fcp/fcp.env        # 填 FCP_ARGS，至少要有 --key=HEX32 或 --key-file=FILE
sudo systemctl enable --now fcp
journalctl -u fcp -f
```

装完自检：`fcp-server --version`。包里同时带客户端
（`fcp-client -H <服务器>:<端口> -k <PSK文件>`，本地 SOCKS5/HTTP :1080）。
服务**不会**在安装时自动启动——没有密钥的进程只会退出，这是有意的。

- 部署与排障：[docs/部署运维指南.md](https://github.com/OWNER_REPO/blob/TAG/docs/部署运维指南.md)
- 协议（v7 与 v6 不互通，升级必须两端同时替换）：[docs/协议规格.md](https://github.com/OWNER_REPO/blob/TAG/docs/协议规格.md)
- 发布说明：[docs/发布流程.md](https://github.com/OWNER_REPO/blob/TAG/docs/发布流程.md)
- 校验：`sha256sum -c SHA256SUMS`
