## 安装

**Ubuntu 服务端**（22.04+，amd64）

```bash
sudo dpkg -i fcp-proxy_VERSION_ARCH.deb   # 依赖缺失时改用：sudo apt install ./fcp-proxy_VERSION_ARCH.deb
sudo editor /etc/fcp/fcp-proxy.env        # 填 FCP_ARGS，至少要有 --key=HEX32
sudo systemctl enable --now fcp-proxy
journalctl -u fcp-proxy -f
```

装完自检：`fcp-proxy-server --version`。包里同时带客户端
（`fcp-proxy-client --key=… --host=… --port=…`，本地 SOCKS5/HTTP :1080）。
服务**不会**在安装时自动启动——没有密钥的进程只会退出，这是有意的。

**Windows 客户端**：`FCP-Client-VERSION-win64-setup.exe`，按用户安装、无需管理员权限，自带 Qt 运行时。

- 部署与排障：[docs/部署运维指南.md](https://github.com/OWNER_REPO/blob/TAG/docs/部署运维指南.md)
- 协议（v7 与 v6 不互通，升级必须两端同时替换）：[docs/协议规格.md](https://github.com/OWNER_REPO/blob/TAG/docs/协议规格.md)
- 发布说明：[docs/发布流程.md](https://github.com/OWNER_REPO/blob/TAG/docs/发布流程.md)
- 校验：`sha256sum -c SHA256SUMS`
