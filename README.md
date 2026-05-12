# knock-proxy

中文 | [English](#english)

`knock-proxy` 是一个端口敲门 TCP 转发工具。服务端用防火墙默认 DROP 公网 TCP 端口；客户端先发送 knock，服务端验证后临时放行来源 IP，然后客户端连接同一 TCP 端口，完成 HMAC-SHA256 二次认证并转发到本机 upstream。

适合隐藏 SSH、RDP、数据库管理端口、Web 管理后台等 TCP 服务。它不是 VPN、QUIC 隧道、多路复用代理或 UDP 代理。

## 功能

- server / client / knock / probe / doctor / status / init 命令
- proxy / direct 访问模式
- TCP SYN knock、UDP knock、udp-passive knock
- Windows TCP-SYN knock：experimental，优先 WinDivert，未找到时回退 Npcap；批量部署推荐 UDP
- HMAC-SHA256 认证；UDP knock/TCP auth 使用 timestamp + nonce 防重放，TCP SYN knock 使用 time-slot HMAC
- 可选 ChaCha20-Poly1305 基础传输加密
- nftables、iptables、ipset-iptables、script 防火墙后端
- OpenWrt 23.x+ nftables/firewall4 支持
- IPv4 / IPv6 基础支持
- 文本日志 / JSON 日志
- Prometheus metrics
- 连接限制、knock 限流、认证失败临时封禁
- systemd / OpenWrt procd 部署示例

## 文档

- [中文总览](docs/README.zh.md)
- [中文配置说明](docs/config.zh.md)
- [中文部署与验收](docs/deployment.zh.md)
- [English Overview](docs/README.en.md)
- [English Configuration Reference](docs/config.en.md)
- [English Deployment And Acceptance](docs/deployment.en.md)

## 构建

```sh
go build -o knock-proxy ./cmd/knock-proxy
```

常用交叉编译：

```sh
GOOS=linux GOARCH=amd64 go build -o knock-proxy-linux-amd64 ./cmd/knock-proxy
GOOS=windows GOARCH=amd64 go build -o knock-proxy-windows-amd64.exe ./cmd/knock-proxy
```

## 快速开始

生成配置：

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

启动服务端：

```sh
sudo ./knock-proxy server --config ./generated/server.yaml
```

启动客户端：

```sh
sudo ./knock-proxy client --config ./generated/client.yaml.sample
```

连接本地代理：

```sh
ssh -p 10022 user@127.0.0.1
```

一次性敲门：

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./generated/secret.key
```

敲门后等待 TCP 端口打开：

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./generated/secret.key --wait-open
```

主动测试：

```sh
./knock-proxy probe --config ./generated/client.yaml.sample
```

环境诊断：

```sh
./knock-proxy doctor --config ./generated/server.yaml
```

服务端状态：

```sh
./knock-proxy status --config ./generated/server.yaml
```

## Windows 客户端

Windows 默认可用 UDP knock：

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

对应服务端使用 UDP 配置：

```sh
sudo ./knock-proxy server --config ./examples/server.udp.yaml
```

Windows TCP-SYN knock 属于 experimental。推荐把 `WinDivert.dll` 放在 `knock-proxy.exe` 同目录，或放在 `WinDivert/` 子目录，并以管理员权限运行：

```powershell
.\knock-proxy.exe knock --server example.com:443 --client-id admin --secret-file .\secret.key --method tcp-syn
```

如果没有 WinDivert，程序会回退到 Npcap `Packet.dll`。

---

## English

`knock-proxy` is a port-knocking TCP forwarder. The server hides a public TCP port with default firewall DROP rules. The client sends a knock first; after verification, the server temporarily allows the source IP. The client then connects to the same TCP port, completes HMAC-SHA256 second-stage authentication, and forwards traffic to a local upstream service.

It is designed for hiding TCP services such as SSH, RDP, database administration ports, web admin panels, and custom management services. It is not a VPN, QUIC tunnel, multiplexed proxy, or UDP proxy.

## Features

- server / client / knock / probe / doctor / status / init commands
- proxy / direct access modes
- TCP SYN knock, UDP knock, and udp-passive knock
- Windows TCP-SYN knock: experimental, WinDivert preferred, Npcap fallback; UDP is recommended for fleets
- HMAC-SHA256 authentication; timestamp + nonce replay protection for UDP knock/TCP auth and time-slot HMAC for TCP SYN knock
- Optional ChaCha20-Poly1305 basic transport encryption
- nftables, iptables, ipset-iptables, and script firewall backends
- OpenWrt 23.x+ nftables/firewall4 support
- Basic IPv4 / IPv6 support
- Text logs / JSON logs
- Prometheus metrics
- Connection limits, knock rate limiting, and temporary bans after authentication failures
- systemd and OpenWrt procd deployment examples

## Documentation

- [Chinese Overview](docs/README.zh.md)
- [Chinese Configuration Reference](docs/config.zh.md)
- [Chinese Deployment And Acceptance](docs/deployment.zh.md)
- [English Overview](docs/README.en.md)
- [English Configuration Reference](docs/config.en.md)
- [English Deployment And Acceptance](docs/deployment.en.md)

## Build

```sh
go build -o knock-proxy ./cmd/knock-proxy
```

Common cross-builds:

```sh
GOOS=linux GOARCH=amd64 go build -o knock-proxy-linux-amd64 ./cmd/knock-proxy
GOOS=windows GOARCH=amd64 go build -o knock-proxy-windows-amd64.exe ./cmd/knock-proxy
```

## Quick Start

Generate configuration:

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

Start the server:

```sh
sudo ./knock-proxy server --config ./generated/server.yaml
```

Start the client:

```sh
sudo ./knock-proxy client --config ./generated/client.yaml.sample
```

Connect to the local proxy:

```sh
ssh -p 10022 user@127.0.0.1
```

One-shot knock:

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./generated/secret.key
```

Wait until the TCP port opens after knocking:

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./generated/secret.key --wait-open
```

Probe:

```sh
./knock-proxy probe --config ./generated/client.yaml.sample
```

Doctor:

```sh
./knock-proxy doctor --config ./generated/server.yaml
```

Server status:

```sh
./knock-proxy status --config ./generated/server.yaml
```

## Windows Client

Windows clients can use UDP knock by default:

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

Use the matching UDP server configuration:

```sh
sudo ./knock-proxy server --config ./examples/server.udp.yaml
```

Windows TCP-SYN knock is experimental. Place `WinDivert.dll` next to `knock-proxy.exe`, or under a `WinDivert/` subdirectory, and run as administrator:

```powershell
.\knock-proxy.exe knock --server example.com:443 --client-id admin --secret-file .\secret.key --method tcp-syn
```

If WinDivert is unavailable, knock-proxy falls back to Npcap `Packet.dll`.
