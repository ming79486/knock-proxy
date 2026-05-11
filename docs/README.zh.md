# knock-proxy 总览

`knock-proxy` 是一个端口敲门 TCP 转发工具，用于隐藏公网 TCP 管理端口。服务端通过防火墙默认 DROP 受保护端口；客户端先发送 knock，服务端验证后临时放行来源 IP，再完成 TCP 二次认证并转发到本机 upstream。

## 工作链路

```text
本地应用
  -> 127.0.0.1:y
  -> knock-proxy client
  -> knock 到 server:x
  -> server 临时放行 client_ip -> tcp/x
  -> client 连接 server:x
  -> HMAC-SHA256 二次认证
  -> knock-proxy server
  -> 127.0.0.1:x1
  -> 实际 TCP 服务
```

## 已实现能力

- C 端本地监听与 TCP 转发
- S 端 TCP 监听与 upstream 转发
- `knock` 一次性敲门命令
- `probe` 主动连通性测试命令
- `doctor` 环境诊断命令
- `init` 配置生成命令
- `server --dry-run`
- proxy / direct 访问模式
- TCP SYN knock、UDP knock、udp-passive knock
- Windows TCP-SYN knock：优先 WinDivert，未找到时回退 Npcap
- HMAC-SHA256 二次认证
- timestamp + nonce 防重放
- ChaCha20-Poly1305 基础传输加密
- nftables、iptables、ipset-iptables、script 防火墙后端
- OpenWrt 23.x+ nftables/firewall4 支持
- IPv4 / IPv6 基础支持
- 文本日志 / JSON 日志
- Prometheus metrics
- 连接统计、限流、失败封禁

## 构建

```sh
go build -o knock-proxy ./cmd/knock-proxy
```

## 快速启动

生成配置：

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

服务端：

```sh
sudo ./knock-proxy server --config ./generated/server.yaml
```

客户端：

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

诊断：

```sh
./knock-proxy doctor --config ./generated/server.yaml
```

## Windows 客户端

Windows 可使用 UDP knock：

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

对应服务端：

```sh
sudo ./knock-proxy server --config ./examples/server.udp.yaml
```

Windows TCP-SYN knock 推荐使用 WinDivert。把 `WinDivert.dll` 放在 `knock-proxy.exe` 同目录或 `WinDivert/` 子目录，并以管理员权限运行。没有 WinDivert 时会回退到 Npcap `Packet.dll`。

## 更多文档

- [配置说明](config.zh.md)
- [部署与验收](deployment.zh.md)
