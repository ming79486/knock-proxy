# 部署与验收

## systemd 服务端

```sh
sudo install -m 0755 knock-proxy /usr/local/bin/knock-proxy
sudo mkdir -p /etc/knock-proxy
sudo cp examples/server.yaml /etc/knock-proxy/server.yaml
sudo cp deploy/systemd/knock-proxy-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now knock-proxy-server
```

## systemd 客户端

```sh
sudo install -m 0755 knock-proxy /usr/local/bin/knock-proxy
sudo mkdir -p /etc/knock-proxy
sudo cp examples/client.yaml /etc/knock-proxy/client.yaml
sudo cp deploy/systemd/knock-proxy-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now knock-proxy-client
```

## Windows 客户端

Windows 客户端可使用 `udp` knock，也可在 v1.2.1 起使用 `tcp-syn` knock。UDP 示例使用 `examples/server.udp.yaml` 和 `examples/client.windows.yaml`：

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

Windows `tcp-syn` 模式在 v1.2.1 起可用，推荐使用 WinDivert：把 `WinDivert.dll` 放在 `knock-proxy.exe` 同目录或 `WinDivert/` 子目录，并以管理员权限运行。若未找到 WinDivert，会回退到 Npcap `Packet.dll`。


## direct 模式

`direct` 模式用于“不运行本地代理 client”的场景：先执行一次 `knock` 打开短暂访问窗口，然后让真实客户端直接连接服务端公网端口。适合 SSH、RDP、MySQL 等原生 TCP 客户端。

服务端配置要点：

```yaml
mode: server

server:
  tcp_listen: "0.0.0.0:443"
  upstream: "127.0.0.1:22"

access:
  mode: "direct"
  require_tcp_auth: false
  remove_after_first_connect: true
  max_connections_per_knock: 1

knock:
  method: "tcp-syn"

firewall:
  backend: "auto"
  port: 443
  allow_seconds: 5
```

启动服务端：

```sh
sudo ./knock-proxy server --config ./server-direct.yaml
```

敲门后直连：

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id client-001 --secret-file ./secret.key --method tcp-syn
ssh -p 443 user@example.com
```

Windows 使用 UDP knock 时，服务端和 knock 命令都改成 `method: "udp"` / `--method udp`，真实应用仍然直接连接 `example.com:443`。

注意：direct 模式不能使用 TCP 二次认证，因为 SSH/RDP/MySQL 等真实客户端不会发送 knock-proxy 的认证帧。它的安全边界是 knock 成功后的短时防火墙放行窗口，因此建议保持较短的 `allow_seconds`，并启用 `remove_after_first_connect`。

## OpenWrt 23.x+

```sh
opkg update
opkg install nftables
scp knock-proxy root@router:/usr/bin/knock-proxy
scp examples/server.yaml root@router:/etc/knock-proxy/server.yaml
scp deploy/openwrt/knock-proxy.init root@router:/etc/init.d/knock-proxy
chmod +x /usr/bin/knock-proxy /etc/init.d/knock-proxy
/etc/init.d/knock-proxy enable
/etc/init.d/knock-proxy start
```

## 验收

未认证状态：

```sh
nmap -Pn -p 443 server_ip
```

期望：

```text
filtered
```

正确敲门：

```sh
ssh -p 10022 user@127.0.0.1
```

服务端日志应出现：

```text
knock accepted
tcp auth accepted
session closed
```

错误密钥或重放认证帧应被拒绝，日志出现 `invalid_hmac`、`expired_timestamp`、`replayed_nonce` 或 `tcp_auth_failed`。

## 新命令验证

dry-run：

```sh
./knock-proxy server --config ./examples/server.yaml --dry-run
```

一次性 knock：

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./secret.key --method tcp-syn
```

`udp` / `udp-passive` 客户端使用普通 UDP 发包，不需要 raw socket：

```sh
./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./secret.key --method udp-passive
```

probe：

```sh
sudo ./knock-proxy probe --config ./examples/client.yaml
```

doctor：

```sh
./knock-proxy doctor --config ./examples/server.yaml
```

init：

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

`init server` 会生成 `server.yaml`、`client.yaml.sample`、`secret.key`、`knock-proxy-server.service` 和客户端启动模板。面向 Windows 客户端时指定平台，生成的 server/client knock 方法会默认匹配为 `udp`：

```sh
./knock-proxy init server --platform windows --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

单独生成 Windows client：

```sh
./knock-proxy init client --platform windows --server example.com:443 --listen 127.0.0.1:10022 --client-id admin --secret-file ./secret.key --out ./client-generated
```

## metrics 验证

启用：

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
  path: "/metrics"
```

查看：

```sh
curl http://127.0.0.1:9090/metrics
```
