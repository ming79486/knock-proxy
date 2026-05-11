# Deployment And Acceptance

## systemd Server

```sh
sudo install -m 0755 knock-proxy /usr/local/bin/knock-proxy
sudo mkdir -p /etc/knock-proxy
sudo cp examples/server.yaml /etc/knock-proxy/server.yaml
sudo cp deploy/systemd/knock-proxy-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now knock-proxy-server
```

## systemd Client

```sh
sudo install -m 0755 knock-proxy /usr/local/bin/knock-proxy
sudo mkdir -p /etc/knock-proxy
sudo cp examples/client.yaml /etc/knock-proxy/client.yaml
sudo cp deploy/systemd/knock-proxy-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now knock-proxy-client
```

## Windows Client

Windows clients can use `udp` knock, and since v1.2.1 can also use `tcp-syn` knock. UDP examples use `examples/server.udp.yaml` and `examples/client.windows.yaml`:

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

Windows `tcp-syn` mode is available since v1.2.1. WinDivert is recommended: place `WinDivert.dll` next to `knock-proxy.exe` or in a `WinDivert/` subdirectory, and run as administrator. If WinDivert is unavailable, knock-proxy falls back to Npcap `Packet.dll`.


## direct Mode

`direct` mode is for deployments without the local proxy client. Run one `knock` command to open a short access window, then let the real TCP client connect directly to the public server port. This is useful for native clients such as SSH, RDP, and MySQL.

Server configuration essentials:

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

Start the server:

```sh
sudo ./knock-proxy server --config ./server-direct.yaml
```

Knock, then connect directly:

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id client-001 --secret-file ./secret.key --method tcp-syn
ssh -p 443 user@example.com
```

For Windows UDP knock, set both the server config and the knock command to `method: "udp"` / `--method udp`. The real application still connects directly to `example.com:443`.

Note: direct mode cannot use TCP second-stage authentication because real clients such as SSH/RDP/MySQL do not send knock-proxy authentication frames. Its security boundary is the short firewall allow window after a successful knock, so keep `allow_seconds` short and enable `remove_after_first_connect`.

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

## Acceptance

Unauthenticated state:

```sh
nmap -Pn -p 443 server_ip
```

Expected:

```text
filtered
```

Correct knock:

```sh
ssh -p 10022 user@127.0.0.1
```

Server logs should contain:

```text
knock accepted
tcp auth accepted
session closed
```

Wrong secrets or replayed authentication frames should be rejected with `invalid_hmac`, `expired_timestamp`, `replayed_nonce`, or `tcp_auth_failed`.

## New Command Checks

dry-run:

```sh
./knock-proxy server --config ./examples/server.yaml --dry-run
```

One-shot knock:

```sh
sudo ./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./secret.key --method tcp-syn
```

`udp` / `udp-passive` clients send normal UDP packets and do not need raw sockets:

```sh
./knock-proxy knock --server example.com:443 --client-id admin --secret-file ./secret.key --method udp-passive
```

probe:

```sh
sudo ./knock-proxy probe --config ./examples/client.yaml
```

doctor:

```sh
./knock-proxy doctor --config ./examples/server.yaml
```

init:

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

`init server` generates `server.yaml`, `client.yaml.sample`, `secret.key`, `knock-proxy-server.service`, and a client launcher template. For Windows clients, specify the target platform so the generated server/client knock method defaults to matching `udp`:

```sh
./knock-proxy init server --platform windows --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

Generate only a Windows client:

```sh
./knock-proxy init client --platform windows --server example.com:443 --listen 127.0.0.1:10022 --client-id admin --secret-file ./secret.key --out ./client-generated
```

## Metrics Check

Enable:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
  path: "/metrics"
```

Read:

```sh
curl http://127.0.0.1:9090/metrics
```
