# knock-proxy Overview

`knock-proxy` uses port knocking to keep public TCP management services behind firewall DROP rules. The client sends a knock first; after verification, the server opens a short allow window for that source IP. The client then completes second-stage TCP authentication and forwards traffic to the local upstream service.

## Flow

```text
Local application
  -> 127.0.0.1:y
  -> knock-proxy client
  -> knock to server:x
  -> server temporarily allows client_ip -> tcp/x
  -> client connects to server:x
  -> HMAC-SHA256 second-stage authentication
  -> knock-proxy server
  -> 127.0.0.1:x1
  -> real TCP service
```

## Features

- Client local listener and TCP forwarding
- Server TCP listener and upstream forwarding
- One-shot `knock` command
- `probe` active connectivity test command
- `doctor` environment diagnostic command
- `init` configuration generator
- `server --dry-run`
- proxy / direct access modes
- TCP SYN knock, UDP knock, and udp-passive knock
- Windows TCP-SYN knock: WinDivert (https://github.com/basil00/WinDivert/) preferred, Npcap fallback; UDP is recommended for fleets
- HMAC-SHA256 second-stage authentication
- Timestamp + nonce replay protection for UDP knock/TCP auth; time-slot HMAC for TCP SYN knock
- ChaCha20-Poly1305 basic transport encryption
- nftables, iptables, ipset-iptables, and script firewall backends
- OpenWrt 23.x+ nftables/firewall4 support
- Basic IPv4 / IPv6 support
- Text logs / JSON logs
- Prometheus metrics
- Connection statistics, rate limiting, and failure bans

## Build

```sh
go build -o knock-proxy ./cmd/knock-proxy
```

## Quick Start

Generate configuration:

```sh
./knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin --out ./generated
```

Server:

```sh
sudo ./knock-proxy server --config ./generated/server.yaml
```

Client:

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

Diagnostics:

```sh
./knock-proxy doctor --config ./generated/server.yaml
```

## Windows Client

Windows clients can use UDP knock:

```powershell
.\knock-proxy.exe client --config .\examples\client.windows.yaml
```

Matching server configuration:

```sh
sudo ./knock-proxy server --config ./examples/server.udp.yaml
```

Windows TCP-SYN knock prefers WinDivert (https://github.com/basil00/WinDivert/). Place `WinDivert.dll` next to `knock-proxy.exe`, or under a `WinDivert/` subdirectory, and run as administrator. When WinDivert is unavailable, knock-proxy falls back to Npcap `Packet.dll`.

## More Documentation

- [Configuration Reference](config.en.md)
- [Deployment And Acceptance](deployment.en.md)


## License

This project is licensed under the Elastic License 2.0. See [LICENSE](LICENSE).
