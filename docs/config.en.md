# Configuration Reference

Configuration files use YAML. Linux client example: `examples/client.yaml`. Windows client example: `examples/client.windows.yaml`. Server examples: `examples/server.yaml` and `examples/server.udp.yaml`.

## Top-Level Fields

| Field | Default | Description |
| --- | --- | --- |
| `mode` | none | `client` or `server`. |
| `client` | none | Client settings. |
| `server` | none | Server settings. |
| `access` | `proxy` | Access mode settings. |
| `knock` | server/Linux client `tcp-syn`, Windows/macOS client `udp` | Knock method settings. |
| `auth` | partial defaults | HMAC second-stage authentication settings. |
| `firewall` | partial defaults | Firewall backend settings. |
| `transport` | plaintext | Basic transport encryption settings. |
| `limits` | partial defaults | Connection, rate-limit, and ban settings. |
| `timeouts` | partial defaults | Timeout settings. |
| `metrics` | disabled | Prometheus metrics settings. |
| `log` | text/stdout | Logging settings. |

## `client`

| Field | Default | Description |
| --- | --- | --- |
| `listen` | none | Local listener. Loopback is recommended, such as `127.0.0.1:10022` or `[::1]:10022`. If a public listen address is explicitly configured, the program emits a warning. |
| `server_addr` | none | TCP server address used for protected TCP auth/relay, such as `example.com:443`. |
| `protected_tcp_port` | port from `server_addr` | Optional HMAC protected TCP port when the TCP dial address differs from the public protected port. |
| `udp_server_addr` | `server_addr` or `server_addr` host + `udp_knock_port` | Optional full UDP knock address when UDP knock host/port differs from `server_addr`. |
| `client_id` | none | Client ID. Must match server-side `auth.clients[].client_id`. |
| `secret` | none | Shared secret. `base64:<data>` is recommended. |
| `secret_file` | none | Read the shared secret from a file. |

## `server`

| Field | Default | Description |
| --- | --- | --- |
| `tcp_listen` | none | Public listen address, such as `0.0.0.0:443` or `[::]:443`. |
| `upstream` | none | Real service after authentication, such as `127.0.0.1:22`. |

`firewall.port` must match the port in `server.tcp_listen`. If omitted, the listen port is used.

## `access`

| Field | Default | Description |
| --- | --- | --- |
| `mode` | `proxy` | `proxy` or `direct`. |
| `require_tcp_auth` | true in proxy | Proxy mode requires TCP second-stage authentication. Direct mode usually sets this to false. |
| `remove_after_first_connect` | `true` | Revoke allow after the first direct connection. |
| `max_connections_per_knock` | `1` | Allowed connections per knock in direct mode. |

`proxy` mode runs the local client and provides the strongest security. `direct` mode lets real clients such as SSH/RDP/MySQL connect directly after a one-shot knock, but it cannot enforce TCP second-stage authentication.

Direct mode must keep `require_tcp_auth: false` and cannot enable `transport.encryption`, because real SSH/RDP/MySQL clients do not send knock-proxy authentication frames or encrypted frames.

## `knock`

| Field | Default | Description |
| --- | --- | --- |
| `method` | server/Linux client `tcp-syn`, Windows/macOS client `udp` | Supports `tcp-syn`, `udp`, or `udp-passive`. Windows clients use `udp` by default; Windows `tcp-syn` is available since v1.2.1, preferring WinDivert and falling back to Npcap when WinDivert is unavailable. |
| `udp_listen` | TCP listen port | Normal UDP socket listen address for `udp` mode. `udp-passive` does not create a normal UDP socket. |
| `udp_knock_port` | TCP listen port | UDP knock port. Legacy `udp_port` is still accepted. On clients, UDP knocks go to this port while HMAC remains bound to `protected_tcp_port` or the TCP port in `client.server_addr`. |
| `log_invalid_knock` | `false` | Log invalid UDP knock packets when diagnostics are needed. Invalid UDP knocks are otherwise dropped silently. |
| `timeout_seconds` | `3` | Client-side timeout for one knock attempt. |
| `retry` | `2` | Retry count. Total attempts are `retry + 1`. |
| `time_window_seconds` | `30` | Time slot size. The server accepts current, previous, and next slots. |

UDP knock note: the TCP port should still appear `filtered`; the UDP port may appear `open|filtered` in UDP scans, which is expected for a UDP socket that silently drops invalid packets.

Windows client note: when `knock.method` is omitted, client mode defaults to `udp`. Windows `tcp-syn` mode is experimental. WinDivert is recommended: place `WinDivert.dll` next to `knock-proxy.exe` or in a `WinDivert/` subdirectory, and run as administrator. If WinDivert is unavailable, knock-proxy falls back to Npcap `Packet.dll`.

`udp-passive` note: server-side support is Linux-only. It captures UDP knock packets through AF_PACKET and does not create a normal UDP socket. When enabled, the server automatically enables `firewall.drop_udp_knock_port` so the firewall drops `knock.udp_knock_port`, while valid knocks are still recognized by passive capture. This mode requires root or `CAP_NET_ADMIN` + `CAP_NET_RAW` on the server. IPv6 UDP knock parsing currently handles packets without IPv6 extension headers.

## `auth`

| Field | Default | Description |
| --- | --- | --- |
| `time_window_seconds` | `30` | Allowed timestamp skew for TCP authentication. |
| `nonce_cache_seconds` | `300` | Nonce replay cache duration. |
| `clients` | none | Allowed clients. |

`auth.clients[]`:

| Field | Default | Description |
| --- | --- | --- |
| `client_id` | none | Client ID. Must be unique. |
| `secret` | none | Shared secret. |
| `secret_file` | none | Secret file path. |
| `max_connections` | global limit | Max concurrent connections for this client ID. |

## Secret Formats

| Format | Example | Description |
| --- | --- | --- |
| base64 | `base64:YWJj...` | Recommended. Decoded value must be at least 16 bytes; 32 bytes is recommended. |
| hex | `hex:001122...` | Decoded value must be at least 16 bytes. |
| plain | `a-very-long-secret` | Plain string, at least 16 bytes. Not recommended for production. |

## `firewall`

| Field | Default | Description |
| --- | --- | --- |
| `backend` | `auto` | `auto`, `openwrt-fw4`, `nftables`, `ipset-iptables`, `iptables`, or `script`. |
| `port` | listen port | Public TCP port to hide and allow. |
| `default_action` | `drop` | Must be `drop`. |
| `allow_seconds` | `15` | Temporary allow duration after a successful knock. |
| `remove_after_auth` | `true` | Revoke temporary allow after successful authentication. |
| `drop_udp_knock_port` | `false`, automatically enabled for `udp-passive` | Also drop the UDP knock port. Use this with `udp-passive` only. |

Auto-detection order:

```text
openwrt-fw4 -> nftables -> ipset-iptables -> iptables -> script
```

### `firewall.nftables`

| Field | Default | Description |
| --- | --- | --- |
| `table` | `knock_proxy` | Dedicated nftables table. |
| `chain` | `input` | input hook chain. |
| `set_v4` | `allowed_clients_v4` | IPv4 temporary allow set. |
| `set_v6` | `allowed_clients_v6` | IPv6 temporary allow set. |
| `family` | `inet` | nftables family. |

### `firewall.iptables`

| Field | Default | Description |
| --- | --- | --- |
| `chain` | `KNOCK_PROXY` | Dedicated chain created by the program. |

If `ip6tables` is installed, IPv6 rules are created as well.

### `firewall.ipset`

| Field | Default | Description |
| --- | --- | --- |
| `set` | `knock_proxy_allowed` | IPv4 ipset. |
| `set_v6` | `knock_proxy_allowed_v6` | IPv6 ipset. |

IPv6 ipset support requires `ip6tables`.

### `firewall.script`

| Field | Description |
| --- | --- |
| `allow_cmd` | `allow.sh <client_ip> <port> <ttl_seconds>` |
| `revoke_cmd` | `revoke.sh <client_ip> <port>` |
| `cleanup_cmd` | `cleanup.sh <port>` |

The `script` backend cannot be used by the program to manage `drop_udp_knock_port`. For `udp-passive`, use nftables/iptables/ipset, or maintain the UDP DROP rule outside the program.

## `transport`

| Field | Default | Description |
| --- | --- | --- |
| `encryption` | `false` | Enable ChaCha20-Poly1305 basic transport encryption. |
| `method` | `chacha20-poly1305` | The only supported method. |

The authentication frame remains plaintext JSON and is HMAC-protected. Application traffic is encrypted after authentication succeeds.

## `limits`

| Field | Default | Description |
| --- | --- | --- |
| `max_global_connections` | `1024` | Max global concurrent connections. |
| `max_connections_per_ip` | `32` | Max concurrent connections per source IP. |
| `max_connections_per_client` | `16` | Max concurrent connections per client ID. |
| `knock_rate_per_ip` | `10/10s` | Knock rate limit per source IP. |
| `auth_fail_ban_seconds` | `300` | Temporary ban duration after repeated authentication failures. |
| `max_tracked_ips` | `10000` | Global capacity limit for per-IP rate/ban tracking maps. |
| `max_nonce_entries` | `100000` | Global nonce replay cache capacity limit. |

## `timeouts`

| Field | Default | Description |
| --- | --- | --- |
| `connect_seconds` | `5` | Client-to-server connect timeout. |
| `upstream_connect_seconds` | `5` | Server-to-upstream connect timeout. |
| `auth_seconds` | `5` | Authentication read/write timeout. |
| `idle_seconds` | `300` | Forwarding idle timeout. |

## `metrics`

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable Prometheus metrics. |
| `listen` | `127.0.0.1:9090` | Metrics HTTP listen address. |
| `path` | `/metrics` | Metrics path. |

## `log`

| Field | Default | Description |
| --- | --- | --- |
| `level` | `info` | Minimum log level: `debug`, `info`, `warn`, or `error`. |
| `format` | `text` | `text` or `json`. |
| `file` | stdout | Log file path. |

## Production Checklist

- Client and server use the same `client_id` and secret.
- `server.tcp_listen` port matches `firewall.port`.
- Prefer a loopback client listener. If `0.0.0.0` or a public address is explicitly used, make sure the local firewall restricts access.
- No higher-priority firewall ACCEPT rule bypasses DROP.
- Server has root or `CAP_NET_ADMIN` + `CAP_NET_RAW` in `tcp-syn` or `udp-passive` mode.
- Linux clients need root or `CAP_NET_RAW` in `tcp-syn` mode. Windows clients use `udp` by default; Windows `tcp-syn` prefers WinDivert, falls back to Npcap, and requires administrator privileges. `udp` / `udp-passive` clients do not need raw sockets.

## Security Notes and State Machine

- Threat model: knock-proxy hides a public TCP service from unauthenticated scans and opportunistic brute force. It is not a VPN, not a zero-trust identity gateway, and does not protect an already-compromised upstream service.
- `proxy` mode is the production default: knock accept -> temporary firewall allow -> TCP HMAC auth -> optional encrypted relay -> revoke. TCP auth uses `version`, timestamp, nonce, protected TCP port, client ID, and HMAC.
- `direct` mode has no TCP HMAC second stage. State is: knock accept -> temporary firewall allow -> first direct TCP connection -> revoke. Use it only for lower-risk or controlled networks.
- UDP knock and TCP auth include a nonce and are protected by the nonce cache. TCP SYN knock has no nonce; it is a time-slot HMAC encoded in SYN fields, so replay resistance is bounded by the configured time window.
- `udp-passive` requires a backend that can drop the UDP knock port. `script` is rejected during config/runtime validation because the program cannot manage that DROP rule safely.
- Windows TCP-SYN knock is experimental because WinDivert/Npcap availability varies. Prefer UDP knock on Windows fleets. macOS TCP-SYN is currently not implemented; use UDP.
- The program does not log secrets or full auth/knock payloads. Keep log level at `info` or `warn` in production unless diagnosing a live issue.

## Operational Notes

- `server --dry-run` validates the parsed runtime, firewall backend construction, TCP listen address, UDP listen address for `udp`, and address syntax. It does not initialize firewall rules or connect to upstream.
- `doctor` reports blocking failures as `[FAIL]` and exits non-zero if any are present. Non-blocking findings are `[WARN]`.
- `doctor` and `status` print the selected firewall backend. `status` supports nftables/OpenWrt sets, ipset members, and iptables/ip6tables chain dumps.
- Prefer `auto`, `nftables`, or `ipset-iptables` over plain `iptables` because they use kernel-managed timeouts. Plain `iptables` ACCEPT rules depend on the process revoke path; the backend cleans its own chain on startup, but a crash or power loss can leave temporary ACCEPT rules until the next startup/cleanup.
- Metrics include accepted/rejected knocks, TCP auth failures by reason, active connections, active allow entries, ban count, rate-limit rejects, byte counters, upstream failures, and build info.
- For OpenWrt 23.x/fw4, use the nftables backend (`openwrt-fw4` via `auto`), store config under `/etc/knock-proxy`, logs under `/var/log` or system log, and inspect with `nft list ruleset`, `logread -f`, and `knock-proxy status --config /etc/knock-proxy/server.yaml`.

## Protocol Compatibility

Current protocol version is `1` for UDP knock and TCP auth JSON frames. Receivers reject unsupported versions instead of silently accepting downgraded or ambiguous frames. TCP SYN knock does not carry a JSON version field; compatibility is defined by the `syn-knock` HMAC purpose, protected TCP port, client ID, and time-slot layout. Future incompatible protocol changes should introduce a new version and retain explicit validation errors during migration.
