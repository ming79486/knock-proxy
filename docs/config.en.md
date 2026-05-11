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
| `server_addr` | none | Server address, such as `example.com:443` or `[2001:db8::1]:443`. |
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
| `udp_port` | TCP listen port | UDP knock port. On clients, this sends UDP knocks to that port while the HMAC remains bound to the TCP port in `client.server_addr`. |
| `silent_drop_invalid` | `true` | Silently drop invalid UDP knock packets. |
| `timeout_seconds` | `3` | Client-side timeout for one knock attempt. |
| `retry` | `2` | Retry count. Total attempts are `retry + 1`. |
| `time_window_seconds` | `30` | Time slot size. The server accepts current, previous, and next slots. |

UDP knock note: the TCP port should still appear `filtered`; the UDP port may appear `open|filtered` in UDP scans, which is expected for a UDP socket that silently drops invalid packets.

Windows client note: when `knock.method` is omitted, client mode defaults to `udp`. Windows `tcp-syn` mode is available since v1.2.1. WinDivert is recommended: place `WinDivert.dll` next to `knock-proxy.exe` or in a `WinDivert/` subdirectory, and run as administrator. If WinDivert is unavailable, knock-proxy falls back to Npcap `Packet.dll`.

`udp-passive` note: server-side support is Linux-only. It captures UDP knock packets through AF_PACKET and does not create a normal UDP socket. When enabled, the server automatically enables `firewall.drop_udp_knock_port` so the firewall drops `knock.udp_port`, while valid knocks are still recognized by passive capture. This mode requires root or `CAP_NET_ADMIN` + `CAP_NET_RAW` on the server. IPv6 UDP knock parsing currently handles packets without IPv6 extension headers.

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
| `level` | `info` | Reserved log level field. |
| `format` | `text` | `text` or `json`. |
| `file` | stdout | Log file path. |

## Production Checklist

- Client and server use the same `client_id` and secret.
- `server.tcp_listen` port matches `firewall.port`.
- Prefer a loopback client listener. If `0.0.0.0` or a public address is explicitly used, make sure the local firewall restricts access.
- No higher-priority firewall ACCEPT rule bypasses DROP.
- Server has root or `CAP_NET_ADMIN` + `CAP_NET_RAW` in `tcp-syn` or `udp-passive` mode.
- Linux clients need root or `CAP_NET_RAW` in `tcp-syn` mode. Windows clients use `udp` by default; Windows `tcp-syn` prefers WinDivert, falls back to Npcap, and requires administrator privileges. `udp` / `udp-passive` clients do not need raw sockets.
