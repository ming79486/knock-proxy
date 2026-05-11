# 配置说明

配置文件使用 YAML。Linux 客户端示例见 `examples/client.yaml`，Windows 客户端示例见 `examples/client.windows.yaml`，服务端示例见 `examples/server.yaml` 和 `examples/server.udp.yaml`。

## 顶层字段

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | 无 | `client` 或 `server`。 |
| `client` | 无 | 客户端配置。 |
| `server` | 无 | 服务端配置。 |
| `access` | `proxy` | 访问模式配置。 |
| `knock` | 服务端/Linux 客户端 `tcp-syn`，Windows/macOS 客户端 `udp` | knock 方法配置。 |
| `auth` | 部分默认 | HMAC 二次认证配置。 |
| `firewall` | 部分默认 | 防火墙后端配置。 |
| `transport` | 明文 | 基础传输加密配置。 |
| `limits` | 部分默认 | 并发、限流、封禁配置。 |
| `timeouts` | 部分默认 | 超时配置。 |
| `metrics` | disabled | Prometheus metrics 配置。 |
| `log` | text/stdout | 日志配置。 |

## `client`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `listen` | 无 | 本地监听地址，默认建议 loopback，例如 `127.0.0.1:10022` 或 `[::1]:10022`。如果显式监听公网地址，程序会输出警告。 |
| `server_addr` | 无 | 服务端地址，例如 `example.com:443` 或 `[2001:db8::1]:443`。 |
| `client_id` | 无 | 客户端 ID，必须匹配服务端 `auth.clients[].client_id`。 |
| `secret` | 无 | 共享密钥，推荐 `base64:<data>`。 |
| `secret_file` | 无 | 从文件读取共享密钥。 |

## `server`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `tcp_listen` | 无 | 公网监听地址，例如 `0.0.0.0:443` 或 `[::]:443`。 |
| `upstream` | 无 | 认证后连接的真实服务，例如 `127.0.0.1:22`。 |

`firewall.port` 必须和 `server.tcp_listen` 端口一致；为空时自动使用监听端口。

## `access`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | `proxy` | `proxy` 或 `direct`。 |
| `require_tcp_auth` | proxy 下 true | proxy 模式要求 TCP 二次认证；direct 模式通常为 false。 |
| `remove_after_first_connect` | `true` | direct 模式首次连接后撤销放行。 |
| `max_connections_per_knock` | `1` | direct 模式每次 knock 允许的连接数。 |

`proxy` 模式需要运行本地 client，安全性最好。`direct` 模式适合一次性 knock 后让 SSH/RDP/MySQL 等真实客户端直接连接服务端公网端口，但它不能强制 TCP 二次认证。

direct 模式必须保持 `require_tcp_auth: false`，且不能启用 `transport.encryption`，因为真实 SSH/RDP/MySQL 等客户端不会发送 knock-proxy 认证帧或加密分帧。

## `knock`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `method` | 服务端/Linux 客户端 `tcp-syn`，Windows/macOS 客户端 `udp` | 支持 `tcp-syn`、`udp` 或 `udp-passive`。Windows 默认使用 `udp`；Windows `tcp-syn` 在 v1.2.1 起可用，推荐 WinDivert，未找到 WinDivert 时回退 Npcap。 |
| `udp_listen` | 使用 TCP 监听端口 | `udp` 模式的普通 socket 监听地址；`udp-passive` 不创建普通 UDP socket。 |
| `udp_port` | 使用 TCP 监听端口 | UDP knock 端口。客户端配置后会把 UDP knock 发到该端口，但 HMAC 仍绑定 `client.server_addr` 的 TCP 端口。 |
| `silent_drop_invalid` | `true` | UDP knock 错误包静默丢弃。 |
| `timeout_seconds` | `3` | 客户端单次 knock 超时。 |
| `retry` | `2` | 客户端重试次数，总尝试次数为 `retry + 1`。 |
| `time_window_seconds` | `30` | 时间片大小，服务端允许当前和前后一个时间片。 |

UDP knock 说明：TCP 端口仍应显示 `filtered`；UDP 端口在 UDP 扫描下可能显示 `open|filtered`，这是普通 UDP socket 静默丢弃错误包的预期表现。

Windows 客户端说明：如果未显式配置 `knock.method`，客户端默认使用 `udp`。Windows `tcp-syn` 模式在 v1.2.1 起可用，推荐把 `WinDivert.dll` 放在 `knock-proxy.exe` 同目录或 `WinDivert/` 子目录，并以管理员权限运行；未找到 WinDivert 时会回退到 Npcap `Packet.dll`。

`udp-passive` 说明：服务端只在 Linux 上可用，通过 AF_PACKET 旁路捕获 UDP knock，不创建普通 UDP socket。启用后服务端会自动开启 `firewall.drop_udp_knock_port`，让防火墙 DROP `knock.udp_port`，合法 knock 仍由旁路捕获识别。该模式要求服务端有 root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`。IPv6 UDP knock 当前只处理无 IPv6 扩展头的数据包。

## `auth`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `time_window_seconds` | `30` | TCP 二次认证 timestamp 允许偏差。 |
| `nonce_cache_seconds` | `300` | nonce 防重放缓存时间。 |
| `clients` | 无 | 服务端允许的客户端列表。 |

`auth.clients[]`：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `client_id` | 无 | 客户端 ID，服务端内不能重复。 |
| `secret` | 无 | 共享密钥。 |
| `secret_file` | 无 | 密钥文件路径。 |
| `max_connections` | 全局限制 | 该 client_id 最大并发连接数。 |

## 密钥格式

| 格式 | 示例 | 说明 |
| --- | --- | --- |
| base64 | `base64:YWJj...` | 推荐，解码后至少 16 字节，建议 32 字节。 |
| hex | `hex:001122...` | 解码后至少 16 字节。 |
| plain | `a-very-long-secret` | 明文至少 16 字节，不推荐生产使用。 |

## `firewall`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `backend` | `auto` | `auto`、`openwrt-fw4`、`nftables`、`ipset-iptables`、`iptables`、`script`。 |
| `port` | 监听端口 | 需要隐藏和放行的 TCP 端口。 |
| `default_action` | `drop` | 当前必须为 `drop`。 |
| `allow_seconds` | `15` | knock 成功后的临时放行秒数。 |
| `remove_after_auth` | `true` | 二次认证成功后是否立即撤销临时放行。 |
| `drop_udp_knock_port` | `false`，`udp-passive` 自动开启 | 是否额外 DROP UDP knock 端口。仅应与 `udp-passive` 一起使用。 |

自动检测顺序：

```text
openwrt-fw4 -> nftables -> ipset-iptables -> iptables -> script
```

### `firewall.nftables`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `table` | `knock_proxy` | 独立 nftables table。 |
| `chain` | `input` | hook input chain。 |
| `set_v4` | `allowed_clients_v4` | IPv4 临时放行 set。 |
| `set_v6` | `allowed_clients_v6` | IPv6 临时放行 set。 |
| `family` | `inet` | nftables family。 |

### `firewall.iptables`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `chain` | `KNOCK_PROXY` | 程序创建的独立 chain。 |

如果系统安装 `ip6tables`，会同时创建 IPv6 规则。

### `firewall.ipset`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `set` | `knock_proxy_allowed` | IPv4 ipset。 |
| `set_v6` | `knock_proxy_allowed_v6` | IPv6 ipset。 |

IPv6 ipset 依赖 `ip6tables`。

### `firewall.script`

| 字段 | 说明 |
| --- | --- |
| `allow_cmd` | `allow.sh <client_ip> <port> <ttl_seconds>` |
| `revoke_cmd` | `revoke.sh <client_ip> <port>` |
| `cleanup_cmd` | `cleanup.sh <port>` |

`script` 后端不能由程序自动管理 `drop_udp_knock_port`；如需 `udp-passive`，请使用 nftables/iptables/ipset 后端，或在程序外自行维护 UDP DROP 规则。

## `transport`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `encryption` | `false` | 是否启用 ChaCha20-Poly1305 基础传输加密。 |
| `method` | `chacha20-poly1305` | 当前仅支持该方法。 |

认证帧仍为明文 JSON，并通过 HMAC 保护；认证通过后的业务流量才进入加密分帧。

## `limits`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `max_global_connections` | `1024` | 全局最大并发连接数。 |
| `max_connections_per_ip` | `32` | 单来源 IP 最大并发。 |
| `max_connections_per_client` | `16` | 单 client_id 最大并发。 |
| `knock_rate_per_ip` | `10/10s` | 单 IP knock 限流。 |
| `auth_fail_ban_seconds` | `300` | 认证失败自动封禁秒数。 |

## `timeouts`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `connect_seconds` | `5` | 客户端连接服务端超时。 |
| `upstream_connect_seconds` | `5` | 服务端连接 upstream 超时。 |
| `auth_seconds` | `5` | 二次认证读写超时。 |
| `idle_seconds` | `300` | 转发空闲超时。 |

## `metrics`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `false` | 是否开启 Prometheus metrics。 |
| `listen` | `127.0.0.1:9090` | metrics HTTP 监听地址。 |
| `path` | `/metrics` | metrics 路径。 |

## `log`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `level` | `info` | 预留日志级别字段。 |
| `format` | `text` | `text` 或 `json`。 |
| `file` | stdout | 日志文件路径。 |

## 生产检查清单

- 客户端和服务端使用同一个 `client_id` 与密钥。
- `server.tcp_listen` 端口和 `firewall.port` 一致。
- 客户端监听地址建议使用 loopback；如显式使用 `0.0.0.0` 或公网地址，确认本机防火墙已限制访问。
- 服务端防火墙没有更高优先级 ACCEPT 绕过 DROP。
- 服务端在 `tcp-syn` 或 `udp-passive` 模式下有 root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`。
- Linux 客户端在 `tcp-syn` 模式下有 root 或 `CAP_NET_RAW`；Windows 客户端默认使用 `udp`；Windows `tcp-syn` 推荐 WinDivert，未找到 WinDivert 时回退 Npcap，并需要管理员权限；`udp` / `udp-passive` 客户端不需要 raw socket。
