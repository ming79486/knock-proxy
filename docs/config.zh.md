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
| `server_addr` | 无 | TCP 服务端地址，用于受保护 TCP auth/relay，例如 `example.com:443`。 |
| `protected_tcp_port` | `server_addr` 中的端口 | 当 TCP dial 地址与公网受保护端口不一致时，指定参与 HMAC 的受保护 TCP 端口。 |
| `udp_server_addr` | `server_addr` 或 `server_addr` host + `udp_knock_port` | 当 UDP knock 的 host/port 与 `server_addr` 不一致时，指定完整 UDP knock 地址。 |
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

`proxy` 模式运行本地 client，链路为 knock 通过 -> 防火墙临时放行 -> TCP HMAC 二次认证 -> 可选加密转发 -> revoke，适合生产默认部署。`direct` 模式用于一次性 knock 后让 SSH/RDP/MySQL 等真实客户端直接连接服务端公网端口，链路为 knock 通过 -> 防火墙临时放行 -> 第一次真实 TCP 连接 -> revoke；建议配合较短的 `allow_seconds`、`remove_after_first_connect: true` 和较小的 `max_connections_per_knock` 使用。

direct 模式配置要点：`require_tcp_auth: false`，`transport.encryption: false`。真实 SSH/RDP/MySQL 客户端直接发送自己的协议流量，由短时防火墙放行窗口提供访问边界。

## `knock`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `method` | 服务端/Linux 客户端 `tcp-syn`，Windows/macOS 客户端 `udp` | 支持 `tcp-syn`、`udp`、`udp-passive`、`udp-seq`、`udp-passive-seq` 和 `tcp-syn-seq`。Windows 默认使用 `udp`；Windows `tcp-syn` 在 v1.2.1 起可用，推荐 WinDivert（https://github.com/basil00/WinDivert/），可回退 Npcap。 |
| `udp_listen` | 使用 TCP 监听端口 | `udp` / `udp-seq` 模式的普通 socket 监听地址；`udp-passive` / `udp-passive-seq` 不创建普通 UDP socket。 |
| `udp_knock_port` | 使用 TCP 监听端口 | UDP knock 端口；兼容旧字段 `udp_port`。客户端会向该端口发送 UDP knock，但 HMAC 绑定到 `protected_tcp_port` 或 `client.server_addr` 中的 TCP 端口。 |
| `log_invalid_knock` | `false` | 排障时记录非法 UDP knock 包；默认静默丢弃非法 UDP knock。 |
| `timeout_seconds` | `3` | 客户端单次 knock 超时。 |
| `retry` | `2` | 客户端重试次数，总尝试次数为 `retry + 1`。 |
| `time_window_seconds` | `30` | 时间片大小，服务端允许当前和前后一个时间片。 |

序列 knock 方法：

- `udp-seq` 发送多个普通 UDP knock 包，服务端只有验证完整序列后才打开 TCP 窗口。
- `udp-passive-seq` 是 `udp-seq` 的旁路捕获版本；UDP knock 端口保持 DROP，要求防火墙后端能管理这条 DROP 规则。
- `tcp-syn-seq` 把序列编码到多个发往受保护 TCP 端口的 SYN 包中。Linux 服务端/客户端路径需要 raw packet 权限；Windows TCP-SYN 支持与 `tcp-syn` 一样受 WinDivert/Npcap 条件约束。

`knock.sequence` 控制序列方法：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `length` | `3` | 序列包数量。合法范围：2-5。 |
| `slot_seconds` | `30` | 序列校验使用的时间片大小。 |
| `window` | `10s` | 未完成序列允许存在的最长时间。 |
| `packet_interval` | `80ms` | 客户端发送序列包之间的间隔。 |
| `max_jitter` | `0ms` | 可选随机额外延迟。 |
| `allow_reorder` | `false` | 预留排序标志；除非明确测试乱序行为，否则保持 false。 |
| `max_inflight_per_ip` | `8` | 单来源 IP 最多跟踪的未完成序列数。 |
| `max_total_inflight` | `4096` | 全局最多未完成序列数。 |
| `gc_interval` | `2s` | 服务端清理过期未完成序列的间隔。 |

`knock.replay.nonce_ttl` 默认 `2m`，且必须大于 `knock.sequence.window`。

UDP knock 说明：TCP 端口仍应显示 `filtered`；普通 `udp` / `udp-seq` 模式下 UDP 端口在扫描时可能显示 `open|filtered`，这是普通 UDP socket 静默丢弃错误包的预期表现。

Windows 客户端说明：默认 knock 方法为 `udp`。Windows `tcp-syn` 模式推荐从 https://github.com/basil00/WinDivert/ 获取 WinDivert，并把 `WinDivert.dll` 放在 `knock-proxy.exe` 同目录或 `WinDivert/` 子目录，并以管理员权限运行；WinDivert 不可用时会回退到 Npcap `Packet.dll`。

`udp-passive` / `udp-passive-seq` 说明：服务端通过 Linux AF_PACKET 旁路捕获 UDP knock，保持 UDP knock 端口由防火墙 DROP，同时合法 knock 仍能被旁路捕获识别。启用后服务端会自动开启 `firewall.drop_udp_knock_port`。这些模式适合希望 UDP knock 端口在扫描时也保持静默的部署，要求服务端有 root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`。IPv6 UDP knock 处理普通 IPv6 包。

## `auth`

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `time_window_seconds` | `30` | TCP 二次认证 timestamp 允许偏差。 |
| `nonce_cache_seconds` | `300` | nonce 防重放缓存时间。 |
| `clients` | 无 | 服务端允许的客户端列表。 |

`auth.clients[]`：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `client_id` | 无 | 客户端 ID，服务端内保持唯一。 |
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
| `drop_udp_knock_port` | `false`，`udp-passive` / `udp-passive-seq` 自动开启 | 是否额外 DROP UDP knock 端口。仅应与 passive UDP 方法一起使用。 |

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

`script` 后端适合接入自定义防火墙脚本。`udp-passive` / `udp-passive-seq` 场景建议使用 nftables/iptables/ipset 后端；如果选择 `script`，需要在程序外自行维护 UDP DROP 规则。

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
| `max_tracked_ips` | `10000` | 单 IP 限流/封禁跟踪 map 的全局容量上限。 |
| `max_nonce_entries` | `100000` | nonce 防重放缓存全局容量上限。 |

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
- 服务端防火墙 DROP 规则优先级覆盖受保护端口的公网入口。
- 服务端在 `tcp-syn`、`tcp-syn-seq`、`udp-passive` 或 `udp-passive-seq` 模式下有 root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`。
- Linux 客户端在 `tcp-syn` / `tcp-syn-seq` 模式下有 root 或 `CAP_NET_RAW`；Windows 客户端默认使用 `udp`；Windows `tcp-syn` 推荐 WinDivert（https://github.com/basil00/WinDivert/），可回退 Npcap，并需要管理员权限；`udp` / `udp-passive` / `udp-seq` / `udp-passive-seq` 客户端使用普通 UDP 发包。

## 安全说明与状态机

- 保护目标：把公网 TCP 服务从未认证扫描和低成本爆破中隐藏起来，并通过 client ID、共享密钥、HMAC、nonce 和短时防火墙放行窗口控制访问入口。
- `proxy` 是生产默认模式：knock 通过 -> 防火墙临时放行 -> TCP HMAC 认证 -> 可选加密转发 -> revoke。TCP auth 使用 `version`、timestamp、nonce、受保护 TCP 端口、client ID 和 HMAC。
- `direct` 状态机：knock 通过 -> 防火墙临时放行 -> 第一次真实 TCP 连接 -> revoke。它适合低风险或受控网络中需要直接使用原生 TCP 客户端的场景。
- UDP knock 和 TCP auth 都带 nonce，并由 nonce cache 防重放。`udp-seq` / `udp-passive-seq` 会把 knock 拆成多个带 nonce 的包，由 `knock.sequence` 和 `knock.replay` 追踪。TCP SYN knock 无 nonce；`tcp-syn` / `tcp-syn-seq` 使用编码在 SYN 字段里的 time-slot HMAC，抗重放边界由配置的时间窗口决定。`tcp-syn-seq` 每一段都使用受保护 TCP 目标端口，因此只在云防火墙/上游防火墙暴露该端口的部署也能收到 knock。
- `udp-passive` / `udp-passive-seq` 需要能 DROP UDP knock 端口的防火墙后端；推荐 nftables/iptables/ipset。使用自定义脚本时，由外部脚本维护对应 DROP 规则。
- Windows TCP-SYN knock 依赖 WinDivert（https://github.com/basil00/WinDivert/）/Npcap，适合可统一安装驱动并以管理员权限运行的环境；Windows 批量部署默认推荐 UDP。macOS 客户端使用 UDP。
- 日志会避免输出 secret 或完整 auth/knock payload。生产环境建议保持 `info` 或 `warn`，仅排障时临时打开 `debug`。

## 运维说明

- `server --dry-run` 用于校验 runtime、firewall backend 构造、TCP listen 地址、`udp` 模式 UDP listen 地址和地址格式，适合部署前检查配置。
- `doctor` 中只要出现阻断性 `[FAIL]` 就返回非 0；非阻断项统一为 `[WARN]`。
- `doctor` 和 `status` 会输出最终选择的 firewall backend。`status` 支持 nftables/OpenWrt set、ipset members、iptables/ip6tables chain dump。
- 优先使用 `auto`、`nftables` 或 `ipset-iptables`，避免纯 `iptables`。纯 `iptables` 的 ACCEPT 临时规则依赖进程 revoke；后端会在启动时清理自建链，但 crash、kill -9 或断电可能残留规则直到下一次启动/cleanup。
- Metrics 覆盖 knock 接受/拒绝、TCP auth 失败原因、活动连接、活动放行、封禁数量、限流拒绝、字节计数、upstream 失败和 build info。
- OpenWrt 23.x/fw4 建议走 nftables 后端（`auto` 会选择 `openwrt-fw4`），配置放 `/etc/knock-proxy`，日志看 `/var/log` 或系统日志；常用检查命令：`nft list ruleset`、`logread -f`、`knock-proxy status --config /etc/knock-proxy/server.yaml`。

## 协议兼容策略

当前 UDP knock 和 TCP auth JSON frame 的协议版本为 `1`。接收端只接受明确支持的版本，并对其他版本返回清晰的校验错误，避免静默降级或语义歧义。TCP SYN knock 的兼容性由 `syn-knock` / `syn-seq-knock` HMAC purpose、受保护 TCP 端口、client ID 和 time-slot 布局共同定义。未来协议变更应引入新 version，并在迁移期间保留明确的校验错误。
