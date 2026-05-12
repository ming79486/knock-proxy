# Sequence Knock 需求说明

> 状态：规划中；本文件是源码仓库内的需求记录，不代表已发布功能。
>
> 发版约束：本次只提交源码/文档，不创建 release，不打 tag。

## 30. Secret-derived sequence knock 需求（规划，不在 v1.2.4 发版范围）

### 30.1 需求名称

在 knock-proxy 服务端和客户端增加基于 secret 动态派生的数据包序列 knock 能力，支持 UDP 序列 knock 和 TCP SYN 序列 knock。

### 30.2 背景与目标

当前 knock-proxy 的 knock 机制主要基于单个 UDP knock 包或单个 TCP SYN knock 特征包。为了降低单包特征被识别、捕获、复现或误触发的风险，需要增加“特定数据包序列”模式。

序列本身必须由 secret 动态派生，不能是固定端口序列、固定时间间隔序列或固定字段序列。每次 knock 的序列应与以下信息绑定：

```text
secret
client_id
protected_port
time_slot
nonce 或 method
server_id（可选，后续用于多服务端/多租户隔离）
```

该功能只替代 knock 阶段，不替代原有 TCP 连接建立后的 HMAC 二次认证。完整流程仍然是：

```text
sequence knock 成功
-> firewall allow source IP for allow_seconds
-> client 建立 TCP
-> server 校验 TCP auth frame
-> auth 成功后 relay
-> remove_after_auth=true 时立即撤销临时防火墙放行
```

### 30.3 新增 knock method

新增 method：

```yaml
knock:
  method: "udp-seq"
```

```yaml
knock:
  method: "udp-passive-seq"
```

```yaml
knock:
  method: "tcp-syn-seq"
```

语义：

- `udp-seq`：使用普通 UDP socket 接收序列 knock 包。实现难度最低，跨平台兼容性最好，推荐作为默认序列模式。
- `udp-passive-seq`：使用 AF_PACKET/pcap 等旁路方式被动捕获 UDP 序列 knock 包，服务端不创建普通 UDP socket，并配合防火墙 DROP UDP knock 端口。主要面向 Linux 服务端，需要 root 或 `CAP_NET_RAW`。
- `tcp-syn-seq`：使用多个 TCP SYN 包组成 knock 序列。字段由 secret 动态派生，服务端通过 raw socket、AF_PACKET 或 pcap 捕获，不要求真实监听这些目标端口。该模式复杂度高、跨平台限制多，必须标记为 experimental，不作为 Windows 客户端默认推荐路径。

### 30.4 核心安全要求

禁止固定序列，例如：

```text
1001 -> 1002 -> 1003
```

禁止仅由固定配置生成的长期不变序列。正确设计应满足：

```text
sequence = KDF(secret, client_id, protected_port, time_slot, nonce, method, server_id)
```

UDP 序列必须包含客户端随机 nonce。服务端必须维护 nonce cache，拒绝重复 nonce，防止同一序列在有效窗口内被重放。

TCP SYN 序列由于 SYN 包没有可靠 payload，nonce 能力有限，可以使用 time-slot HMAC 派生字段。文档必须明确：`tcp-syn-seq` 是基于时间窗口的 secret-derived sequence，不具备与 UDP nonce 相同强度的防重放能力。

序列 knock 成功后不得直接长期放行业务端口，必须继续使用现有临时防火墙窗口和 TCP auth 流程。

### 30.5 UDP sequence 协议要求

默认长度为 3，允许配置为 2 到 5。

客户端每次 knock 生成随机 nonce：

```text
client_nonce = random(16 bytes)
time_slot = floor(unix_time / slot_seconds)
```

派生本次 sequence key：

```text
seq_key = HKDF(
  secret,
  salt = client_nonce,
  info = "knock-proxy/udp-seq/v1" || client_id || protected_port || time_slot || method
)
```

每个 UDP sequence part 必须包含：

```text
version
method
client_id
protected_port
timestamp 或 time_slot
nonce
index
total
tag
```

每个分片 tag：

```text
tag_i = HMAC(seq_key, "part" || index || total || protected_port || method)
```

最后一个包携带最终 MAC：

```text
final_mac = HMAC(seq_key, "final" || digest(all_parts_metadata))
```

服务端收到 UDP sequence 包后，根据 `client_id` 找到 secret，重新计算 `seq_key`，校验每个 part 的 tag，并在完整序列到达后校验 `final_mac`。只有完整序列、顺序、时间窗口、nonce、final_mac 全部合法时，才执行 firewall allow。

默认不允许乱序：

```yaml
knock:
  sequence:
    allow_reorder: false
```

如后续支持乱序，必须限制状态表容量，并清晰定义重复包、缺包、乱序包的处理规则。

### 30.6 UDP passive sequence 要求

`udp-passive-seq` 的协议内容与 `udp-seq` 相同，区别在于服务端不通过普通 UDP socket 监听 knock 端口，而是通过 AF_PACKET/pcap 被动捕获。

配置示例：

```yaml
knock:
  method: "udp-passive-seq"
  udp_knock_port: 8443

firewall:
  drop_udp_knock_port: true
```

如果 `firewall.drop_udp_knock_port=true`，则 firewall backend 必须支持管理 UDP knock 端口 DROP 规则。`script` backend 如果无法保证该能力，必须在配置校验、`doctor`、`server --dry-run` 阶段提前报错，而不是等真实启动时失败。

### 30.7 TCP SYN sequence 协议要求

`tcp-syn-seq` 不使用固定端口序列。每个 SYN 包的目标端口、sequence number、window、TCP timestamp 等字段必须由 secret 动态派生。

推荐派生方式：

```text
slot = floor(unix_time / slot_seconds)

syn_key = HKDF(
  secret,
  salt = nil,
  info = "knock-proxy/tcp-syn-seq/v1" || client_id || protected_port || slot
)
```

每个 SYN 包字段：

```text
dst_port = derive_port(syn_key, index)
seq = derive_u32(syn_key, "seq", index)
window = derive_u16(syn_key, "win", index)
tsval = derive_u32(syn_key, "ts", index)
```

服务端按来源 IP、client_id、protected_port、time_slot 维护 TCP SYN sequence 状态。只有在有效时间窗口内按顺序捕获完整序列，才认为 knock 成功。

`tcp-syn-seq` 必须明确标记为 experimental。原因是它依赖 raw packet 能力，可能受 NAT、防火墙、操作系统 TCP 栈、网卡 offload、杀软、Npcap/WinDivert 环境影响。文档中不得把它描述成具备 UDP nonce 同等级别的防重放能力。

### 30.8 配置需求

新增 sequence 配置块：

```yaml
knock:
  method: "udp-seq"
  udp_knock_port: 8443
  sequence:
    length: 3
    allow_reorder: false
    state_ttl_seconds: 10
    max_inflight: 4096
    max_inflight_per_ip: 16
```

字段说明：

- `length`：序列长度，默认 3，允许 2 到 5。
- `allow_reorder`：默认 false。初版不建议实现 true。
- `state_ttl_seconds`：服务端等待序列补齐的状态 TTL。
- `max_inflight`：全局 sequence 状态上限。
- `max_inflight_per_ip`：单来源 IP sequence 状态上限。

### 30.9 libknock-proxy-client 对应要求

`libknock-proxy-client` 先实现客户端 `udp-seq` 发送能力：

- 新增 `KNOCK_UDP_METHOD_UDP_SEQ`。
- CLI 增加 `--method udp|udp-seq`，默认 `udp`。
- CLI 增加 `--seq-len N`，默认 3，允许 2 到 5，仅 `udp-seq` 生效。
- `udp-seq` 使用同一套 `libknockudp` C API，不允许 CLI 另写协议逻辑。
- JSON/text 输出不得包含 secret、完整 payload、完整 HMAC、nonce 原文或可复用认证材料。
- 文档必须说明：当前库只实现客户端 `udp-seq` 发送，不代表服务端已支持。


### 30.10 sequence 配置详细语义补充

推荐配置形态：

```yaml
knock:
  method: "udp-seq"
  udp_port: 8443

  sequence:
    length: 3
    slot_seconds: 30
    window: "10s"
    packet_interval: "80ms"
    max_jitter: "50ms"
    allow_reorder: false
    max_inflight_per_ip: 8
    max_total_inflight: 4096
    gc_interval: "2s"

  replay:
    nonce_ttl: "2m"
```

字段语义：

- `length`：序列包数量，默认 3，建议允许范围 2 到 5。
- `slot_seconds`：HMAC 派生时使用的时间片长度，默认 30 秒。
- `window`：服务端等待完整序列的最大时间，默认 10 秒。
- `packet_interval`：客户端发送序列包之间的默认间隔。
- `max_jitter`：客户端可选发送抖动，避免固定时间间隔形成明显指纹。
- `allow_reorder`：服务端是否接受乱序包，默认 false。
- `max_inflight_per_ip`：每个来源 IP 最多允许多少个未完成 sequence 状态。
- `max_total_inflight`：全局最多允许多少个未完成 sequence 状态。
- `gc_interval`：sequence 状态表清理周期。
- `nonce_ttl`：已使用 nonce 的缓存时间。

### 30.11 服务端状态表要求

服务端需要新增 sequence tracker，用于维护未完成序列状态。

状态 key 建议为：

```text
src_ip + client_id + nonce + protected_port + method
```

UDP sequence 状态包含：

```text
first_seen
last_seen
expected_total
received_bitmap
sequence_digest
time_slot
client_id
nonce
protected_port
src_ip
```

TCP SYN sequence 状态包含：

```text
src_ip
client_id
protected_port
time_slot
matched_index
first_seen
last_seen
```

状态表必须有容量上限和 GC。超过 `max_inflight_per_ip` 或 `max_total_inflight` 时，应静默丢弃新的未完成序列，或按策略丢弃最老状态。不能无限增长，避免公网扫描造成内存 DoS。

失败包不应默认输出详细日志。应只记录计数指标，避免日志 DoS。

### 30.12 客户端行为要求

客户端在连接 server 前，根据配置 method 发送对应 sequence knock。

UDP sequence 客户端行为：

```text
生成 nonce
计算 seq_key
按 index 生成多个 UDP knock 包
按 packet_interval + jitter 发送
发送完成后立即尝试 TCP connect
发送 TCP auth frame
进入 relay
```

TCP SYN sequence 客户端行为：

```text
根据 secret、client_id、protected_port、time_slot 派生 SYN 字段
按顺序发送多个 SYN 包
发送完成后立即尝试 TCP connect
发送 TCP auth frame
进入 relay
```

Windows 客户端默认不推荐 `tcp-syn-seq`，文档应推荐使用 `udp-seq`。

### 30.13 防火墙行为要求

sequence knock 成功前，受保护 TCP 端口默认不可访问。

sequence knock 成功后，服务端调用现有 firewall backend 临时放行来源 IP：

```text
source_ip -> protected_tcp_port allow allow_seconds
```

如果 `remove_after_auth=true`，TCP auth 成功后立即撤销该来源 IP 的临时放行规则。

如果 sequence knock 失败，不应修改防火墙。

如果服务端重启，启动阶段应清理自己管理的临时防火墙状态，避免旧 allow 残留。

### 30.14 doctor / dry-run 要求

`doctor` 和 `server --dry-run` 必须识别 sequence 模式。

必须检查：

- method 是否受当前 OS 支持。
- `udp-seq` 是否配置 UDP knock 端口。
- `udp-passive-seq` 是否具备 `CAP_NET_RAW` 或 root 权限。
- `tcp-syn-seq` 是否具备 raw packet 发送/捕获能力。
- `sequence.length` 是否在合法范围。
- `sequence.window` 是否合理。
- `max_inflight_per_ip` / `max_total_inflight` 是否设置。
- `nonce_ttl` 是否大于 sequence window。
- firewall backend 是否支持 `drop_udp_knock_port`。
- `firewall.New(rt.Firewall)` 是否可构造。

如果配置组合必然导致真实启动失败，`doctor` 和 dry-run 必须提前报错。

如果输出 `[FAIL]`，退出码必须非 0。

### 30.15 metrics 要求

新增 sequence 相关指标：

```text
knock_sequence_attempts_total
knock_sequence_success_total
knock_sequence_failed_total
knock_sequence_timeout_total
knock_sequence_replay_total
knock_sequence_inflight
knock_sequence_inflight_per_ip_rejected_total
knock_sequence_global_rejected_total
knock_sequence_invalid_mac_total
knock_sequence_invalid_order_total
```

失败原因建议分 label，但 label 不能包含 `client_id`、IP、nonce 等高基数字段。

### 30.16 日志要求

日志不得输出 secret。

默认不得输出完整 packet payload、完整 tag、完整 final_mac、完整 nonce。debug 模式下如需输出，也应截断。

推荐日志示例：

```text
udp-seq accepted src=1.2.3.4 client_id=admin parts=3
udp-seq rejected reason=invalid_mac src=1.2.3.4
udp-seq rejected reason=replay src=1.2.3.4
tcp-syn-seq accepted src=1.2.3.4 client_id=admin parts=3
```

### 30.17 文档要求

文档必须明确说明：

- `udp-seq` 和 `udp-passive-seq` 使用 secret + nonce + time_slot 派生序列，并使用 nonce cache 防重放。
- `tcp-syn-seq` 使用 secret + time_slot 派生 TCP SYN 字段序列，但不具备 UDP nonce 同等级别的防重放能力。
- sequence knock 只负责敲门，不替代 TCP auth。
- 禁止把本功能描述成 VPN、零信任网关或 TLS 替代品。

生产推荐优先级：

1. Linux server + nftables + proxy mode + udp-seq
2. Linux server + nftables + proxy mode + udp-passive-seq
3. tcp-syn-seq 仅高级/实验场景
4. Windows client 推荐 udp-seq

### 30.18 测试要求

需要增加单元测试：

- 相同 secret + 相同 nonce + 相同 slot 派生结果一致。
- 不同 secret 派生结果不同。
- 不同 nonce 派生结果不同。
- 不同 protected_port 派生结果不同。
- 过期 slot 被拒绝。
- 重复 nonce 被拒绝。
- 缺少 part 被拒绝。
- 错误顺序被拒绝。
- 错误 final_mac 被拒绝。
- 超过 `max_inflight_per_ip` 被拒绝。
- 超过 `max_total_inflight` 被拒绝。
- GC 能清理过期状态。

需要增加集成测试：

- 未 knock 前 TCP connect 失败。
- `udp-seq` 成功后 TCP connect + auth 成功。
- 错误 `udp-seq` 不放行。
- 重复 `udp-seq` 不放行。
- `allow_seconds` 过期后再次 connect 失败。
- `remove_after_auth=true` 时认证成功后撤销 allow。
- `udp-passive-seq` 在 `drop_udp_knock_port` 下仍可被动捕获并放行。

`tcp-syn-seq` 至少需要 Linux privileged e2e 测试，Windows/macOS 可先标 experimental。
