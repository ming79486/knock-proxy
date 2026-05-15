package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ModeClient = "client"
	ModeServer = "server"
)

type Config struct {
	Mode      string          `yaml:"mode"`
	Client    ClientConfig    `yaml:"client"`
	Server    ServerConfig    `yaml:"server"`
	Access    AccessConfig    `yaml:"access"`
	Knock     KnockConfig     `yaml:"knock"`
	Auth      AuthConfig      `yaml:"auth"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Transport TransportConfig `yaml:"transport"`
	Limits    LimitsConfig    `yaml:"limits"`
	Timeouts  TimeoutsConfig  `yaml:"timeouts"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Log       LogConfig       `yaml:"log"`
}

type ClientConfig struct {
	Listen           string `yaml:"listen"`
	ServerAddr       string `yaml:"server_addr"`
	ProtectedTCPPort int    `yaml:"protected_tcp_port"`
	UDPServerAddr    string `yaml:"udp_server_addr"`
	ClientID         string `yaml:"client_id"`
	Secret           string `yaml:"secret"`
	SecretFile       string `yaml:"secret_file"`
}

type ServerConfig struct {
	TCPListen string `yaml:"tcp_listen"`
	Upstream  string `yaml:"upstream"`
}

type AccessConfig struct {
	Mode                    string `yaml:"mode"`
	RequireTCPAuth          bool   `yaml:"require_tcp_auth"`
	RemoveAfterFirstConnect bool   `yaml:"remove_after_first_connect"`
	MaxConnectionsPerKnock  int    `yaml:"max_connections_per_knock"`
}

type KnockConfig struct {
	Method            string         `yaml:"method"`
	UDPListen         string         `yaml:"udp_listen"`
	UDPPort           int            `yaml:"udp_port"`
	UDPKnockPort      int            `yaml:"udp_knock_port"`
	LogInvalidKnock   bool           `yaml:"log_invalid_knock"`
	SilentDropInvalid bool           `yaml:"silent_drop_invalid"`
	TimeoutSeconds    int            `yaml:"timeout_seconds"`
	Retry             int            `yaml:"retry"`
	TimeWindowSeconds int            `yaml:"time_window_seconds"`
	Sequence          SequenceConfig `yaml:"sequence"`
	Replay            ReplayConfig   `yaml:"replay"`
}

type SequenceConfig struct {
	Length           int    `yaml:"length"`
	SlotSeconds      int    `yaml:"slot_seconds"`
	Window           string `yaml:"window"`
	PacketInterval   string `yaml:"packet_interval"`
	MaxJitter        string `yaml:"max_jitter"`
	AllowReorder     bool   `yaml:"allow_reorder"`
	MaxInflightPerIP int    `yaml:"max_inflight_per_ip"`
	MaxTotalInflight int    `yaml:"max_total_inflight"`
	GCInterval       string `yaml:"gc_interval"`
}

type ReplayConfig struct {
	NonceTTL string `yaml:"nonce_ttl"`
}

type AuthConfig struct {
	TimeWindowSeconds int          `yaml:"time_window_seconds"`
	NonceCacheSeconds int          `yaml:"nonce_cache_seconds"`
	Clients           []AuthClient `yaml:"clients"`
}

type AuthClient struct {
	ClientID       string `yaml:"client_id"`
	Secret         string `yaml:"secret"`
	SecretFile     string `yaml:"secret_file"`
	MaxConnections int    `yaml:"max_connections"`
}

type FirewallConfig struct {
	Backend          string         `yaml:"backend"`
	Port             int            `yaml:"port"`
	DefaultAction    string         `yaml:"default_action"`
	AllowSeconds     int            `yaml:"allow_seconds"`
	RemoveAfterAuth  bool           `yaml:"remove_after_auth"`
	DropUDPKnockPort bool           `yaml:"drop_udp_knock_port"`
	UDPKnockPort     int            `yaml:"-"`
	Nftables         NftablesConfig `yaml:"nftables"`
	Iptables         IptablesConfig `yaml:"iptables"`
	IPSet            IPSetConfig    `yaml:"ipset"`
	Script           ScriptConfig   `yaml:"script"`
}

type NftablesConfig struct {
	Table  string `yaml:"table"`
	Chain  string `yaml:"chain"`
	SetV4  string `yaml:"set_v4"`
	SetV6  string `yaml:"set_v6"`
	Family string `yaml:"family"`
}

type IptablesConfig struct {
	Chain string `yaml:"chain"`
}

type IPSetConfig struct {
	Set   string `yaml:"set"`
	SetV6 string `yaml:"set_v6"`
}

type ScriptConfig struct {
	AllowCmd   string `yaml:"allow_cmd"`
	RevokeCmd  string `yaml:"revoke_cmd"`
	CleanupCmd string `yaml:"cleanup_cmd"`
}

type TransportConfig struct {
	Encryption bool   `yaml:"encryption"`
	Method     string `yaml:"method"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

type LimitsConfig struct {
	MaxGlobalConnections    int    `yaml:"max_global_connections"`
	MaxConnectionsPerIP     int    `yaml:"max_connections_per_ip"`
	MaxConnectionsPerClient int    `yaml:"max_connections_per_client"`
	MaxPendingAuth          int    `yaml:"max_pending_auth"`
	MaxAuthWorkers          int    `yaml:"max_auth_workers"`
	KnockRatePerIP          string `yaml:"knock_rate_per_ip"`
	AuthFailBanSeconds      int    `yaml:"auth_fail_ban_seconds"`
	MaxTrackedIPs           int    `yaml:"max_tracked_ips"`
	MaxNonceEntries         int    `yaml:"max_nonce_entries"`
}

type TimeoutsConfig struct {
	ConnectSeconds         int `yaml:"connect_seconds"`
	UpstreamConnectSeconds int `yaml:"upstream_connect_seconds"`
	AuthSeconds            int `yaml:"auth_seconds"`
	IdleSeconds            int `yaml:"idle_seconds"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

type ClientRuntime struct {
	Listen             string
	ServerAddr         string
	UDPServerAddr      string
	ClientID           string
	Secret             []byte
	ServerPort         int
	KnockTimeout       time.Duration
	KnockRetry         int
	KnockMethod        string
	KnockTimeWindow    time.Duration
	SequenceLength     int
	SequenceSlot       int
	SequenceInterval   time.Duration
	SequenceJitter     time.Duration
	ConnectTimeout     time.Duration
	AuthTimeout        time.Duration
	IdleTimeout        time.Duration
	TransportEncrypted bool
	TransportMethod    string
	LogFile            string
	LogLevel           string
	LogFormat          string
}

type ServerRuntime struct {
	Listen                  string
	Upstream                string
	Port                    int
	AccessMode              string
	RequireTCPAuth          bool
	RemoveAfterFirstConnect bool
	MaxConnectionsPerKnock  int
	Clients                 map[string]ServerClient
	KnockMethod             string
	UDPListen               string
	UDPPort                 int
	KnockTimeWindow         time.Duration
	SequenceLength          int
	SequenceSlot            int
	SequenceWindow          time.Duration
	SequencePacketInterval  time.Duration
	SequenceMaxJitter       time.Duration
	SequenceAllowReorder    bool
	SequenceMaxInflightIP   int
	SequenceMaxInflight     int
	SequenceGCInterval      time.Duration
	SequenceNonceTTL        time.Duration
	AuthTimeWindow          time.Duration
	NonceCacheTTL           time.Duration
	Firewall                FirewallConfig
	AllowTTL                time.Duration
	RemoveAfterAuth         bool
	UpstreamConnectTimeout  time.Duration
	AuthTimeout             time.Duration
	IdleTimeout             time.Duration
	MaxGlobalConnections    int
	MaxConnectionsPerIP     int
	MaxConnectionsPerClient int
	MaxPendingAuth          int
	MaxAuthWorkers          int
	KnockRatePerIP          string
	AuthFailBanTTL          time.Duration
	TransportEncrypted      bool
	TransportMethod         string
	MetricsEnabled          bool
	MetricsListen           string
	MetricsPath             string
	LogFile                 string
	LogLevel                string
	LogFormat               string
	LogInvalidKnock         bool
	MaxTrackedIPs           int
	MaxNonceEntries         int
}

type ServerClient struct {
	ID             string
	Secret         []byte
	MaxConnections int
}

func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func DefaultConfig() Config {
	return Config{
		Knock: KnockConfig{
			SilentDropInvalid: true,
			TimeoutSeconds:    3,
			Retry:             2,
			TimeWindowSeconds: 30,
			Sequence:          SequenceConfig{Length: 3, SlotSeconds: 30, Window: "10s", PacketInterval: "80ms", MaxJitter: "0ms", MaxInflightPerIP: 8, MaxTotalInflight: 4096, GCInterval: "2s"},
			Replay:            ReplayConfig{NonceTTL: "2m"},
		},
		Access: AccessConfig{
			Mode:                    "proxy",
			RequireTCPAuth:          false,
			RemoveAfterFirstConnect: true,
			MaxConnectionsPerKnock:  1,
		},
		Auth: AuthConfig{
			TimeWindowSeconds: 30,
			NonceCacheSeconds: 300,
		},
		Firewall: FirewallConfig{
			Backend:         "auto",
			DefaultAction:   "drop",
			AllowSeconds:    15,
			RemoveAfterAuth: true,
			Nftables: NftablesConfig{
				Table:  "knock_proxy",
				Chain:  "input",
				SetV4:  "allowed_clients_v4",
				SetV6:  "allowed_clients_v6",
				Family: "inet",
			},
			Iptables: IptablesConfig{Chain: "KNOCK_PROXY"},
			IPSet:    IPSetConfig{Set: "knock_proxy_allowed", SetV6: "knock_proxy_allowed_v6"},
		},
		Transport: TransportConfig{
			Encryption: false,
			Method:     "chacha20-poly1305",
		},
		Limits: LimitsConfig{
			MaxGlobalConnections:    1024,
			MaxConnectionsPerIP:     32,
			MaxConnectionsPerClient: 16,
			KnockRatePerIP:          "10/10s",
			AuthFailBanSeconds:      300,
			MaxTrackedIPs:           10000,
			MaxNonceEntries:         100000,
		},
		Timeouts: TimeoutsConfig{
			ConnectSeconds:         5,
			UpstreamConnectSeconds: 5,
			AuthSeconds:            5,
			IdleSeconds:            300,
		},
		Metrics: MetricsConfig{
			Enabled: false,
			Listen:  "127.0.0.1:9090",
			Path:    "/metrics",
		},
		Log: LogConfig{Level: "info", Format: "text"},
	}
}

func (c Config) ClientRuntime() (ClientRuntime, error) {
	if c.Mode != "" && c.Mode != ModeClient {
		return ClientRuntime{}, fmt.Errorf("config mode must be %q for client", ModeClient)
	}
	knockMethod := defaultString(c.Knock.Method, DefaultClientKnockMethod(runtime.GOOS))
	if !isKnockMethod(knockMethod) {
		return ClientRuntime{}, fmt.Errorf("unsupported client knock.method %q; expected tcp-syn, udp, udp-passive, udp-seq, udp-passive-seq, or tcp-syn-seq", knockMethod)
	}
	seq, err := parseSequence(c.Knock.Sequence, c.Knock.Replay)
	if err != nil {
		return ClientRuntime{}, err
	}
	if err := validateTransport(c.Transport); err != nil {
		return ClientRuntime{}, err
	}
	if err := validateLog(c.Log); err != nil {
		return ClientRuntime{}, err
	}

	secret, err := ParseSecret(c.Client.Secret, c.Client.SecretFile)
	if err != nil {
		return ClientRuntime{}, fmt.Errorf("client.secret: %w", err)
	}

	serverHost, serverPort, err := SplitHostPort(c.Client.ServerAddr)
	if err != nil {
		return ClientRuntime{}, fmt.Errorf("client.server_addr: %w", err)
	}
	protectedPort := serverPort
	if c.Client.ProtectedTCPPort > 0 {
		if c.Client.ProtectedTCPPort > 65535 {
			return ClientRuntime{}, fmt.Errorf("client.protected_tcp_port (%d) is invalid", c.Client.ProtectedTCPPort)
		}
		protectedPort = c.Client.ProtectedTCPPort
	}
	udpServerAddr := c.Client.ServerAddr
	if c.Client.UDPServerAddr != "" {
		if _, _, err := SplitHostPort(c.Client.UDPServerAddr); err != nil {
			return ClientRuntime{}, fmt.Errorf("client.udp_server_addr: %w", err)
		}
		udpServerAddr = c.Client.UDPServerAddr
	}
	udpKnockPort := c.Knock.UDPKnockPort
	if udpKnockPort == 0 {
		udpKnockPort = c.Knock.UDPPort
	}
	if udpKnockPort > 0 {
		if udpKnockPort > 65535 {
			return ClientRuntime{}, fmt.Errorf("knock.udp_knock_port (%d) is invalid", udpKnockPort)
		}
		udpServerAddr = net.JoinHostPort(serverHost, strconv.Itoa(udpKnockPort))
	} else if udpKnockPort < 0 {
		return ClientRuntime{}, fmt.Errorf("knock.udp_knock_port (%d) is invalid", udpKnockPort)
	}

	if err := validateClientListen(c.Client.Listen); err != nil {
		return ClientRuntime{}, err
	}
	if c.Client.ClientID == "" {
		return ClientRuntime{}, errors.New("client.client_id is required")
	}

	return ClientRuntime{
		Listen:             c.Client.Listen,
		ServerAddr:         c.Client.ServerAddr,
		UDPServerAddr:      udpServerAddr,
		ClientID:           c.Client.ClientID,
		Secret:             secret,
		ServerPort:         protectedPort,
		KnockTimeout:       seconds(c.Knock.TimeoutSeconds),
		KnockRetry:         defaultInt(c.Knock.Retry, 2),
		KnockMethod:        knockMethod,
		KnockTimeWindow:    seconds(defaultInt(c.Knock.TimeWindowSeconds, 30)),
		SequenceLength:     seq.length,
		SequenceSlot:       seq.slotSeconds,
		SequenceInterval:   seq.packetInterval,
		SequenceJitter:     seq.maxJitter,
		ConnectTimeout:     seconds(defaultInt(c.Timeouts.ConnectSeconds, 5)),
		AuthTimeout:        seconds(defaultInt(c.Timeouts.AuthSeconds, 5)),
		IdleTimeout:        seconds(defaultInt(c.Timeouts.IdleSeconds, 300)),
		TransportEncrypted: c.Transport.Encryption,
		TransportMethod:    defaultString(c.Transport.Method, "chacha20-poly1305"),
		LogFile:            c.Log.File,
		LogLevel:           defaultString(c.Log.Level, "info"),
		LogFormat:          defaultString(c.Log.Format, "text"),
	}, nil
}

func (c Config) ServerRuntime() (ServerRuntime, error) {
	if c.Mode != "" && c.Mode != ModeServer {
		return ServerRuntime{}, fmt.Errorf("config mode must be %q for server", ModeServer)
	}
	knockMethod := defaultString(c.Knock.Method, "tcp-syn")
	if !isKnockMethod(knockMethod) {
		return ServerRuntime{}, fmt.Errorf("unsupported server knock.method %q; expected tcp-syn, udp, udp-passive, udp-seq, udp-passive-seq, or tcp-syn-seq", knockMethod)
	}
	seq, err := parseSequence(c.Knock.Sequence, c.Knock.Replay)
	if err != nil {
		return ServerRuntime{}, err
	}
	accessMode := defaultString(c.Access.Mode, "proxy")
	if accessMode != "proxy" && accessMode != "direct" {
		return ServerRuntime{}, fmt.Errorf("unsupported access.mode %q; expected proxy or direct", accessMode)
	}
	if accessMode == "direct" && c.Access.RequireTCPAuth {
		return ServerRuntime{}, errors.New("access.require_tcp_auth cannot be true when access.mode is direct")
	}
	if accessMode == "direct" && c.Transport.Encryption {
		return ServerRuntime{}, errors.New("transport.encryption cannot be true when access.mode is direct")
	}
	if err := validateTransport(c.Transport); err != nil {
		return ServerRuntime{}, err
	}
	if err := validateLog(c.Log); err != nil {
		return ServerRuntime{}, err
	}
	if err := validateLimits(c.Limits); err != nil {
		return ServerRuntime{}, err
	}
	if c.Server.TCPListen == "" {
		return ServerRuntime{}, errors.New("server.tcp_listen is required")
	}
	if c.Server.Upstream == "" {
		return ServerRuntime{}, errors.New("server.upstream is required")
	}

	if err := validateAddress("server.tcp_listen", c.Server.TCPListen); err != nil {
		return ServerRuntime{}, err
	}
	if err := validateAddress("server.upstream", c.Server.Upstream); err != nil {
		return ServerRuntime{}, err
	}
	_, listenPort, err := SplitHostPort(c.Server.TCPListen)
	if err != nil {
		return ServerRuntime{}, fmt.Errorf("server.tcp_listen: %w", err)
	}
	port := c.Firewall.Port
	if port == 0 {
		port = listenPort
	}
	if port != listenPort {
		return ServerRuntime{}, fmt.Errorf("firewall.port (%d) must match server.tcp_listen port (%d)", port, listenPort)
	}
	udpListen, udpPort, err := resolveUDPListen(c.Knock, c.Server.TCPListen)
	if err != nil {
		return ServerRuntime{}, err
	}

	clients := make(map[string]ServerClient, len(c.Auth.Clients))
	for _, client := range c.Auth.Clients {
		if client.ClientID == "" {
			return ServerRuntime{}, errors.New("auth.clients contains empty client_id")
		}
		if _, exists := clients[client.ClientID]; exists {
			return ServerRuntime{}, fmt.Errorf("duplicate auth client_id %q", client.ClientID)
		}
		secret, err := ParseSecret(client.Secret, client.SecretFile)
		if err != nil {
			return ServerRuntime{}, fmt.Errorf("auth.clients[%s].secret: %w", client.ClientID, err)
		}
		clients[client.ClientID] = ServerClient{
			ID:             client.ClientID,
			Secret:         secret,
			MaxConnections: client.MaxConnections,
		}
	}
	if len(clients) == 0 {
		return ServerRuntime{}, errors.New("auth.clients must contain at least one client")
	}

	fw := c.Firewall
	fw.Port = port
	fw.UDPKnockPort = udpPort
	if knockMethod == "udp-passive" || knockMethod == "udp-passive-seq" {
		fw.DropUDPKnockPort = true
	}
	if (knockMethod == "udp" || knockMethod == "udp-seq") && fw.DropUDPKnockPort {
		return ServerRuntime{}, errors.New("firewall.drop_udp_knock_port cannot be true with ordinary udp socket methods; use udp-passive or udp-passive-seq")
	}
	if (knockMethod == "udp-passive" || knockMethod == "udp-passive-seq") && fw.Backend == "script" {
		return ServerRuntime{}, errors.New("knock.method udp-passive/udp-passive-seq is incompatible with firewall.backend script because script cannot manage drop_udp_knock_port; use nftables, iptables, ipset-iptables, or udp mode")
	}
	if fw.Backend == "" {
		fw.Backend = "auto"
	}
	if fw.DefaultAction == "" {
		fw.DefaultAction = "drop"
	}
	if fw.DefaultAction != "drop" {
		return ServerRuntime{}, errors.New("firewall.default_action must be drop")
	}
	if fw.AllowSeconds == 0 {
		fw.AllowSeconds = 15
	}

	return ServerRuntime{
		Listen:                  c.Server.TCPListen,
		Upstream:                c.Server.Upstream,
		Port:                    port,
		AccessMode:              accessMode,
		RequireTCPAuth:          accessMode == "proxy" || c.Access.RequireTCPAuth,
		RemoveAfterFirstConnect: c.Access.RemoveAfterFirstConnect,
		MaxConnectionsPerKnock:  defaultInt(c.Access.MaxConnectionsPerKnock, 1),
		Clients:                 clients,
		KnockMethod:             knockMethod,
		UDPListen:               udpListen,
		UDPPort:                 udpPort,
		KnockTimeWindow:         seconds(defaultInt(c.Knock.TimeWindowSeconds, 30)),
		SequenceLength:          seq.length,
		SequenceSlot:            seq.slotSeconds,
		SequenceWindow:          seq.window,
		SequencePacketInterval:  seq.packetInterval,
		SequenceMaxJitter:       seq.maxJitter,
		SequenceAllowReorder:    seq.allowReorder,
		SequenceMaxInflightIP:   seq.maxInflightPerIP,
		SequenceMaxInflight:     seq.maxTotalInflight,
		SequenceGCInterval:      seq.gcInterval,
		SequenceNonceTTL:        seq.nonceTTL,
		AuthTimeWindow:          seconds(defaultInt(c.Auth.TimeWindowSeconds, 30)),
		NonceCacheTTL:           seconds(defaultInt(c.Auth.NonceCacheSeconds, 300)),
		Firewall:                fw,
		AllowTTL:                seconds(fw.AllowSeconds),
		RemoveAfterAuth:         fw.RemoveAfterAuth,
		UpstreamConnectTimeout:  seconds(defaultInt(c.Timeouts.UpstreamConnectSeconds, defaultInt(c.Timeouts.ConnectSeconds, 5))),
		AuthTimeout:             seconds(defaultInt(c.Timeouts.AuthSeconds, 5)),
		IdleTimeout:             seconds(defaultInt(c.Timeouts.IdleSeconds, 300)),
		MaxGlobalConnections:    defaultInt(c.Limits.MaxGlobalConnections, 1024),
		MaxConnectionsPerIP:     defaultInt(c.Limits.MaxConnectionsPerIP, 32),
		MaxConnectionsPerClient: defaultInt(c.Limits.MaxConnectionsPerClient, 16),
		MaxPendingAuth:          defaultInt(c.Limits.MaxPendingAuth, 128),
		MaxAuthWorkers:          defaultInt(c.Limits.MaxAuthWorkers, 32),
		KnockRatePerIP:          defaultString(c.Limits.KnockRatePerIP, "10/10s"),
		AuthFailBanTTL:          seconds(defaultInt(c.Limits.AuthFailBanSeconds, 300)),
		TransportEncrypted:      c.Transport.Encryption,
		TransportMethod:         defaultString(c.Transport.Method, "chacha20-poly1305"),
		MetricsEnabled:          c.Metrics.Enabled,
		MetricsListen:           defaultString(c.Metrics.Listen, "127.0.0.1:9090"),
		MetricsPath:             defaultString(c.Metrics.Path, "/metrics"),
		LogFile:                 c.Log.File,
		LogLevel:                defaultString(c.Log.Level, "info"),
		LogFormat:               defaultString(c.Log.Format, "text"),
		LogInvalidKnock:         c.Knock.LogInvalidKnock,
		MaxTrackedIPs:           defaultInt(c.Limits.MaxTrackedIPs, 10000),
		MaxNonceEntries:         defaultInt(c.Limits.MaxNonceEntries, 100000),
	}, nil
}

func ParseSecret(value, file string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return nil, errors.New("secret is required")
	}

	switch {
	case strings.HasPrefix(value, "base64:"):
		raw := strings.TrimPrefix(value, "base64:")
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			if decoded, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
				return nil, fmt.Errorf("invalid base64 secret: %w", err)
			}
		}
		if len(decoded) < 16 {
			return nil, errors.New("secret must decode to at least 16 bytes")
		}
		return decoded, nil
	case strings.HasPrefix(value, "hex:"):
		decoded, err := hex.DecodeString(strings.TrimPrefix(value, "hex:"))
		if err != nil {
			return nil, fmt.Errorf("invalid hex secret: %w", err)
		}
		if len(decoded) < 16 {
			return nil, errors.New("secret must decode to at least 16 bytes")
		}
		return decoded, nil
	default:
		if len(value) < 16 {
			return nil, errors.New("plain secret must be at least 16 bytes; prefer base64:<data>")
		}
		return []byte(value), nil
	}
}

func SplitHostPort(addr string) (string, int, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return host, port, nil
}

func validateClientListen(addr string) error {
	host, _, err := SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("client.listen: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("client.listen must use an IP address, got %q", host)
	}
	return nil
}

func IsLoopbackListen(addr string) bool {
	host, _, err := SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateTransport(t TransportConfig) error {
	method := defaultString(t.Method, "chacha20-poly1305")
	if method != "chacha20-poly1305" {
		return fmt.Errorf("unsupported transport.method %q; only chacha20-poly1305 is supported", method)
	}
	return nil
}

func validateLog(l LogConfig) error {
	level := defaultString(l.Level, "info")
	switch level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log.level %q; expected debug, info, warn, or error", level)
	}
	format := defaultString(l.Format, "text")
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported log.format %q; expected text or json", format)
	}
	return nil
}

func validateLimits(l LimitsConfig) error {
	if l.MaxTrackedIPs < 0 {
		return errors.New("limits.max_tracked_ips cannot be negative")
	}
	if l.MaxNonceEntries < 0 {
		return errors.New("limits.max_nonce_entries cannot be negative")
	}
	return nil
}

func validateAddress(name, addr string) error {
	host, _, err := SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s: host is empty", name)
	}
	return nil
}

func seconds(v int) time.Duration {
	return time.Duration(v) * time.Second
}

func defaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

type sequenceRuntime struct {
	length           int
	slotSeconds      int
	window           time.Duration
	packetInterval   time.Duration
	maxJitter        time.Duration
	allowReorder     bool
	maxInflightPerIP int
	maxTotalInflight int
	gcInterval       time.Duration
	nonceTTL         time.Duration
}

func parseSequence(s SequenceConfig, r ReplayConfig) (sequenceRuntime, error) {
	length := defaultInt(s.Length, 3)
	if length < 2 || length > 5 {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.length must be between 2 and 5")
	}
	slot := defaultInt(s.SlotSeconds, 30)
	if slot < 5 {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.slot_seconds must be at least 5")
	}
	window, err := parseDurationDefault(s.Window, 10*time.Second)
	if err != nil {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.window: %w", err)
	}
	interval, err := parseDurationDefault(s.PacketInterval, 80*time.Millisecond)
	if err != nil {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.packet_interval: %w", err)
	}
	jitter, err := parseDurationDefault(s.MaxJitter, 0)
	if err != nil {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.max_jitter: %w", err)
	}
	gc, err := parseDurationDefault(s.GCInterval, 2*time.Second)
	if err != nil {
		return sequenceRuntime{}, fmt.Errorf("knock.sequence.gc_interval: %w", err)
	}
	nonce, err := parseDurationDefault(r.NonceTTL, 2*time.Minute)
	if err != nil {
		return sequenceRuntime{}, fmt.Errorf("knock.replay.nonce_ttl: %w", err)
	}
	if nonce <= window {
		return sequenceRuntime{}, fmt.Errorf("knock.replay.nonce_ttl must be greater than knock.sequence.window")
	}
	return sequenceRuntime{length: length, slotSeconds: slot, window: window, packetInterval: interval, maxJitter: jitter, allowReorder: s.AllowReorder, maxInflightPerIP: defaultInt(s.MaxInflightPerIP, 8), maxTotalInflight: defaultInt(s.MaxTotalInflight, 4096), gcInterval: gc, nonceTTL: nonce}, nil
}

func parseDurationDefault(v string, d time.Duration) (time.Duration, error) {
	if v == "" {
		return d, nil
	}
	return time.ParseDuration(v)
}

func isKnockMethod(method string) bool {
	return method == "tcp-syn" || method == "udp" || method == "udp-passive" || method == "udp-seq" || method == "udp-passive-seq" || method == "tcp-syn-seq"
}

func DefaultClientKnockMethod(goos string) string {
	switch goos {
	case "windows", "darwin":
		return "udp"
	default:
		return "tcp-syn"
	}
}

func defaultUDPListen(udpListen, tcpListen string, udpPort int) string {
	if udpListen != "" {
		return udpListen
	}
	host, port, err := SplitHostPort(tcpListen)
	if err != nil {
		return ""
	}
	if udpPort > 0 {
		port = udpPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func resolveUDPListen(k KnockConfig, tcpListen string) (string, int, error) {
	host, tcpPort, err := SplitHostPort(tcpListen)
	if err != nil {
		return "", 0, fmt.Errorf("server.tcp_listen: %w", err)
	}
	udpPort := k.UDPKnockPort
	if udpPort == 0 {
		udpPort = k.UDPPort
	}
	if udpPort < 0 || udpPort > 65535 {
		return "", 0, fmt.Errorf("knock.udp_knock_port (%d) is invalid", udpPort)
	}
	if k.UDPListen != "" {
		_, parsedPort, err := SplitHostPort(k.UDPListen)
		if err != nil {
			return "", 0, fmt.Errorf("knock.udp_listen: %w", err)
		}
		if udpPort == 0 {
			udpPort = parsedPort
		}
		return k.UDPListen, udpPort, nil
	}
	if udpPort == 0 {
		udpPort = tcpPort
	}
	return net.JoinHostPort(host, strconv.Itoa(udpPort)), udpPort, nil
}
