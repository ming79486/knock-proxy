package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/knock"
	"github.com/ming79486/knock-proxy/internal/secure"
)

func RunKnock(ctx context.Context, opts KnockOptions) error {
	if opts.ServerAddr == "" || opts.ClientID == "" {
		return errors.New("knock requires --server and --client-id")
	}
	secret, err := config.ParseSecret(opts.Secret, opts.SecretFile)
	if err != nil {
		return err
	}
	_, port, err := config.SplitHostPort(opts.ServerAddr)
	if err != nil {
		return err
	}
	method := opts.Method
	if method == "" {
		method = config.DefaultClientKnockMethod(runtime.GOOS)
	}
	sendOpts := knock.SendOptions{
		ServerAddr: opts.ServerAddr,
		ClientID:   opts.ClientID,
		Secret:     secret,
		ServerPort: port,
		TimeWindow: 30 * time.Second,
	}
	switch method {
	case "tcp-syn":
		if err := knock.CheckClientSupport(method); err != nil {
			return err
		}
		return knock.Send(ctx, sendOpts)
	case "udp":
		return knock.SendUDPMethod(ctx, sendOpts, "udp")
	case "udp-passive":
		return knock.SendUDPMethod(ctx, sendOpts, "udp-passive")
	default:
		return fmt.Errorf("unsupported knock method %q", method)
	}
}

func RunProbe(ctx context.Context, opts ProbeOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	if cfg.Mode == "" {
		cfg.Mode = config.ModeClient
	}
	rt, err := cfg.ClientRuntime()
	if err != nil {
		return err
	}
	fmt.Println("[OK] config loaded")
	fmt.Printf("[OK] knock method: %s\n", rt.KnockMethod)
	if err := sendKnock(ctx, rt); err != nil {
		return fmt.Errorf("[FAIL] knock failed: %w", err)
	}
	fmt.Println("[OK] knock sent")
	if opts.KnockOnly {
		return nil
	}
	conn, err := dialServer(ctx, rt)
	if err != nil {
		return fmt.Errorf("[FAIL] tcp connect failed after knock: %w", err)
	}
	defer conn.Close()
	fmt.Println("[OK] tcp connected")
	frame, err := auth.NewFrame(rt.ClientID, rt.Secret, rt.ServerPort, rt.TransportEncrypted, time.Now())
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(rt.AuthTimeout))
	if err := auth.WriteFrame(conn, frame); err != nil {
		return fmt.Errorf("[FAIL] tcp auth write failed: %w", err)
	}
	fmt.Println("[OK] tcp auth frame sent")
	if rt.TransportEncrypted {
		conn, err = secure.Wrap(conn, rt.Secret, rt.ClientID, frame.Nonce, rt.ServerPort, secure.ClientRole)
		if err != nil {
			return fmt.Errorf("[FAIL] transport encryption setup failed: %w", err)
		}
		fmt.Println("[OK] transport encryption enabled")
	}
	if opts.Payload != "" {
		if _, err := conn.Write([]byte(opts.Payload)); err != nil {
			return fmt.Errorf("[FAIL] probe payload write failed: %w", err)
		}
		fmt.Println("[OK] probe payload sent")
	}
	return nil
}

func RunDoctor(ctx context.Context, opts DoctorOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	fmt.Println("knock-proxy doctor")
	if cfg.Mode == "" {
		fmt.Println("[WARN] mode is empty; assuming server checks where possible")
	}
	if cfg.Mode == config.ModeClient {
		rt, err := cfg.ClientRuntime()
		if err != nil {
			return fmt.Errorf("[FAIL] client config invalid: %w", err)
		}
		fmt.Println("[OK] client config valid")
		if err := knock.CheckClientSupport(rt.KnockMethod); err != nil {
			fmt.Printf("[WARN] %v\n", err)
		} else {
			fmt.Printf("[OK] client knock method available: %s\n", rt.KnockMethod)
		}
		return nil
	}
	if geteuid() == 0 {
		fmt.Println("[OK] running as root")
	} else {
		fmt.Println("[WARN] not running as root; server tcp-syn/udp-passive modes may require CAP_NET_RAW/CAP_NET_ADMIN")
	}
	for _, cmd := range []string{"nft", "iptables", "ipset", "ip6tables"} {
		if path, err := exec.LookPath(cmd); err == nil {
			fmt.Printf("[OK] %s found: %s\n", cmd, path)
		} else {
			fmt.Printf("[WARN] %s not found\n", cmd)
		}
	}
	rt, err := cfg.ServerRuntime()
	if err != nil {
		return fmt.Errorf("[FAIL] server config invalid: %w", err)
	}
	fmt.Println("[OK] server config valid")
	if canListen(rt.Listen) {
		fmt.Printf("[OK] tcp listen address available: %s\n", rt.Listen)
	} else {
		fmt.Printf("[WARN] tcp listen address may be unavailable: %s\n", rt.Listen)
	}
	if rt.MetricsEnabled {
		if canListen(rt.MetricsListen) {
			fmt.Printf("[OK] metrics listen address available: %s\n", rt.MetricsListen)
		} else {
			fmt.Printf("[WARN] metrics listen address may be unavailable: %s\n", rt.MetricsListen)
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, rt.UpstreamConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", rt.Upstream)
	if err != nil {
		fmt.Printf("[WARN] upstream not reachable: %v\n", err)
	} else {
		_ = conn.Close()
		fmt.Printf("[OK] upstream reachable: %s\n", rt.Upstream)
	}
	fmt.Println("[OK] doctor completed")
	return nil
}

func RunInit(ctx context.Context, opts InitOptions) error {
	if opts.Kind != "server" && opts.Kind != "client" {
		return errors.New("init kind must be server or client")
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return err
	}
	switch opts.Kind {
	case "server":
		return initServer(opts)
	case "client":
		return initClient(opts)
	default:
		return nil
	}
}

func initServer(opts InitOptions) error {
	secret, encoded, err := generateSecret()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(opts.OutDir, "secret.key"), []byte("base64:"+encoded+"\n"), 0o600); err != nil {
		return err
	}
	knockMethod := initClientMethod(opts)
	if err := validateInitKnockMethod(knockMethod); err != nil {
		return err
	}
	serverYAML := fmt.Sprintf(`mode: server
server:
  tcp_listen: %q
  upstream: %q
access:
  mode: "proxy"
  require_tcp_auth: true
knock:
  method: %q
auth:
  clients:
    - client_id: %q
      secret: "base64:%s"
firewall:
  backend: "auto"
  default_action: "drop"
  allow_seconds: 15
  remove_after_auth: true
transport:
  encryption: false
metrics:
  enabled: false
log:
  format: "text"
`, opts.Listen, opts.Upstream, knockMethod, opts.ClientID, encoded)
	if err := os.WriteFile(filepath.Join(opts.OutDir, "server.yaml"), []byte(serverYAML), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(opts.OutDir, "knock-proxy-server.service"), []byte(serverServiceTemplate), 0o644); err != nil {
		return err
	}
	clientYAML := fmt.Sprintf(`mode: client
client:
  listen: "127.0.0.1:10022"
  server_addr: "example.com:443"
  client_id: %q
  secret: "base64:%s"
knock:
  method: %q
transport:
  encryption: false
`, opts.ClientID, base64.StdEncoding.EncodeToString(secret), knockMethod)
	if err := os.WriteFile(filepath.Join(opts.OutDir, "client.yaml.sample"), []byte(clientYAML), 0o600); err != nil {
		return err
	}
	if err := writeClientLauncher(opts.OutDir, opts.Platform); err != nil {
		return err
	}
	return writeInitNotes(opts.OutDir, opts.Platform, knockMethod)
}

func initClient(opts InitOptions) error {
	if opts.ServerAddr == "" {
		return errors.New("init client requires --server")
	}
	secret, err := config.ParseSecret("", opts.SecretFile)
	if err != nil {
		return err
	}
	method := initClientMethod(opts)
	if err := validateInitKnockMethod(method); err != nil {
		return err
	}
	clientYAML := fmt.Sprintf(`mode: client
client:
  listen: %q
  server_addr: %q
  client_id: %q
  secret: "base64:%s"
knock:
  method: %q
transport:
  encryption: false
`, opts.Listen, opts.ServerAddr, opts.ClientID, base64.StdEncoding.EncodeToString(secret), method)
	if err := os.WriteFile(filepath.Join(opts.OutDir, "client.yaml"), []byte(clientYAML), 0o600); err != nil {
		return err
	}
	if err := writeClientLauncher(opts.OutDir, opts.Platform); err != nil {
		return err
	}
	return writeInitNotes(opts.OutDir, opts.Platform, method)
}

func initClientMethod(opts InitOptions) string {
	if opts.Method != "" {
		return opts.Method
	}
	if opts.Platform == "" {
		opts.Platform = runtime.GOOS
	}
	return config.DefaultClientKnockMethod(opts.Platform)
}

func validateInitKnockMethod(method string) error {
	switch method {
	case "tcp-syn", "udp", "udp-passive":
		return nil
	default:
		return fmt.Errorf("unsupported knock method %q", method)
	}
}

func writeInitNotes(outDir, platform, method string) error {
	if platform == "" {
		platform = runtime.GOOS
	}
	notes := fmt.Sprintf("knock-proxy generated client notes\n\nplatform: %s\nknock.method: %s\n", platform, method)
	if platform == "windows" && method == "tcp-syn" {
		notes += "\nWindows tcp-syn knock uses WinDivert when WinDivert.dll is available, otherwise Npcap Packet.dll. Run as administrator.\n"
	}
	if platform == "darwin" && method == "tcp-syn" {
		notes += "\nmacOS tcp-syn knock requires root/BPF packet injection permission.\nFor easier deployment, use knock.method: udp.\n"
	}
	return os.WriteFile(filepath.Join(outDir, "NOTES.txt"), []byte(notes), 0o644)
}

func writeClientLauncher(outDir, platform string) error {
	if platform == "" {
		platform = runtime.GOOS
	}
	if platform == "windows" {
		return os.WriteFile(filepath.Join(outDir, "knock-proxy-client.ps1"), []byte(windowsClientLauncherTemplate), 0o644)
	}
	return os.WriteFile(filepath.Join(outDir, "knock-proxy-client.service"), []byte(clientServiceTemplate), 0o644)
}

const serverServiceTemplate = `[Unit]
Description=Knock Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/knock-proxy server --config /etc/knock-proxy/server.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

const clientServiceTemplate = `[Unit]
Description=Knock Proxy Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/knock-proxy client --config /etc/knock-proxy/client.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

const windowsClientLauncherTemplate = `param(
    [string]$Config = ".\client.yaml"
)

.\knock-proxy.exe client --config $Config
`

func generateSecret() ([]byte, string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}
	return secret, base64.StdEncoding.EncodeToString(secret), nil
}

func canListen(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
