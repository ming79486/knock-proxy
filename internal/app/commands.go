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
	"strconv"
	"strings"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/firewall"
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
	host, port, err := config.SplitHostPort(opts.ServerAddr)
	if err != nil {
		return err
	}
	protectedPort := port
	if opts.ProtectedTCPPort > 0 {
		if opts.ProtectedTCPPort > 65535 {
			return fmt.Errorf("--protected-port %d is invalid", opts.ProtectedTCPPort)
		}
		protectedPort = opts.ProtectedTCPPort
	}
	knockAddr := opts.ServerAddr
	if opts.UDPKnockPort > 0 {
		if opts.UDPKnockPort > 65535 {
			return fmt.Errorf("--udp-port %d is invalid", opts.UDPKnockPort)
		}
		knockAddr = net.JoinHostPort(host, strconv.Itoa(opts.UDPKnockPort))
	}
	method := opts.Method
	if method == "" {
		method = config.DefaultClientKnockMethod(runtime.GOOS)
	}
	sendOpts := knock.SendOptions{
		ServerAddr: opts.ServerAddr,
		ClientID:   opts.ClientID,
		Secret:     secret,
		ServerPort: protectedPort,
		TimeWindow: 30 * time.Second,
	}
	switch method {
	case "tcp-syn":
		if err := knock.CheckClientSupport(method); err != nil {
			return err
		}
		err = knock.Send(ctx, sendOpts)
	case "udp":
		sendOpts.ServerAddr = knockAddr
		err = knock.SendUDPMethod(ctx, sendOpts, "udp")
	case "udp-passive":
		sendOpts.ServerAddr = knockAddr
		err = knock.SendUDPMethod(ctx, sendOpts, "udp-passive")
	case "udp-seq", "udp-passive-seq":
		sendOpts.ServerAddr = knockAddr
		err = knock.SendUDPSequence(ctx, sendOpts)
	case "tcp-syn-seq":
		if err := knock.CheckClientSupport(method); err != nil {
			return err
		}
		err = knock.SendSYNSequence(ctx, sendOpts)
	default:
		return fmt.Errorf("unsupported knock method %q", method)
	}
	if err != nil {
		return err
	}
	if !opts.WaitOpen {
		return nil
	}
	timeout := opts.WaitOpenTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if err := waitTCPOpen(ctx, opts.ServerAddr, timeout); err != nil {
		return fmt.Errorf("wait-open failed: %w", err)
	}
	fmt.Printf("[OK] tcp port open: %s\n", opts.ServerAddr)
	return nil
}

func RunProbe(ctx context.Context, opts ProbeOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("[FAIL] config load failed: %w", err)
	}
	if cfg.Mode == "" {
		cfg.Mode = config.ModeClient
	}
	rt, err := cfg.ClientRuntime()
	if err != nil {
		return fmt.Errorf("[FAIL] client config invalid: %w", err)
	}
	fmt.Println("[OK] config loaded")
	fmt.Println("[OK] secret loaded")
	fmt.Printf("[OK] knock method: %s\n", rt.KnockMethod)
	if err := probeResolveServer(rt.ServerAddr); err != nil {
		return err
	}
	knockStart := time.Now()
	if err := sendKnock(ctx, rt); err != nil {
		return fmt.Errorf("[FAIL] knock_send_failed: %w\nhint: verify client privileges/driver support and server knock.method", err)
	}
	fmt.Println("[OK] knock sent")
	fmt.Printf("[OK] knock RTT: %s\n", time.Since(knockStart).Round(time.Millisecond))
	if opts.KnockOnly {
		return nil
	}
	start := time.Now()
	conn, err := dialServer(ctx, rt)
	if err != nil {
		return fmt.Errorf("[FAIL] tcp_connect_timeout: %w\nhint: server may not have accepted the knock or firewall allow did not take effect", err)
	}
	defer conn.Close()
	fmt.Printf("[OK] tcp connected: %s\n", time.Since(start).Round(time.Millisecond))
	frame, err := auth.NewFrame(rt.ClientID, rt.Secret, rt.ServerPort, rt.TransportEncrypted, time.Now())
	if err != nil {
		return fmt.Errorf("[FAIL] auth_frame_failed: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(rt.AuthTimeout))
	if err := auth.WriteFrame(conn, frame); err != nil {
		return fmt.Errorf("[FAIL] tcp_auth_write_failed: %w", err)
	}
	fmt.Printf("[OK] tcp auth frame sent: %s\n", time.Since(start).Round(time.Millisecond))
	_ = conn.SetDeadline(time.Time{})
	if rt.TransportEncrypted {
		conn, err = secure.Wrap(conn, rt.Secret, rt.ClientID, frame.Nonce, rt.ServerPort, secure.ClientRole)
		if err != nil {
			return fmt.Errorf("[FAIL] transport_encryption_setup_failed: %w", err)
		}
		fmt.Println("[OK] transport encryption enabled")
	}
	if opts.Payload != "" {
		if _, err := conn.Write([]byte(opts.Payload)); err != nil {
			return fmt.Errorf("[FAIL] probe_payload_write_failed: %w", err)
		}
		fmt.Println("[OK] probe payload sent")
		fmt.Printf("[OK] upstream write RTT: %s\n", time.Since(start).Round(time.Millisecond))
	}
	fmt.Println("[OK] probe completed")
	return nil
}

func RunDoctor(ctx context.Context, opts DoctorOptions) error {
	d := &doctorReport{}
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
			d.fail("client config invalid: %v", err)
			return d.finish()
		}
		d.ok("client config valid")
		d.ok("method: %s", rt.KnockMethod)
		if err := probeResolveServer(rt.ServerAddr); err != nil {
			d.fail("%s", strings.TrimPrefix(err.Error(), "[FAIL] "))
		}
		if err := checkSecretFileMode(cfg.Client.SecretFile); err != nil {
			d.warn("%v", err)
		}
		printPlatformClientDoctor(rt)
		return d.finish()
	}
	if geteuid() == 0 {
		d.ok("running as root")
	} else {
		d.warn("not running as root; server tcp-syn/tcp-syn-seq/udp-passive/udp-passive-seq modes may require CAP_NET_RAW/CAP_NET_ADMIN")
	}
	for _, cap := range effectiveCapabilityStatuses() {
		if cap.Err != nil {
			d.warn("%s status unavailable: %v", cap.Name, cap.Err)
			continue
		}
		if cap.OK {
			d.ok("%s available", cap.Name)
		} else {
			d.warn("%s not available", cap.Name)
		}
	}
	for _, cmd := range []string{"nft", "iptables", "ipset", "ip6tables"} {
		if path, err := exec.LookPath(cmd); err == nil {
			d.ok("%s found: %s", cmd, path)
		} else {
			d.warn("%s not found", cmd)
		}
	}
	rt, err := cfg.ServerRuntime()
	if err != nil {
		d.fail("server config invalid: %v", err)
		return d.finish()
	}
	d.ok("server config valid")

	if caps, err := firewall.Validate(rt.Firewall); err != nil {
		d.fail("firewall backend invalid: %v", err)
	} else {
		d.ok("firewall backend selected: %s", caps.Backend)
		for _, cmd := range []string{"nft", "ipset", "iptables", "ip6tables"} {
			if path := caps.Commands[cmd]; path != "" {
				d.ok("firewall command %s: %s", cmd, path)
			}
		}
		d.ok("firewall capabilities: timeout=%v drop_udp=%v", caps.Timeout, caps.DropUDP)
	}
	if rt.AccessMode == "direct" {
		d.warn("direct mode uses IP-based firewall allow without TCP HMAC authentication; clients behind the same NAT share the window")
		if rt.AllowTTL > 30*time.Second {
			d.warn("direct mode allow_seconds is high: %s", rt.AllowTTL)
		}
	}
	if canListen(rt.Listen) {
		d.ok("tcp listen address available: %s", rt.Listen)
	} else {
		d.fail("tcp listen address unavailable: %s", rt.Listen)
	}
	if rt.MetricsEnabled {
		if canListen(rt.MetricsListen) {
			d.ok("metrics listen address available: %s", rt.MetricsListen)
		} else {
			d.fail("metrics listen address unavailable: %s", rt.MetricsListen)
		}
	}
	if rt.LogFile != "" {
		if err := checkWritableDir(filepath.Dir(rt.LogFile)); err != nil {
			d.warn("log directory not writable: %v", err)
		} else {
			d.ok("log directory writable: %s", filepath.Dir(rt.LogFile))
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, rt.UpstreamConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", rt.Upstream)
	if err != nil {
		d.warn("upstream not reachable: %v", err)
	} else {
		_ = conn.Close()
		d.ok("upstream reachable: %s", rt.Upstream)
	}
	if isNFTBackend(rt.Firewall.Backend) || rt.Firewall.Backend == "auto" || rt.Firewall.Backend == "" {
		if err := checkNFTTemporaryTable(ctx); err != nil {
			d.warn("nft temporary table check failed: %v", err)
		} else {
			d.ok("nft temporary table check passed")
		}
	}
	if release, ok := readOpenWrtRelease(); ok {
		d.ok("OpenWrt detected: %s", release)
	}
	return d.finish()
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
	case "tcp-syn", "udp", "udp-passive", "udp-seq", "udp-passive-seq", "tcp-syn-seq":
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
		return errors.New("macOS tcp-syn/tcp-syn-seq knock is currently not implemented; use knock.method: udp or udp-seq")
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

func waitTCPOpen(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		dialTimeout := 250 * time.Millisecond
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return lastErr
			}
			return context.DeadlineExceeded
		}
		if remaining < dialTimeout {
			dialTimeout = remaining
		}
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func probeResolveServer(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("[FAIL] server_addr_invalid: %w", err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("[FAIL] dns_resolve_failed: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("[FAIL] dns_resolve_failed: no addresses for %s", host)
	}
	fmt.Printf("[OK] server DNS resolved: %s -> %s\n", host, ips[0])
	return nil
}

func checkSecretFileMode(path string) error {
	if path == "" || runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("secret file stat failed: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secret file is readable by group/others: %s mode=%#o", path, info.Mode().Perm())
	}
	fmt.Printf("[OK] secret file permissions: %s mode=%#o\n", path, info.Mode().Perm())
	return nil
}

func checkWritableDir(dir string) error {
	if dir == "" || dir == "." {
		dir = "."
	}
	file, err := os.CreateTemp(dir, ".knock-proxy-doctor-*")
	if err != nil {
		return err
	}
	name := file.Name()
	_ = file.Close()
	return os.Remove(name)
}

func checkNFTTemporaryTable(ctx context.Context) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return err
	}
	name := fmt.Sprintf("knock_proxy_doctor_%d", os.Getpid())
	cmd := exec.CommandContext(ctx, "nft", "add", "table", "inet", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add table failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	cmd = exec.CommandContext(ctx, "nft", "delete", "table", "inet", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete table failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readOpenWrtRelease() (string, bool) {
	data, err := os.ReadFile("/etc/openwrt_release")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
			return strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), "'\""), true
		}
	}
	return strings.TrimSpace(string(data)), true
}

type doctorReport struct{ failures int }

func (d *doctorReport) ok(format string, args ...any)   { fmt.Printf("[OK] "+format+"\n", args...) }
func (d *doctorReport) warn(format string, args ...any) { fmt.Printf("[WARN] "+format+"\n", args...) }
func (d *doctorReport) fail(format string, args ...any) {
	d.failures++
	fmt.Printf("[FAIL] "+format+"\n", args...)
}
func (d *doctorReport) finish() error {
	if d.failures > 0 {
		return fmt.Errorf("doctor completed with %d blocking failure(s)", d.failures)
	}
	fmt.Println("[OK] doctor completed")
	return nil
}
