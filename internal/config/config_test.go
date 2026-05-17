package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestParseSecretBase64(t *testing.T) {
	secret := []byte("1234567890123456")
	got, err := ParseSecret("base64:"+base64.StdEncoding.EncodeToString(secret), "")
	if err != nil {
		t.Fatalf("ParseSecret returned error: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("secret mismatch: got %q", got)
	}
}

func TestClientRuntimeAllowsNonLoopbackListenWithDetectableWarningCondition(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeClient
	cfg.Client.Listen = "0.0.0.0:10022"
	cfg.Client.ServerAddr = "example.com:443"
	cfg.Client.ClientID = "client-001"
	cfg.Client.Secret = "1234567890123456"

	if _, err := cfg.ClientRuntime(); err != nil {
		t.Fatalf("expected explicit non-loopback client listen address to be allowed: %v", err)
	}
	if IsLoopbackListen(cfg.Client.Listen) {
		t.Fatal("expected non-loopback client listen address to be detectable")
	}
}

func TestServerRuntimeRejectsDuplicateClientID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Auth.Clients = []AuthClient{
		{ClientID: "client-001", Secret: "1234567890123456"},
		{ClientID: "client-001", Secret: "abcdefghijklmnop"},
	}

	if _, err := cfg.ServerRuntime(); err == nil {
		t.Fatal("expected duplicate client_id to be rejected")
	}
}

func TestServerRuntimeAcceptsUDPPassive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Knock.Method = "udp-passive"
	cfg.Knock.UDPPort = 8443
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}

	rt, err := cfg.ServerRuntime()
	if err != nil {
		t.Fatalf("ServerRuntime returned error: %v", err)
	}
	if !rt.Firewall.DropUDPKnockPort {
		t.Fatal("expected udp-passive to enable UDP knock port drop")
	}
	if rt.UDPPort != 8443 || rt.Firewall.UDPKnockPort != 8443 {
		t.Fatalf("udp port mismatch: runtime=%d firewall=%d", rt.UDPPort, rt.Firewall.UDPKnockPort)
	}
}

func TestServerRuntimeRejectsUnsupportedKnockMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Knock.Method = "icmp"
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}

	if _, err := cfg.ServerRuntime(); err == nil {
		t.Fatal("expected unsupported knock method to be rejected")
	}
}

func TestClientRuntimeUsesConfiguredUDPPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeClient
	cfg.Client.Listen = "127.0.0.1:10022"
	cfg.Client.ServerAddr = "example.com:443"
	cfg.Client.ClientID = "client-001"
	cfg.Client.Secret = "1234567890123456"
	cfg.Knock.Method = "udp-passive"
	cfg.Knock.UDPPort = 8443

	rt, err := cfg.ClientRuntime()
	if err != nil {
		t.Fatalf("ClientRuntime returned error: %v", err)
	}
	if rt.ServerPort != 443 {
		t.Fatalf("expected TCP auth port 443, got %d", rt.ServerPort)
	}
	if rt.UDPServerAddr != "example.com:8443" {
		t.Fatalf("unexpected UDP server address %q", rt.UDPServerAddr)
	}
}

func TestDefaultClientKnockMethodIsPlatformAware(t *testing.T) {
	cases := map[string]string{
		"linux":   "tcp-syn",
		"windows": "udp",
		"darwin":  "udp",
	}
	for goos, want := range cases {
		if got := DefaultClientKnockMethod(goos); got != want {
			t.Fatalf("DefaultClientKnockMethod(%q) = %q, want %q", goos, got, want)
		}
	}
}

func TestClientRuntimeUsesPlatformDefaultKnockMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeClient
	cfg.Client.Listen = "127.0.0.1:10022"
	cfg.Client.ServerAddr = "example.com:443"
	cfg.Client.ClientID = "client-001"
	cfg.Client.Secret = "1234567890123456"

	rt, err := cfg.ClientRuntime()
	if err != nil {
		t.Fatalf("ClientRuntime returned error: %v", err)
	}
	if want := DefaultClientKnockMethod(runtime.GOOS); rt.KnockMethod != want {
		t.Fatalf("KnockMethod = %q, want %q", rt.KnockMethod, want)
	}
}

func TestServerRuntimeRejectsDirectModeWithTCPAuth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Access.Mode = "direct"
	cfg.Access.RequireTCPAuth = true
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}

	if _, err := cfg.ServerRuntime(); err == nil {
		t.Fatal("expected direct mode with TCP auth to be rejected")
	}
}

func TestServerRuntimeRejectsUDPPassiveWithScriptBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Knock.Method = "udp-passive"
	cfg.Firewall.Backend = "script"
	cfg.Firewall.Script.AllowCmd = "true"
	cfg.Firewall.Script.RevokeCmd = "true"
	cfg.Firewall.Script.CleanupCmd = "true"
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}
	if _, err := cfg.ServerRuntime(); err == nil {
		t.Fatal("expected udp-passive + script backend to be rejected")
	}
}

func TestServerRuntimeRejectsBadUpstreamAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1"
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}
	if _, err := cfg.ServerRuntime(); err == nil {
		t.Fatal("expected malformed upstream to be rejected")
	}
}

func TestServerRuntimeAuthStageLimitDefaultsAndOverrides(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}
	rt, err := cfg.ServerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.MaxPendingAuth != 128 || rt.MaxAuthWorkers != 32 {
		t.Fatalf("auth stage defaults = %d/%d, want 128/32", rt.MaxPendingAuth, rt.MaxAuthWorkers)
	}
	cfg.Limits.MaxPendingAuth = 7
	cfg.Limits.MaxAuthWorkers = 3
	rt, err = cfg.ServerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.MaxPendingAuth != 7 || rt.MaxAuthWorkers != 3 {
		t.Fatalf("auth stage overrides = %d/%d, want 7/3", rt.MaxPendingAuth, rt.MaxAuthWorkers)
	}
}

func TestAuthEnvelopeV2Defaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeServer
	cfg.Server.TCPListen = "0.0.0.0:443"
	cfg.Server.Upstream = "127.0.0.1:22"
	cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}

	rt, err := cfg.ServerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.AuthFrame != "envelope-v2" || rt.AuthHintMode != "route-hint" || rt.AuthPaddingPolicy != "random-bucket" {
		t.Fatalf("auth defaults = frame=%q hint=%q padding=%q", rt.AuthFrame, rt.AuthHintMode, rt.AuthPaddingPolicy)
	}
	if got, want := rt.AuthFrameBuckets, []int{128, 192, 256, 384, 512}; len(got) != len(want) || got[0] != want[0] || got[len(got)-1] != want[len(want)-1] {
		t.Fatalf("auth buckets = %v, want %v", got, want)
	}
	if rt.AuthFailDelayJitterMin != 20*time.Millisecond || rt.AuthFailDelayJitterMax != 80*time.Millisecond {
		t.Fatalf("auth jitter = %s/%s", rt.AuthFailDelayJitterMin, rt.AuthFailDelayJitterMax)
	}
}

func TestAuthFrameV1CompatibilityConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeClient
	cfg.Client.Listen = "127.0.0.1:10022"
	cfg.Client.ServerAddr = "example.com:443"
	cfg.Client.ClientID = "client-001"
	cfg.Client.Secret = "1234567890123456"
	cfg.Auth.Frame = "frame-v1"

	rt, err := cfg.ClientRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if rt.AuthFrame != "frame-v1" {
		t.Fatalf("AuthFrame = %q, want frame-v1", rt.AuthFrame)
	}
}

func TestAuthConfigRejectsInvalidEnvelopeV2Settings(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Auth.Frame = "json" },
		func(c *Config) { c.Auth.HintMode = "plain" },
		func(c *Config) { c.Auth.PaddingPolicy = "continuous" },
		func(c *Config) { c.Auth.FrameSizeBuckets = []int{128, 128} },
		func(c *Config) { c.Auth.FrameSizeBuckets = []int{64} },
		func(c *Config) { c.Auth.FailDelayJitterMin = "90ms"; c.Auth.FailDelayJitterMax = "20ms" },
		func(c *Config) { c.Auth.DrainOnFailBytes = -1 },
	}
	for _, mutate := range cases {
		cfg := DefaultConfig()
		cfg.Mode = ModeServer
		cfg.Server.TCPListen = "0.0.0.0:443"
		cfg.Server.Upstream = "127.0.0.1:22"
		cfg.Auth.Clients = []AuthClient{{ClientID: "client-001", Secret: "1234567890123456"}}
		mutate(&cfg)
		if _, err := cfg.ServerRuntime(); err == nil {
			t.Fatal("expected invalid auth config to be rejected")
		}
	}
}

func TestLoadRejectsLegacyJSONKnockOptions(t *testing.T) {
	for _, body := range []string{
		"knock_frame_format: json\n",
		"legacy_json: true\n",
		"allow_json_knock: true\n",
		"json_compat: true\n",
		"json_sequence_compat: true\n",
		"knock:\n  frame: json\n",
		"knock:\n  frame: legacy-json\n",
	} {
		_, err := Load(writeTempConfig(t, "mode: server\n"+body))
		if err == nil {
			t.Fatalf("Load(%q) succeeded, want legacy rejection", body)
		}
	}
}

func TestLoadAllowsUnrelatedJSONKeys(t *testing.T) {
	_, err := Load(writeTempConfig(t, `mode: server
log:
  format: json
output:
  json: true
`))
	if err != nil {
		t.Fatalf("Load rejected unrelated json keys: %v", err)
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
