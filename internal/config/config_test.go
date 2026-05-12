package config

import (
	"encoding/base64"
	"runtime"
	"testing"
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
