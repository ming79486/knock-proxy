package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitClientDefaultsWindowsToUDP(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("1234567890123456"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	err := RunInit(context.Background(), InitOptions{
		Kind:       "client",
		Listen:     "127.0.0.1:10022",
		ServerAddr: "example.com:443",
		ClientID:   "client-001",
		SecretFile: secretFile,
		OutDir:     dir,
		Platform:   "windows",
	})
	if err != nil {
		t.Fatalf("RunInit returned error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "client.yaml"))
	if err != nil {
		t.Fatalf("read client.yaml: %v", err)
	}
	if !strings.Contains(string(data), `method: "udp"`) {
		t.Fatalf("expected windows client init to default to udp, got:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "knock-proxy-client.ps1")); err != nil {
		t.Fatalf("expected Windows client launcher: %v", err)
	}
}

func TestInitServerSampleUsesRequestedClientPlatformDefault(t *testing.T) {
	dir := t.TempDir()
	err := RunInit(context.Background(), InitOptions{
		Kind:     "server",
		Listen:   "0.0.0.0:443",
		Upstream: "127.0.0.1:22",
		ClientID: "client-001",
		OutDir:   dir,
		Platform: "windows",
	})
	if err != nil {
		t.Fatalf("RunInit returned error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "client.yaml.sample"))
	if err != nil {
		t.Fatalf("read client.yaml.sample: %v", err)
	}
	if !strings.Contains(string(data), `method: "udp"`) {
		t.Fatalf("expected windows sample client method udp, got:\n%s", data)
	}
	server, err := os.ReadFile(filepath.Join(dir, "server.yaml"))
	if err != nil {
		t.Fatalf("read server.yaml: %v", err)
	}
	if !strings.Contains(string(server), `method: "udp"`) {
		t.Fatalf("expected windows server init method udp to match sample client, got:\n%s", server)
	}
	if _, err := os.Stat(filepath.Join(dir, "knock-proxy-server.service")); err != nil {
		t.Fatalf("expected server systemd service: %v", err)
	}
}

func TestInitClientWindowsTCPSYNWritesWarning(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("1234567890123456"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	err := RunInit(context.Background(), InitOptions{
		Kind:       "client",
		Listen:     "127.0.0.1:10022",
		ServerAddr: "example.com:443",
		ClientID:   "client-001",
		SecretFile: secretFile,
		OutDir:     dir,
		Platform:   "windows",
		Method:     "tcp-syn",
	})
	if err != nil {
		t.Fatalf("RunInit returned error: %v", err)
	}
	notes, err := os.ReadFile(filepath.Join(dir, "NOTES.txt"))
	if err != nil {
		t.Fatalf("read NOTES.txt: %v", err)
	}
	if !strings.Contains(string(notes), "WinDivert") || !strings.Contains(string(notes), "administrator") {
		t.Fatalf("expected Windows tcp-syn note to mention WinDivert and administrator privileges, got:\n%s", notes)
	}
}
