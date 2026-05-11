package secure

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestEncryptedConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	secret := []byte("12345678901234567890123456789012")
	client, err := Wrap(a, secret, "client-001", "nonce", 443, ClientRole)
	if err != nil {
		t.Fatalf("Wrap client: %v", err)
	}
	server, err := Wrap(b, secret, "client-001", "nonce", 443, ServerRole)
	if err != nil {
		t.Fatalf("Wrap server: %v", err)
	}

	payload := bytes.Repeat([]byte("abc123"), 5000)
	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errCh <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull server: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncryptedConnRejectsWrongSecret(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	client, err := Wrap(a, []byte("12345678901234567890123456789012"), "client-001", "nonce", 443, ClientRole)
	if err != nil {
		t.Fatalf("Wrap client: %v", err)
	}
	server, err := Wrap(b, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "client-001", "nonce", 443, ServerRole)
	if err != nil {
		t.Fatalf("Wrap server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		errCh <- err
	}()

	buf := make([]byte, 5)
	if _, err := server.Read(buf); err == nil {
		t.Fatal("expected read to fail with wrong key")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client Write: %v", err)
	}
}
