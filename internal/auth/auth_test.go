package auth

import (
	"testing"
	"time"
)

func TestFrameRoundTripValidation(t *testing.T) {
	secret := []byte("1234567890123456")
	now := time.Unix(1710000000, 0)
	frame, err := NewFrame("client-001", secret, 443, false, now)
	if err != nil {
		t.Fatalf("NewFrame returned error: %v", err)
	}

	if err := ValidateFrame(frame, secret, 443, false, now, 30*time.Second); err != nil {
		t.Fatalf("ValidateFrame returned error: %v", err)
	}
}

func TestFrameRejectsWrongSecret(t *testing.T) {
	secret := []byte("1234567890123456")
	now := time.Unix(1710000000, 0)
	frame, err := NewFrame("client-001", secret, 443, false, now)
	if err != nil {
		t.Fatalf("NewFrame returned error: %v", err)
	}

	if err := ValidateFrame(frame, []byte("abcdefghijklmnop"), 443, false, now, 30*time.Second); err != ErrInvalidHMAC {
		t.Fatalf("expected ErrInvalidHMAC, got %v", err)
	}
}

func TestNonceCacheRejectsReplay(t *testing.T) {
	cache := NewNonceCache(5 * time.Minute)
	now := time.Unix(1710000000, 0)
	if err := cache.Add("client-001", "nonce", now); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if err := cache.Add("client-001", "nonce", now); err != ErrReplayedNonce {
		t.Fatalf("expected ErrReplayedNonce, got %v", err)
	}
}

func TestSYNFieldsVerifyAcrossSlots(t *testing.T) {
	secret := []byte("1234567890123456")
	now := time.Unix(1710000031, 0)
	fields := ComputeSYNFields(secret, "client-001", 443, SlotFor(now, 30*time.Second))
	clientID, ok := VerifySYNFields(fields, []ClientSecret{{ClientID: "client-001", Secret: secret}}, 443, now, 30*time.Second)
	if !ok || clientID != "client-001" {
		t.Fatalf("expected client-001 to verify, got %q ok=%v", clientID, ok)
	}
}

func TestKnockFrameValidation(t *testing.T) {
	secret := []byte("1234567890123456")
	now := time.Unix(1710000000, 0)
	frame, err := NewKnockFrame("client-001", secret, 443, "udp", now)
	if err != nil {
		t.Fatalf("NewKnockFrame returned error: %v", err)
	}
	if err := ValidateKnockFrame(frame, secret, 443, "udp", now, 30*time.Second); err != nil {
		t.Fatalf("ValidateKnockFrame returned error: %v", err)
	}
}

func TestNonceCacheCapacityLimit(t *testing.T) {
	cache := NewNonceCacheWithLimit(time.Minute, 2)
	now := time.Now()
	for _, nonce := range []string{"a", "b", "c"} {
		if err := cache.Add("client", nonce, now); err != nil {
			t.Fatalf("Add(%s): %v", nonce, err)
		}
	}
	if got := cache.Len(now); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
}
