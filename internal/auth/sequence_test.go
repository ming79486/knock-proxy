package auth

import (
	"testing"
	"time"
)

func TestUDPSeqDerivation(t *testing.T) {
	secret := []byte("0123456789abcdef")
	nonce := []byte("1234567890abcdef")
	now := time.Unix(1700000000, 0)
	parts1, err := BuildUDPSeqParts("client", secret, 443, now, 30, 3, nonce, "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	parts2, err := BuildUDPSeqParts("client", secret, 443, now, 30, 3, nonce, "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	if parts1[0].Tag != parts2[0].Tag || parts1[2].FinalMAC != parts2[2].FinalMAC {
		t.Fatal("same inputs produced different sequence")
	}
	parts3, err := BuildUDPSeqParts("client", []byte("fedcba9876543210"), 443, now, 30, 3, nonce, "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	if parts1[0].Tag == parts3[0].Tag {
		t.Fatal("different secret produced same tag")
	}
	parts4, err := BuildUDPSeqParts("client", secret, 444, now, 30, 3, nonce, "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	if parts1[0].Tag == parts4[0].Tag {
		t.Fatal("different port produced same tag")
	}
}

func TestUDPSeqValidationRejectsFinalMAC(t *testing.T) {
	secret := []byte("0123456789abcdef")
	nonce := []byte("1234567890abcdef")
	now := time.Unix(1700000000, 0)
	parts, err := BuildUDPSeqParts("client", secret, 443, now, 30, 3, nonce, "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		if err := ValidateUDPSeqPart(part, secret, 443, now, 30, 3); err != nil {
			t.Fatalf("part validate: %v", err)
		}
	}
	parts[2].FinalMAC = "00" + parts[2].FinalMAC[2:]
	if err := ValidateUDPSeqFinal(parts, secret, 443); err != ErrInvalidHMAC {
		t.Fatalf("expected invalid hmac, got %v", err)
	}
}

func TestSYNSeqUsesProtectedPort(t *testing.T) {
	secret := []byte("0123456789abcdef")
	slot := int64(1700000000 / 30)
	parts := ComputeSYNSeqParts(secret, "client", 443, slot, 3)
	seen := map[SYNFields]bool{}
	for i, part := range parts {
		if part.Port != 443 {
			t.Fatalf("part %d port = %d, want protected port 443", i, part.Port)
		}
		if seen[part.Fields] {
			t.Fatalf("part %d reused SYN fields %+v", i, part.Fields)
		}
		seen[part.Fields] = true
		clientID, gotSlot, ok := VerifySYNSeqPart(part.Fields, 443, []ClientSecret{{ClientID: "client", Secret: secret}}, 443, time.Unix(slot*30, 0), 30, 3, i)
		if !ok || clientID != "client" || gotSlot != slot {
			t.Fatalf("part %d did not verify: client=%q slot=%d ok=%v", i, clientID, gotSlot, ok)
		}
	}
}

func TestSYNSeqVerifyAcceptsLegacyRandomPorts(t *testing.T) {
	secret := []byte("0123456789abcdef")
	slot := int64(1700000000 / 30)
	parts := computeLegacySYNSeqParts(secret, "client", 443, slot, 3)
	for i, part := range parts {
		if part.Port == 443 {
			t.Fatalf("legacy part %d unexpectedly used protected port", i)
		}
		clientID, gotSlot, ok := VerifySYNSeqPart(part.Fields, part.Port, []ClientSecret{{ClientID: "client", Secret: secret}}, 443, time.Unix(slot*30, 0), 30, 3, i)
		if !ok || clientID != "client" || gotSlot != slot {
			t.Fatalf("legacy part %d did not verify: client=%q slot=%d ok=%v", i, clientID, gotSlot, ok)
		}
	}
}
