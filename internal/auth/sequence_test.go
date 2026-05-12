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
