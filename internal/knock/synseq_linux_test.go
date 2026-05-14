//go:build linux

package knock

import (
	"net"
	"testing"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
)

func TestSYNSequenceTrackerAcceptsProtectedPortParts(t *testing.T) {
	secret := []byte("0123456789abcdef")
	now := time.Unix(1700000000, 0)
	seq := SequenceOptions{Length: 3, SlotSeconds: 30, Window: time.Second}
	parts := auth.ComputeSYNSeqParts(secret, "client", 443, now.Unix()/30, 3)
	tracker := newSYNSequenceTracker(seq)
	src := net.IPv4(192, 0, 2, 10)
	for i, part := range parts {
		if part.Port != 443 {
			t.Fatalf("part %d port = %d, want 443", i, part.Port)
		}
		complete, clientID := tracker.add(src, part.Port, part.Fields, []auth.ClientSecret{{ClientID: "client", Secret: secret}}, 443, now)
		if i < len(parts)-1 && complete {
			t.Fatalf("part %d completed sequence early", i)
		}
		if i == len(parts)-1 && (!complete || clientID != "client") {
			t.Fatalf("final part complete=%v client=%q, want client", complete, clientID)
		}
	}
}
