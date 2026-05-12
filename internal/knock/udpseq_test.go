package knock

import (
	"net"
	"testing"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
)

func TestSequenceTrackerRejectsReplayAndOrder(t *testing.T) {
	secret := []byte("0123456789abcdef")
	now := time.Now()
	parts, err := auth.BuildUDPSeqParts("client", secret, 443, now, 30, 3, []byte("1234567890abcdef"), "MTIzNDU2Nzg5MGFiY2RlZg")
	if err != nil {
		t.Fatal(err)
	}
	tr := newSequenceTracker(SequenceOptions{Length: 3, SlotSeconds: 30, Window: time.Second, MaxInflightPerIP: 8, MaxTotalInflight: 8}, time.Minute)
	src := net.ParseIP("192.0.2.1")
	if ok, err := tr.add(src, parts[1], secret, 443, now); err == nil || ok {
		t.Fatalf("expected order rejection, ok=%v err=%v", ok, err)
	}
	for i, part := range parts {
		ok, err := tr.add(src, part, secret, 443, now)
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if i < len(parts)-1 && ok {
			t.Fatalf("part %d completed early", i)
		}
		if i == len(parts)-1 && !ok {
			t.Fatalf("final part did not complete")
		}
	}
	if ok, err := tr.add(src, parts[0], secret, 443, now); err != auth.ErrReplayedNonce || ok {
		t.Fatalf("expected replay, ok=%v err=%v", ok, err)
	}
}

func TestSequenceTrackerLimits(t *testing.T) {
	secret := []byte("0123456789abcdef")
	now := time.Now()
	tr := newSequenceTracker(SequenceOptions{Length: 3, SlotSeconds: 30, Window: time.Second, MaxInflightPerIP: 1, MaxTotalInflight: 1}, time.Minute)
	for i, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		parts, err := auth.BuildUDPSeqParts("client", secret, 443, now, 30, 3, []byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "AAECAwQFBgcICQoLDA0ODw")
		if err != nil {
			t.Fatal(err)
		}
		ok, err := tr.add(net.ParseIP(ip), parts[0], secret, 443, now)
		if i == 0 && (err != nil || ok) {
			t.Fatalf("first add ok=%v err=%v", ok, err)
		}
		if i == 1 && err == nil {
			t.Fatal("expected total inflight rejection")
		}
	}
}
