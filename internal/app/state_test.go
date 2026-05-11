package app

import (
	"net"
	"testing"
	"time"
)

func TestKnockStoreDoesNotExpireRefreshedEntry(t *testing.T) {
	store := newKnockStore()
	ip := net.ParseIP("1.2.3.4")
	t0 := time.Unix(100, 0)

	store.add(ip, "client-001", 15*time.Second, t0, 1)
	store.add(ip, "client-001", 15*time.Second, t0.Add(10*time.Second), 1)

	if revoke := store.expire(ip, "client-001", t0.Add(16*time.Second)); revoke {
		t.Fatal("old timer should not revoke a refreshed knock")
	}
	if !store.has(ip, "client-001", t0.Add(16*time.Second)) {
		t.Fatal("refreshed knock should still be valid")
	}
	if revoke := store.expire(ip, "client-001", t0.Add(26*time.Second)); !revoke {
		t.Fatal("expired knock should request firewall revoke")
	}
}

func TestKnockStoreCountsPendingKnocks(t *testing.T) {
	store := newKnockStore()
	ip := net.ParseIP("1.2.3.4")
	now := time.Unix(100, 0)

	store.add(ip, "client-001", 15*time.Second, now, 1)
	store.add(ip, "client-001", 15*time.Second, now, 1)

	if revoke := store.removeOne(ip, "client-001", now); revoke {
		t.Fatal("first consumed knock should leave another pending knock")
	}
	if revoke := store.removeOne(ip, "client-001", now); !revoke {
		t.Fatal("last consumed knock should request firewall revoke")
	}
}
