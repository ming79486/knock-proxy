package app

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/logging"
)

type checkerFirewall struct{ allowed bool }

func (f checkerFirewall) Name() string                                            { return "checker" }
func (f checkerFirewall) Init(context.Context) error                              { return nil }
func (f checkerFirewall) Allow(context.Context, net.IP, int, time.Duration) error { return nil }
func (f checkerFirewall) Revoke(context.Context, net.IP, int) error               { return nil }
func (f checkerFirewall) Cleanup(context.Context) error                           { return nil }
func (f checkerFirewall) IsAllowed(context.Context, net.IP, int) (bool, error)    { return f.allowed, nil }

func TestHasRecentAccessAcceptsExistingFirewallAllow(t *testing.T) {
	log, err := logging.New("", "text")
	if err != nil {
		t.Fatal(err)
	}
	state := &serverState{rt: config.ServerRuntime{Port: 443}, fw: checkerFirewall{allowed: true}, log: log, knocks: newKnockStore()}
	ok, err := state.hasRecentAccess(context.Background(), net.ParseIP("1.2.3.4"), "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("existing firewall allow entry should satisfy recent access")
	}
}

func TestHasRecentAccessRejectsWithoutKnockOrFirewallAllow(t *testing.T) {
	log, err := logging.New("", "text")
	if err != nil {
		t.Fatal(err)
	}
	state := &serverState{rt: config.ServerRuntime{Port: 443}, fw: checkerFirewall{allowed: false}, log: log, knocks: newKnockStore()}
	ok, err := state.hasRecentAccess(context.Background(), net.ParseIP("1.2.3.4"), "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("missing knock and firewall allow should be rejected")
	}
}
