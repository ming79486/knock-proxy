package firewall

import (
	"context"
	"net"
	"net/netip"
	"time"

	cfg "github.com/ming79486/knock-proxy/internal/config"
	libfw "github.com/ming79486/libknock/firewall"
)

type Backend interface {
	Name() string
	Init(context.Context) error
	Allow(context.Context, net.IP, int, time.Duration) error
	Revoke(context.Context, net.IP, int) error
	Cleanup(context.Context) error
}

type Checker interface {
	IsAllowed(context.Context, net.IP, int) (bool, error)
}
type Capabilities = libfw.Capabilities

type adapter struct{ backend libfw.Backend }

func (a adapter) Name() string                      { return a.backend.Name() }
func (a adapter) Init(ctx context.Context) error    { return a.backend.Init(ctx) }
func (a adapter) Cleanup(ctx context.Context) error { return a.backend.Cleanup(ctx) }
func (a adapter) Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	return a.backend.Allow(ctx, addr, port, ttl)
}
func (a adapter) Revoke(ctx context.Context, ip net.IP, port int) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	return a.backend.Revoke(ctx, addr, port)
}
func (a adapter) IsAllowed(ctx context.Context, ip net.IP, port int) (bool, error) {
	checker, ok := a.backend.(libfw.Checker)
	if !ok {
		return false, nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false, nil
	}
	return checker.IsAllowed(ctx, addr, port)
}

func New(c cfg.FirewallConfig) (Backend, error) {
	b, err := libfw.New(convert(c))
	if err != nil {
		return nil, err
	}
	return adapter{backend: b}, nil
}

func Validate(c cfg.FirewallConfig) (Capabilities, error) { return libfw.Validate(convert(c)) }
func Describe(name string) Capabilities                   { return libfw.Describe(name) }
func Detect(c cfg.FirewallConfig) (string, error)         { return libfw.Detect(convert(c)) }

func convert(c cfg.FirewallConfig) libfw.Config {
	return libfw.Config{
		Backend: c.Backend, Port: c.Port, DefaultAction: c.DefaultAction, AllowSeconds: c.AllowSeconds, DropUDPKnockPort: c.DropUDPKnockPort, UDPKnockPort: c.UDPKnockPort,
		Nftables: libfw.NftablesConfig{Table: c.Nftables.Table, Chain: c.Nftables.Chain, SetV4: c.Nftables.SetV4, SetV6: c.Nftables.SetV6, Family: c.Nftables.Family},
		Iptables: libfw.IptablesConfig{Chain: c.Iptables.Chain},
		IPSet:    libfw.IPSetConfig{Set: c.IPSet.Set, SetV6: c.IPSet.SetV6},
		Script:   libfw.ScriptConfig{AllowCmd: c.Script.AllowCmd, RevokeCmd: c.Script.RevokeCmd, CleanupCmd: c.Script.CleanupCmd},
	}
}
