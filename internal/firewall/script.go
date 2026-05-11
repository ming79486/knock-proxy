package firewall

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
)

type Script struct {
	cfg config.FirewallConfig
}

func NewScript(cfg config.FirewallConfig) *Script {
	return &Script{cfg: cfg}
}

func (s *Script) Name() string { return "script" }

func (s *Script) Init(ctx context.Context) error {
	return nil
}

func (s *Script) Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error {
	return run(ctx, s.cfg.Script.AllowCmd, ip.String(), strconv.Itoa(port), strconv.Itoa(int(ttl.Seconds())))
}

func (s *Script) Revoke(ctx context.Context, ip net.IP, port int) error {
	return run(ctx, s.cfg.Script.RevokeCmd, ip.String(), strconv.Itoa(port))
}

func (s *Script) Cleanup(ctx context.Context) error {
	return run(ctx, s.cfg.Script.CleanupCmd, strconv.Itoa(s.cfg.Port))
}
