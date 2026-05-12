package firewall

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
)

type Iptables struct {
	cfg   config.FirewallConfig
	chain string
}

func NewIptables(cfg config.FirewallConfig) *Iptables {
	chain := cfg.Iptables.Chain
	if chain == "" {
		chain = "KNOCK_PROXY"
	}
	return &Iptables{cfg: cfg, chain: chain}
}

func (i *Iptables) Name() string { return "iptables" }

func (i *Iptables) Init(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	i.cleanupCommand(ctx, "iptables", port, udpPort)
	if err := i.initCommand(ctx, "iptables", port, udpPort); err != nil {
		return err
	}
	if commandExists("ip6tables") {
		i.cleanupCommand(ctx, "ip6tables", port, udpPort)
		return i.initCommand(ctx, "ip6tables", port, udpPort)
	}
	return nil
}

func (i *Iptables) Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error {
	cmd := "iptables"
	if ip.To4() == nil {
		if !commandExists("ip6tables") {
			return errIPv6Unsupported("iptables")
		}
		cmd = "ip6tables"
	}
	args := []string{"-s", ip.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if err := run(ctx, cmd, append([]string{"-C", i.chain}, args...)...); err == nil {
		return nil
	}
	return run(ctx, cmd, append([]string{"-I", i.chain, "1"}, args...)...)
}

func (i *Iptables) IsAllowed(ctx context.Context, ip net.IP, port int) (bool, error) {
	cmd := "iptables"
	if ip.To4() == nil {
		if !commandExists("ip6tables") {
			return false, nil
		}
		cmd = "ip6tables"
	}
	args := []string{"-s", ip.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
	if err := run(ctx, cmd, append([]string{"-C", i.chain}, args...)...); err != nil {
		return false, nil
	}
	return true, nil
}

func (i *Iptables) Revoke(ctx context.Context, ip net.IP, port int) error {
	cmd := "iptables"
	if ip.To4() == nil {
		if !commandExists("ip6tables") {
			return nil
		}
		cmd = "ip6tables"
	}
	return run(ctx, cmd, "-D", i.chain, "-s", ip.String(), "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (i *Iptables) Cleanup(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	i.cleanupCommand(ctx, "iptables", port, udpPort)
	if commandExists("ip6tables") {
		i.cleanupCommand(ctx, "ip6tables", port, udpPort)
	}
	return nil
}

func (i *Iptables) initCommand(ctx context.Context, cmd, port, udpPort string) error {
	_ = run(ctx, cmd, "-N", i.chain)
	_ = run(ctx, cmd, "-F", i.chain)
	if err := run(ctx, cmd, "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
		if err := run(ctx, cmd, "-I", "INPUT", "1", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
			return err
		}
	}
	if i.cfg.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", udpPort, "-m", "comment", "--comment", "knock-proxy udp-passive", "-j", "DROP"}
		if err := run(ctx, cmd, append([]string{"-C", "INPUT"}, udpArgs...)...); err != nil {
			if err := run(ctx, cmd, append([]string{"-I", "INPUT", "1"}, udpArgs...)...); err != nil {
				return err
			}
		}
	}
	if err := run(ctx, cmd, "-A", i.chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	return run(ctx, cmd, "-A", i.chain, "-p", "tcp", "--dport", port, "-j", "DROP")
}

func (i *Iptables) cleanupCommand(ctx context.Context, cmd, port, udpPort string) {
	if i.cfg.DropUDPKnockPort {
		udpArgs := []string{"-p", "udp", "--dport", udpPort, "-m", "comment", "--comment", "knock-proxy udp-passive", "-j", "DROP"}
		for {
			if err := run(ctx, cmd, append([]string{"-D", "INPUT"}, udpArgs...)...); err != nil {
				break
			}
		}
	}
	for {
		if err := run(ctx, cmd, "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", i.chain); err != nil {
			break
		}
	}
	_ = run(ctx, cmd, "-F", i.chain)
	_ = run(ctx, cmd, "-X", i.chain)
}
