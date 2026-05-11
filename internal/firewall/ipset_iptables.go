package firewall

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
)

type IPSetIptables struct {
	cfg   config.FirewallConfig
	set   string
	setV6 string
	chain string
}

func NewIPSetIptables(cfg config.FirewallConfig) *IPSetIptables {
	set := cfg.IPSet.Set
	if set == "" {
		set = "knock_proxy_allowed"
	}
	setV6 := cfg.IPSet.SetV6
	if setV6 == "" {
		setV6 = "knock_proxy_allowed_v6"
	}
	chain := cfg.Iptables.Chain
	if chain == "" {
		chain = "KNOCK_PROXY"
	}
	return &IPSetIptables{cfg: cfg, set: set, setV6: setV6, chain: chain}
}

func (i *IPSetIptables) Name() string { return "ipset-iptables" }

func (i *IPSetIptables) Init(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	if err := run(ctx, "ipset", "create", i.set, "hash:ip", "timeout", strconv.Itoa(i.cfg.AllowSeconds), "-exist"); err != nil {
		return err
	}
	_ = run(ctx, "ipset", "flush", i.set)
	if err := i.initCommand(ctx, "iptables", i.set, port, udpPort); err != nil {
		return err
	}
	if commandExists("ip6tables") {
		if err := run(ctx, "ipset", "create", i.setV6, "hash:ip", "family", "inet6", "timeout", strconv.Itoa(i.cfg.AllowSeconds), "-exist"); err != nil {
			return err
		}
		_ = run(ctx, "ipset", "flush", i.setV6)
		return i.initCommand(ctx, "ip6tables", i.setV6, port, udpPort)
	}
	return nil
}

func (i *IPSetIptables) Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error {
	set := i.set
	if ip.To4() == nil {
		if !commandExists("ip6tables") {
			return errIPv6Unsupported("ipset-iptables")
		}
		set = i.setV6
	}
	return run(ctx, "ipset", "add", set, ip.String(), "timeout", strconv.Itoa(int(ttl.Seconds())), "-exist")
}

func (i *IPSetIptables) Revoke(ctx context.Context, ip net.IP, port int) error {
	set := i.set
	if ip.To4() == nil {
		if !commandExists("ip6tables") {
			return nil
		}
		set = i.setV6
	}
	return run(ctx, "ipset", "del", set, ip.String())
}

func (i *IPSetIptables) Cleanup(ctx context.Context) error {
	port := strconv.Itoa(i.cfg.Port)
	udpPort := strconv.Itoa(udpKnockPort(i.cfg))
	i.cleanupCommand(ctx, "iptables", port, udpPort)
	if commandExists("ip6tables") {
		i.cleanupCommand(ctx, "ip6tables", port, udpPort)
		_ = run(ctx, "ipset", "flush", i.setV6)
		_ = run(ctx, "ipset", "destroy", i.setV6)
	}
	_ = run(ctx, "ipset", "flush", i.set)
	return run(ctx, "ipset", "destroy", i.set)
}

func (i *IPSetIptables) initCommand(ctx context.Context, cmd, set, port, udpPort string) error {
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
	if err := run(ctx, cmd, "-A", i.chain, "-m", "set", "--match-set", set, "src", "-j", "ACCEPT"); err != nil {
		return err
	}
	return run(ctx, cmd, "-A", i.chain, "-p", "tcp", "--dport", port, "-j", "DROP")
}

func (i *IPSetIptables) cleanupCommand(ctx context.Context, cmd, port, udpPort string) {
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
