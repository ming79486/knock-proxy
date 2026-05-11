package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
)

type Nftables struct {
	name   string
	cfg    config.FirewallConfig
	family string
	table  string
	chain  string
	setV4  string
	setV6  string
}

func NewNftables(cfg config.FirewallConfig, name string) *Nftables {
	family := cfg.Nftables.Family
	if family == "" {
		family = "inet"
	}
	table := cfg.Nftables.Table
	if table == "" {
		table = "knock_proxy"
	}
	chain := cfg.Nftables.Chain
	if chain == "" {
		chain = "input"
	}
	setV4 := cfg.Nftables.SetV4
	if setV4 == "" {
		setV4 = "allowed_clients_v4"
	}
	setV6 := cfg.Nftables.SetV6
	if setV6 == "" {
		setV6 = "allowed_clients_v6"
	}
	return &Nftables{name: name, cfg: cfg, family: family, table: table, chain: chain, setV4: setV4, setV6: setV6}
}

func (n *Nftables) Name() string {
	if n.name == "" {
		return "nftables"
	}
	return n.name
}

func (n *Nftables) Init(ctx context.Context) error {
	udpDropRule := ""
	if n.cfg.DropUDPKnockPort {
		udpDropRule = fmt.Sprintf("    udp dport %d drop\n", udpKnockPort(n.cfg))
	}
	script := fmt.Sprintf(`delete table %s %s
table %s %s {
  set %s {
    type ipv4_addr
    timeout %ds
  }

  set %s {
    type ipv6_addr
    timeout %ds
  }

  chain %s {
    type filter hook input priority -10; policy accept;
    ct state established,related accept
    ip saddr @%s tcp dport %d accept
    ip6 saddr @%s tcp dport %d accept
    tcp dport %d drop
%s
  }
}
`, n.family, n.table, n.family, n.table, n.setV4, int(n.cfg.AllowSeconds), n.setV6, int(n.cfg.AllowSeconds), n.chain, n.setV4, n.cfg.Port, n.setV6, n.cfg.Port, n.cfg.Port, udpDropRule)

	if err := runInput(ctx, fmt.Sprintf("delete table %s %s\n", n.family, n.table), "nft", "-f", "-"); err != nil {
		// Ignore missing table on first start.
	}
	return runInput(ctx, strings.TrimPrefix(script, fmt.Sprintf("delete table %s %s\n", n.family, n.table)), "nft", "-f", "-")
}

func (n *Nftables) Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error {
	v4 := ip.To4()
	if v4 == nil {
		if ip.To16() == nil {
			return fmt.Errorf("invalid IP address %s", ip.String())
		}
		deleteInput := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV6, ip.String())
		_ = runInput(ctx, deleteInput, "nft", "-f", "-")
		input := fmt.Sprintf("add element %s %s %s { %s timeout %ds }\n", n.family, n.table, n.setV6, ip.String(), int(ttl.Seconds()))
		return runInput(ctx, input, "nft", "-f", "-")
	}
	deleteInput := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV4, v4.String())
	_ = runInput(ctx, deleteInput, "nft", "-f", "-")
	input := fmt.Sprintf("add element %s %s %s { %s timeout %ds }\n", n.family, n.table, n.setV4, v4.String(), int(ttl.Seconds()))
	return runInput(ctx, input, "nft", "-f", "-")
}

func (n *Nftables) IsAllowed(ctx context.Context, ip net.IP, port int) (bool, error) {
	v4 := ip.To4()
	set := n.setV4
	addr := ip.String()
	if v4 == nil {
		if ip.To16() == nil {
			return false, fmt.Errorf("invalid IP address %s", ip.String())
		}
		set = n.setV6
	} else {
		addr = v4.String()
	}
	if err := run(ctx, "nft", "get", "element", n.family, n.table, set, "{", addr, "}"); err != nil {
		return false, nil
	}
	return true, nil
}

func (n *Nftables) Revoke(ctx context.Context, ip net.IP, port int) error {
	v4 := ip.To4()
	if v4 == nil {
		if ip.To16() == nil {
			return nil
		}
		input := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV6, ip.String())
		return runInput(ctx, input, "nft", "-f", "-")
	}
	input := fmt.Sprintf("delete element %s %s %s { %s }\n", n.family, n.table, n.setV4, v4.String())
	return runInput(ctx, input, "nft", "-f", "-")
}

func (n *Nftables) Cleanup(ctx context.Context) error {
	return runInput(ctx, fmt.Sprintf("delete table %s %s\n", n.family, n.table), "nft", "-f", "-")
}
