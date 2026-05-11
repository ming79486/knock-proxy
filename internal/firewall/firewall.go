package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
)

type Backend interface {
	Name() string
	Init(ctx context.Context) error
	Allow(ctx context.Context, ip net.IP, port int, ttl time.Duration) error
	Revoke(ctx context.Context, ip net.IP, port int) error
	Cleanup(ctx context.Context) error
}

type Checker interface {
	IsAllowed(ctx context.Context, ip net.IP, port int) (bool, error)
}

func New(cfg config.FirewallConfig) (Backend, error) {
	name := cfg.Backend
	if name == "" {
		name = "auto"
	}
	if name == "auto" {
		detected, err := Detect(cfg)
		if err != nil {
			return nil, err
		}
		name = detected
	}

	switch name {
	case "openwrt-fw4", "nftables":
		if !commandExists("nft") {
			return nil, errors.New(`firewall backend nftables selected, but command "nft" was not found.

Install nftables first:

Debian/Ubuntu:
  apt install nftables

RHEL/Rocky/Alma:
  dnf install nftables

OpenWrt 23.x+:
  opkg update
  opkg install nftables`)
		}
		return NewNftables(cfg, name), nil
	case "ipset-iptables":
		if !commandExists("ipset") {
			return nil, errors.New(`firewall backend ipset-iptables selected, but command "ipset" was not found.

Debian/Ubuntu:
  apt install ipset

RHEL/Rocky/Alma:
  dnf install ipset`)
		}
		if !commandExists("iptables") {
			return nil, iptablesMissingError()
		}
		return NewIPSetIptables(cfg), nil
	case "iptables":
		if !commandExists("iptables") {
			return nil, iptablesMissingError()
		}
		return NewIptables(cfg), nil
	case "script":
		if cfg.Script.AllowCmd == "" || cfg.Script.RevokeCmd == "" || cfg.Script.CleanupCmd == "" {
			return nil, errors.New("firewall backend script requires allow_cmd, revoke_cmd, and cleanup_cmd")
		}
		if cfg.DropUDPKnockPort {
			return nil, errors.New("firewall backend script cannot manage drop_udp_knock_port; use nftables, iptables, ipset-iptables, or disable udp-passive")
		}
		return NewScript(cfg), nil
	default:
		return nil, fmt.Errorf("unknown firewall backend %q", name)
	}
}

func Detect(cfg config.FirewallConfig) (string, error) {
	if runtime.GOOS != "linux" {
		if cfg.Script.AllowCmd != "" {
			return "script", nil
		}
		return "", fmt.Errorf("firewall backend auto is only supported on linux unless script backend is configured; current OS is %s", runtime.GOOS)
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil && commandExists("nft") {
		return "openwrt-fw4", nil
	}
	if commandExists("nft") {
		return "nftables", nil
	}
	if commandExists("ipset") && commandExists("iptables") {
		return "ipset-iptables", nil
	}
	if commandExists("iptables") {
		return "iptables", nil
	}
	if cfg.Script.AllowCmd != "" {
		return "script", nil
	}
	return "", errors.New(`no usable firewall backend was detected.

Install nftables or iptables/ipset, or configure firewall.backend: script.`)
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runInput(ctx context.Context, input, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s\ninput:\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)), input)
	}
	return nil
}

func iptablesMissingError() error {
	return errors.New(`firewall backend iptables selected, but command "iptables" was not found.

Debian/Ubuntu:
  apt install iptables

RHEL/Rocky/Alma:
  dnf install iptables

OpenWrt:
  not recommended. Use OpenWrt 23.x+ nftables backend.`)
}

func errIPv6Unsupported(backend string) error {
	return fmt.Errorf("firewall backend %s received an IPv6 client address, but command \"ip6tables\" was not found", backend)
}

func udpKnockPort(cfg config.FirewallConfig) int {
	if cfg.UDPKnockPort > 0 {
		return cfg.UDPKnockPort
	}
	return cfg.Port
}
