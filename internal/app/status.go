package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/firewall"
)

type allowedClientStatus struct {
	Address string
	Expires string
}

func RunStatus(ctx context.Context, opts StatusOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	if cfg.Mode == "" {
		cfg.Mode = config.ModeServer
	}
	rt, err := cfg.ServerRuntime()
	if err != nil {
		return err
	}

	backend := rt.Firewall.Backend
	if backend == "" || backend == "auto" {
		if detected, err := firewall.Detect(rt.Firewall); err == nil {
			backend = detected
		} else {
			backend = "auto (detect failed: " + err.Error() + ")"
		}
	}

	fmt.Println("knock-proxy status")
	fmt.Printf("firewall backend: %s\n", backend)
	if isNFTBackend(backend) {
		fmt.Printf("table: %s %s\n", nftFamily(rt.Firewall), nftTable(rt.Firewall))
	}
	fmt.Printf("tcp port: %d\n", rt.Port)
	fmt.Printf("knock method: %s\n", rt.KnockMethod)
	fmt.Printf("access mode: %s\n", rt.AccessMode)

	fmt.Println("allowed clients:")
	var clients []allowedClientStatus
	var inspectErr error
	switch backend {
	case "nftables", "openwrt-fw4":
		clients, inspectErr = inspectNFTAllowedClients(ctx, rt.Firewall)
	case "ipset-iptables":
		clients, inspectErr = inspectIPSetAllowedClients(ctx, rt.Firewall)
	case "iptables":
		clients, inspectErr = inspectIptablesAllowedClients(ctx, rt.Firewall)
	default:
		fmt.Printf("  inspection is not implemented for backend=%s\n", backend)
		printStatusMetrics(rt)
		return nil
	}
	if inspectErr != nil {
		fmt.Printf("  unavailable: %v\n", inspectErr)
		printStatusMetrics(rt)
		return nil
	}
	if len(clients) == 0 {
		fmt.Println("  (none)")
		printStatusMetrics(rt)
		return nil
	}
	for _, client := range clients {
		if client.Expires != "" {
			fmt.Printf("  %s expires in %s\n", client.Address, client.Expires)
		} else {
			fmt.Printf("  %s\n", client.Address)
		}
	}
	printStatusMetrics(rt)
	return nil
}

func printStatusMetrics(rt config.ServerRuntime) {
	if rt.MetricsEnabled {
		fmt.Printf("metrics: %s%s\n", rt.MetricsListen, rt.MetricsPath)
	} else {
		fmt.Println("metrics: disabled")
	}
}

func inspectNFTAllowedClients(ctx context.Context, cfg config.FirewallConfig) ([]allowedClientStatus, error) {
	var out []allowedClientStatus
	var errs []string
	for _, set := range []string{nftSetV4(cfg), nftSetV6(cfg)} {
		clients, err := listNFTSet(ctx, nftFamily(cfg), nftTable(cfg), set)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, clients...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func listNFTSet(ctx context.Context, family, table, set string) ([]allowedClientStatus, error) {
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "set", family, table, set)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list set %s %s %s failed: %w: %s", family, table, set, err, strings.TrimSpace(string(output)))
	}
	clients, err := parseNFTAllowedClients(output)
	if err != nil {
		return nil, err
	}
	return clients, nil
}

func parseNFTAllowedClients(data []byte) ([]allowedClientStatus, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []allowedClientStatus
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			if val, ok := x["val"]; ok {
				addr := nftValueString(val)
				if isIPLiteral(addr) && !seen[addr] {
					seen[addr] = true
					out = append(out, allowedClientStatus{Address: addr, Expires: nftExpiresString(x["expires"])})
				}
			}
			if elem, ok := x["elem"]; ok {
				addr := nftValueString(elem)
				if isIPLiteral(addr) && !seen[addr] {
					seen[addr] = true
					out = append(out, allowedClientStatus{Address: addr, Expires: nftExpiresString(x["expires"])})
				}
				walk(elem)
			}
			for key, child := range x {
				if key == "elem" {
					continue
				}
				walk(child)
			}
		}
	}
	walk(root)
	return out, nil
}

func nftValueString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func nftExpiresString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x <= 0 {
			return ""
		}
		return (time.Duration(x) * time.Second).String()
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func isIPLiteral(s string) bool {
	return net.ParseIP(s) != nil
}

func isNFTBackend(name string) bool {
	return strings.HasPrefix(name, "nftables") || strings.HasPrefix(name, "openwrt-fw4")
}

func nftFamily(cfg config.FirewallConfig) string {
	if cfg.Nftables.Family != "" {
		return cfg.Nftables.Family
	}
	return "inet"
}

func nftTable(cfg config.FirewallConfig) string {
	if cfg.Nftables.Table != "" {
		return cfg.Nftables.Table
	}
	return "knock_proxy"
}

func nftSetV4(cfg config.FirewallConfig) string {
	if cfg.Nftables.SetV4 != "" {
		return cfg.Nftables.SetV4
	}
	return "allowed_clients_v4"
}

func nftSetV6(cfg config.FirewallConfig) string {
	if cfg.Nftables.SetV6 != "" {
		return cfg.Nftables.SetV6
	}
	return "allowed_clients_v6"
}

func inspectIPSetAllowedClients(ctx context.Context, cfg config.FirewallConfig) ([]allowedClientStatus, error) {
	sets := []string{ipsetName(cfg), ipsetNameV6(cfg)}
	var out []allowedClientStatus
	var errs []string
	for _, set := range sets {
		clients, err := listIPSet(ctx, set)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, clients...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func listIPSet(ctx context.Context, set string) ([]allowedClientStatus, error) {
	cmd := exec.CommandContext(ctx, "ipset", "list", set)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipset list %s failed: %w: %s", set, err, strings.TrimSpace(string(output)))
	}
	var out []allowedClientStatus
	inMembers := false
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "Members:" {
			inMembers = true
			continue
		}
		if !inMembers || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && isIPLiteral(fields[0]) {
			status := allowedClientStatus{Address: fields[0]}
			for i := 1; i+1 < len(fields); i++ {
				if fields[i] == "timeout" {
					status.Expires = fields[i+1] + "s"
				}
			}
			out = append(out, status)
		}
	}
	return out, nil
}

func inspectIptablesAllowedClients(ctx context.Context, cfg config.FirewallConfig) ([]allowedClientStatus, error) {
	var out []allowedClientStatus
	var errs []string
	for _, cmdName := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(cmdName); err != nil {
			continue
		}
		clients, err := listIptablesChain(ctx, cmdName, iptablesChain(cfg))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, clients...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func listIptablesChain(ctx context.Context, cmdName, chain string) ([]allowedClientStatus, error) {
	cmd := exec.CommandContext(ctx, cmdName, "-S", chain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s -S %s failed: %w: %s", cmdName, chain, err, strings.TrimSpace(string(output)))
	}
	seen := map[string]bool{}
	var out []allowedClientStatus
	fields := strings.Fields(string(output))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-s" {
			addr := strings.TrimSuffix(fields[i+1], "/32")
			addr = strings.TrimSuffix(addr, "/128")
			if isIPLiteral(addr) && !seen[addr] {
				seen[addr] = true
				out = append(out, allowedClientStatus{Address: addr})
			}
		}
	}
	return out, nil
}

func ipsetName(cfg config.FirewallConfig) string {
	if cfg.IPSet.Set != "" {
		return cfg.IPSet.Set
	}
	return "knock_proxy_allowed"
}
func ipsetNameV6(cfg config.FirewallConfig) string {
	if cfg.IPSet.SetV6 != "" {
		return cfg.IPSet.SetV6
	}
	return "knock_proxy_allowed_v6"
}
func iptablesChain(cfg config.FirewallConfig) string {
	if cfg.Iptables.Chain != "" {
		return cfg.Iptables.Chain
	}
	return "KNOCK_PROXY"
}
