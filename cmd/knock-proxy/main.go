package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ming79486/knock-proxy/internal/app"
)

var (
	version = "1.2.2"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usageError()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "client":
		return runClient(ctx, os.Args[2:])
	case "server":
		return runServer(ctx, os.Args[2:])
	case "knock":
		return runKnock(ctx, os.Args[2:])
	case "probe":
		return runProbe(ctx, os.Args[2:])
	case "doctor":
		return runDoctor(ctx, os.Args[2:])
	case "init":
		return runInit(ctx, os.Args[2:])
	case "version", "-v", "--version":
		printVersion()
		return nil
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageError()
	}
}

func runClient(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts app.ClientOptions
	fs.StringVar(&opts.ConfigPath, "config", "", "path to client YAML config")
	fs.StringVar(&opts.Listen, "listen", "", "local listen address, for example 127.0.0.1:10022")
	fs.StringVar(&opts.ServerAddr, "server", "", "server address, for example example.com:443")
	fs.StringVar(&opts.ClientID, "client-id", "", "client id")
	fs.StringVar(&opts.Secret, "secret", "", "shared secret, preferably base64:<data>")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "path to shared secret file")
	fs.StringVar(&opts.Method, "method", "", "knock method override: tcp-syn, udp, or udp-passive")

	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunClient(ctx, opts)
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var opts app.ServerOptions
	fs.StringVar(&opts.ConfigPath, "config", "", "path to server YAML config")
	fs.StringVar(&opts.Listen, "listen", "", "server listen address, for example 0.0.0.0:443")
	fs.StringVar(&opts.Upstream, "upstream", "", "upstream address, for example 127.0.0.1:22")
	fs.StringVar(&opts.FirewallBackend, "firewall", "", "firewall backend: auto, nftables, iptables, ipset-iptables, openwrt-fw4, script")
	fs.IntVar(&opts.AllowSeconds, "allow-seconds", 0, "temporary firewall allow duration in seconds")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print server plan and exit without modifying firewall or starting listeners")

	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunServer(ctx, opts)
}

func runKnock(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("knock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts app.KnockOptions
	fs.StringVar(&opts.ServerAddr, "server", "", "server address, for example example.com:443")
	fs.StringVar(&opts.ClientID, "client-id", "", "client id")
	fs.StringVar(&opts.Secret, "secret", "", "shared secret, preferably base64:<data>")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "path to shared secret file")
	fs.StringVar(&opts.Method, "method", "", "knock method: tcp-syn, udp, or udp-passive; default is platform-aware")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunKnock(ctx, opts)
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts app.ProbeOptions
	fs.StringVar(&opts.ConfigPath, "config", "", "path to client YAML config")
	fs.StringVar(&opts.Payload, "payload", "", "optional probe payload")
	fs.BoolVar(&opts.KnockOnly, "knock-only", false, "only send knock without TCP connect/auth")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunProbe(ctx, opts)
}

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts app.DoctorOptions
	fs.StringVar(&opts.ConfigPath, "config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return app.RunDoctor(ctx, opts)
}

func runInit(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: knock-proxy init <server|client> [flags]")
	}
	fs := flag.NewFlagSet("init "+args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts app.InitOptions
	opts.Kind = args[0]
	defaultListen := "127.0.0.1:10022"
	if opts.Kind == "server" {
		defaultListen = "0.0.0.0:443"
	}
	fs.StringVar(&opts.Listen, "listen", defaultListen, "client listen or server listen address")
	fs.StringVar(&opts.ServerAddr, "server", "", "server address for client config")
	fs.StringVar(&opts.Upstream, "upstream", "127.0.0.1:22", "server upstream address")
	fs.StringVar(&opts.ClientID, "client-id", "admin", "client id")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "existing secret file for client init")
	fs.StringVar(&opts.OutDir, "out", ".", "output directory")
	fs.StringVar(&opts.Platform, "platform", runtime.GOOS, "target platform for generated client notes/defaults: linux, windows, or darwin")
	fs.StringVar(&opts.Method, "method", "", "knock method for generated config: tcp-syn, udp, or udp-passive")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return app.RunInit(ctx, opts)
}

func printVersion() {
	fmt.Fprintf(os.Stdout, "knock-proxy %s (%s, %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
}

func usageError() error {
	printUsage()
	return errors.New("usage: knock-proxy <client|server|knock|probe|doctor|init|version> [flags]")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  knock-proxy client --config /etc/knock-proxy/client.yaml
  knock-proxy server --config /etc/knock-proxy/server.yaml

Quick client:
  knock-proxy client --listen 127.0.0.1:10022 --server example.com:443 --client-id client-001 --secret-file ./secret.key

Quick server:
  knock-proxy server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --firewall auto --allow-seconds 15 --config /etc/knock-proxy/server.yaml

Other:
  knock-proxy knock --server example.com:443 --client-id admin --secret-file ./secret.key
  knock-proxy probe --config ./client.yaml
  knock-proxy doctor --config ./server.yaml
  knock-proxy init server --listen 0.0.0.0:443 --upstream 127.0.0.1:22 --client-id admin
  knock-proxy init client --platform windows --server example.com:443 --secret-file ./secret.key
  knock-proxy version`)
}
