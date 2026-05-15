package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/logging"
	"github.com/ming79486/knock-proxy/internal/relay"
	"github.com/ming79486/knock-proxy/internal/secure"
	"github.com/ming79486/libknock"
	"github.com/ming79486/libknock/knock"
)

func RunClient(ctx context.Context, opts ClientOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	applyClientOverrides(&cfg, opts)

	rt, err := cfg.ClientRuntime()
	if err != nil {
		return err
	}
	if err := knock.CheckClientSupport(rt.KnockMethod); err != nil {
		return err
	}

	log, err := logging.NewWithLevel(rt.LogFile, rt.LogLevel, rt.LogFormat)
	if err != nil {
		return err
	}
	defer log.Close()

	listener, err := net.Listen("tcp", rt.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Event("client listening", logging.F("listen", rt.Listen), logging.F("server", rt.ServerAddr), logging.F("client_id", rt.ClientID))
	if !config.IsLoopbackListen(rt.Listen) {
		log.Event("client listen warning", logging.F("listen", rt.Listen), logging.F("reason", "non_loopback_listen"))
	}

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			log.Event("client accept failed", logging.F("error", err))
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleClientConn(ctx, rt, log, conn)
		}()
	}
}

func applyClientOverrides(cfg *config.Config, opts ClientOptions) {
	if cfg.Mode == "" {
		cfg.Mode = config.ModeClient
	}
	if opts.Listen != "" {
		cfg.Client.Listen = opts.Listen
	}
	if opts.ServerAddr != "" {
		cfg.Client.ServerAddr = opts.ServerAddr
	}
	if opts.ClientID != "" {
		cfg.Client.ClientID = opts.ClientID
	}
	if opts.Secret != "" {
		cfg.Client.Secret = opts.Secret
	}
	if opts.SecretFile != "" {
		cfg.Client.SecretFile = opts.SecretFile
	}
	if opts.Method != "" {
		cfg.Knock.Method = opts.Method
	}
}

func handleClientConn(parent context.Context, rt config.ClientRuntime, log *logging.Logger, local net.Conn) {
	defer local.Close()
	start := time.Now()

	if err := sendKnock(parent, rt); err != nil {
		log.Event("knock send failed", logging.F("client_id", rt.ClientID), logging.F("error", err))
		return
	}

	remote, err := dialServer(parent, rt)
	if err != nil {
		log.Event("server connect failed", logging.F("server", rt.ServerAddr), logging.F("error", err))
		return
	}
	defer remote.Close()

	peer, err := libknock.ClientAuthWithInfo(parent, remote, libknock.ClientConfig{ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, AuthTimeout: rt.AuthTimeout})
	if err != nil {
		log.Event("auth write failed", logging.F("server", rt.ServerAddr), logging.F("error", err))
		return
	}

	if rt.TransportEncrypted {
		remote, err = secure.Wrap(remote, rt.Secret, rt.ClientID, base64.RawStdEncoding.EncodeToString(peer.Nonce), rt.ServerPort, secure.ClientRole)
		if err != nil {
			log.Event("transport encryption failed", logging.F("client_id", rt.ClientID), logging.F("error", err))
			return
		}
	}

	stats := relay.Bidirectional(local, remote, rt.IdleTimeout)
	log.Event("client session closed",
		logging.F("server", rt.ServerAddr),
		logging.F("client_id", rt.ClientID),
		logging.F("duration", int(time.Since(start).Seconds())),
		logging.F("rx", stats.RX),
		logging.F("tx", stats.TX),
	)
}

func sendKnock(parent context.Context, rt config.ClientRuntime) error {
	attempts := rt.KnockRetry + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(parent, rt.KnockTimeout)
		serverAddr := rt.ServerAddr
		if rt.KnockMethod == "udp" || rt.KnockMethod == "udp-passive" || rt.KnockMethod == "udp-seq" || rt.KnockMethod == "udp-passive-seq" {
			serverAddr = rt.UDPServerAddr
		}
		sendOpts := knock.SendOptions{
			ServerAddr: serverAddr,
			ClientID:   rt.ClientID,
			Secret:     rt.Secret,
			ServerPort: rt.ServerPort,
			TimeWindow: rt.KnockTimeWindow,
		}
		var err error
		switch rt.KnockMethod {
		case "udp":
			err = knock.SendUDPMethod(ctx, sendOpts, "udp")
		case "udp-passive":
			err = knock.SendUDPMethod(ctx, sendOpts, "udp-passive")
		case "udp-seq", "udp-passive-seq":
			err = knock.SendUDPSequence(ctx, sendOpts)
		case "tcp-syn-seq":
			if supportErr := knock.CheckClientSupport(rt.KnockMethod); supportErr != nil {
				err = supportErr
				break
			}
			err = knock.SendSYNSequence(ctx, sendOpts)
		default:
			if supportErr := knock.CheckClientSupport(rt.KnockMethod); supportErr != nil {
				err = supportErr
				break
			}
			err = knock.Send(ctx, sendOpts)
		}
		cancel()
		if err == nil {
			time.Sleep(250 * time.Millisecond)
			return nil
		}
		lastErr = err
		if i+1 < attempts {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return fmt.Errorf("%s knock failed after %d attempts: %w", rt.KnockMethod, attempts, lastErr)
}

func dialServer(parent context.Context, rt config.ClientRuntime) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, rt.ConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "tcp", rt.ServerAddr)
}
