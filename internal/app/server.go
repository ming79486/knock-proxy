package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libknock/libknock"
	"github.com/libknock/libknock/knock"
	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/knock-proxy/internal/firewall"
	"github.com/ming79486/knock-proxy/internal/limits"
	"github.com/ming79486/knock-proxy/internal/logging"
	"github.com/ming79486/knock-proxy/internal/metrics"
	"github.com/ming79486/knock-proxy/internal/relay"
	"github.com/ming79486/knock-proxy/internal/secure"
)

func RunServer(ctx context.Context, opts ServerOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	applyServerOverrides(&cfg, opts)

	rt, err := cfg.ServerRuntime()
	if err != nil {
		return err
	}
	if opts.DryRun {
		return printServerDryRun(ctx, rt)
	}
	if rt.KnockMethod == "tcp-syn" || rt.KnockMethod == "tcp-syn-seq" || rt.KnockMethod == "udp-passive" || rt.KnockMethod == "udp-passive-seq" {
		if err := knock.CheckServerPrivileges(); err != nil {
			return err
		}
	}

	log, err := logging.NewWithLevel(rt.LogFile, rt.LogLevel, rt.LogFormat)
	if err != nil {
		return err
	}
	defer log.Close()

	fw, err := firewall.New(rt.Firewall)
	if err != nil {
		return err
	}
	if err := fw.Init(ctx); err != nil {
		return fmt.Errorf("initialize firewall backend %s: %w", fw.Name(), err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fw.Cleanup(cleanupCtx); err != nil {
			log.Event("firewall cleanup failed", logging.F("backend", fw.Name()), logging.F("error", err))
		}
	}()
	log.Event("firewall initialized", logging.F("backend", fw.Name()), logging.F("port", rt.Port), logging.F("allow_seconds", int(rt.AllowTTL.Seconds())))
	if err := checkUpstream(ctx, rt); err != nil {
		log.Event("upstream check warning", logging.F("upstream", rt.Upstream), logging.F("error", err))
	}

	state, err := newServerState(rt, fw, log)
	if err != nil {
		return err
	}
	metricsServer := startMetricsServer(ctx, rt, state.metrics, log)
	if metricsServer != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
	}

	listener, err := net.Listen("tcp", rt.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Event("server listening", logging.F("listen", rt.Listen), logging.F("upstream", rt.Upstream))

	knockErr := make(chan error, 1)
	go func() {
		listenOpts := knock.ListenOptions{
			Port:          rt.Port,
			KnockPort:     rt.UDPPort,
			Clients:       state.knockClients,
			TimeWindow:    rt.KnockTimeWindow,
			AllowPacket:   state.allowKnockPacket,
			InvalidPacket: state.invalidKnockPacket,
		}
		switch rt.KnockMethod {
		case "tcp-syn":
			knockErr <- knock.Listen(ctx, listenOpts, state.handleKnock)
		case "udp":
			knockErr <- knock.ListenUDP(ctx, rt.UDPListen, listenOpts, state.handleKnock)
		case "udp-seq":
			knockErr <- knock.ListenUDPSequence(ctx, rt.UDPListen, listenOpts, state.handleKnock)
		case "udp-passive":
			knockErr <- knock.ListenUDPPassive(ctx, listenOpts, state.handleKnock)
		case "udp-passive-seq":
			knockErr <- knock.ListenUDPPassiveSequence(ctx, listenOpts, state.handleKnock)
		case "tcp-syn-seq":
			knockErr <- knock.ListenSYNSequence(ctx, listenOpts, state.handleKnock)
		default:
			knockErr <- fmt.Errorf("knock method %q is not implemented", rt.KnockMethod)
		}
		_ = listener.Close()
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	pending := make(chan net.Conn, rt.MaxPendingAuth)
	var wg sync.WaitGroup
	for range rt.MaxAuthWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for conn := range pending {
				state.handleConn(ctx, conn)
			}
		}()
	}
	defer func() {
		close(pending)
		wg.Wait()
	}()
	for {
		select {
		case err := <-knockErr:
			if err != nil && ctx.Err() == nil {
				return fmt.Errorf("knock listener failed: %w", err)
			}
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case err := <-knockErr:
				if err != nil {
					return fmt.Errorf("knock listener failed: %w", err)
				}
				return nil
			default:
			}
			log.Event("server accept failed", logging.F("error", err))
			continue
		}
		select {
		case pending <- conn:
		case <-ctx.Done():
			_ = conn.Close()
			return nil
		default:
			_ = conn.Close()
			log.Event("server auth queue full", logging.F("remote", conn.RemoteAddr()))
		}
	}
}

func applyServerOverrides(cfg *config.Config, opts ServerOptions) {
	if cfg.Mode == "" {
		cfg.Mode = config.ModeServer
	}
	if opts.Listen != "" {
		cfg.Server.TCPListen = opts.Listen
	}
	if opts.Upstream != "" {
		cfg.Server.Upstream = opts.Upstream
	}
	if opts.FirewallBackend != "" {
		cfg.Firewall.Backend = opts.FirewallBackend
	}
	if opts.AllowSeconds > 0 {
		cfg.Firewall.AllowSeconds = opts.AllowSeconds
	}
}

func checkUpstream(parent context.Context, rt config.ServerRuntime) error {
	ctx, cancel := context.WithTimeout(parent, rt.UpstreamConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", rt.Upstream)
	if err != nil {
		return err
	}
	return conn.Close()
}

func printServerDryRun(ctx context.Context, rt config.ServerRuntime) error {
	if err := validateRuntimeStartup(ctx, rt, false); err != nil {
		return err
	}
	fmt.Println("DRY-RUN server configuration")
	fmt.Printf("tcp_listen: %s\n", rt.Listen)
	fmt.Printf("upstream: %s\n", rt.Upstream)
	fmt.Printf("access.mode: %s\n", rt.AccessMode)
	fmt.Printf("knock.method: %s\n", rt.KnockMethod)
	if rt.KnockMethod == "udp" || rt.KnockMethod == "udp-seq" {
		fmt.Printf("knock.udp_listen: %s\n", rt.UDPListen)
	}
	if rt.KnockMethod == "udp-seq" || rt.KnockMethod == "udp-passive-seq" || rt.KnockMethod == "tcp-syn-seq" {
		fmt.Printf("knock.sequence.length: %d\n", rt.SequenceLength)
		fmt.Printf("knock.sequence.slot_seconds: %d\n", rt.SequenceSlot)
		fmt.Printf("knock.sequence.window: %s\n", rt.SequenceWindow)
	}
	if rt.KnockMethod == "udp-passive" {
		fmt.Printf("knock.udp_knock_port: %d\n", rt.UDPPort)
		fmt.Printf("firewall.drop_udp_knock_port: %v\n", rt.Firewall.DropUDPKnockPort)
	}
	if caps, err := firewall.Validate(rt.Firewall); err == nil {
		fmt.Printf("firewall.backend: %s (selected: %s)\n", rt.Firewall.Backend, caps.Backend)
		fmt.Printf("firewall.supports_timeout: %v\n", caps.Timeout)
		fmt.Printf("firewall.supports_drop_udp: %v\n", caps.DropUDP)
	} else {
		fmt.Printf("firewall.backend: %s (invalid: %v)\n", rt.Firewall.Backend, err)
	}
	fmt.Printf("firewall.default_action: %s\n", rt.Firewall.DefaultAction)
	fmt.Printf("firewall.port: %d\n", rt.Port)
	fmt.Printf("firewall.allow_seconds: %d\n", int(rt.AllowTTL.Seconds()))
	fmt.Printf("transport.encryption: %v\n", rt.TransportEncrypted)
	fmt.Printf("metrics.enabled: %v\n", rt.MetricsEnabled)
	if rt.MetricsEnabled {
		fmt.Printf("metrics.listen: %s\n", rt.MetricsListen)
		fmt.Printf("metrics.path: %s\n", rt.MetricsPath)
	}
	fmt.Println("No changes applied.")
	return nil
}

func validateRuntimeStartup(ctx context.Context, rt config.ServerRuntime, checkUpstreamReachable bool) error {
	ln, err := net.Listen("tcp", rt.Listen)
	if err != nil {
		return fmt.Errorf("tcp listen address unavailable %s: %w; remediation: choose a free address/port or stop the existing listener", rt.Listen, err)
	}
	_ = ln.Close()
	if rt.KnockMethod == "udp" || rt.KnockMethod == "udp-seq" {
		pc, err := net.ListenPacket("udp", rt.UDPListen)
		if err != nil {
			return fmt.Errorf("udp knock listen address unavailable %s: %w; remediation: choose a free udp_knock_port/udp_listen", rt.UDPListen, err)
		}
		_ = pc.Close()
	}
	if _, err := firewall.New(rt.Firewall); err != nil {
		return fmt.Errorf("firewall backend invalid: %w", err)
	}
	if checkUpstreamReachable {
		if err := checkUpstream(ctx, rt); err != nil {
			return fmt.Errorf("upstream unreachable %s: %w; remediation: start the upstream service or fix server.upstream", rt.Upstream, err)
		}
	}
	return nil
}

type serverState struct {
	rt           config.ServerRuntime
	fw           firewall.Backend
	log          *logging.Logger
	metrics      *metrics.Registry
	knocks       *knockStore
	nonces       libknock.ReplayCache
	tcpAuth      libknock.ServerConfig
	rate         *limits.RateLimiter
	bans         *limits.BanTracker
	conns        *limits.Connections
	knockClients []knock.ClientSecret
}

func newServerState(rt config.ServerRuntime, fw firewall.Backend, log *logging.Logger) (*serverState, error) {
	rate, err := limits.NewRateLimiterWithLimit(rt.KnockRatePerIP, rt.MaxTrackedIPs)
	if err != nil {
		return nil, err
	}
	clients := make([]knock.ClientSecret, 0, len(rt.Clients))
	secrets := make(map[string][]byte, len(rt.Clients))
	for _, client := range rt.Clients {
		clients = append(clients, knock.ClientSecret{ClientID: client.ID, Secret: client.Secret})
		secrets[client.ID] = append([]byte(nil), client.Secret...)
	}
	return &serverState{
		rt:           rt,
		fw:           fw,
		log:          log,
		metrics:      metrics.NewBuildInfo(),
		knocks:       newKnockStore(),
		nonces:       libknock.NewMemoryReplayCache(rt.NonceCacheTTL),
		tcpAuth:      libknock.ServerConfig{ServerPort: rt.Port, Secrets: libknock.NewStaticSecretResolver(secrets), ReplayCache: libknock.NewMemoryReplayCache(rt.NonceCacheTTL), AuthTimeout: rt.AuthTimeout, TimeWindow: rt.AuthTimeWindow, MaxFrameSize: libknock.DefaultMaxFrameSize},
		rate:         rate,
		bans:         limits.NewBanTrackerWithLimit(rt.AuthFailBanTTL, rt.MaxTrackedIPs),
		conns:        limits.NewConnections(rt.MaxGlobalConnections, rt.MaxConnectionsPerIP, rt.MaxConnectionsPerClient),
		knockClients: clients,
	}, nil
}

func (s *serverState) allowKnockPacket(src net.IP) bool {
	now := time.Now()
	if s.bans.IsBanned("ip:"+src.String(), now) {
		s.log.Event("knock rejected", logging.F("src", src), logging.F("reason", "rate_limited"))
		s.metrics.Inc("knock_proxy_rate_limit_rejected_total", nil)
		s.metrics.Inc("knock_proxy_knock_rejected_total", metrics.Reason("rate_limited"))
		return false
	}
	if !s.rate.Allow(src.String(), now) {
		s.log.Event("knock rejected", logging.F("src", src), logging.F("reason", "rate_limited"))
		s.metrics.Inc("knock_proxy_rate_limit_rejected_total", nil)
		s.metrics.Inc("knock_proxy_knock_rejected_total", metrics.Reason("rate_limited"))
		return false
	}
	return true
}

func (s *serverState) invalidKnockPacket(src net.IP, reason string) {
	if !s.rt.LogInvalidKnock {
		return
	}
	s.log.Warn("invalid knock packet", logging.F("src", src), logging.F("reason", reason))
}

func (s *serverState) handleKnock(ev knock.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.bans.IsBanned("client:"+ev.ClientID, time.Now()) {
		s.log.Event("knock rejected", logging.F("src", ev.SourceIP), logging.F("client_id", ev.ClientID), logging.F("reason", "rate_limited"))
		s.metrics.Inc("knock_proxy_rate_limit_rejected_total", nil)
		s.metrics.Inc("knock_proxy_knock_rejected_total", metrics.Reason("rate_limited"))
		return
	}
	if ev.Nonce != "" {
		if err := s.nonces.CheckAndMark(ev.ClientID, []byte(ev.Nonce)); err != nil {
			s.log.Event("knock rejected", logging.F("src", ev.SourceIP), logging.F("client_id", ev.ClientID), logging.F("reason", "replayed_nonce"))
			s.metrics.Inc("knock_proxy_knock_rejected_total", metrics.Reason("replayed_nonce"))
			return
		}
	}

	if err := s.fw.Allow(ctx, ev.SourceIP, s.rt.Port, s.rt.AllowTTL); err != nil {
		s.log.Event("knock rejected",
			logging.F("src", ev.SourceIP),
			logging.F("client_id", ev.ClientID),
			logging.F("reason", "firewall_allow_failed"),
			logging.F("backend", s.fw.Name()),
			logging.F("error", err),
		)
		s.metrics.Inc("knock_proxy_knock_rejected_total", metrics.Reason("firewall_allow_failed"))
		return
	}

	now := time.Now()
	knockConnections := 1
	if s.rt.AccessMode == "direct" {
		knockConnections = s.rt.MaxConnectionsPerKnock
	}
	s.knocks.add(ev.SourceIP, ev.ClientID, s.rt.AllowTTL, now, knockConnections)
	fields := []logging.Field{logging.F("src", ev.SourceIP), logging.F("client_id", ev.ClientID), logging.F("ttl", s.rt.AllowTTL.String()), logging.F("backend", s.fw.Name())}
	if ev.Method != "" {
		fields = append(fields, logging.F("method", ev.Method), logging.F("parts", ev.Parts))
	}
	s.log.Event("knock accepted", fields...)
	s.metrics.Inc("knock_proxy_knock_accepted_total", nil)
	s.metrics.AddGauge("knock_proxy_active_allow_entries", nil, 1)

	time.AfterFunc(s.rt.AllowTTL, func() {
		if !s.knocks.expire(ev.SourceIP, ev.ClientID, time.Now()) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.fw.Revoke(ctx, ev.SourceIP, s.rt.Port)
		s.metrics.AddGauge("knock_proxy_active_allow_entries", nil, -1)
	})
}

func (s *serverState) handleConn(parent context.Context, conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	srcIP := remoteIP(conn.RemoteAddr())
	if srcIP == nil {
		s.log.Event("tcp auth rejected", logging.F("reason", "tcp_auth_failed"), logging.F("remote", conn.RemoteAddr()))
		return
	}

	if s.bans.IsBanned("ip:"+srcIP.String(), time.Now()) {
		s.log.Event("tcp auth rejected", logging.F("src", srcIP), logging.F("reason", "rate_limited"))
		s.metrics.Inc("knock_proxy_tcp_auth_rejected_total", metrics.Reason("rate_limited"))
		return
	}
	if err := s.conns.AcquireIP(srcIP.String()); err != nil {
		s.log.Event("tcp auth rejected", logging.F("src", srcIP), logging.F("reason", "connection_limit_exceeded"))
		s.metrics.Inc("knock_proxy_tcp_auth_rejected_total", metrics.Reason("connection_limit_exceeded"))
		return
	}
	defer s.conns.ReleaseIP(srcIP.String())

	if s.rt.AccessMode == "direct" {
		s.handleDirectConn(parent, conn, srcIP, start)
		return
	}

	authConn, peer, err := libknock.ServerAuth(parent, conn, s.tcpAuth)
	if err != nil {
		s.recordFailure(srcIP, "", reasonFromAuthError(err), err)
		return
	}
	conn = authConn
	clientID := peer.ClientID
	if s.bans.IsBanned("client:"+clientID, time.Now()) {
		s.recordFailure(srcIP, clientID, "rate_limited", nil)
		return
	}

	client, ok := s.rt.Clients[clientID]
	if !ok {
		s.recordFailure(srcIP, clientID, "unknown_client_id", nil)
		return
	}
	now := time.Now()
	if ok, err := s.hasRecentAccess(parent, srcIP, clientID, now); err != nil {
		s.recordFailure(srcIP, clientID, "tcp_auth_failed", err)
		return
	} else if !ok {
		s.recordFailure(srcIP, clientID, "tcp_auth_failed", errors.New("source IP has no recent accepted knock or firewall allow entry"))
		return
	}
	if err := s.conns.AcquireClient(clientID, client.MaxConnections); err != nil {
		s.log.Event("tcp auth rejected", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("reason", "connection_limit_exceeded"))
		s.metrics.Inc("knock_proxy_tcp_auth_rejected_total", metrics.Reason("connection_limit_exceeded"))
		return
	}
	defer s.conns.ReleaseClient(clientID)

	if s.rt.RemoveAfterAuth {
		shouldRevoke := s.knocks.removeOne(srcIP, clientID, time.Now())
		if shouldRevoke {
			revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.metrics.AddGauge("knock_proxy_active_allow_entries", nil, -1)
			if err := s.fw.Revoke(revokeCtx, srcIP, s.rt.Port); err != nil {
				s.log.Event("firewall revoke failed", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("backend", s.fw.Name()), logging.F("error", err))
			}
			cancel()
		}
	}

	upstream, err := s.dialUpstream(parent)
	if err != nil {
		s.log.Event("upstream connect failed",
			logging.F("src", srcIP),
			logging.F("client_id", clientID),
			logging.F("reason", "upstream_connect_failed"),
			logging.F("upstream", s.rt.Upstream),
			logging.F("error", err),
		)
		s.metrics.Inc("knock_proxy_upstream_connect_failed_total", nil)
		return
	}
	defer upstream.Close()

	relayConn := conn
	if s.rt.TransportEncrypted {
		relayConn, err = secure.Wrap(conn, client.Secret, clientID, base64.RawStdEncoding.EncodeToString(peer.Nonce), s.rt.Port, secure.ServerRole)
		if err != nil {
			s.recordFailure(srcIP, clientID, "tcp_auth_failed", err)
			return
		}
	}

	s.log.Event("tcp auth accepted", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("upstream", s.rt.Upstream), logging.F("encryption", s.rt.TransportEncrypted))
	s.metrics.Inc("knock_proxy_tcp_auth_accepted_total", nil)
	s.metrics.AddGauge("knock_proxy_active_connections", nil, 1)
	stats := relay.Bidirectional(relayConn, upstream, s.rt.IdleTimeout)
	s.metrics.AddGauge("knock_proxy_active_connections", nil, -1)
	s.metrics.Inc("knock_proxy_sessions_total", nil)
	s.metrics.Add("knock_proxy_session_rx_bytes_total", nil, float64(stats.RX))
	s.metrics.Add("knock_proxy_session_tx_bytes_total", nil, float64(stats.TX))
	s.log.Event("session closed",
		logging.F("src", srcIP),
		logging.F("client_id", clientID),
		logging.F("duration", int(time.Since(start).Seconds())),
		logging.F("rx", stats.RX),
		logging.F("tx", stats.TX),
	)
}

func (s *serverState) hasRecentAccess(parent context.Context, ip net.IP, clientID string, now time.Time) (bool, error) {
	if s.knocks.has(ip, clientID, now) {
		return true, nil
	}
	checker, ok := s.fw.(firewall.Checker)
	if !ok {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	allowed, err := checker.IsAllowed(ctx, ip, s.rt.Port)
	if err != nil {
		return false, err
	}
	if allowed {
		s.log.Event("tcp auth using existing firewall allow", logging.F("src", ip), logging.F("client_id", clientID), logging.F("backend", s.fw.Name()))
	}
	return allowed, nil
}

func (s *serverState) handleDirectConn(parent context.Context, conn net.Conn, srcIP net.IP, start time.Time) {
	clientID, ok, shouldRevoke := s.knocks.consumeAny(srcIP, time.Now())
	if !ok {
		s.log.Event("direct rejected", logging.F("src", srcIP), logging.F("reason", "tcp_auth_failed"))
		s.metrics.Inc("knock_proxy_tcp_auth_rejected_total", metrics.Reason("tcp_auth_failed"))
		return
	}
	if s.rt.RemoveAfterFirstConnect && shouldRevoke {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.fw.Revoke(ctx, srcIP, s.rt.Port)
		cancel()
		s.metrics.AddGauge("knock_proxy_active_allow_entries", nil, -1)
	}
	upstream, err := s.dialUpstream(parent)
	if err != nil {
		s.log.Event("upstream connect failed", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("reason", "upstream_connect_failed"), logging.F("upstream", s.rt.Upstream), logging.F("error", err))
		s.metrics.Inc("knock_proxy_upstream_connect_failed_total", nil)
		return
	}
	defer upstream.Close()
	s.log.Event("direct accepted", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("upstream", s.rt.Upstream))
	s.metrics.AddGauge("knock_proxy_active_connections", nil, 1)
	stats := relay.Bidirectional(conn, upstream, s.rt.IdleTimeout)
	s.metrics.AddGauge("knock_proxy_active_connections", nil, -1)
	s.metrics.Inc("knock_proxy_sessions_total", nil)
	s.metrics.Add("knock_proxy_session_rx_bytes_total", nil, float64(stats.RX))
	s.metrics.Add("knock_proxy_session_tx_bytes_total", nil, float64(stats.TX))
	s.log.Event("session closed", logging.F("src", srcIP), logging.F("client_id", clientID), logging.F("duration", int(time.Since(start).Seconds())), logging.F("rx", stats.RX), logging.F("tx", stats.TX))
}

func (s *serverState) dialUpstream(parent context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, s.rt.UpstreamConnectTimeout)
	defer cancel()
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "tcp", s.rt.Upstream)
}

func (s *serverState) recordFailure(srcIP net.IP, clientID, reason string, err error) {
	fields := []logging.Field{
		logging.F("src", srcIP),
		logging.F("reason", reason),
	}
	if clientID != "" {
		fields = append(fields, logging.F("client_id", clientID))
	}
	if err != nil {
		fields = append(fields, logging.F("error", err))
	}
	if s.bans.RecordFailure("ip:"+srcIP.String(), time.Now()) {
		fields = append(fields, logging.F("ban", s.rt.AuthFailBanTTL.String()))
		s.metrics.Set("knock_proxy_ban_count", nil, float64(s.bans.Count(time.Now())))
	}
	if clientID != "" && s.bans.RecordFailure("client:"+clientID, time.Now()) {
		fields = append(fields, logging.F("client_ban", s.rt.AuthFailBanTTL.String()))
		s.metrics.Set("knock_proxy_ban_count", nil, float64(s.bans.Count(time.Now())))
	}
	s.log.Event("tcp auth rejected", fields...)
	s.metrics.Inc("knock_proxy_tcp_auth_rejected_total", metrics.Reason(reason))

	if s.rt.RemoveAfterAuth {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.fw.Revoke(ctx, srcIP, s.rt.Port)
		removed := 0
		if clientID != "" {
			if s.knocks.removeOne(srcIP, clientID, time.Now()) {
				removed = 1
			}
		} else {
			removed = s.knocks.removeIP(srcIP)
		}
		if removed > 0 {
			s.metrics.AddGauge("knock_proxy_active_allow_entries", nil, -float64(removed))
		}
	}
}

func startMetricsServer(ctx context.Context, rt config.ServerRuntime, registry *metrics.Registry, log *logging.Logger) *http.Server {
	if !rt.MetricsEnabled {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle(rt.MetricsPath, registry.Handler())
	server := &http.Server{Addr: rt.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: rt.IdleTimeout}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		log.Event("metrics listening", logging.F("listen", rt.MetricsListen), logging.F("path", rt.MetricsPath))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Event("metrics server failed", logging.F("error", err))
		}
	}()
	return server
}

func reasonFromAuthError(err error) string {
	switch {
	case errors.Is(err, libknock.ErrTimeSkew):
		return "expired_timestamp"
	case errors.Is(err, libknock.ErrReplayDetected):
		return "replayed_nonce"
	case errors.Is(err, libknock.ErrUnknownClient):
		return "unknown_client_id"
	case errors.Is(err, libknock.ErrFrameTooLarge), errors.Is(err, libknock.ErrInvalidFrame):
		return "invalid_frame"
	case errors.Is(err, libknock.ErrAuthFailed):
		return "invalid_hmac"
	default:
		return "tcp_auth_failed"
	}
}

func remoteIP(addr net.Addr) net.IP {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
