package knock

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
)

type SequenceOptions struct {
	Length           int
	SlotSeconds      int
	Window           time.Duration
	PacketInterval   time.Duration
	MaxJitter        time.Duration
	AllowReorder     bool
	MaxInflightPerIP int
	MaxTotalInflight int
}

type seqState struct {
	firstSeen time.Time
	lastSeen  time.Time
	parts     []auth.UDPSeqPart
	nextIndex int
}

type sequenceTracker struct {
	mu      sync.Mutex
	opts    SequenceOptions
	states  map[string]*seqState
	perIP   map[string]int
	total   int
	nonces  map[string]time.Time
	nonceTT time.Duration
}

func normalizedSequenceOptions(opts SequenceOptions) SequenceOptions {
	if opts.Length == 0 {
		opts.Length = 3
	}
	if opts.SlotSeconds == 0 {
		opts.SlotSeconds = 30
	}
	if opts.Window <= 0 {
		opts.Window = 10 * time.Second
	}
	if opts.PacketInterval <= 0 {
		opts.PacketInterval = 80 * time.Millisecond
	}
	if opts.MaxInflightPerIP == 0 {
		opts.MaxInflightPerIP = 8
	}
	if opts.MaxTotalInflight == 0 {
		opts.MaxTotalInflight = 4096
	}
	return opts
}

func newSequenceTracker(opts SequenceOptions, nonceTTL time.Duration) *sequenceTracker {
	opts = normalizedSequenceOptions(opts)
	if nonceTTL <= opts.Window {
		nonceTTL = 2 * time.Minute
	}
	return &sequenceTracker{opts: opts, states: make(map[string]*seqState), perIP: make(map[string]int), nonces: make(map[string]time.Time), nonceTT: nonceTTL}
}

func SendUDPSequence(ctx context.Context, opts SendOptions) error {
	seq := normalizedSequenceOptions(opts.Sequence)
	parts, err := auth.NewUDPSeqParts(opts.ClientID, opts.Secret, opts.ServerPort, time.Now(), seq.SlotSeconds, seq.Length)
	if err != nil {
		return err
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", opts.ServerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	for i, part := range parts {
		data, err := json.Marshal(part)
		if err != nil {
			return err
		}
		if _, err := conn.Write(data); err != nil {
			return err
		}
		if i+1 < len(parts) {
			time.Sleep(seq.PacketInterval + jitter(seq.MaxJitter))
		}
	}
	return nil
}

func ListenUDPSequence(ctx context.Context, listen string, opts ListenOptions, handler Handler) error {
	if listen == "" {
		return fmt.Errorf("udp listen address is required")
	}
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() { <-ctx.Done(); _ = conn.Close() }()
	clients := make(map[string]auth.ClientSecret, len(opts.Clients))
	for _, client := range opts.Clients {
		clients[client.ClientID] = client
	}
	tracker := newSequenceTracker(opts.Sequence, opts.NonceTTL)
	buf := make([]byte, auth.MaxAuthFrameSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr.IP == nil {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(udpAddr.IP) {
			continue
		}
		var part auth.UDPSeqPart
		if err := json.Unmarshal(buf[:n], &part); err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, "invalid_json")
			}
			continue
		}
		client, ok := clients[part.ClientID]
		if !ok {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, "unknown_client_id")
			}
			continue
		}
		complete, err := tracker.add(udpAddr.IP, part, client.Secret, opts.Port, time.Now())
		if err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		if complete {
			handler(Event{SourceIP: udpAddr.IP, ClientID: part.ClientID, Nonce: part.Nonce, Parts: part.Total, Method: auth.UDPSeqMethod})
		}
	}
}

func (t *sequenceTracker) add(src net.IP, part auth.UDPSeqPart, secret []byte, protectedPort int, now time.Time) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	if err := auth.ValidateUDPSeqPart(part, secret, protectedPort, now, t.opts.SlotSeconds, t.opts.Length); err != nil {
		return false, err
	}
	key := src.String() + "\x00" + part.ClientID + "\x00" + part.Nonce + "\x00" + fmt.Sprint(part.ProtectedPort) + "\x00" + part.Method
	if expires, ok := t.nonces[part.ClientID+"\x00"+part.Nonce]; ok && expires.After(now) {
		return false, auth.ErrReplayedNonce
	}
	state := t.states[key]
	if state == nil {
		if t.perIP[src.String()] >= t.opts.MaxInflightPerIP {
			return false, fmt.Errorf("sequence_inflight_per_ip_exceeded")
		}
		if t.total >= t.opts.MaxTotalInflight {
			return false, fmt.Errorf("sequence_inflight_total_exceeded")
		}
		state = &seqState{firstSeen: now, parts: make([]auth.UDPSeqPart, part.Total)}
		t.states[key] = state
		t.perIP[src.String()]++
		t.total++
	}
	if now.Sub(state.firstSeen) > t.opts.Window {
		t.removeLocked(key, src.String())
		return false, fmt.Errorf("sequence_timeout")
	}
	if !t.opts.AllowReorder && part.Index != state.nextIndex {
		return false, fmt.Errorf("invalid_order")
	}
	if state.parts[part.Index].Nonce != "" {
		return false, fmt.Errorf("duplicate_part")
	}
	state.parts[part.Index] = part
	state.lastSeen = now
	state.nextIndex++
	for i := 0; i < len(state.parts); i++ {
		if state.parts[i].Nonce == "" {
			return false, nil
		}
	}
	if err := auth.ValidateUDPSeqFinal(state.parts, secret, protectedPort); err != nil {
		return false, err
	}
	t.nonces[part.ClientID+"\x00"+part.Nonce] = now.Add(t.nonceTT)
	t.removeLocked(key, src.String())
	return true, nil
}

func (t *sequenceTracker) pruneLocked(now time.Time) {
	for key, state := range t.states {
		if now.Sub(state.firstSeen) > t.opts.Window {
			parts := splitStateKey(key)
			if len(parts) > 0 {
				t.removeLocked(key, parts[0])
			}
		}
	}
	for key, expires := range t.nonces {
		if !expires.After(now) {
			delete(t.nonces, key)
		}
	}
}

func (t *sequenceTracker) removeLocked(key, ip string) {
	delete(t.states, key)
	if t.perIP[ip] > 0 {
		t.perIP[ip]--
	}
	if t.total > 0 {
		t.total--
	}
}
func splitStateKey(key string) []string {
	out := make([]string, 0, 5)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	return append(out, key[start:])
}
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(int(b[0])<<8|int(b[1])) % (max + 1)
}
