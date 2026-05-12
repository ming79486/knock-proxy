//go:build linux

package knock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
	"golang.org/x/sys/unix"
)

func SendSYNSequence(ctx context.Context, opts SendOptions) error {
	seq := normalizedSequenceOptions(opts.Sequence)
	remote, err := net.ResolveTCPAddr("tcp", opts.ServerAddr)
	if err != nil {
		return err
	}
	if remote.IP == nil {
		return fmt.Errorf("server address %q did not resolve to an IP address", opts.ServerAddr)
	}
	if remote.IP.To4() != nil {
		return sendSYNSequenceIPv4(ctx, opts, remote, seq)
	}
	return sendSYNSequenceIPv6(ctx, opts, remote, seq)
}

func sendSYNSequenceIPv4(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq knock requires CAP_NET_RAW or root")
		}
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	parts := auth.ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	var dst [4]byte
	copy(dst[:], remote.IP.To4())
	addr := &unix.SockaddrInet4{Addr: dst}
	for i, part := range parts {
		packet, err := buildSYNPacket(localIP, remote.IP.To4(), randomEphemeralPort(), part.Port, part.Fields)
		if err != nil {
			return err
		}
		addr.Port = part.Port
		errCh := make(chan error, 1)
		go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return err
			}
		}
		if i+1 < len(parts) {
			time.Sleep(seq.PacketInterval + jitter(seq.MaxJitter))
		}
	}
	return nil
}

func sendSYNSequenceIPv6(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv6(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq knock requires CAP_NET_RAW or root")
		}
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return err
	}
	parts := auth.ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	var dst [16]byte
	copy(dst[:], remote.IP.To16())
	addr := &unix.SockaddrInet6{Addr: dst}
	if remote.Zone != "" {
		if iface, err := net.InterfaceByName(remote.Zone); err == nil {
			addr.ZoneId = uint32(iface.Index)
		}
	}
	for i, part := range parts {
		packet, err := buildSYNPacketIPv6(localIP, remote.IP.To16(), randomEphemeralPort(), part.Port, part.Fields)
		if err != nil {
			return err
		}
		addr.Port = part.Port
		errCh := make(chan error, 1)
		go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return err
			}
		}
		if i+1 < len(parts) {
			time.Sleep(seq.PacketInterval + jitter(seq.MaxJitter))
		}
	}
	return nil
}

func ListenSYNSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	seq := normalizedSequenceOptions(opts.Sequence)
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer unix.Close(fd)
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	tracker := newSYNSequenceTracker(seq)
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		src, dstPort, fields, ok := parseSYNPacket(buf[:n])
		if !ok {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		complete, clientID := tracker.add(src, dstPort, fields, opts.Clients, opts.Port, time.Now())
		if complete {
			handler(Event{SourceIP: src, ClientID: clientID, Method: "tcp-syn-seq", Parts: seq.Length})
		}
	}
}

type synSeqState struct {
	firstSeen time.Time
	lastSeen  time.Time
	matched   int
	clientID  string
	slot      int64
}
type synSeqTracker struct {
	opts   SequenceOptions
	states map[string]*synSeqState
	perIP  map[string]int
	total  int
}

func newSYNSequenceTracker(opts SequenceOptions) *synSeqTracker {
	return &synSeqTracker{opts: normalizedSequenceOptions(opts), states: map[string]*synSeqState{}, perIP: map[string]int{}}
}
func (t *synSeqTracker) add(src net.IP, dstPort int, fields auth.SYNFields, clients []auth.ClientSecret, protectedPort int, now time.Time) (bool, string) {
	t.prune(now)
	ip := src.String()
	keyPrefix := ip + "\x00"
	for key, st := range t.states {
		if len(key) >= len(keyPrefix) && key[:len(keyPrefix)] == keyPrefix {
			if client, slot, ok := auth.VerifySYNSeqPart(fields, dstPort, clients, protectedPort, now, t.opts.SlotSeconds, t.opts.Length, st.matched); ok && client == st.clientID && slot == st.slot {
				st.matched++
				st.lastSeen = now
				if st.matched >= t.opts.Length {
					delete(t.states, key)
					t.perIP[ip]--
					t.total--
					return true, client
				}
				return false, ""
			}
		}
	}
	client, slot, ok := auth.VerifySYNSeqPart(fields, dstPort, clients, protectedPort, now, t.opts.SlotSeconds, t.opts.Length, 0)
	if !ok || t.perIP[ip] >= t.opts.MaxInflightPerIP || t.total >= t.opts.MaxTotalInflight {
		return false, ""
	}
	key := fmt.Sprintf("%s\x00%s\x00%d", ip, client, slot)
	t.states[key] = &synSeqState{firstSeen: now, lastSeen: now, matched: 1, clientID: client, slot: slot}
	t.perIP[ip]++
	t.total++
	if t.opts.Length == 1 {
		return true, client
	}
	return false, ""
}
func (t *synSeqTracker) prune(now time.Time) {
	for key, st := range t.states {
		if now.Sub(st.firstSeen) > t.opts.Window {
			delete(t.states, key)
			t.perIP[key[:len(st.clientID)]]--
			t.total--
		}
	}
}
