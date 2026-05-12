//go:build linux

package knock

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
	"golang.org/x/sys/unix"
)

func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	knockPort := opts.KnockPort
	if knockPort == 0 {
		knockPort = opts.Port
	}
	if knockPort < 1 || knockPort > 65535 {
		return fmt.Errorf("invalid udp knock port %d", knockPort)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("udp-passive-seq server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer unix.Close(fd)
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	clients := make(map[string]auth.ClientSecret, len(opts.Clients))
	for _, client := range opts.Clients {
		clients[client.ClientID] = client
	}
	tracker := newSequenceTracker(opts.Sequence, opts.NonceTTL)
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
		src, payload, ok := parseUDPKnockDatagram(buf[:n], knockPort)
		if !ok || len(payload) > auth.MaxAuthFrameSize {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		var part auth.UDPSeqPart
		if err := json.Unmarshal(payload, &part); err != nil {
			continue
		}
		client, ok := clients[part.ClientID]
		if !ok {
			continue
		}
		complete, err := tracker.add(src, part, client.Secret, opts.Port, time.Now())
		if err != nil {
			continue
		}
		if complete {
			handler(Event{SourceIP: src, ClientID: part.ClientID, Nonce: part.Nonce, Method: "udp-passive-seq", Parts: part.Total})
		}
	}
}

func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	knockPort := opts.KnockPort
	if knockPort == 0 {
		knockPort = opts.Port
	}
	if knockPort < 1 || knockPort > 65535 {
		return fmt.Errorf("invalid udp knock port %d", knockPort)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("udp-passive server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer unix.Close(fd)

	go func() {
		<-ctx.Done()
		_ = unix.Close(fd)
	}()

	clients := make(map[string]auth.ClientSecret, len(opts.Clients))
	for _, client := range opts.Clients {
		clients[client.ClientID] = client
	}

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

		src, payload, ok := parseUDPKnockDatagram(buf[:n], knockPort)
		if !ok || len(payload) > auth.MaxAuthFrameSize {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}

		var frame auth.Frame
		if err := json.Unmarshal(payload, &frame); err != nil {
			continue
		}
		client, ok := clients[frame.ClientID]
		if !ok {
			continue
		}
		if err := auth.ValidateKnockFrame(frame, client.Secret, opts.Port, "udp-passive", time.Now(), opts.TimeWindow); err != nil {
			continue
		}
		handler(Event{SourceIP: src, ClientID: frame.ClientID, Nonce: frame.Nonce})
	}
}

func parseUDPKnockDatagram(frame []byte, dstPort int) (net.IP, []byte, bool) {
	if src, payload, ok := parseUDPKnockIPv6(frame, dstPort); ok {
		return src, payload, true
	}
	return parseUDPKnockIPv4(frame, dstPort)
}

func parseUDPKnockIPv4(frame []byte, dstPort int) (net.IP, []byte, bool) {
	ipOff := findIPv4OffsetForProtocol(frame, ipv4ProtocolUDP)
	if ipOff < 0 || len(frame) < ipOff+20 {
		return nil, nil, false
	}
	ip := frame[ipOff:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return nil, nil, false
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total <= ihl || len(ip) < total {
		total = len(ip)
	}
	if ip[9] != ipv4ProtocolUDP {
		return nil, nil, false
	}
	udp := ip[ihl:total]
	payload, ok := parseUDPPayload(udp, dstPort)
	if !ok {
		return nil, nil, false
	}
	src := net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	return src, payload, true
}

func parseUDPKnockIPv6(frame []byte, dstPort int) (net.IP, []byte, bool) {
	ipOff := findIPv6OffsetForProtocol(frame, ipv4ProtocolUDP)
	if ipOff < 0 || len(frame) < ipOff+40 {
		return nil, nil, false
	}
	ip := frame[ipOff:]
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if ip[6] != ipv4ProtocolUDP || payloadLen < 8 || len(ip) < 40+payloadLen {
		return nil, nil, false
	}
	payload, ok := parseUDPPayload(ip[40:40+payloadLen], dstPort)
	if !ok {
		return nil, nil, false
	}
	src := make(net.IP, net.IPv6len)
	copy(src, ip[8:24])
	return src, payload, true
}

func parseUDPPayload(udp []byte, dstPort int) ([]byte, bool) {
	if len(udp) < 8 {
		return nil, false
	}
	if int(binary.BigEndian.Uint16(udp[2:4])) != dstPort {
		return nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil, false
	}
	return udp[8:udpLen], true
}
