package knock

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/ming79486/knock-proxy/internal/auth"
)

func TestBuildAndParseSYNKnockIPv4(t *testing.T) {
	fields := auth.SYNFields{Sequence: 0x11223344, Window: 0x5566, Timestamp: 0x77889900}
	pkt, err := buildSYNPacket(net.IPv4(192, 0, 2, 10), net.IPv4(198, 51, 100, 20), 40000, 443, fields)
	if err != nil {
		t.Fatalf("buildSYNPacket returned error: %v", err)
	}
	frame := make([]byte, 14+len(pkt))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], pkt)
	src, got, ok := parseSYNKnock(frame, 443)
	if !ok {
		t.Fatalf("parseSYNKnock failed")
	}
	if !src.Equal(net.IPv4(192, 0, 2, 10)) || got != fields {
		t.Fatalf("unexpected parse result src=%s fields=%+v", src, got)
	}
}

func TestBuildAndParseSYNKnockIPv6(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::10")
	dstIP := net.ParseIP("2001:db8::20")
	fields := auth.SYNFields{Sequence: 0x01020304, Window: 0x1111, Timestamp: 0xaabbccdd}
	pkt, err := buildSYNPacketIPv6(srcIP, dstIP, 40000, 443, fields)
	if err != nil {
		t.Fatalf("buildSYNPacketIPv6 returned error: %v", err)
	}
	frame := make([]byte, 14+len(pkt))
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	copy(frame[14:], pkt)
	src, got, ok := parseSYNKnock(frame, 443)
	if !ok {
		t.Fatalf("parseSYNKnock failed")
	}
	if !src.Equal(srcIP) || got != fields {
		t.Fatalf("unexpected parse result src=%s fields=%+v", src, got)
	}
}
