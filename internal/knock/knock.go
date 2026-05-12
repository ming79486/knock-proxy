package knock

import (
	"errors"
	"net"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
)

var ErrUnsupported = errors.New("raw knock requires linux raw sockets and CAP_NET_RAW")

type Event struct {
	SourceIP net.IP
	ClientID string
	Nonce    string
	Method   string
	Parts    int
}

type ListenOptions struct {
	Port          int
	KnockPort     int
	Clients       []auth.ClientSecret
	TimeWindow    time.Duration
	AllowPacket   func(net.IP) bool
	InvalidPacket func(net.IP, string)
	Sequence      SequenceOptions
	NonceTTL      time.Duration
}

type SendOptions struct {
	ServerAddr string
	ClientID   string
	Secret     []byte
	ServerPort int
	TimeWindow time.Duration
	Sequence   SequenceOptions
}

type Handler func(Event)
