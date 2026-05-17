package app

import (
	"testing"
	"time"

	libknock "github.com/libknock/libknock"
	"github.com/libknock/libknock/protocol"

	"github.com/ming79486/knock-proxy/internal/config"
)

func TestClientAuthConfigUsesEnvelopeV2(t *testing.T) {
	rt := config.ClientRuntime{ClientID: "client", Secret: []byte("1234567890123456"), ServerPort: 443, AuthTimeout: time.Second, AuthFrame: "envelope-v2", AuthHintMode: "route-hint", AuthFrameBuckets: []int{128, 192}, AuthPaddingPolicy: "random-bucket"}
	cfg := clientAuthConfig(rt)
	if cfg.Protocol != libknock.AuthProtocolEnvelopeV2 {
		t.Fatalf("Protocol = %q, want envelope-v2", cfg.Protocol)
	}
	if cfg.EnvelopeV2.HintMode != protocol.EnvelopeV2HintModeRouteHint || cfg.EnvelopeV2.PaddingPolicy != protocol.EnvelopeV2PaddingRandomBucket {
		t.Fatalf("EnvelopeV2 = %+v", cfg.EnvelopeV2)
	}
}

func TestServerAuthConfigUsesFrameV1Compatibility(t *testing.T) {
	rt := config.ServerRuntime{Port: 443, NonceCacheTTL: time.Minute, AuthTimeout: time.Second, AuthTimeWindow: time.Second, AuthFrame: "frame-v1"}
	cfg := serverAuthConfig(rt, map[string][]byte{"client": []byte("1234567890123456")})
	if cfg.Protocol != libknock.AuthProtocolFrameV1 {
		t.Fatalf("Protocol = %q, want frame-v1", cfg.Protocol)
	}
	if len(cfg.AcceptProtocols) != 1 || cfg.AcceptProtocols[0] != libknock.AuthProtocolFrameV1 {
		t.Fatalf("AcceptProtocols = %v", cfg.AcceptProtocols)
	}
}
