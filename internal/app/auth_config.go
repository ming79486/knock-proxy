package app

import (
	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/protocol"

	"github.com/ming79486/knock-proxy/internal/config"
)

func clientAuthConfig(rt config.ClientRuntime) auth.ClientConfig {
	cfg := auth.ClientConfig{ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, AuthTimeout: rt.AuthTimeout}
	applyAuthProtocol(&cfg.Protocol, &cfg.EnvelopeV2, rt.AuthFrame, rt.AuthHintMode, rt.AuthFrameBuckets, rt.AuthPaddingPolicy)
	return cfg
}

func serverAuthConfig(rt config.ServerRuntime, secrets map[string][]byte) auth.ServerConfig {
	cfg := auth.ServerConfig{
		ServerPort:         rt.Port,
		Secrets:            auth.NewStaticSecretResolver(secrets),
		ReplayCache:        auth.NewMemoryReplayCache(rt.NonceCacheTTL),
		AuthTimeout:        rt.AuthTimeout,
		TimeWindow:         rt.AuthTimeWindow,
		MaxFrameSize:       auth.DefaultMaxFrameSize,
		FailDelayJitterMin: rt.AuthFailDelayJitterMin,
		FailDelayJitterMax: rt.AuthFailDelayJitterMax,
		DrainOnFailBytes:   rt.AuthDrainOnFailBytes,
		DrainOnFailTimeout: rt.AuthDrainOnFailTimeout,
	}
	applyAuthProtocol(&cfg.Protocol, &cfg.EnvelopeV2, rt.AuthFrame, rt.AuthHintMode, rt.AuthFrameBuckets, rt.AuthPaddingPolicy)
	cfg.AcceptProtocols = []auth.AuthProtocol{cfg.Protocol}
	if cfg.Protocol == auth.AuthProtocolEnvelopeV2 {
		cfg.MaxFrameSize = protocol.EnvelopeV2DefaultMaxSize
	}
	return cfg
}

func applyAuthProtocol(protocolOut *auth.AuthProtocol, envelope *auth.EnvelopeV2Config, frame, hintMode string, buckets []int, paddingPolicy string) {
	if frame == "frame-v1" {
		*protocolOut = auth.AuthProtocolFrameV1
		return
	}
	*protocolOut = auth.AuthProtocolEnvelopeV2
	*envelope = auth.EnvelopeV2Config{
		HintMode:         protocol.EnvelopeV2HintMode(hintMode),
		FrameSizeBuckets: append([]int(nil), buckets...),
		PaddingPolicy:    protocol.EnvelopeV2PaddingPolicy(paddingPolicy),
	}
}
