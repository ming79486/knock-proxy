package app

import (
	libknock "github.com/libknock/libknock"
	"github.com/libknock/libknock/protocol"

	"github.com/ming79486/knock-proxy/internal/config"
)

func clientAuthConfig(rt config.ClientRuntime) libknock.ClientConfig {
	cfg := libknock.ClientConfig{ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, AuthTimeout: rt.AuthTimeout}
	applyAuthProtocol(&cfg.Protocol, &cfg.EnvelopeV2, rt.AuthFrame, rt.AuthHintMode, rt.AuthFrameBuckets, rt.AuthPaddingPolicy)
	return cfg
}

func serverAuthConfig(rt config.ServerRuntime, secrets map[string][]byte) libknock.ServerConfig {
	cfg := libknock.ServerConfig{
		ServerPort:         rt.Port,
		Secrets:            libknock.NewStaticSecretResolver(secrets),
		ReplayCache:        libknock.NewMemoryReplayCache(rt.NonceCacheTTL),
		AuthTimeout:        rt.AuthTimeout,
		TimeWindow:         rt.AuthTimeWindow,
		MaxFrameSize:       libknock.DefaultMaxFrameSize,
		FailDelayJitterMin: rt.AuthFailDelayJitterMin,
		FailDelayJitterMax: rt.AuthFailDelayJitterMax,
		DrainOnFailBytes:   rt.AuthDrainOnFailBytes,
		DrainOnFailTimeout: rt.AuthDrainOnFailTimeout,
	}
	applyAuthProtocol(&cfg.Protocol, &cfg.EnvelopeV2, rt.AuthFrame, rt.AuthHintMode, rt.AuthFrameBuckets, rt.AuthPaddingPolicy)
	cfg.AcceptProtocols = []libknock.AuthProtocol{cfg.Protocol}
	if cfg.Protocol == libknock.AuthProtocolEnvelopeV2 {
		cfg.MaxFrameSize = protocol.EnvelopeV2DefaultMaxSize
	}
	return cfg
}

func applyAuthProtocol(protocolOut *libknock.AuthProtocol, envelope *libknock.EnvelopeV2Config, frame, hintMode string, buckets []int, paddingPolicy string) {
	if frame == "frame-v1" {
		*protocolOut = libknock.AuthProtocolFrameV1
		return
	}
	*protocolOut = libknock.AuthProtocolEnvelopeV2
	*envelope = libknock.EnvelopeV2Config{
		HintMode:         protocol.EnvelopeV2HintMode(hintMode),
		FrameSizeBuckets: append([]int(nil), buckets...),
		PaddingPolicy:    protocol.EnvelopeV2PaddingPolicy(paddingPolicy),
	}
}
