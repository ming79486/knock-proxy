package app

import (
	"time"

	"github.com/ming79486/knock-proxy/internal/config"
	oldknock "github.com/ming79486/knock-proxy/internal/knock"
	libseq "github.com/ming79486/libknock/knock"
)

func libSeqOptions(length, slot int, window, interval, jitter time.Duration, allowReorder bool, maxPerIP, maxTotal int) libseq.SequenceOptions {
	return libseq.SequenceOptions{Length: length, SlotSeconds: slot, Window: window, PacketInterval: interval, MaxJitter: jitter, AllowReorder: allowReorder, MaxInflightPerIP: maxPerIP, MaxTotalInflight: maxTotal}
}

func libSeqSendOptionsFromClient(rt config.ClientRuntime, serverAddr string) libseq.SendOptions {
	return libseq.SendOptions{ServerAddr: serverAddr, ClientID: rt.ClientID, Secret: rt.Secret, ServerPort: rt.ServerPort, TimeWindow: rt.KnockTimeWindow, Sequence: libSeqOptions(rt.SequenceLength, rt.SequenceSlot, 0, rt.SequenceInterval, rt.SequenceJitter, false, 0, 0)}
}

func libSeqListenOptions(rt config.ServerRuntime, s *serverState) libseq.ListenOptions {
	return libseq.ListenOptions{Port: rt.Port, KnockPort: rt.UDPPort, Clients: s.seqKnockClients, TimeWindow: rt.KnockTimeWindow, AllowPacket: s.allowKnockPacket, InvalidPacket: s.invalidKnockPacket, Sequence: libSeqOptions(rt.SequenceLength, rt.SequenceSlot, rt.SequenceWindow, rt.SequencePacketInterval, rt.SequenceMaxJitter, rt.SequenceAllowReorder, rt.SequenceMaxInflightIP, rt.SequenceMaxInflight), NonceTTL: rt.SequenceNonceTTL}
}

func handleLibSeqKnock(s *serverState) libseq.Handler {
	return func(ev libseq.Event) {
		s.handleKnock(oldknock.Event{SourceIP: ev.SourceIP, ClientID: ev.ClientID, Nonce: ev.Nonce, Method: ev.Method, Parts: ev.Parts})
	}
}
