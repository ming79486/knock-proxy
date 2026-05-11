package knock

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/ming79486/knock-proxy/internal/auth"
)

func SendUDP(ctx context.Context, opts SendOptions) error {
	return SendUDPMethod(ctx, opts, "udp")
}

func SendUDPMethod(ctx context.Context, opts SendOptions, method string) error {
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	frame, err := auth.NewKnockFrame(opts.ClientID, opts.Secret, opts.ServerPort, method, time.Now())
	if err != nil {
		return err
	}
	data, err := json.Marshal(frame)
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
	_, err = conn.Write(data)
	return err
}

func ListenUDP(ctx context.Context, listen string, opts ListenOptions, handler Handler) error {
	if listen == "" {
		return fmt.Errorf("udp listen address is required")
	}
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	clients := make(map[string]auth.ClientSecret, len(opts.Clients))
	for _, client := range opts.Clients {
		clients[client.ClientID] = client
	}

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
		var frame auth.Frame
		if err := json.Unmarshal(buf[:n], &frame); err != nil {
			continue
		}
		client, ok := clients[frame.ClientID]
		if !ok {
			continue
		}
		if err := auth.ValidateKnockFrame(frame, client.Secret, opts.Port, "udp", time.Now(), opts.TimeWindow); err != nil {
			continue
		}
		handler(Event{SourceIP: udpAddr.IP, ClientID: frame.ClientID, Nonce: frame.Nonce})
	}
}
