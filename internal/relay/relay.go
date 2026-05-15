package relay

import (
	"net"
	"time"

	librelay "github.com/libknock/libknock/relay"
)

type Stats = librelay.Stats

func Bidirectional(a, b net.Conn, idleTimeout time.Duration) Stats {
	return librelay.Bidirectional(a, b, idleTimeout)
}
