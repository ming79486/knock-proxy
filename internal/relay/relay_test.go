package relay

import (
	"net"
	"testing"
	"time"
)

func TestBidirectionalIdleTimeoutReturns(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan Stats, 1)
	go func() { done <- Bidirectional(a, b, 20*time.Millisecond) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Bidirectional did not return after idle timeout")
	}
}
