package limits

import (
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	limiter, err := NewRateLimiter("2/1s")
	if err != nil {
		t.Fatalf("NewRateLimiter returned error: %v", err)
	}
	now := time.Unix(100, 0)
	if !limiter.Allow("1.2.3.4", now) {
		t.Fatal("first event should be allowed")
	}
	if !limiter.Allow("1.2.3.4", now.Add(100*time.Millisecond)) {
		t.Fatal("second event should be allowed")
	}
	if limiter.Allow("1.2.3.4", now.Add(200*time.Millisecond)) {
		t.Fatal("third event within window should be rejected")
	}
	if !limiter.Allow("1.2.3.4", now.Add(1100*time.Millisecond)) {
		t.Fatal("event after window should be allowed")
	}
}

func TestRateLimiterCapacityLimit(t *testing.T) {
	limiter, err := NewRateLimiterWithLimit("10/1m", 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, key := range []string{"1", "2", "3"} {
		if !limiter.Allow(key, now) {
			t.Fatalf("Allow(%s) rejected", key)
		}
	}
	if len(limiter.events) != 2 {
		t.Fatalf("tracked keys = %d, want 2", len(limiter.events))
	}
}
