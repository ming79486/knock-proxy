package limits

import (
	"sync"
	"time"
)

const authFailThreshold = 5

type BanTracker struct {
	mu        sync.Mutex
	ttl       time.Duration
	failures  map[string]failureState
	bannedTil map[string]time.Time
}

type failureState struct {
	count     int
	firstSeen time.Time
}

func NewBanTracker(ttl time.Duration) *BanTracker {
	return &BanTracker{
		ttl:       ttl,
		failures:  make(map[string]failureState),
		bannedTil: make(map[string]time.Time),
	}
}

func (b *BanTracker) IsBanned(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	until, ok := b.bannedTil[key]
	if !ok {
		return false
	}
	if until.After(now) {
		return true
	}
	delete(b.bannedTil, key)
	delete(b.failures, key)
	return false
}

func (b *BanTracker) RecordFailure(key string, now time.Time) bool {
	if b.ttl <= 0 {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	state := b.failures[key]
	if state.firstSeen.IsZero() || now.Sub(state.firstSeen) > time.Minute {
		state = failureState{firstSeen: now}
	}
	state.count++
	b.failures[key] = state
	if state.count >= authFailThreshold {
		b.bannedTil[key] = now.Add(b.ttl)
		delete(b.failures, key)
		return true
	}
	return false
}
