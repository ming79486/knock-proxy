package limits

import (
	"sync"
	"time"
)

const authFailThreshold = 5

type BanTracker struct {
	mu        sync.Mutex
	ttl       time.Duration
	maxKeys   int
	failures  map[string]failureState
	bannedTil map[string]time.Time
}

type failureState struct {
	count     int
	firstSeen time.Time
}

func NewBanTracker(ttl time.Duration) *BanTracker { return NewBanTrackerWithLimit(ttl, 0) }

func NewBanTrackerWithLimit(ttl time.Duration, maxKeys int) *BanTracker {
	return &BanTracker{ttl: ttl, maxKeys: maxKeys, failures: make(map[string]failureState), bannedTil: make(map[string]time.Time)}
}

func (b *BanTracker) IsBanned(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pruneLocked(now)
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
	b.pruneLocked(now)

	state := b.failures[key]
	if state.firstSeen.IsZero() || now.Sub(state.firstSeen) > time.Minute {
		state = failureState{firstSeen: now}
	}
	state.count++
	b.failures[key] = state
	if state.count >= authFailThreshold {
		b.bannedTil[key] = now.Add(b.ttl)
		delete(b.failures, key)
		b.enforceLimitLocked()
		return true
	}
	b.enforceLimitLocked()
	return false
}

func (b *BanTracker) Count(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now)
	return len(b.bannedTil)
}

func (b *BanTracker) pruneLocked(now time.Time) {
	for key, until := range b.bannedTil {
		if !until.After(now) {
			delete(b.bannedTil, key)
		}
	}
	for key, state := range b.failures {
		if state.firstSeen.IsZero() || now.Sub(state.firstSeen) > time.Minute {
			delete(b.failures, key)
		}
	}
}

func (b *BanTracker) enforceLimitLocked() {
	if b.maxKeys <= 0 {
		return
	}
	for len(b.failures)+len(b.bannedTil) > b.maxKeys {
		oldestKey := ""
		oldestKind := ""
		var oldest time.Time
		for key, state := range b.failures {
			if oldestKey == "" || state.firstSeen.Before(oldest) {
				oldestKey, oldestKind, oldest = key, "failure", state.firstSeen
			}
		}
		for key, until := range b.bannedTil {
			if oldestKey == "" || until.Before(oldest) {
				oldestKey, oldestKind, oldest = key, "ban", until
			}
		}
		if oldestKey == "" {
			return
		}
		if oldestKind == "failure" {
			delete(b.failures, oldestKey)
		} else {
			delete(b.bannedTil, oldestKey)
		}
	}
}
