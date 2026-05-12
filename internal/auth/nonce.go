package auth

import (
	"errors"
	"sync"
	"time"
)

var ErrReplayedNonce = errors.New("replayed_nonce")

type NonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]time.Time
}

func NewNonceCache(ttl time.Duration) *NonceCache { return NewNonceCacheWithLimit(ttl, 0) }

func NewNonceCacheWithLimit(ttl time.Duration, maxEntries int) *NonceCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceCache{ttl: ttl, max: maxEntries, entries: make(map[string]time.Time)}
}

func (c *NonceCache) Add(clientID, nonce string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)
	key := clientID + "\x00" + nonce
	if expiresAt, exists := c.entries[key]; exists && expiresAt.After(now) {
		return ErrReplayedNonce
	}
	c.entries[key] = now.Add(c.ttl)
	c.enforceLimitLocked()
	return nil
}

func (c *NonceCache) Len(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	return len(c.entries)
}

func (c *NonceCache) pruneLocked(now time.Time) {
	for key, expiresAt := range c.entries {
		if !expiresAt.After(now) {
			delete(c.entries, key)
		}
	}
}

func (c *NonceCache) enforceLimitLocked() {
	if c.max <= 0 {
		return
	}
	for len(c.entries) > c.max {
		oldestKey := ""
		var oldest time.Time
		for key, expiresAt := range c.entries {
			if oldestKey == "" || expiresAt.Before(oldest) {
				oldestKey, oldest = key, expiresAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(c.entries, oldestKey)
	}
}
