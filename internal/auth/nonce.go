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
	entries map[string]time.Time
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceCache{
		ttl:     ttl,
		entries: make(map[string]time.Time),
	}
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
	return nil
}

func (c *NonceCache) pruneLocked(now time.Time) {
	for key, expiresAt := range c.entries {
		if !expiresAt.After(now) {
			delete(c.entries, key)
		}
	}
}
