package limits

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	maxKeys  int
	events   map[string][]time.Time
	lastSeen map[string]time.Time
}

func NewRateLimiter(spec string) (*RateLimiter, error) { return NewRateLimiterWithLimit(spec, 0) }

func NewRateLimiterWithLimit(spec string, maxKeys int) (*RateLimiter, error) {
	limit, window, err := ParseRate(spec)
	if err != nil {
		return nil, err
	}
	return &RateLimiter{
		limit: limit, window: window, maxKeys: maxKeys,
		events: make(map[string][]time.Time), lastSeen: make(map[string]time.Time),
	}, nil
}

func ParseRate(spec string) (int, time.Duration, error) {
	parts := strings.Split(spec, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid rate %q, expected count/duration like 10/10s", spec)
	}
	limit, err := strconv.Atoi(parts[0])
	if err != nil || limit <= 0 {
		return 0, 0, fmt.Errorf("invalid rate count %q", parts[0])
	}
	window, err := time.ParseDuration(parts[1])
	if err != nil || window <= 0 {
		return 0, 0, fmt.Errorf("invalid rate window %q", parts[1])
	}
	return limit, window, nil
}

func (r *RateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)
	r.pruneLocked(cutoff, now)
	events := r.events[key]
	keep := events[:0]
	for _, t := range events {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= r.limit {
		r.events[key] = keep
		return false
	}
	keep = append(keep, now)
	r.events[key] = keep
	r.lastSeen[key] = now
	if r.maxKeys > 0 && len(r.events) > r.maxKeys {
		r.evictOldestLocked()
	}
	return true
}

func (r *RateLimiter) pruneLocked(cutoff, now time.Time) {
	for key, events := range r.events {
		keep := events[:0]
		for _, t := range events {
			if t.After(cutoff) {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(r.events, key)
			delete(r.lastSeen, key)
		} else {
			r.events[key] = keep
			r.lastSeen[key] = keep[len(keep)-1]
		}
	}
}

func (r *RateLimiter) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, t := range r.lastSeen {
		if oldestKey == "" || t.Before(oldest) {
			oldestKey, oldest = key, t
		}
	}
	if oldestKey != "" {
		delete(r.events, oldestKey)
		delete(r.lastSeen, oldestKey)
	}
}
