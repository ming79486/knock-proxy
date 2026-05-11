package limits

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events map[string][]time.Time
}

func NewRateLimiter(spec string) (*RateLimiter, error) {
	limit, window, err := ParseRate(spec)
	if err != nil {
		return nil, err
	}
	return &RateLimiter{
		limit:  limit,
		window: window,
		events: make(map[string][]time.Time),
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
	return true
}
