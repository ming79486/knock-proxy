package app

import (
	"net"
	"sync"
	"time"
)

type knockStore struct {
	mu      sync.Mutex
	entries map[string]map[string]knockEntry
}

type knockEntry struct {
	count     int
	expiresAt time.Time
}

func newKnockStore() *knockStore {
	return &knockStore{entries: make(map[string]map[string]knockEntry)}
}

func (s *knockStore) add(ip net.IP, clientID string, ttl time.Duration, now time.Time, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count <= 0 {
		count = 1
	}
	key := ip.String()
	if s.entries[key] == nil {
		s.entries[key] = make(map[string]knockEntry)
	}
	entry := s.entries[key][clientID]
	entry.count += count
	entry.expiresAt = now.Add(ttl)
	s.entries[key][clientID] = entry
}

func (s *knockStore) has(ip net.IP, clientID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := ip.String()
	clients, ok := s.entries[key]
	if !ok {
		return false
	}
	entry, ok := clients[clientID]
	if !ok {
		return false
	}
	if !entry.expiresAt.After(now) {
		delete(clients, clientID)
		if len(clients) == 0 {
			delete(s.entries, key)
		}
		return false
	}
	return true
}

func (s *knockStore) removeOne(ip net.IP, clientID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ip.String()
	clients, ok := s.entries[key]
	if !ok {
		return true
	}
	s.pruneIPLocked(key, now)
	entry, ok := clients[clientID]
	if ok {
		entry.count--
		if entry.count <= 0 {
			delete(clients, clientID)
		} else {
			clients[clientID] = entry
		}
	}
	if len(clients) == 0 {
		delete(s.entries, key)
		return true
	}
	return false
}

func (s *knockStore) expire(ip net.IP, clientID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ip.String()
	clients, ok := s.entries[key]
	if !ok {
		return true
	}
	entry, ok := clients[clientID]
	if ok && !entry.expiresAt.After(now) {
		delete(clients, clientID)
	}
	s.pruneIPLocked(key, now)
	if len(clients) == 0 {
		delete(s.entries, key)
		return true
	}
	return false
}

func (s *knockStore) removeIP(ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, ip.String())
}

func (s *knockStore) consumeAny(ip net.IP, now time.Time) (string, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ip.String()
	clients, ok := s.entries[key]
	if !ok {
		return "", false, true
	}
	s.pruneIPLocked(key, now)
	for clientID, entry := range clients {
		entry.count--
		if entry.count <= 0 {
			delete(clients, clientID)
		} else {
			clients[clientID] = entry
		}
		if len(clients) == 0 {
			delete(s.entries, key)
			return clientID, true, true
		}
		return clientID, true, false
	}
	delete(s.entries, key)
	return "", false, true
}

func (s *knockStore) pruneIPLocked(key string, now time.Time) {
	clients := s.entries[key]
	for clientID, entry := range clients {
		if !entry.expiresAt.After(now) {
			delete(clients, clientID)
		}
	}
}
