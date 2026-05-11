package limits

import (
	"errors"
	"sync"
)

var ErrConnectionLimitExceeded = errors.New("connection_limit_exceeded")

type Connections struct {
	mu           sync.Mutex
	maxGlobal    int
	maxPerIP     int
	maxPerClient int
	global       int
	byIP         map[string]int
	byClient     map[string]int
}

func NewConnections(maxGlobal, maxPerIP, maxPerClient int) *Connections {
	return &Connections{
		maxGlobal:    maxGlobal,
		maxPerIP:     maxPerIP,
		maxPerClient: maxPerClient,
		byIP:         make(map[string]int),
		byClient:     make(map[string]int),
	}
}

func (c *Connections) AcquireIP(ip string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxGlobal > 0 && c.global >= c.maxGlobal {
		return ErrConnectionLimitExceeded
	}
	if c.maxPerIP > 0 && c.byIP[ip] >= c.maxPerIP {
		return ErrConnectionLimitExceeded
	}
	c.global++
	c.byIP[ip]++
	return nil
}

func (c *Connections) ReleaseIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.global > 0 {
		c.global--
	}
	if c.byIP[ip] <= 1 {
		delete(c.byIP, ip)
	} else {
		c.byIP[ip]--
	}
}

func (c *Connections) AcquireClient(clientID string, clientLimit int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	limit := c.maxPerClient
	if clientLimit > 0 && (limit == 0 || clientLimit < limit) {
		limit = clientLimit
	}
	if limit > 0 && c.byClient[clientID] >= limit {
		return ErrConnectionLimitExceeded
	}
	c.byClient[clientID]++
	return nil
}

func (c *Connections) ReleaseClient(clientID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.byClient[clientID] <= 1 {
		delete(c.byClient, clientID)
	} else {
		c.byClient[clientID]--
	}
}
