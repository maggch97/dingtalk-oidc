package store

import (
	"errors"
	"sync"
	"time"
)

// PendingAuth stores data about an in-progress DingTalk authorization (before we have DingTalk code exchanged).
type PendingAuth struct {
	ClientID      string
	RedirectURI   string
	OriginalState string // state provided by OIDC client
	Nonce         string
	Scope         string
	CreatedAt     time.Time
}

type PendingStore struct {
	mu   sync.RWMutex
	data map[string]PendingAuth
}

func NewPendingStore() *PendingStore { return &PendingStore{data: make(map[string]PendingAuth)} }

// Create stores and returns an internal state key.
func (s *PendingStore) Create(p PendingAuth) (string, error) {
	key, err := secureRandomString(24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.data[key] = p
	s.mu.Unlock()
	return key, nil
}

// Consume returns and removes an entry.
func (s *PendingStore) Consume(key string) (PendingAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data[key]
	if !ok {
		return PendingAuth{}, errors.New("invalid_state")
	}
	delete(s.data, key)
	// basic expiry (10 min)
	if time.Since(p.CreatedAt) > 10*time.Minute {
		return PendingAuth{}, errors.New("expired_state")
	}
	return p, nil
}

// Cleanup removes expired entries.
func (s *PendingStore) Cleanup() {
	cut := time.Now().Add(-10 * time.Minute)
	s.mu.Lock()
	for k, v := range s.data {
		if v.CreatedAt.Before(cut) {
			delete(s.data, k)
		}
	}
	s.mu.Unlock()
}
