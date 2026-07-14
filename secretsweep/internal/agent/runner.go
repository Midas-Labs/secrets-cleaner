package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"secretsweep/internal/protocol"
)

type Poller interface {
	Lease(ctx context.Context, agentID string) (*protocol.Envelope, error)
	Complete(ctx context.Context, jobID string, result protocol.Envelope) error
}

type Executor interface {
	Execute(ctx context.Context, command []byte) ([]byte, error)
}

type ReplayStore interface {
	Use(key string, expiresAt time.Time, now time.Time) bool
}

type Runner struct {
	TenantID          string
	AgentID           string
	DecryptKey        *ecdh.PrivateKey
	ControlVerifyKey  ed25519.PublicKey
	ControlEncryptKey *ecdh.PublicKey
	AgentSignKey      ed25519.PrivateKey
	Poller            Poller
	Executor          Executor
	Replays           ReplayStore
	Now               func() time.Time
}

func (r Runner) RunOnce(ctx context.Context) (bool, error) {
	if r.Poller == nil {
		return false, errors.New("poller is required")
	}
	envelope, err := r.Poller.Lease(ctx, r.AgentID)
	if err != nil {
		return false, fmt.Errorf("lease command: %w", err)
	}
	if envelope == nil {
		return false, nil
	}
	if envelope.TenantID != r.TenantID {
		return false, errors.New("leased command belongs to another tenant")
	}
	if envelope.AgentID != r.AgentID {
		return false, errors.New("leased command belongs to another agent")
	}
	if r.Executor == nil || r.Replays == nil || r.Now == nil || r.ControlEncryptKey == nil {
		return false, errors.New("runner is not fully configured")
	}
	now := r.Now().UTC()
	command, err := protocol.Open(*envelope, r.DecryptKey, r.ControlVerifyKey, now)
	if err != nil {
		return false, fmt.Errorf("open command: %w", err)
	}
	if !r.Replays.Use(envelope.ReplayKey(), envelope.ExpiresAt, now) {
		return false, errors.New("command replay rejected")
	}
	result, err := r.Executor.Execute(ctx, command)
	if err != nil {
		return false, fmt.Errorf("execute command: %w", err)
	}
	resultEnvelope, err := protocol.Seal(result, protocol.Metadata{
		TenantID:       envelope.TenantID,
		AgentID:        envelope.AgentID,
		JobID:          envelope.JobID,
		IdempotencyKey: envelope.IdempotencyKey + ":result",
		CreatedAt:      now,
		ExpiresAt:      envelope.ExpiresAt,
	}, r.ControlEncryptKey, r.AgentSignKey)
	if err != nil {
		return false, fmt.Errorf("seal result: %w", err)
	}
	if err := r.Poller.Complete(ctx, envelope.JobID, resultEnvelope); err != nil {
		return false, fmt.Errorf("complete command: %w", err)
	}
	return true, nil
}

type MemoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: make(map[string]time.Time)}
}

func (s *MemoryReplayStore) Use(key string, expiresAt, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for existing, expiry := range s.seen {
		if now.After(expiry) {
			delete(s.seen, existing)
		}
	}
	if _, exists := s.seen[key]; exists {
		return false
	}
	s.seen[key] = expiresAt
	return true
}
