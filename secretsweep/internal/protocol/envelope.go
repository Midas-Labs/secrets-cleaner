package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	CurrentVersion = 1
	maxClockSkew   = 2 * time.Minute
	maxLifetime    = 24 * time.Hour
)

type Metadata struct {
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	JobID          string    `json:"job_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Envelope struct {
	Version int `json:"version"`
	Metadata
	EphemeralPublic []byte `json:"ephemeral_public"`
	Nonce           []byte `json:"nonce"`
	Ciphertext      []byte `json:"ciphertext"`
	Signature       []byte `json:"signature"`
}

func (e Envelope) ReplayKey() string {
	return strings.Join([]string{e.TenantID, e.AgentID, e.IdempotencyKey}, "/")
}

func Seal(plaintext []byte, meta Metadata, recipient *ecdh.PublicKey, signer ed25519.PrivateKey) (Envelope, error) {
	if recipient == nil {
		return Envelope{}, errors.New("recipient public key is required")
	}
	if len(signer) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("valid signing key is required")
	}
	if err := validateMetadata(meta); err != nil {
		return Envelope{}, err
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Envelope{}, fmt.Errorf("derive shared key: %w", err)
	}

	envelope := Envelope{
		Version:         CurrentVersion,
		Metadata:        normalizeMetadata(meta),
		EphemeralPublic: ephemeral.PublicKey().Bytes(),
	}
	aead, nonce, err := newAEAD(shared, nil)
	if err != nil {
		return Envelope{}, err
	}
	envelope.Nonce = nonce
	aad, err := envelope.associatedData()
	if err != nil {
		return Envelope{}, err
	}
	envelope.Ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	signed, err := envelope.signingBytes()
	if err != nil {
		return Envelope{}, err
	}
	envelope.Signature = ed25519.Sign(signer, signed)
	return envelope, nil
}

func Open(envelope Envelope, recipient *ecdh.PrivateKey, verifier ed25519.PublicKey, now time.Time) ([]byte, error) {
	if envelope.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", envelope.Version)
	}
	if recipient == nil {
		return nil, errors.New("recipient private key is required")
	}
	if len(verifier) != ed25519.PublicKeySize {
		return nil, errors.New("valid verification key is required")
	}
	if err := validateMetadata(envelope.Metadata); err != nil {
		return nil, err
	}
	signed, err := envelope.signingBytes()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(verifier, signed, envelope.Signature) {
		return nil, errors.New("envelope signature is invalid")
	}
	now = now.UTC()
	if now.After(envelope.ExpiresAt) {
		return nil, errors.New("envelope has expired")
	}
	if envelope.CreatedAt.After(now.Add(maxClockSkew)) {
		return nil, errors.New("envelope creation time is too far in the future")
	}

	public, err := ecdh.X25519().NewPublicKey(envelope.EphemeralPublic)
	if err != nil {
		return nil, errors.New("invalid ephemeral public key")
	}
	shared, err := recipient.ECDH(public)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}
	aead, _, err := newAEAD(shared, envelope.Nonce)
	if err != nil {
		return nil, err
	}
	aad, err := envelope.associatedData()
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("envelope authentication failed")
	}
	return plaintext, nil
}

func validateMetadata(meta Metadata) error {
	if strings.TrimSpace(meta.TenantID) == "" || strings.TrimSpace(meta.AgentID) == "" ||
		strings.TrimSpace(meta.JobID) == "" || strings.TrimSpace(meta.IdempotencyKey) == "" {
		return errors.New("tenant, agent, job, and idempotency identifiers are required")
	}
	if meta.CreatedAt.IsZero() || meta.ExpiresAt.IsZero() {
		return errors.New("creation and expiry times are required")
	}
	if !meta.ExpiresAt.After(meta.CreatedAt) {
		return errors.New("expiry must be after creation time")
	}
	if meta.ExpiresAt.Sub(meta.CreatedAt) > maxLifetime {
		return errors.New("envelope lifetime exceeds 24 hours")
	}
	return nil
}

func normalizeMetadata(meta Metadata) Metadata {
	meta.CreatedAt = meta.CreatedAt.UTC()
	meta.ExpiresAt = meta.ExpiresAt.UTC()
	return meta
}

func newAEAD(shared, nonce []byte) (cipher.AEAD, []byte, error) {
	key, err := hkdf.Key(sha256.New, shared, nil, "secretsweep/envelope/v1", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create AEAD: %w", err)
	}
	if nonce == nil {
		nonce = make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, nil, fmt.Errorf("generate nonce: %w", err)
		}
	}
	if len(nonce) != aead.NonceSize() {
		return nil, nil, errors.New("invalid nonce length")
	}
	return aead, nonce, nil
}

func (e Envelope) associatedData() ([]byte, error) {
	return json.Marshal(struct {
		Version int `json:"version"`
		Metadata
		EphemeralPublic []byte `json:"ephemeral_public"`
		Nonce           []byte `json:"nonce"`
	}{e.Version, normalizeMetadata(e.Metadata), e.EphemeralPublic, e.Nonce})
}

func (e Envelope) signingBytes() ([]byte, error) {
	return json.Marshal(struct {
		Version int `json:"version"`
		Metadata
		EphemeralPublic []byte `json:"ephemeral_public"`
		Nonce           []byte `json:"nonce"`
		Ciphertext      []byte `json:"ciphertext"`
	}{e.Version, normalizeMetadata(e.Metadata), e.EphemeralPublic, e.Nonce, e.Ciphertext})
}
