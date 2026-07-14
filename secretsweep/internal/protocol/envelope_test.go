package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func protocolKeys(t *testing.T) (*ecdh.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return recipient, verify, sign
}

func testMetadata(now time.Time) Metadata {
	return Metadata{
		TenantID:       "tenant-1",
		AgentID:        "agent-1",
		JobID:          "job-1",
		IdempotencyKey: "idem-1",
		CreatedAt:      now,
		ExpiresAt:      now.Add(5 * time.Minute),
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	recipient, verify, sign := protocolKeys(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	payload := []byte(`{"operation":"scan","plan_hash":"abc123"}`)
	envelope, err := Seal(payload, testMetadata(now), recipient.PublicKey(), sign)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(envelope, recipient, verify, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("Open payload = %q; want %q", got, payload)
	}
	if got := envelope.ReplayKey(); got != "tenant-1/agent-1/idem-1" {
		t.Fatalf("ReplayKey = %q", got)
	}
}

func TestEnvelopeJSONDoesNotContainPlaintext(t *testing.T) {
	recipient, _, sign := protocolKeys(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	secret := "ghp_" + strings.Repeat("x", 36)
	envelope, err := Seal([]byte(`{"secret":"`+secret+`"}`), testMetadata(now), recipient.PublicKey(), sign)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("serialized envelope contains plaintext")
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	recipient, verify, sign := protocolKeys(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	envelope, err := Seal([]byte("command"), testMetadata(now), recipient.PublicKey(), sign)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("metadata", func(t *testing.T) {
		tampered := envelope
		tampered.JobID = "another-job"
		if _, err := Open(tampered, recipient, verify, now); err == nil {
			t.Fatal("tampered metadata was accepted")
		}
	})

	t.Run("ciphertext", func(t *testing.T) {
		tampered := envelope
		tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
		tampered.Ciphertext[0] ^= 0xff
		if _, err := Open(tampered, recipient, verify, now); err == nil {
			t.Fatal("tampered ciphertext was accepted")
		}
	})

	t.Run("signature", func(t *testing.T) {
		tampered := envelope
		tampered.Signature = append([]byte(nil), envelope.Signature...)
		tampered.Signature[0] ^= 0xff
		if _, err := Open(tampered, recipient, verify, now); err == nil {
			t.Fatal("tampered signature was accepted")
		}
	})
}

func TestEnvelopeRejectsExpiredFutureAndUnknownVersion(t *testing.T) {
	recipient, verify, sign := protocolKeys(t)
	now := time.Unix(1_800_000_000, 0).UTC()

	expiredMeta := testMetadata(now)
	expiredMeta.ExpiresAt = now.Add(-time.Second)
	if _, err := Seal([]byte("command"), expiredMeta, recipient.PublicKey(), sign); err == nil {
		t.Fatal("Seal accepted an already-expired envelope")
	}

	envelope, err := Seal([]byte("command"), testMetadata(now), recipient.PublicKey(), sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(envelope, recipient, verify, envelope.ExpiresAt.Add(time.Nanosecond)); err == nil {
		t.Fatal("Open accepted an expired envelope")
	}

	future := envelope
	future.CreatedAt = now.Add(10 * time.Minute)
	if _, err := Open(future, recipient, verify, now); err == nil {
		t.Fatal("Open accepted future-dated metadata")
	}

	unknown := envelope
	unknown.Version = 99
	if _, err := Open(unknown, recipient, verify, now); err == nil {
		t.Fatal("Open accepted an unknown protocol version")
	}
}

func TestEnvelopeValidatesRequiredMetadata(t *testing.T) {
	recipient, _, sign := protocolKeys(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	meta := testMetadata(now)
	meta.IdempotencyKey = ""
	if _, err := Seal([]byte("command"), meta, recipient.PublicKey(), sign); err == nil {
		t.Fatal("Seal accepted a missing idempotency key")
	}
}
