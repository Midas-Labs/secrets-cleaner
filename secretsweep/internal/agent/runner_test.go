package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"secretsweep/internal/protocol"
)

type fakePoller struct {
	command   *protocol.Envelope
	completed *protocol.Envelope
}

func (p *fakePoller) Lease(context.Context, string) (*protocol.Envelope, error) {
	return p.command, nil
}

func (p *fakePoller) Complete(_ context.Context, _ string, result protocol.Envelope) error {
	p.completed = &result
	return nil
}

type recordingExecutor struct {
	got []byte
}

func (e *recordingExecutor) Execute(_ context.Context, command []byte) ([]byte, error) {
	e.got = append([]byte(nil), command...)
	return []byte(`{"status":"review-required"}`), nil
}

func TestRunnerDecryptsCommandAndEncryptsResult(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	agentDecrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlDecrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlVerify, controlSign, _ := ed25519.GenerateKey(rand.Reader)
	_, agentSign, _ := ed25519.GenerateKey(rand.Reader)
	secret := "ghp_" + strings.Repeat("x", 36)
	commandBody := []byte(`{"operation":"scan","opaque":"` + secret + `"}`)
	command, err := protocol.Seal(commandBody, protocol.Metadata{
		TenantID: "tenant-1", AgentID: "agent-1", JobID: "job-1", IdempotencyKey: "idem-1",
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}, agentDecrypt.PublicKey(), controlSign)
	if err != nil {
		t.Fatal(err)
	}
	poller := &fakePoller{command: &command}
	executor := &recordingExecutor{}
	runner := Runner{
		TenantID: "tenant-1", AgentID: "agent-1", DecryptKey: agentDecrypt,
		ControlVerifyKey: controlVerify, ControlEncryptKey: controlDecrypt.PublicKey(),
		AgentSignKey: agentSign, Poller: poller, Executor: executor,
		Replays: NewMemoryReplayStore(), Now: func() time.Time { return now.Add(time.Minute) },
	}

	handled, err := runner.RunOnce(context.Background())
	if err != nil || !handled {
		t.Fatalf("RunOnce = %v, %v; want true, nil", handled, err)
	}
	if string(executor.got) != string(commandBody) {
		t.Fatalf("executor command = %q", executor.got)
	}
	if poller.completed == nil {
		t.Fatal("encrypted result was not completed")
	}
	encoded, _ := json.Marshal(poller.completed)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "review-required") {
		t.Fatal("completed envelope contains plaintext command or result")
	}
	result, err := protocol.Open(*poller.completed, controlDecrypt, agentSign.Public().(ed25519.PublicKey), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"status":"review-required"}` {
		t.Fatalf("result = %s", result)
	}
}

func TestRunnerRejectsReplayAndWrongTenant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	agentDecrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlDecrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlVerify, controlSign, _ := ed25519.GenerateKey(rand.Reader)
	_, agentSign, _ := ed25519.GenerateKey(rand.Reader)
	command, err := protocol.Seal([]byte("scan"), protocol.Metadata{
		TenantID: "tenant-1", AgentID: "agent-1", JobID: "job-1", IdempotencyKey: "same",
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}, agentDecrypt.PublicKey(), controlSign)
	if err != nil {
		t.Fatal(err)
	}
	poller := &fakePoller{command: &command}
	runner := Runner{
		TenantID: "tenant-1", AgentID: "agent-1", DecryptKey: agentDecrypt,
		ControlVerifyKey: controlVerify, ControlEncryptKey: controlDecrypt.PublicKey(), AgentSignKey: agentSign,
		Poller: poller, Executor: &recordingExecutor{}, Replays: NewMemoryReplayStore(), Now: func() time.Time { return now },
	}
	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("second RunOnce error = %v; want replay rejection", err)
	}

	wrong := runner
	wrong.TenantID = "tenant-2"
	wrong.Replays = NewMemoryReplayStore()
	if _, err := wrong.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("wrong-tenant error = %v", err)
	}
}

func TestRunnerNoCommandIsNotAnError(t *testing.T) {
	runner := Runner{Poller: &fakePoller{}}
	handled, err := runner.RunOnce(context.Background())
	if err != nil || handled {
		t.Fatalf("RunOnce = %v, %v; want false, nil", handled, err)
	}
}
