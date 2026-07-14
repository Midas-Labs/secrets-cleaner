package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secretsweep/internal/protocol"
)

type staticAuthenticator struct {
	identity Identity
	err      error
}

func (a staticAuthenticator) Authenticate(*http.Request) (Identity, error) {
	return a.identity, a.err
}

type memoryStore struct {
	command     *protocol.Envelope
	result      *protocol.Envelope
	leaseCalls  int
	resultCalls int
}

func (s *memoryStore) Lease(_ context.Context, tenant, agent string) (*protocol.Envelope, error) {
	s.leaseCalls++
	command := s.command
	s.command = nil
	return command, nil
}

func (s *memoryStore) Complete(_ context.Context, tenant, agent, job string, result protocol.Envelope) (bool, error) {
	s.resultCalls++
	if s.result != nil {
		return false, nil
	}
	s.result = &result
	return true, nil
}

func routedEnvelope() protocol.Envelope {
	return protocol.Envelope{Version: 1, Metadata: protocol.Metadata{
		TenantID: "tenant-1", AgentID: "agent-1", JobID: "job-1", IdempotencyKey: "idem-1",
	}}
}

func TestHandlerLeasesOnlyToAuthenticatedAgent(t *testing.T) {
	store := &memoryStore{command: ptrEnvelope(routedEnvelope())}
	handler := NewHandler(staticAuthenticator{identity: Identity{TenantID: "tenant-1", AgentID: "agent-1"}}, store)

	request := httptest.NewRequest(http.MethodPost, "/v1/agents/agent-1/commands:lease", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	var leased protocol.Envelope
	if err := json.NewDecoder(response.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if leased.JobID != "job-1" {
		t.Fatalf("leased job = %q", leased.JobID)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("empty lease status = %d; want 204", response.Code)
	}
}

func TestHandlerRejectsCrossAgentLease(t *testing.T) {
	store := &memoryStore{command: ptrEnvelope(routedEnvelope())}
	handler := NewHandler(staticAuthenticator{identity: Identity{TenantID: "tenant-1", AgentID: "agent-2"}}, store)
	request := httptest.NewRequest(http.MethodPost, "/v1/agents/agent-1/commands:lease", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || store.leaseCalls != 0 {
		t.Fatalf("status=%d leaseCalls=%d", response.Code, store.leaseCalls)
	}
}

func TestHandlerAcceptsCiphertextResultIdempotently(t *testing.T) {
	store := &memoryStore{}
	handler := NewHandler(staticAuthenticator{identity: Identity{TenantID: "tenant-1", AgentID: "agent-1"}}, store)
	envelope := routedEnvelope()
	envelope.IdempotencyKey += ":result"
	envelope.Ciphertext = []byte("ciphertext-only")
	body, _ := json.Marshal(envelope)
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/jobs/job-1/results", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	if store.resultCalls != 2 || store.result == nil {
		t.Fatalf("resultCalls=%d result=%v", store.resultCalls, store.result)
	}
}

func TestHandlerRejectsMismatchedResultMetadataAndLargeBody(t *testing.T) {
	store := &memoryStore{}
	handler := NewHandler(staticAuthenticator{identity: Identity{TenantID: "tenant-1", AgentID: "agent-1"}}, store)
	envelope := routedEnvelope()
	envelope.TenantID = "tenant-2"
	body, _ := json.Marshal(envelope)
	request := httptest.NewRequest(http.MethodPost, "/v1/jobs/job-1/results", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("metadata mismatch status=%d", response.Code)
	}

	large := routedEnvelope()
	large.Ciphertext = []byte(strings.Repeat("x", MaxEnvelopeBytes+1))
	largeBody, _ := json.Marshal(large)
	request = httptest.NewRequest(http.MethodPost, "/v1/jobs/job-1/results", bytes.NewReader(largeBody))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large result status=%d", response.Code)
	}
}

func TestHandlerRequiresAuthentication(t *testing.T) {
	handler := NewHandler(staticAuthenticator{err: ErrUnauthenticated}, &memoryStore{})
	request := httptest.NewRequest(http.MethodPost, "/v1/agents/agent-1/commands:lease", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
}

func ptrEnvelope(envelope protocol.Envelope) *protocol.Envelope { return &envelope }
