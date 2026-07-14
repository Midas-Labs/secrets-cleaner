package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"secretsweep/internal/protocol"
)

const MaxEnvelopeBytes = 4 << 20

var ErrUnauthenticated = errors.New("unauthenticated")

type Identity struct {
	TenantID string
	AgentID  string
}

type Authenticator interface {
	Authenticate(request *http.Request) (Identity, error)
}

type Store interface {
	Lease(ctx context.Context, tenantID, agentID string) (*protocol.Envelope, error)
	Complete(ctx context.Context, tenantID, agentID, jobID string, result protocol.Envelope) (inserted bool, err error)
}

type Handler struct {
	auth  Authenticator
	store Store
	mux   *http.ServeMux
}

func NewHandler(auth Authenticator, store Store) *Handler {
	handler := &Handler{auth: auth, store: store, mux: http.NewServeMux()}
	handler.mux.HandleFunc("POST /v1/agents/{agent}/commands:lease", handler.lease)
	handler.mux.HandleFunc("POST /v1/jobs/{job}/results", handler.complete)
	handler.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return handler
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	h.mux.ServeHTTP(response, request)
}

func (h *Handler) lease(response http.ResponseWriter, request *http.Request) {
	identity, ok := h.authenticate(response, request)
	if !ok {
		return
	}
	if identity.AgentID != request.PathValue("agent") {
		writeError(response, http.StatusForbidden, "agent access denied")
		return
	}
	envelope, err := h.store.Lease(request.Context(), identity.TenantID, identity.AgentID)
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "command store unavailable")
		return
	}
	if envelope == nil {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if envelope.TenantID != identity.TenantID || envelope.AgentID != identity.AgentID {
		writeError(response, http.StatusInternalServerError, "invalid command routing metadata")
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(response).Encode(envelope); err != nil {
		return
	}
}

func (h *Handler) complete(response http.ResponseWriter, request *http.Request) {
	identity, ok := h.authenticate(response, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaxEnvelopeBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var envelope protocol.Envelope
	if err := decoder.Decode(&envelope); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(response, http.StatusRequestEntityTooLarge, "envelope is too large")
			return
		}
		writeError(response, http.StatusBadRequest, "invalid result envelope")
		return
	}
	jobID := request.PathValue("job")
	if envelope.TenantID != identity.TenantID || envelope.AgentID != identity.AgentID || envelope.JobID != jobID {
		writeError(response, http.StatusForbidden, "result routing metadata does not match identity")
		return
	}
	if _, err := h.store.Complete(request.Context(), identity.TenantID, identity.AgentID, jobID, envelope); err != nil {
		writeError(response, http.StatusServiceUnavailable, "result store unavailable")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authenticate(response http.ResponseWriter, request *http.Request) (Identity, bool) {
	if h.auth == nil || h.store == nil {
		writeError(response, http.StatusServiceUnavailable, "service unavailable")
		return Identity{}, false
	}
	identity, err := h.auth.Authenticate(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication required")
		return Identity{}, false
	}
	if identity.TenantID == "" || identity.AgentID == "" {
		writeError(response, http.StatusUnauthorized, "authentication required")
		return Identity{}, false
	}
	return identity, true
}

func writeError(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": message})
}
