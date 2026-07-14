package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secretsweep/internal/protocol"
)

func TestParseLocalCommandAllowsOnlyNonDestructiveOperations(t *testing.T) {
	for _, operation := range []string{"scan", "dry-run"} {
		command, err := ParseLocalCommand([]byte(`{"operation":"` + operation + `","targets":["/repos/team"]}`))
		if err != nil || command.Operation != operation {
			t.Fatalf("ParseLocalCommand(%s) = %#v, %v", operation, command, err)
		}
	}
	for _, body := range []string{
		`{"operation":"rewrite","targets":["/repos/team"]}`,
		`{"operation":"scan","targets":[]}`,
		`{"operation":"scan","targets":["relative"]}`,
		`{"operation":"scan","targets":["/repos/team"],"replacement":"secret"}`,
	} {
		if _, err := ParseLocalCommand([]byte(body)); err == nil {
			t.Fatalf("unsafe command accepted: %s", body)
		}
	}
}

func TestHTTPPollerLeasesAndCompletesWithBearerToken(t *testing.T) {
	var completed bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/commands:lease"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"version": 1})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/results"):
			completed = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	poller, err := NewHTTPPoller(server.URL, "local-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := poller.Lease(context.Background(), "agent/id"); err != nil {
		t.Fatal(err)
	}
	if err := poller.Complete(context.Background(), "job/id", protocol.Envelope{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("completion endpoint was not called")
	}
}

func TestHTTPPollerRequiresHTTPSExceptLoopback(t *testing.T) {
	if _, err := NewHTTPPoller("http://example.com", "token", http.DefaultClient); err == nil {
		t.Fatal("non-loopback plaintext HTTP was accepted")
	}
	if _, err := NewHTTPPoller("http://localhost:8080", "token", http.DefaultClient); err != nil {
		t.Fatalf("loopback development HTTP rejected: %v", err)
	}
}
