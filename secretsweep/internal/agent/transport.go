package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"secretsweep/internal/protocol"
)

const maxEnvelopeBytes = 4 << 20

type LocalCommand struct {
	Operation string   `json:"operation"`
	Targets   []string `json:"targets"`
}

func ParseLocalCommand(data []byte) (LocalCommand, error) {
	var command LocalCommand
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return LocalCommand{}, fmt.Errorf("decode local command: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return LocalCommand{}, err
	}
	if command.Operation != "scan" && command.Operation != "dry-run" {
		return LocalCommand{}, errors.New("remote operation must be scan or dry-run; rewrite approval is local-only")
	}
	if len(command.Targets) == 0 {
		return LocalCommand{}, errors.New("at least one local target is required")
	}
	for _, target := range command.Targets {
		if !filepath.IsAbs(target) || strings.ContainsRune(target, '\x00') {
			return LocalCommand{}, errors.New("all local targets must be absolute paths")
		}
	}
	return command, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("command contains multiple JSON values")
		}
		return err
	}
	return nil
}

type HTTPPoller struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewHTTPPoller(baseURL, token string, client *http.Client) (*HTTPPoller, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" {
		return nil, errors.New("valid control-plane URL is required")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("control-plane URL must use HTTPS except on loopback")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("agent bearer token is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPPoller{baseURL: strings.TrimRight(baseURL, "/"), token: token, client: client}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *HTTPPoller) Lease(ctx context.Context, agentID string) (*protocol.Envelope, error) {
	endpoint := p.baseURL + "/v1/agents/" + url.PathEscape(agentID) + "/commands:lease"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	p.authorize(req)
	response, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, responseError(response)
	}
	var envelope protocol.Envelope
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxEnvelopeBytes))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode leased envelope: %w", err)
	}
	return &envelope, nil
}

func (p *HTTPPoller) Complete(ctx context.Context, jobID string, result protocol.Envelope) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	endpoint := p.baseURL + "/v1/jobs/" + url.PathEscape(jobID) + "/results"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	p.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return responseError(response)
	}
	return nil
}

func (p *HTTPPoller) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Accept", "application/json")
}

func responseError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("control plane returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
