package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"secretsweep/internal/agent"
)

const agentVersion = "0.1.0"

type config struct {
	tenantID       string
	agentID        string
	controlURL     string
	token          string
	binary         string
	decryptKey     *ecdh.PrivateKey
	controlEncrypt *ecdh.PublicKey
	controlVerify  ed25519.PublicKey
	agentSign      ed25519.PrivateKey
}

func main() {
	once := flag.Bool("once", false, "lease and process at most one command")
	interval := flag.Duration("poll-interval", 5*time.Second, "delay between empty leases")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("secretsweep-agent %s\n", agentVersion)
		return
	}
	if *interval < time.Second {
		fatal("poll interval must be at least one second")
	}
	configuration, err := loadConfig(os.Getenv)
	if err != nil {
		fatal("configuration: %v", err)
	}
	client := &http.Client{Timeout: 45 * time.Second}
	poller, err := agent.NewHTTPPoller(configuration.controlURL, configuration.token, client)
	if err != nil {
		fatal("configuration: %v", err)
	}
	runner := agent.Runner{
		TenantID:          configuration.tenantID,
		AgentID:           configuration.agentID,
		DecryptKey:        configuration.decryptKey,
		ControlVerifyKey:  configuration.controlVerify,
		ControlEncryptKey: configuration.controlEncrypt,
		AgentSignKey:      configuration.agentSign,
		Poller:            poller,
		Executor:          agent.CLIExecutor{Binary: configuration.binary},
		Replays:           agent.NewMemoryReplayStore(),
		Now:               time.Now,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		handled, err := runner.RunOnce(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent command failed: %v\n", err)
		}
		if *once {
			if err != nil {
				os.Exit(1)
			}
			return
		}
		if handled {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}

func loadConfig(getenv func(string) string) (config, error) {
	required := []string{
		"SECRETSWEEP_TENANT_ID", "SECRETSWEEP_AGENT_ID", "SECRETSWEEP_CONTROL_URL", "SECRETSWEEP_AGENT_TOKEN",
		"SECRETSWEEP_X25519_PRIVATE", "SECRETSWEEP_CONTROL_X25519_PUBLIC",
		"SECRETSWEEP_CONTROL_ED25519_PUBLIC", "SECRETSWEEP_AGENT_ED25519_PRIVATE",
	}
	for _, key := range required {
		if strings.TrimSpace(getenv(key)) == "" {
			return config{}, fmt.Errorf("%s is required", key)
		}
	}
	privateBytes, err := decodeKey(getenv("SECRETSWEEP_X25519_PRIVATE"), 32)
	if err != nil {
		return config{}, fmt.Errorf("agent X25519 private key: %w", err)
	}
	decryptKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return config{}, fmt.Errorf("agent X25519 private key: %w", err)
	}
	publicBytes, err := decodeKey(getenv("SECRETSWEEP_CONTROL_X25519_PUBLIC"), 32)
	if err != nil {
		return config{}, fmt.Errorf("control X25519 public key: %w", err)
	}
	controlEncrypt, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return config{}, fmt.Errorf("control X25519 public key: %w", err)
	}
	controlVerify, err := decodeKey(getenv("SECRETSWEEP_CONTROL_ED25519_PUBLIC"), ed25519.PublicKeySize)
	if err != nil {
		return config{}, fmt.Errorf("control Ed25519 public key: %w", err)
	}
	agentSign, err := decodeKey(getenv("SECRETSWEEP_AGENT_ED25519_PRIVATE"), ed25519.PrivateKeySize)
	if err != nil {
		return config{}, fmt.Errorf("agent Ed25519 private key: %w", err)
	}
	binary := strings.TrimSpace(getenv("SECRETSWEEP_BINARY"))
	if binary == "" {
		binary = "secretsweep"
	}
	return config{
		tenantID: strings.TrimSpace(getenv("SECRETSWEEP_TENANT_ID")), agentID: strings.TrimSpace(getenv("SECRETSWEEP_AGENT_ID")),
		controlURL: strings.TrimSpace(getenv("SECRETSWEEP_CONTROL_URL")), token: getenv("SECRETSWEEP_AGENT_TOKEN"), binary: binary,
		decryptKey: decryptKey, controlEncrypt: controlEncrypt, controlVerify: ed25519.PublicKey(controlVerify), agentSign: ed25519.PrivateKey(agentSign),
	}, nil
}

func decodeKey(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("must be standard base64")
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("decoded length is %d, want %d", len(decoded), size)
	}
	return decoded, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
