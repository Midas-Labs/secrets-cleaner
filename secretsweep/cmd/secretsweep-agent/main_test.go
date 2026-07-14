package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestLoadConfigValidatesAndDecodesKeys(t *testing.T) {
	decrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlDecrypt, _ := ecdh.X25519().GenerateKey(rand.Reader)
	controlVerify, _, _ := ed25519.GenerateKey(rand.Reader)
	_, agentSign, _ := ed25519.GenerateKey(rand.Reader)
	values := map[string]string{
		"SECRETSWEEP_TENANT_ID":              "tenant-1",
		"SECRETSWEEP_AGENT_ID":               "agent-1",
		"SECRETSWEEP_CONTROL_URL":            "https://control.example.test",
		"SECRETSWEEP_AGENT_TOKEN":            "token",
		"SECRETSWEEP_BINARY":                 "/usr/local/bin/secretsweep",
		"SECRETSWEEP_X25519_PRIVATE":         base64.StdEncoding.EncodeToString(decrypt.Bytes()),
		"SECRETSWEEP_CONTROL_X25519_PUBLIC":  base64.StdEncoding.EncodeToString(controlDecrypt.PublicKey().Bytes()),
		"SECRETSWEEP_CONTROL_ED25519_PUBLIC": base64.StdEncoding.EncodeToString(controlVerify),
		"SECRETSWEEP_AGENT_ED25519_PRIVATE":  base64.StdEncoding.EncodeToString(agentSign),
	}
	config, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.tenantID != "tenant-1" || config.agentID != "agent-1" || config.decryptKey == nil {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadConfigRejectsMissingAndMalformedValues(t *testing.T) {
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("missing configuration was accepted")
	}
	values := map[string]string{
		"SECRETSWEEP_TENANT_ID":              "tenant",
		"SECRETSWEEP_AGENT_ID":               "agent",
		"SECRETSWEEP_CONTROL_URL":            "https://control.example.test",
		"SECRETSWEEP_AGENT_TOKEN":            "token",
		"SECRETSWEEP_BINARY":                 "secretsweep",
		"SECRETSWEEP_X25519_PRIVATE":         "not-base64",
		"SECRETSWEEP_CONTROL_X25519_PUBLIC":  "not-base64",
		"SECRETSWEEP_CONTROL_ED25519_PUBLIC": "not-base64",
		"SECRETSWEEP_AGENT_ED25519_PRIVATE":  "not-base64",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("malformed keys were accepted")
	}
}
