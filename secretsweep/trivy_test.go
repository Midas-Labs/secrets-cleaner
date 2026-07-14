package main

import (
	"strings"
	"testing"
)

// token builds a fake secret at runtime so the source itself never contains
// a literal that a secret scanner would flag.
func token(prefix string, n int) string {
	return prefix + strings.Repeat("x", n)
}

func TestRecoverSecret(t *testing.T) {
	secret := token("ghp_", 36)
	raw := `github_token = "` + secret + `"`
	match := `github_token = "` + strings.Repeat("*", len(secret)) + `"`

	got, ok := recoverSecret(raw, match)
	if !ok || got != secret {
		t.Fatalf("recoverSecret = %q, %v; want %q, true", got, ok, secret)
	}
}

func TestRecoverSecretLengthMismatch(t *testing.T) {
	if _, ok := recoverSecret("short", "much longer redacted ****"); ok {
		t.Fatal("expected recovery to fail on length mismatch")
	}
}

func TestRecoverSecretNoMask(t *testing.T) {
	if _, ok := recoverSecret("plain line", "plain line"); ok {
		t.Fatal("expected recovery to fail without a mask run")
	}
}

func TestRecoverSecretRawAsterisks(t *testing.T) {
	raw := `password = "` + strings.Repeat("*", 12) + `"`
	if _, ok := recoverSecret(raw, raw); ok {
		t.Fatal("expected recovery to fail when the raw text is asterisks")
	}
}

func TestRecoverSecretPicksLongestRun(t *testing.T) {
	secret := token("sk_live_", 24)
	raw := `x = "**"; key = "` + secret + `"`
	match := `x = "**"; key = "` + strings.Repeat("*", len(secret)) + `"`
	got, ok := recoverSecret(raw, match)
	if !ok || got != secret {
		t.Fatalf("recoverSecret = %q, %v; want %q, true", got, ok, secret)
	}
}

func TestUniqueSecrets(t *testing.T) {
	a, b := token("ghp_", 36), token("AKIA", 16)
	findings := []Finding{
		{Secret: a},
		{Secret: b},
		{Secret: a},
		{Secret: ""},
	}
	secrets, unrecovered := UniqueSecrets(findings)
	if len(secrets) != 2 || secrets[0] != a || secrets[1] != b {
		t.Fatalf("secrets = %v; want [%s %s]", secrets, a, b)
	}
	if unrecovered != 1 {
		t.Fatalf("unrecovered = %d; want 1", unrecovered)
	}
}

func TestMasked(t *testing.T) {
	f := Finding{Secret: token("ghp_", 36)}
	masked := f.Masked()
	if strings.Contains(masked, "x") && strings.Count(masked, "x") > 4 {
		t.Fatalf("masked form leaks too much: %q", masked)
	}
	if !strings.HasPrefix(masked, "ghp_") {
		t.Fatalf("masked form should keep a short prefix: %q", masked)
	}
}
