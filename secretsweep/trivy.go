package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Finding is one secret Trivy located in a repository's working tree.
type Finding struct {
	Repo     string // absolute repository path
	File     string // path relative to the repository root
	Line     int
	RuleID   string
	Title    string
	Severity string
	Secret   string // exact recovered secret; empty when recovery failed
}

// StableID identifies a finding across filtering and sorting without placing
// the raw secret in UI state or logs.
func (f Finding) StableID() string {
	secretDigest := sha256.Sum256([]byte(f.Secret))
	material := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%x", f.Repo, f.File, f.Line, f.RuleID, secretDigest)
	digest := sha256.Sum256([]byte(material))
	return fmt.Sprintf("fnd_%x", digest[:12])
}

// Masked returns a display-safe form of the secret.
func (f Finding) Masked() string {
	s := f.Secret
	if s == "" {
		return "(unrecovered — review manually)"
	}
	if len(s) <= 12 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + strings.Repeat("•", 6) + s[len(s)-4:]
}

type trivyReport struct {
	Results []struct {
		Target  string `json:"Target"`
		Class   string `json:"Class"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Match     string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

// ScanRepo runs a Trivy secret scan over the repository's working tree and
// recovers the exact secret values that Trivy redacts in its output.
func ScanRepo(repo string) ([]Finding, error) {
	cmd := exec.Command("trivy", "fs", "--scanners", "secret", "--format", "json", "--quiet", repo)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("trivy failed: %w", err)
	}

	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("cannot parse trivy output: %w", err)
	}

	var findings []Finding
	for _, result := range report.Results {
		if result.Class != "secret" {
			continue
		}
		for _, s := range result.Secrets {
			finding := Finding{
				Repo:     repo,
				File:     result.Target,
				Line:     s.StartLine,
				RuleID:   s.RuleID,
				Title:    s.Title,
				Severity: s.Severity,
			}
			if s.StartLine == s.EndLine {
				if raw, ok := readLine(filepath.Join(repo, result.Target), s.StartLine); ok {
					if secret, ok := recoverSecret(raw, s.Match); ok {
						finding.Secret = secret
					}
				}
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// TrivyAvailable reports whether the trivy binary can be executed.
func TrivyAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func readLine(path string, number int) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(data), "\n")
	if number < 1 || number > len(lines) {
		return "", false
	}
	return strings.TrimSuffix(lines[number-1], "\r"), true
}

// recoverSecret reverses Trivy's redaction. Trivy reports the matched line
// with the secret's characters replaced by asterisks; because the redacted
// and raw lines are the same length, the longest asterisk run in the match
// addresses the secret's exact position in the raw line.
func recoverSecret(raw, match string) (string, bool) {
	if len(raw) != len(match) {
		return "", false
	}
	bestStart, bestLen := -1, 0
	curStart, curLen := -1, 0
	for i := 0; i <= len(match); i++ {
		if i < len(match) && match[i] == '*' {
			if curStart < 0 {
				curStart = i
			}
			curLen++
			continue
		}
		if curLen > bestLen {
			bestStart, bestLen = curStart, curLen
		}
		curStart, curLen = -1, 0
	}
	if bestLen < 4 {
		return "", false
	}
	secret := raw[bestStart : bestStart+bestLen]
	if strings.Count(secret, "*") == len(secret) {
		return "", false // the raw text really is asterisks; nothing to recover
	}
	return secret, true
}

// UniqueSecrets returns the distinct recovered secret values in order of
// first appearance, plus the number of findings whose secret could not be
// recovered.
func UniqueSecrets(findings []Finding) (secrets []string, unrecovered int) {
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Secret == "" {
			unrecovered++
			continue
		}
		if !seen[f.Secret] {
			seen[f.Secret] = true
			secrets = append(secrets, f.Secret)
		}
	}
	return secrets, unrecovered
}
