package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestComposeProfileContainsSelfHostedDependencies(t *testing.T) {
	data, err := os.ReadFile("../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, service := range []string{"postgres:", "temporal:", "automq:", "rustfs:", "openbao:", "otel-collector:"} {
		if !strings.Contains(text, "  "+service) {
			t.Errorf("compose profile is missing %s", service)
		}
	}
	if strings.Contains(text, ":latest") {
		t.Fatal("compose profile contains a floating latest image tag")
	}
	for _, insecure := range []string{"rustfsadmin", "changeme", "postgres_password: password"} {
		if strings.Contains(strings.ToLower(text), insecure) {
			t.Fatalf("compose profile contains insecure default %q", insecure)
		}
	}
}

func TestComposeStatefulServicesHaveHealthChecksAndNoPublishedPorts(t *testing.T) {
	data, err := os.ReadFile("../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, service := range []string{"postgres", "temporal", "automq", "rustfs", "openbao"} {
		block := composeServiceBlock(text, service)
		if block == "" {
			t.Fatalf("service %s not found", service)
		}
		if !strings.Contains(block, "healthcheck:") {
			t.Errorf("service %s has no healthcheck", service)
		}
		if strings.Contains(block, "\n    ports:") {
			t.Errorf("stateful service %s publishes host ports", service)
		}
		if !strings.Contains(block, "read_only: true") {
			t.Errorf("service %s does not use a read-only root filesystem", service)
		}
	}
}

func TestComposeOnlyLoopbackPortsArePublished(t *testing.T) {
	data, err := os.ReadFile("../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	portLine := regexp.MustCompile(`(?m)^\s+-\s+"([^\"]+)"\s*$`)
	for _, match := range portLine.FindAllStringSubmatch(string(data), -1) {
		if strings.Count(match[1], ":") >= 2 && !strings.HasPrefix(match[1], "127.0.0.1:") {
			t.Errorf("published port is not loopback-bound: %s", match[1])
		}
	}
}

func composeServiceBlock(compose, service string) string {
	marker := "  " + service + ":\n"
	start := strings.Index(compose, marker)
	if start < 0 {
		return ""
	}
	rest := compose[start+len(marker):]
	lines := strings.Split(rest, "\n")
	end := len(lines)
	for i, line := range lines {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			end = i
			break
		}
	}
	return marker + strings.Join(lines[:end], "\n")
}
