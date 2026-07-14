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

func TestComposeRuntimeHardeningIsCompatibleWithPinnedImages(t *testing.T) {
	data, err := os.ReadFile("../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	temporal := composeServiceBlock(text, "temporal")
	if !strings.Contains(temporal, "temporal-config:/etc/temporal/config") {
		t.Fatal("Temporal auto-setup needs a writable, container-initialized config volume")
	}
	if strings.Contains(temporal, "development-sql.yaml") {
		t.Fatal("Temporal 1.28.1 does not contain the old development-sql dynamic config")
	}
	if !strings.Contains(temporal, "temporal operator cluster health --address temporal:7233") {
		t.Fatal("Temporal healthcheck must use the bundled CLI and the IPv6-compatible service address")
	}
	rustfs := composeServiceBlock(text, "rustfs")
	if !strings.Contains(rustfs, "nc -z 127.0.0.1 9000") {
		t.Fatal("RustFS healthcheck must use the nc binary present in the pinned image")
	}
	openbao := composeServiceBlock(text, "openbao")
	if !strings.Contains(openbao, `user: "100:1000"`) {
		t.Fatal("OpenBao must start as its image user when SETGID is dropped")
	}
	if !strings.Contains(openbao, "openbao-data:/openbao/file") {
		t.Fatal("OpenBao data volume must use the image-owned /openbao/file directory")
	}
	hcl, err := os.ReadFile("../deploy/compose/openbao.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hcl), `path    = "/openbao/file"`) {
		t.Fatal("OpenBao Raft storage must match the image-owned data directory")
	}
	if strings.Contains(string(hcl), "disable_mlock") {
		t.Fatal("OpenBao 2.3 rejects the removed disable_mlock setting")
	}
	if !strings.Contains(openbao, "BAO_ADDR=http://127.0.0.1:8200") {
		t.Fatal("OpenBao healthcheck must explicitly use the configured HTTP listener")
	}
	rustfsInit := composeServiceBlock(text, "rustfs-init")
	if !strings.Contains(rustfsInit, "MC_CONFIG_DIR: /tmp/.mc") {
		t.Fatal("read-only MinIO Client needs its config redirected to writable tmpfs")
	}
	automq := composeServiceBlock(text, "automq")
	if !strings.Contains(automq, "/opt/automq/kafka/logs") {
		t.Fatal("read-only AutoMQ needs a writable tmpfs for Kafka and GC logs")
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
