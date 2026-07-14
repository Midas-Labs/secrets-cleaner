package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIExecutorUsesArgumentArrayAndReturnsStructuredResult(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-secretsweep")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	executor := CLIExecutor{Binary: binary}
	resultJSON, err := executor.Execute(context.Background(), []byte(`{"operation":"scan","targets":["/repos/team one"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var result ExecutionResult
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 3 {
		t.Fatalf("exit = %d; want 3", result.ExitCode)
	}
	for _, argument := range []string{"--headless", "--action", "scan", "/repos/team one"} {
		if !strings.Contains(result.Output, argument+"\n") {
			t.Fatalf("output missing discrete argument %q: %q", argument, result.Output)
		}
	}
}

func TestCLIExecutorRejectsRewriteBeforeStartingProcess(t *testing.T) {
	executor := CLIExecutor{Binary: "/does/not/exist"}
	if _, err := executor.Execute(context.Background(), []byte(`{"operation":"rewrite","targets":["/repos/team"]}`)); err == nil || !strings.Contains(err.Error(), "local-only") {
		t.Fatalf("rewrite error = %v", err)
	}
}
