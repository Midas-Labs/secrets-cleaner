package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// initGitRepo creates a repo containing secret in a committed file and returns
// its path.
func initGitRepo(t *testing.T, secret string) string {
	t.Helper()
	dir := t.TempDir()
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "conf"), []byte("key = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "add")
	return dir
}

// pump drives the model through its message loop, executing each returned
// command synchronously, until phaseDone or a timeout.
func pump(t *testing.T, m model, first tea.Cmd) model {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	cmds := []tea.Cmd{first}
	for len(cmds) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("model did not reach phaseDone within timeout")
		}
		cmd := cmds[0]
		cmds = cmds[1:]
		if cmd == nil {
			continue
		}
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			return m
		}
		var next tea.Cmd
		var updated tea.Model
		updated, next = m.Update(msg)
		m = updated.(model)
		if m.phase == phaseDone {
			return m
		}
		if next != nil {
			cmds = append(cmds, next)
		}
	}
	return m
}

// TestEngineStreamsToDone verifies the in-process engine streams output through
// the channel writer and the model reaches phaseDone with a clean exit.
func TestEngineStreamsToDone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	secret := token("ghp_", 36)
	repo := initGitRepo(t, secret)

	m := newModel([]string{repo}, nil)
	m.repos = []string{repo}
	m.findings = []Finding{{Repo: repo, File: "conf", Line: 1, Secret: secret, Severity: "CRITICAL", RuleID: "github-pat"}}

	cmd := m.startEngine(ActionScan)
	if cmd == nil {
		t.Fatal("startEngine returned nil for a repo with a recovered secret")
	}
	final := pump(t, m, cmd)

	if final.phase != phaseDone {
		t.Fatalf("phase = %v; want phaseDone", final.phase)
	}
	if final.engineExit != 3 {
		t.Fatalf("engineExit = %d; want 3 (scan found the secret)", final.engineExit)
	}
	joined := ""
	for _, l := range final.engineLines {
		joined += l + "\n"
	}
	if !contains(joined, "MATCH") {
		t.Fatalf("streamed output did not report a MATCH:\n%s", joined)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
