package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func tuiReviewModel(t *testing.T) (model, []Finding, string) {
	t.Helper()
	findings, secret, _ := reviewFindings(t)
	m := newModel([]string{"."}, nil)
	m.width, m.height = 120, 36
	m.repos = []string{findings[0].Repo, findings[1].Repo}
	m.findings = findings
	m.enterReview()
	return m, findings, secret
}

func key(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func specialKey(keyType tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: keyType}
}

func updateKey(t *testing.T, m model, msg tea.KeyMsg) model {
	t.Helper()
	updated, _ := m.Update(msg)
	return updated.(model)
}

func TestTUIReviewStartsWithNothingSelected(t *testing.T) {
	m, _, _ := tuiReviewModel(t)
	if m.phase != phaseReview {
		t.Fatalf("phase = %v; want phaseReview", m.phase)
	}
	if m.review.SelectedCount() != 0 {
		t.Fatalf("selected = %d; want 0", m.review.SelectedCount())
	}
	if !strings.Contains(m.View(), "Selected: 0") {
		t.Fatalf("review view does not make empty selection clear:\n%s", m.View())
	}
}

func TestTUISearchAndBackPreserveSelection(t *testing.T) {
	m, findings, _ := tuiReviewModel(t)
	m = updateKey(t, m, key(' '))
	if m.review.ActionFor(findings[0]) != ActionReplace {
		t.Fatal("space did not select the current finding for replacement")
	}

	m = updateKey(t, m, key('/'))
	if m.phase != phaseSearch {
		t.Fatalf("phase = %v; want phaseSearch", m.phase)
	}
	for _, r := range "stripe" {
		m = updateKey(t, m, key(r))
	}
	if visible := m.review.Visible(); len(visible) != 1 || visible[0].RuleID != "stripe-secret" {
		t.Fatalf("search results = %#v", visible)
	}
	m = updateKey(t, m, specialKey(tea.KeyEsc))
	if m.phase != phaseReview {
		t.Fatalf("escape phase = %v; want review", m.phase)
	}
	m.review.SetQuery("")
	if m.review.ActionFor(findings[0]) != ActionReplace {
		t.Fatal("selection was lost after searching and going back")
	}
}

func TestTUIActionCyclesAndNavigation(t *testing.T) {
	m, findings, _ := tuiReviewModel(t)
	m = updateKey(t, m, specialKey(tea.KeyDown))
	current, _ := m.review.Current()
	if current.StableID() != findings[1].StableID() {
		t.Fatalf("down selected %s; want %s", current.File, findings[1].File)
	}
	m = updateKey(t, m, key(' '))
	if m.review.ActionFor(findings[1]) != ActionReplace {
		t.Fatal("first space must choose replace")
	}
	m = updateKey(t, m, key(' '))
	if m.review.ActionFor(findings[1]) != ActionDeleteFile {
		t.Fatal("second space must choose delete-file")
	}
	m = updateKey(t, m, key(' '))
	if m.review.ActionFor(findings[1]) != ActionNone {
		t.Fatal("third space must clear the action")
	}
}

func TestTUIPreviewRequiresSelectionAndNeverLeaksSecret(t *testing.T) {
	m, _, secret := tuiReviewModel(t)
	m = updateKey(t, m, key('p'))
	if m.phase != phaseReview || !strings.Contains(m.notice, "Select at least one") {
		t.Fatalf("empty preview phase=%v notice=%q", m.phase, m.notice)
	}
	m = updateKey(t, m, key(' '))
	m = updateKey(t, m, key('p'))
	if m.phase != phasePreview {
		t.Fatalf("phase = %v; want phasePreview (notice %q)", m.phase, m.notice)
	}
	view := m.View()
	for _, want := range []string{"Exact cleanup plan", "REPLACE", defaultReplacement} {
		if !strings.Contains(view, want) {
			t.Fatalf("preview missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, secret) {
		t.Fatal("preview leaked the raw secret")
	}
}

func TestTUIEditsAndValidatesReplacement(t *testing.T) {
	m, _, _ := tuiReviewModel(t)
	m = updateKey(t, m, key(' '))
	m = updateKey(t, m, key('e'))
	if m.phase != phaseReplacement {
		t.Fatalf("phase = %v; want phaseReplacement", m.phase)
	}
	m = updateKey(t, m, specialKey(tea.KeyCtrlU))
	for _, r := range "SAFE_VALUE" {
		m = updateKey(t, m, key(r))
	}
	m = updateKey(t, m, specialKey(tea.KeyEnter))
	if m.phase != phaseReview || m.review.Replacement != "SAFE_VALUE" {
		t.Fatalf("replacement edit failed: phase=%v value=%q notice=%q", m.phase, m.review.Replacement, m.notice)
	}
}

func TestTUIConfirmationRequiresExactWord(t *testing.T) {
	m, _, _ := tuiReviewModel(t)
	m = updateKey(t, m, key(' '))
	m = updateKey(t, m, key('p'))
	m = updateKey(t, m, key('r'))
	if m.phase != phaseConfirm {
		t.Fatalf("phase = %v; want confirm", m.phase)
	}
	for _, r := range "wrong" {
		m = updateKey(t, m, key(r))
	}
	m = updateKey(t, m, specialKey(tea.KeyEnter))
	if m.phase != phaseConfirm {
		t.Fatalf("incorrect confirmation escaped confirm phase: %v", m.phase)
	}
	if !strings.Contains(m.notice, `Type "apply" exactly`) {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestScanViewReportsFindingsAsTheyArrive(t *testing.T) {
	m := newModel([]string{"."}, nil)
	m.phase = phaseScan
	m.repos = []string{"/repos/one", "/repos/two"}
	m.scanIndex = 0
	secret := token("ghp_", 36)
	updated, _ := m.Update(scannedMsg{index: 0, findings: []Finding{{Repo: m.repos[0], File: "config.env", Line: 4, RuleID: "github-pat", Severity: "CRITICAL", Secret: secret}}})
	m = updated.(model)
	view := m.View()
	if !strings.Contains(view, "Found: 1") || !strings.Contains(view, "config.env:4") {
		t.Fatalf("scan progress does not show live finding feedback:\n%s", view)
	}
	if strings.Contains(view, secret) {
		t.Fatal("scan progress leaked the raw secret")
	}
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
	m.enterReview()
	current, ok := m.review.Current()
	if !ok {
		t.Fatal("review has no current finding")
	}
	if err := m.review.SetAction(current, ActionReplace); err != nil {
		t.Fatal(err)
	}

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
