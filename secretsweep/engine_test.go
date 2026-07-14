package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testPlan(secret string) CleanupPlan {
	return CleanupPlan{
		Replacements: []ReplacementRule{{Secret: secret, With: "SAFE_PLACEHOLDER"}},
		DeletePaths:  make(map[string][]string),
	}
}

func TestFilterRepoArgsForPlanIncludesRepositoryDeletePaths(t *testing.T) {
	args := filterRepoArgsForPlan("/secure/rules", true, []string{"config/prod.env", "keys/old.txt"})
	wantSequence := []string{
		"--replace-text", "/secure/rules",
		"--replace-message", "/secure/rules",
		"--invert-paths",
		"--path", "config/prod.env",
		"--path", "keys/old.txt",
		"--sensitive-data-removal",
		"--force",
		"--no-fetch",
	}
	if !slices.Equal(args, wantSequence) {
		t.Fatalf("args = %#v\nwant %#v", args, wantSequence)
	}
}

func TestReplacementRulesFileIsPrivateAndUsesCustomReplacement(t *testing.T) {
	secret := token("ghp_", 36)
	path, cleanup, err := writeReplacementRules([]ReplacementRule{{Secret: secret, With: "SAFE_PLACEHOLDER"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("replacement rules mode = %o; want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "literal:" + secret + "==>SAFE_PLACEHOLDER\n"
	if string(data) != want {
		t.Fatalf("replacement rules file has unexpected content")
	}
}

func TestRunCleanupPlanDryRunPrintsExactSafePlan(t *testing.T) {
	secret := token("ghp_", 36)
	repo := initGitRepo(t, secret)
	plan := testPlan(secret)
	plan.DeletePaths[repo] = []string{"conf"}

	var output bytes.Buffer
	exit := RunCleanupPlan(&output, ActionDryRun, plan, []string{repo})
	if exit != 3 {
		t.Fatalf("exit = %d; want 3\n%s", exit, output.String())
	}
	for _, want := range []string{
		"would DELETE from history: conf",
		"would REPLACE 1 selected secret everywhere with SAFE_PLACEHOLDER",
		"Dry run only: nothing was modified",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("dry-run output leaked the raw secret:\n%s", output.String())
	}
}

func TestRunCleanupPlanDryRunRefusesDirtyRepository(t *testing.T) {
	secret := token("ghp_", 36)
	repo := initGitRepo(t, secret)
	if err := os.WriteFile(filepath.Join(repo, "uncommitted"), []byte("change"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	exit := RunCleanupPlan(&output, ActionDryRun, testPlan(secret), []string{repo})
	if exit != 3 {
		t.Fatalf("exit = %d; want 3", exit)
	}
	if !strings.Contains(output.String(), "would SKIP (working tree has uncommitted changes)") {
		t.Fatalf("dirty-tree refusal missing:\n%s", output.String())
	}
}

func TestRunCleanupPlanScanFindsSecretWithoutPrintingIt(t *testing.T) {
	secret := token("sk_live_", 24)
	repo := initGitRepo(t, secret)
	var output bytes.Buffer
	exit := RunCleanupPlan(&output, ActionScan, testPlan(secret), []string{repo})
	if exit != 3 {
		t.Fatalf("exit = %d; want 3\n%s", exit, output.String())
	}
	if !strings.Contains(output.String(), "MATCH") {
		t.Fatalf("scan did not report a match:\n%s", output.String())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("scan output leaked the raw secret:\n%s", output.String())
	}
}

func TestRunCleanupPlanRewriteDeletesPathAndReplacesElsewhere(t *testing.T) {
	if _, err := exec.LookPath("git-filter-repo"); err != nil {
		t.Skip("git-filter-repo not available")
	}
	secret := token("ghp_", 36)
	repo := initGitRepo(t, secret)
	other := filepath.Join(repo, "other")
	if err := os.WriteFile(other, []byte("backup = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "other")
	gitRun(t, repo, "commit", "-qm", "other copy")

	plan := testPlan(secret)
	plan.DeletePaths[repo] = []string{"conf"}
	var output bytes.Buffer
	if exit := RunCleanupPlan(&output, ActionRewrite, plan, []string{repo}); exit != 0 {
		t.Fatalf("rewrite exit = %d:\n%s", exit, output.String())
	}
	if _, err := os.Stat(filepath.Join(repo, "conf")); !os.IsNotExist(err) {
		t.Fatalf("conf still exists after delete-file rewrite: %v", err)
	}
	data, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), "SAFE_PLACEHOLDER") {
		t.Fatalf("other file was not safely replaced")
	}
}

func gitRun(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
