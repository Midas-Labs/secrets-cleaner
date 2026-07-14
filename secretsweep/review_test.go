package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func reviewFindings(t *testing.T) ([]Finding, string, string) {
	t.Helper()
	first := token("ghp_", 36)
	second := token("sk_live_", 24)
	repoA := filepath.Join(t.TempDir(), "payments")
	repoB := filepath.Join(t.TempDir(), "website")
	return []Finding{
		{Repo: repoA, File: "config/prod.env", Line: 7, RuleID: "github-pat", Title: "GitHub token", Severity: "CRITICAL", Secret: first},
		{Repo: repoB, File: "deploy/app.yml", Line: 12, RuleID: "github-pat", Title: "GitHub token", Severity: "HIGH", Secret: first},
		{Repo: repoA, File: "billing/key.txt", Line: 2, RuleID: "stripe-secret", Title: "Stripe key", Severity: "MEDIUM", Secret: second},
		{Repo: repoA, File: "manual.txt", Line: 3, RuleID: "unknown", Title: "Manual review", Severity: "LOW"},
	}, first, second
}

func TestStableFindingIDIsDeterministicAndDoesNotLeakSecret(t *testing.T) {
	findings, first, _ := reviewFindings(t)
	got := findings[0].StableID()
	if got == "" || got != findings[0].StableID() {
		t.Fatalf("StableID = %q; want a non-empty deterministic ID", got)
	}
	if strings.Contains(got, first) {
		t.Fatalf("StableID leaks the secret: %q", got)
	}
	changed := findings[0]
	changed.Line++
	if changed.StableID() == got {
		t.Fatal("StableID must change when the finding location changes")
	}
}

func TestReviewStartsWithNothingSelected(t *testing.T) {
	findings, _, _ := reviewFindings(t)
	review := NewReviewState(findings)
	if review.SelectedCount() != 0 {
		t.Fatalf("SelectedCount = %d; want 0", review.SelectedCount())
	}
	for _, finding := range findings {
		if got := review.ActionFor(finding); got != ActionNone {
			t.Fatalf("ActionFor(%s) = %q; want none", finding.File, got)
		}
	}
}

func TestReviewSearchIsCaseInsensitiveAndKeepsSelection(t *testing.T) {
	findings, _, _ := reviewFindings(t)
	review := NewReviewState(findings)
	if err := review.SetAction(findings[2], ActionReplace); err != nil {
		t.Fatal(err)
	}
	review.SetQuery("PAYMENTS STRIPE")
	visible := review.Visible()
	if len(visible) != 1 || visible[0].File != "billing/key.txt" {
		t.Fatalf("Visible = %#v; want the Stripe finding in payments", visible)
	}
	review.SetQuery("")
	if review.ActionFor(findings[2]) != ActionReplace {
		t.Fatal("selection was lost after clearing search")
	}
}

func TestReviewNavigationIsBounded(t *testing.T) {
	findings, _, _ := reviewFindings(t)
	review := NewReviewState(findings)
	review.Move(-100)
	if got, ok := review.Current(); !ok || got.StableID() != findings[0].StableID() {
		t.Fatalf("Current after moving above start = %#v, %v", got, ok)
	}
	review.Move(100)
	if got, ok := review.Current(); !ok || got.StableID() != findings[len(findings)-1].StableID() {
		t.Fatalf("Current after moving past end = %#v, %v", got, ok)
	}
	review.SetQuery("no such finding")
	if _, ok := review.Current(); ok {
		t.Fatal("Current must report false for an empty filtered result")
	}
}

func TestReviewRejectsSelectingUnrecoveredFinding(t *testing.T) {
	findings, _, _ := reviewFindings(t)
	review := NewReviewState(findings)
	if err := review.SetAction(findings[3], ActionReplace); err == nil {
		t.Fatal("expected unrecovered finding selection to fail")
	}
}

func TestReviewManualKeyCannotBecomeDeleteFileAction(t *testing.T) {
	finding := Finding{File: "key-file entry 1", RuleID: "manual-key", Secret: token("ghp_", 36)}
	review := NewReviewState([]Finding{finding})
	if err := review.SetAction(finding, ActionReplace); err != nil {
		t.Fatal(err)
	}
	if err := review.CycleCurrentAction(); err != nil {
		t.Fatal(err)
	}
	if got := review.ActionFor(finding); got != ActionNone {
		t.Fatalf("manual-key action = %q; want none after replace", got)
	}
	if err := review.SetAction(finding, ActionDeleteFile); err == nil {
		t.Fatal("manual key without a repository path must reject delete-file")
	}
}

func TestBuildCleanupPlanReplacesSameSecretEverywhereOnce(t *testing.T) {
	findings, first, _ := reviewFindings(t)
	review := NewReviewState(findings)
	review.Replacement = "SAFE_PLACEHOLDER"
	if err := review.SetAction(findings[0], ActionReplace); err != nil {
		t.Fatal(err)
	}
	if err := review.SetAction(findings[1], ActionReplace); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildCleanupPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Replacements) != 1 {
		t.Fatalf("Replacements = %#v; want one rule for the shared secret", plan.Replacements)
	}
	if plan.Replacements[0].Secret != first || plan.Replacements[0].With != "SAFE_PLACEHOLDER" {
		t.Fatalf("replacement = %#v", plan.Replacements[0])
	}
	if len(plan.DeletePaths) != 0 {
		t.Fatalf("DeletePaths = %#v; want none", plan.DeletePaths)
	}
}

func TestBuildCleanupPlanScopesDeleteAndStillReplacesGlobally(t *testing.T) {
	findings, first, _ := reviewFindings(t)
	review := NewReviewState(findings)
	if err := review.SetAction(findings[0], ActionDeleteFile); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildCleanupPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Replacements) != 1 || plan.Replacements[0].Secret != first {
		t.Fatalf("Replacements = %#v; delete must still replace the secret globally", plan.Replacements)
	}
	paths := plan.DeletePaths[findings[0].Repo]
	if len(paths) != 1 || paths[0] != findings[0].File {
		t.Fatalf("DeletePaths = %#v; want only %s in its repository", plan.DeletePaths, findings[0].File)
	}
	if _, exists := plan.DeletePaths[findings[1].Repo]; exists {
		t.Fatalf("delete leaked into another repository: %#v", plan.DeletePaths)
	}
}

func TestValidateReplacement(t *testing.T) {
	secret := token("ghp_", 36)
	tests := []struct {
		name        string
		replacement string
		wantErr     bool
	}{
		{name: "default", replacement: "REMOVED_API_KEY"},
		{name: "trimmed plain text", replacement: "revoked-key"},
		{name: "empty", replacement: "", wantErr: true},
		{name: "whitespace", replacement: "   ", wantErr: true},
		{name: "newline", replacement: "safe\nunsafe", wantErr: true},
		{name: "carriage return", replacement: "safe\runsafe", wantErr: true},
		{name: "filter rule delimiter", replacement: "safe==>unsafe", wantErr: true},
		{name: "same compromised value", replacement: secret, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReplacement(tt.replacement, []string{secret})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateReplacement(%q) error = %v; wantErr %v", tt.replacement, err, tt.wantErr)
			}
		})
	}
}

func TestBuildCleanupPlanRejectsNoSelectionAndUnsafePath(t *testing.T) {
	findings, _, _ := reviewFindings(t)
	review := NewReviewState(findings)
	if _, err := BuildCleanupPlan(review); err == nil {
		t.Fatal("expected an empty plan to fail")
	}

	bad := findings[0]
	bad.File = "../outside"
	review = NewReviewState([]Finding{bad})
	if err := review.SetAction(bad, ActionDeleteFile); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCleanupPlan(review); err == nil {
		t.Fatal("expected a traversal delete path to fail")
	}
}
