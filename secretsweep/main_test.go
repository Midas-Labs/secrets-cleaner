package main

import "testing"

func TestBuildHeadlessPlanDeduplicatesAndUsesCustomReplacement(t *testing.T) {
	first := token("ghp_", 36)
	second := token("sk_live_", 24)
	findings := []Finding{{Secret: first}, {Secret: first}, {Secret: second}}
	plan, err := buildHeadlessPlan(findings, []string{second, first}, "SAFE_VALUE")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Replacements) != 2 {
		t.Fatalf("replacement rules = %#v; want 2 unique secrets", plan.Replacements)
	}
	for _, rule := range plan.Replacements {
		if rule.With != "SAFE_VALUE" {
			t.Fatalf("replacement = %q; want SAFE_VALUE", rule.With)
		}
	}
}

func TestBuildHeadlessPlanRejectsCompromisedReplacement(t *testing.T) {
	secret := token("ghp_", 36)
	if _, err := buildHeadlessPlan([]Finding{{Secret: secret}}, nil, secret); err == nil {
		t.Fatal("expected compromised replacement to be rejected")
	}
}

func TestBuildHeadlessPlanAllowsHistoryOnlyKeys(t *testing.T) {
	secret := token("history_", 20)
	plan, err := buildHeadlessPlan(nil, []string{secret}, defaultReplacement)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Replacements) != 1 || plan.Replacements[0].Secret != secret {
		t.Fatalf("plan = %#v", plan)
	}
}
