package main

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const defaultReplacement = "REMOVED_API_KEY"

type ReviewAction string

const (
	ActionNone       ReviewAction = "none"
	ActionReplace    ReviewAction = "replace"
	ActionDeleteFile ReviewAction = "delete-file"
)

type ReplacementRule struct {
	Secret string
	With   string
}

// CleanupPlan is the exact local mutation contract. It deliberately remains
// in memory because ReplacementRule.Secret contains compromised plaintext.
type CleanupPlan struct {
	Replacements []ReplacementRule
	DeletePaths  map[string][]string
}

type ReviewState struct {
	findings    []Finding
	query       string
	cursor      int
	actions     map[string]ReviewAction
	Replacement string
}

func NewReviewState(findings []Finding) ReviewState {
	copyOfFindings := append([]Finding(nil), findings...)
	return ReviewState{
		findings:    copyOfFindings,
		actions:     make(map[string]ReviewAction),
		Replacement: defaultReplacement,
	}
}

func (r *ReviewState) SetQuery(query string) {
	r.query = strings.TrimSpace(query)
	r.cursor = 0
}

func (r ReviewState) Query() string { return r.query }

func (r ReviewState) Visible() []Finding {
	terms := strings.Fields(strings.ToLower(r.query))
	if len(terms) == 0 {
		return append([]Finding(nil), r.findings...)
	}
	visible := make([]Finding, 0, len(r.findings))
	for _, finding := range r.findings {
		haystack := strings.ToLower(strings.Join([]string{
			finding.Severity,
			finding.RuleID,
			finding.Title,
			finding.Repo,
			filepath.Base(finding.Repo),
			finding.File,
			finding.Masked(),
		}, " "))
		matches := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				matches = false
				break
			}
		}
		if matches {
			visible = append(visible, finding)
		}
	}
	return visible
}

func (r *ReviewState) Move(delta int) {
	visible := r.Visible()
	if len(visible) == 0 {
		r.cursor = 0
		return
	}
	r.cursor += delta
	if r.cursor < 0 {
		r.cursor = 0
	}
	if r.cursor >= len(visible) {
		r.cursor = len(visible) - 1
	}
}

func (r ReviewState) Cursor() int { return r.cursor }

func (r ReviewState) Current() (Finding, bool) {
	visible := r.Visible()
	if len(visible) == 0 {
		return Finding{}, false
	}
	cursor := r.cursor
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(visible) {
		cursor = len(visible) - 1
	}
	return visible[cursor], true
}

func (r ReviewState) ActionFor(finding Finding) ReviewAction {
	action, ok := r.actions[finding.StableID()]
	if !ok {
		return ActionNone
	}
	return action
}

func (r *ReviewState) SetAction(finding Finding, action ReviewAction) error {
	switch action {
	case ActionNone:
		delete(r.actions, finding.StableID())
		return nil
	case ActionReplace, ActionDeleteFile:
		if finding.Secret == "" {
			return errors.New("finding has no recoverable secret and must be reviewed manually")
		}
		if action == ActionDeleteFile {
			if finding.Repo == "" {
				return errors.New("finding is not associated with a repository file")
			}
		}
		r.actions[finding.StableID()] = action
		return nil
	default:
		return fmt.Errorf("unknown review action %q", action)
	}
}

func (r *ReviewState) CycleCurrentAction() error {
	finding, ok := r.Current()
	if !ok {
		return errors.New("no visible finding")
	}
	next := ActionReplace
	switch r.ActionFor(finding) {
	case ActionReplace:
		if finding.Repo == "" {
			next = ActionNone
		} else {
			next = ActionDeleteFile
		}
	case ActionDeleteFile:
		next = ActionNone
	}
	return r.SetAction(finding, next)
}

func (r ReviewState) SelectedCount() int {
	return len(r.actions)
}

func (r ReviewState) SelectedSecrets() []string {
	seen := make(map[string]bool)
	var secrets []string
	for _, finding := range r.findings {
		if r.ActionFor(finding) == ActionNone || finding.Secret == "" || seen[finding.Secret] {
			continue
		}
		seen[finding.Secret] = true
		secrets = append(secrets, finding.Secret)
	}
	return secrets
}

func ValidateReplacement(replacement string, compromised []string) error {
	if strings.TrimSpace(replacement) == "" {
		return errors.New("replacement cannot be empty")
	}
	if replacement != strings.TrimSpace(replacement) {
		return errors.New("replacement cannot start or end with whitespace")
	}
	if strings.ContainsAny(replacement, "\r\n") {
		return errors.New("replacement must be a single line")
	}
	if strings.Contains(replacement, "==>") {
		return errors.New("replacement cannot contain the filter-rule delimiter ==>")
	}
	for _, secret := range compromised {
		if replacement == secret {
			return errors.New("replacement is one of the compromised values")
		}
	}
	return nil
}

func BuildCleanupPlan(review ReviewState) (CleanupPlan, error) {
	secrets := review.SelectedSecrets()
	if len(secrets) == 0 {
		return CleanupPlan{}, errors.New("select at least one recovered finding")
	}
	if err := ValidateReplacement(review.Replacement, secrets); err != nil {
		return CleanupPlan{}, err
	}

	plan := CleanupPlan{DeletePaths: make(map[string][]string)}
	for _, secret := range secrets {
		plan.Replacements = append(plan.Replacements, ReplacementRule{Secret: secret, With: review.Replacement})
	}

	seenPaths := make(map[string]map[string]bool)
	for _, finding := range review.findings {
		if review.ActionFor(finding) != ActionDeleteFile {
			continue
		}
		cleaned, err := validateDeletePath(finding.File)
		if err != nil {
			return CleanupPlan{}, fmt.Errorf("cannot delete %q: %w", finding.File, err)
		}
		if seenPaths[finding.Repo] == nil {
			seenPaths[finding.Repo] = make(map[string]bool)
		}
		if !seenPaths[finding.Repo][cleaned] {
			seenPaths[finding.Repo][cleaned] = true
			plan.DeletePaths[finding.Repo] = append(plan.DeletePaths[finding.Repo], cleaned)
		}
	}
	for repo := range plan.DeletePaths {
		sort.Strings(plan.DeletePaths[repo])
	}
	return plan, nil
}

func validateDeletePath(file string) (string, error) {
	if file == "" || filepath.IsAbs(file) || strings.ContainsRune(file, '\x00') {
		return "", errors.New("path must be a non-empty repository-relative path")
	}
	cleaned := path.Clean(filepath.ToSlash(file))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path escapes the repository")
	}
	return cleaned, nil
}
