package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// EngineAction is a cleanup mode.
type EngineAction string

const (
	ActionScan    EngineAction = "scan"
	ActionDryRun  EngineAction = "dry-run"
	ActionRewrite EngineAction = "rewrite"
)

// FilterRepoAvailable reports whether git-filter-repo can be executed.
func FilterRepoAvailable() bool {
	_, err := exec.LookPath("git-filter-repo")
	return err == nil
}

// RunEngine performs the requested action over every repository, writing
// human-readable progress to w, and returns a process-style exit code:
//
//	0  every repository is clear (or a rewrite completed with none skipped)
//	3  compromised material was found (scan or dry-run)
//	4  a rewrite was skipped or failed verification for some repository
func RunEngine(w io.Writer, action EngineAction, secrets, repos []string) int {
	plan := CleanupPlan{DeletePaths: make(map[string][]string)}
	for _, secret := range secrets {
		plan.Replacements = append(plan.Replacements, ReplacementRule{Secret: secret, With: defaultReplacement})
	}
	return RunCleanupPlan(w, action, plan, repos)
}

// RunCleanupPlan executes an already-reviewed plan. Replacement secrets are
// applied in every repository in which they occur, while DeletePaths are
// scoped to the repository selected by the user.
func RunCleanupPlan(w io.Writer, action EngineAction, plan CleanupPlan, repos []string) int {
	secrets := make([]string, 0, len(plan.Replacements))
	for _, rule := range plan.Replacements {
		secrets = append(secrets, rule.Secret)
	}

	replaceFile := ""
	if action == ActionRewrite {
		path, cleanup, err := writeReplacementRules(plan.Replacements)
		if err != nil {
			fmt.Fprintf(w, "Cannot prepare replacement rules: %v\n", err)
			return 4
		}
		defer cleanup()
		replaceFile = path
	}

	matches, rewritten, skipped, wouldRewrite, wouldSkip := 0, 0, 0, 0, 0

	for i, repo := range repos {
		fmt.Fprintf(w, "[%d/%d] Repository: %s\n", i+1, len(repos), repo)
		bare := isBareRepo(repo)
		deletePaths := plan.DeletePaths[repo]

		currentMatch := false
		if bare {
			fmt.Fprintln(w, "  Working tree: n/a (bare or mirror repository)")
		} else if currentTreeMatch(repo, secrets) {
			currentMatch = true
			fmt.Fprintln(w, "  Working tree: MATCH")
		} else {
			fmt.Fprintln(w, "  Working tree: clear")
		}

		fmt.Fprintln(w, "  Full object database: scanning...")
		objectMatch, err := objectDatabaseMatch(repo, secrets)
		if err != nil {
			fmt.Fprintf(w, "  Full object database: error (%v)\n", err)
		} else if objectMatch {
			fmt.Fprintln(w, "  Full object database: MATCH (history, tags, messages, unreachable)")
		} else {
			fmt.Fprintln(w, "  Full object database: clear")
		}

		if !currentMatch && !objectMatch && len(deletePaths) == 0 {
			fmt.Fprintln(w, "")
			continue
		}
		matches++

		switch action {
		case ActionScan:
			fmt.Fprintln(w, "  Action: report only")
			fmt.Fprintln(w, "")

		case ActionDryRun:
			if !bare && workingTreeDirty(repo) {
				fmt.Fprintln(w, "  Action: would SKIP (working tree has uncommitted changes)")
				fmt.Fprintln(w, "")
				wouldSkip++
				continue
			}
			noFetch := !hasOrigin(repo)
			if noFetch {
				fmt.Fprintln(w, "  Action: would rewrite history (no origin remote; locally available refs only)")
			} else {
				fmt.Fprintln(w, "  Action: would rewrite history (all fetchable origin refs)")
			}
			for _, file := range deletePaths {
				fmt.Fprintf(w, "    would DELETE from history: %s\n", file)
			}
			if len(plan.Replacements) > 0 {
				fmt.Fprintf(w, "    would REPLACE %d selected secret everywhere with %s\n", len(plan.Replacements), replacementSummary(plan.Replacements))
			}
			fmt.Fprintf(w, "    Command: git -C %s filter-repo %s\n", repo, strings.Join(filterRepoArgsForPlan("<replacement-rules>", noFetch, deletePaths), " "))
			fmt.Fprintln(w, "    Then: verify every remaining Git object against the recovered secrets.")
			fmt.Fprintln(w, "")
			wouldRewrite++

		case ActionRewrite:
			if !bare && workingTreeDirty(repo) {
				fmt.Fprintln(w, "  Action: SKIPPED (working tree has uncommitted changes)")
				fmt.Fprintln(w, "")
				skipped++
				continue
			}
			noFetch := !hasOrigin(repo)
			if noFetch {
				fmt.Fprintln(w, "  Warning: no origin remote; only locally available refs can be rewritten.")
			}
			fmt.Fprintln(w, "  Rewriting history...")
			if err := runFilterRepoPlan(w, repo, replaceFile, noFetch, deletePaths); err != nil {
				fmt.Fprintf(w, "  Action: FAILED (%v)\n\n", err)
				skipped++
				continue
			}
			fmt.Fprintln(w, "  Verifying every remaining Git object...")
			remaining, err := objectDatabaseMatch(repo, secrets)
			if err != nil {
				fmt.Fprintf(w, "  Action: FAILED VERIFICATION (%v)\n\n", err)
				skipped++
			} else if remaining {
				fmt.Fprintln(w, "  Action: FAILED VERIFICATION (a secret remains in the object database)")
				fmt.Fprintln(w, "")
				skipped++
			} else if pathsRemain, err := historyPathsMatch(repo, deletePaths); err != nil {
				fmt.Fprintf(w, "  Action: FAILED VERIFICATION (%v)\n\n", err)
				skipped++
			} else if pathsRemain {
				fmt.Fprintln(w, "  Action: FAILED VERIFICATION (a deleted path remains in reachable history)")
				fmt.Fprintln(w, "")
				skipped++
			} else {
				fmt.Fprintln(w, "  Action: rewritten and verified; inspect before pushing")
				fmt.Fprintln(w, "")
				rewritten++
			}
		}
	}

	switch action {
	case ActionDryRun:
		fmt.Fprintf(w, "Summary: %d matching repositories, %d would be rewritten, %d would be skipped\n", matches, wouldRewrite, wouldSkip)
		if matches > 0 {
			fmt.Fprintln(w, "Dry run only: nothing was modified. Revoke the keys and back up before rewriting.")
			return 3
		}
	case ActionScan:
		fmt.Fprintf(w, "Summary: %d matching repositories\n", matches)
		if matches > 0 {
			fmt.Fprintln(w, "Revoke the exposed keys and back up your repositories, then rewrite.")
			return 3
		}
	case ActionRewrite:
		fmt.Fprintf(w, "Summary: %d matching repositories, %d rewritten, %d skipped\n", matches, rewritten, skipped)
		if skipped > 0 {
			return 4
		}
	}
	return 0
}

func replacementSummary(rules []ReplacementRule) string {
	if len(rules) == 0 {
		return "(none)"
	}
	first := rules[0].With
	for _, rule := range rules[1:] {
		if rule.With != first {
			return "reviewed replacement strings"
		}
	}
	return first
}

// filterRepoArgs is the git-filter-repo argument list; replaceFile is either a
// real path or a placeholder used when printing a dry-run plan.
func filterRepoArgs(replaceFile string, noFetch bool) []string {
	return filterRepoArgsForPlan(replaceFile, noFetch, nil)
}

func filterRepoArgsForPlan(replaceFile string, noFetch bool, deletePaths []string) []string {
	args := []string{
		"--replace-text", replaceFile,
		"--replace-message", replaceFile,
	}
	if len(deletePaths) > 0 {
		args = append(args, "--invert-paths")
		for _, file := range deletePaths {
			args = append(args, "--path", file)
		}
	}
	args = append(args, "--sensitive-data-removal", "--force")
	if noFetch {
		args = append(args, "--no-fetch")
	}
	return args
}

func runFilterRepo(w io.Writer, repo, replaceFile string, noFetch bool) error {
	return runFilterRepoPlan(w, repo, replaceFile, noFetch, nil)
}

func runFilterRepoPlan(w io.Writer, repo, replaceFile string, noFetch bool, deletePaths []string) error {
	args := append([]string{"-C", repo, "filter-repo"}, filterRepoArgsForPlan(replaceFile, noFetch, deletePaths)...)
	cmd := exec.Command("git", args...)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

// writeReplaceFile writes a git-filter-repo replacement rules file. Every
// secret is written as an exact (literal) match so no regex metacharacter in a
// key is misinterpreted.
func writeReplaceFile(secrets []string) (string, func(), error) {
	rules := make([]ReplacementRule, 0, len(secrets))
	for _, secret := range secrets {
		rules = append(rules, ReplacementRule{Secret: secret, With: defaultReplacement})
	}
	return writeReplacementRules(rules)
}

func writeReplacementRules(rules []ReplacementRule) (string, func(), error) {
	f, err := os.CreateTemp("", "secretsweep-replace-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.Remove(f.Name()) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	for _, rule := range rules {
		if _, err := fmt.Fprintf(f, "literal:%s==>%s\n", rule.Secret, rule.With); err != nil {
			f.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}

func historyPathsMatch(repo string, paths []string) (bool, error) {
	if len(paths) == 0 {
		return false, nil
	}
	args := []string{"-C", repo, "log", "--all", "--format=", "--name-only", "--"}
	args = append(args, paths...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// currentTreeMatch reports whether any secret appears in the repository's
// tracked working-tree files.
func currentTreeMatch(repo string, secrets []string) bool {
	args := []string{"-C", repo, "grep", "-I", "-F"}
	for _, s := range secrets {
		args = append(args, "-e", s)
	}
	args = append(args, "--", ".")
	// git grep exits 0 on a match, 1 on none, >1 on error.
	return exec.Command("git", args...).Run() == nil
}

// objectDatabaseMatch streams every object in the repository (including
// unreachable ones, commit messages, and annotated tags) and reports whether
// any secret appears. This is the authoritative infection and verification
// check.
func objectDatabaseMatch(repo string, secrets []string) (bool, error) {
	cmd := exec.Command("git", "-C", repo, "cat-file", "--batch-all-objects", "--batch")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	defer func() {
		stdout.Close()
		cmd.Wait()
	}()

	needles := make([][]byte, len(secrets))
	for i, s := range secrets {
		needles[i] = []byte(s)
	}

	r := bufio.NewReaderSize(stdout, 1<<20)
	found := false
	for {
		header, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return found, err
		}
		fields := strings.Fields(strings.TrimRight(header, "\n"))
		// A present object header is "<oid> <type> <size>"; anything else
		// (e.g. "<oid> missing") carries no payload to consume.
		if len(fields) != 3 {
			continue
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		payload := make([]byte, size+1) // include the trailing newline
		if _, err := io.ReadFull(r, payload); err != nil {
			return found, err
		}
		if found {
			continue // keep draining to let git exit cleanly
		}
		switch fields[1] {
		case "blob", "commit", "tag":
			for _, needle := range needles {
				if containsBytes(payload[:size], needle) {
					found = true
					break
				}
			}
		}
	}
	return found, nil
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	return strings.Contains(string(haystack), string(needle))
}

func workingTreeDirty(repo string) bool {
	out, err := exec.Command("git", "-C", repo, "status", "--porcelain").Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

func hasOrigin(repo string) bool {
	return exec.Command("git", "-C", repo, "remote", "get-url", "origin").Run() == nil
}
