package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

const version = "2.0.0"

func main() {
	var (
		headless    = flag.Bool("headless", false, "run without the TUI (for automation and CI)")
		action      = flag.String("action", "scan", "headless action: scan | dry-run | rewrite | none")
		yes         = flag.Bool("yes", false, "confirm a headless rewrite")
		keyFile     = flag.String("key-file", "", "file of extra exact keys to clean (one per line), in addition to Trivy findings")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("secretsweep %s\n", version)
		return
	}

	targets := flag.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}

	extraKeys, err := loadKeyFile(*keyFile)
	if err != nil {
		fatal(2, "%v", err)
	}

	if !*headless {
		if err := runTUI(targets, extraKeys); err != nil {
			fatal(2, "TUI error: %v", err)
		}
		return
	}
	os.Exit(runHeadless(targets, extraKeys, EngineAction(*action), *yes))
}

func usage() {
	fmt.Fprintf(os.Stderr, `secretsweep %s — Trivy-powered discovery and cleanup of compromised keys.

Usage:
  secretsweep [flags] [PATH ...]

Each PATH may be a single Git repository (working clone, worktree, bare, or
mirror) or a folder searched recursively. Defaults to the current directory.

With no flags an interactive TUI opens: repositories are discovered, Trivy
scans every working tree for secrets, and the findings drive a built-in engine
that scans full history, previews a rewrite, or rewrites and verifies. No
external script is required — git-filter-repo performs the rewrite.

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Headless examples:
  secretsweep --headless ~/code                       # Trivy + history scan
  secretsweep --headless --action dry-run ~/code      # preview the rewrite
  secretsweep --headless --action rewrite --yes ~/code
  secretsweep --headless --action none ~/code         # Trivy findings only
  secretsweep --headless --key-file keys.txt ~/code   # add history-only keys

Exit status (headless):
  0  no findings / everything clear
  2  usage or environment error
  3  compromised material found (scan or dry-run)
  4  rewrite skipped or failed at least one repository
`)
}

func runHeadless(targets, extraKeys []string, action EngineAction, yes bool) int {
	switch action {
	case ActionScan, ActionDryRun, ActionRewrite, "none":
	default:
		fmt.Fprintf(os.Stderr, "invalid --action: %s (want scan, dry-run, rewrite, or none)\n", action)
		return 2
	}
	if action == ActionRewrite && !yes {
		fmt.Fprintln(os.Stderr, "a headless rewrite requires --yes")
		return 2
	}
	if action == ActionRewrite && !FilterRepoAvailable() {
		fmt.Fprintln(os.Stderr, "rewrite requires git-filter-repo; install it with: brew install git-filter-repo")
		return 2
	}
	trivy := TrivyAvailable()
	if !trivy && len(extraKeys) == 0 {
		fmt.Fprintln(os.Stderr, "trivy is not installed; install it with: brew install trivy (or pass --key-file)")
		return 2
	}

	repos, err := DiscoverRepos(targets)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(repos) == 0 {
		fmt.Println("No Git repositories found.")
		return 0
	}
	fmt.Printf("Discovered %d Git repositories.\n", len(repos))

	var findings []Finding
	if trivy {
		for i, repo := range repos {
			fmt.Printf("[%d/%d] trivy scan: %s\n", i+1, len(repos), repo)
			fs, err := ScanRepo(repo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  scan error: %v\n", err)
				continue
			}
			for _, f := range fs {
				fmt.Printf("  %-8s %-24s %s:%d  %s\n", f.Severity, f.RuleID, f.File, f.Line, f.Masked())
			}
			findings = append(findings, fs...)
		}
	} else {
		fmt.Println("trivy not available; using --key-file keys only.")
	}

	recovered, unrecovered := UniqueSecrets(findings)
	secrets := mergeSecrets(recovered, extraKeys)
	fmt.Printf("\nTrivy findings: %d (%d recovered", len(findings), len(recovered))
	if unrecovered > 0 {
		fmt.Printf(", %d unrecovered — review manually", unrecovered)
	}
	if len(extraKeys) > 0 {
		fmt.Printf("; %d key(s) from --key-file", len(extraKeys))
	}
	fmt.Println(")")

	if len(secrets) == 0 {
		fmt.Println("No secrets to clean.")
		return 0
	}
	if action == "none" {
		return 3
	}

	fmt.Printf("\nRunning %s over %d repositories...\n\n", action, len(repos))
	return RunEngine(os.Stdout, action, secrets, repos)
}

// loadKeyFile reads one exact key per non-empty line. Blank lines and lines
// beginning with '#' are ignored.
func loadKeyFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %w", err)
	}
	defer f.Close()
	var keys []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			keys = append(keys, line)
		}
	}
	return keys, scanner.Err()
}

// mergeSecrets unions two key lists, preserving order and dropping duplicates.
func mergeSecrets(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
