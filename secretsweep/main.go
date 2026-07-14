package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

const version = "1.0.0"

func main() {
	var (
		headless    = flag.Bool("headless", false, "run without the TUI (for automation and CI)")
		action      = flag.String("action", "scan", "headless action after the Trivy scan: scan | dry-run | rewrite | none")
		yes         = flag.Bool("yes", false, "confirm a headless rewrite")
		enginePath  = flag.String("engine", "", "path to clean-secret-from-repos.sh (auto-detected by default)")
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

	engine, err := FindEngine(*enginePath)
	if err != nil {
		fatal(2, "%v", err)
	}

	if !*headless {
		if err := runTUI(targets, engine); err != nil {
			fatal(2, "TUI error: %v", err)
		}
		return
	}
	os.Exit(runHeadless(targets, engine, EngineAction(*action), *yes))
}

func usage() {
	fmt.Fprintf(os.Stderr, `secretsweep %s — Trivy-powered discovery and cleanup of compromised keys.

Usage:
  secretsweep [flags] [PATH ...]

Each PATH may be a single Git repository or a folder searched recursively.
Defaults to the current directory. Without flags an interactive TUI opens:
repositories are discovered, Trivy scans every working tree for secrets,
and the findings can be sent to the clean-secret-from-repos.sh engine to
scan full history, preview a rewrite, or rewrite and verify.

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Headless examples:
  secretsweep --headless ~/code                       # Trivy + history scan
  secretsweep --headless --action dry-run ~/code      # preview the rewrite
  secretsweep --headless --action rewrite --yes ~/code
  secretsweep --headless --action none ~/code         # Trivy findings only

Exit status (headless):
  0  no findings / everything clear
  2  usage or environment error
  3  compromised material found (scan or dry-run)
  4  rewrite skipped or failed at least one repository
`)
}

func runHeadless(targets []string, engine string, action EngineAction, yes bool) int {
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
	if !TrivyAvailable() {
		fmt.Fprintln(os.Stderr, "trivy is not installed; install it with: brew install trivy")
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

	secrets, unrecovered := UniqueSecrets(findings)
	fmt.Printf("\nTrivy findings: %d (%d distinct secrets recovered", len(findings), len(secrets))
	if unrecovered > 0 {
		fmt.Printf(", %d unrecovered — review manually", unrecovered)
	}
	fmt.Println(")")

	if len(secrets) == 0 {
		fmt.Println("No secrets recovered; nothing to hand to the cleanup engine.")
		return 0
	}
	if action == "none" {
		return 3
	}

	fmt.Printf("\nRunning engine %s over %d repositories...\n\n", action, len(repos))
	cmd, cleanup, err := BuildEngineCmd(engine, action, secrets, repos)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer cleanup()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
