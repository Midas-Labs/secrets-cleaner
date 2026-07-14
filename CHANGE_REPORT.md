# Change report

Status: tested and ready for controlled use on disposable mirrors before organization rollout.

## secretsweep 1.0.0 (Trivy + Bubble Tea TUI)

- New Go tool in `secretsweep/` built on charmbracelet/bubbletea: discovers repositories, finds compromised keys automatically with Trivy secret scanning, and drives the bash cleanup engine (history scan, dry run, rewrite) from an interactive TUI or a `--headless` mode for automation.
- Recovers exact secret values from Trivy's redacted output by aligning the masked match against the raw file line; unrecoverable findings are flagged for manual review.
- Feeds every recovered key to the engine across every discovered repository, so a key found in one working tree is purged from all histories.
- Rewrite requires typing `rewrite` in the TUI (or `--yes` headless). Secrets touch disk only as a `0600` temp key file that is removed after the run; the UI always masks values.
- Verified end to end on fixtures: Trivy found a GitHub PAT and an AWS access key, the engine rewrote three repositories (including a mirror and a history-only occurrence), and a re-scan plus full-history grep confirmed zero remaining secrets. TUI review/confirm/run/done screens exercised in a real pty via expect; unit tests cover secret recovery and deduplication.

## CLI 2.0.0

- Accepts multiple target paths in one run; each path may be a single repository (working clone, worktree, bare, or mirror) or a folder searched recursively. Duplicate targets are scanned once. Defaults to the current directory.
- `--dry-run` mode: full scan plus the exact per-repository rewrite plan (would rewrite or would skip, including the `git filter-repo` command), with nothing modified.
- `--list` mode: prints the repositories a run would cover without requiring key input.
- `--no-recurse`: requires every path to be a repository itself.
- Rewrite mode asks for a typed confirmation (`rewrite`); `--yes` skips it for unattended runs, and non-interactive runs without `--yes` are refused.
- Colored MATCH/clear output with `[n/N]` progress counters; disabled via `--no-color`, the `NO_COLOR` environment variable, or when stdout is not a terminal.
- Options may appear anywhere on the command line; `--key-file=FILE` form, `--version`, expanded `--help` with examples, and conflicting-mode detection added.
- Verified on macOS Bash 3.2: scan/dry-run/rewrite against fixtures covering clean, infected, dirty-working-tree, bare-mirror, and no-origin repositories, exact and masked keys, and all documented exit codes (0, 2, 3, 4).

## Current capabilities

- Discovers ordinary, worktree, bare, and mirror Git repositories below any number of target folders, or accepts repositories directly as targets.
- Accepts multiple exact compromised keys.
- Accepts masked patterns using runs of two or more asterisks at the start, middle, end, or both ends.
- Requires at least four visible characters in each mask.
- Treats `literal:` entries as exact values when a key genuinely contains `**`.
- Audits working files, every local ref, all reachable commits, commit messages, annotated tags, and unreachable Git objects.
- Lists and counts every infected branch.
- Uses sensitive-data-removal mode to fetch and rewrite all fetchable `origin` refs.
- Verifies the complete remaining local object database after rewriting.
- Returns a nonzero status when infection remains or a rewrite is skipped.
- Never pushes automatically.

## Verification performed

- Exact-key scan and rewrite across multiple repositories.
- Mirror clone scan, all-ref rewrite, force-push to a disposable remote, and fresh protocol clone verification.
- Prefix, suffix, prefix-and-suffix, middle, and literal-asterisk key patterns.
- Variable display-mask lengths such as `tok2***i72i`; a 2+ asterisk run represents one unknown segment.
- File-content and commit-message cleanup.
- Configuration structure preservation around every masked replacement.
- Rejection of masks exposing fewer than four characters.

The successful fresh-mirror result was zero matching repositories, zero infected branches, and a clear Git object database.

## Remaining external cleanup

Repository rewriting cannot revoke credentials or guarantee deletion from provider caches, pull-request views, forks, build logs, releases, artifacts, backups, or existing clones. Revoke every key first and follow the hosting provider's sensitive-data-removal procedure after publishing rewritten refs.
