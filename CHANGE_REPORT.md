# Change report

Status: tested and ready for controlled use on disposable mirrors before organization rollout.

## secretsweep 2.0.0 — single self-contained tool

The Bash engine (`clean-secret-from-repos.sh`) has been removed. All scanning,
previewing, and rewriting now happens natively inside the Go `secretsweep`
binary, with the interactive TUI as the default entry point.

- **Native engine.** Full object-database scanning (`git cat-file
  --batch-all-objects`), dry-run planning, and rewriting via `git filter-repo`
  are implemented in Go (`engine.go`). No external script is required at
  runtime; the only runtime dependencies are `trivy` and `git-filter-repo`.
- **Trivy discovery.** Repositories are discovered under any number of target
  paths (single repos or folders, deduplicated), Trivy finds secrets, and their
  exact values are recovered from Trivy's redacted output by aligning the masked
  match against the raw file line.
- **Cleans every recovered key across every repository at once**, so a key found
  in one working tree is purged from all histories.
- **`--key-file`** supplies extra exact keys for secrets that exist only in
  history (which Trivy, a working-tree scanner, cannot see).
- **Rewrite safety.** Requires typing `rewrite` in the TUI or `--yes` headless;
  skips repositories with uncommitted changes; verifies the object database
  after rewriting; never pushes. Secrets touch disk only as a `0600` temp file
  removed after the run and are always masked in the UI.
- **Makefile** targets: `build`, `install`, `check`, `tui`, `scan`, `dry-run`,
  and `prune` (which refuses to run without an explicit `PATHS`).

### Verification performed

- Native headless scan / dry-run / rewrite over fixtures covering ordinary,
  bare-mirror, no-origin, dirty-working-tree, and history-only-key repositories.
- Trivy found a GitHub PAT and an AWS access key; the engine rewrote three
  repositories (including a mirror and a key present only in another repo's
  history) and a re-scan plus full object-database grep confirmed zero remaining
  secrets.
- `--key-file` cleaned a history-only key that Trivy does not recognize.
- The interactive TUI dry-run and full rewrite flows (review → confirm →
  streamed engine output → done) were exercised live in a pty; the key was
  confirmed removed afterward.
- Go unit tests cover secret recovery, deduplication, and the model's
  engine-streaming path through to completion.
- All documented exit codes (0, 2, 3, 4) verified.

## Remaining external cleanup

Repository rewriting cannot revoke credentials or guarantee deletion from
provider caches, pull-request views, forks, build logs, releases, artifacts,
backups, or existing clones. Revoke every key first and follow the hosting
provider's sensitive-data-removal procedure after publishing rewritten refs.
