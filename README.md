# Compromised API Key Cleanup

`secretsweep` finds compromised API keys across your Git repositories — including keys that exist only in earlier commits, branch histories, tags, commit messages, and unreachable Git objects — and removes them from history.

It is a single self-contained tool built with [Bubble Tea](https://github.com/charmbracelet/bubbletea):

- **Discovers** repositories under any number of target paths (a single repository or a folder searched recursively).
- **Finds** secrets automatically with [Trivy](https://trivy.dev) secret scanning — no hand-written key list required.
- **Cleans** history with a built-in engine that scans the full object database, previews the rewrite, and rewrites with [`git-filter-repo`](https://github.com/newren/git-filter-repo), verifying that nothing remains.

The interactive TUI is the default; a `--headless` mode runs the same flow for automation and CI.

> **Revoke or rotate every compromised key with its provider first.** Rewriting Git history does not invalidate a key that has already been copied. Rewriting shared history also changes commit IDs — coordinate with collaborators and back up first.

## Repository layout

```
secretsweep/     # the tool (Go): discovery, Trivy scan, and the cleanup engine
Makefile         # build / install and run scan / dry-run / prune
CHANGE_REPORT.md # implementation and verification status
LICENSE          # Apache License 2.0
```

## Requirements

- macOS or Linux with Git
- [Go](https://go.dev) 1.21 or newer, to build the binary
- [Trivy](https://trivy.dev), for secret discovery
- [`git-filter-repo`](https://github.com/newren/git-filter-repo), for the rewrite
- Clean working trees in repositories that will be rewritten
- A backup of the repositories and coordination with their collaborators

On macOS:

```bash
brew install go trivy git-filter-repo
```

## Quick start

```bash
make build                    # build secretsweep/secretsweep

make scan    PATHS=~/code      # find keys, report only
make dry-run PATHS=~/code      # preview the rewrite, nothing changes
make prune   PATHS=~/code      # find keys and rewrite history

make tui     PATHS=~/code      # or drive it all interactively (the default)
make check                     # go vet + unit tests
```

`PATHS` accepts one or more repositories or folders (space separated), and defaults to the current directory. `make prune` is the one-command cleanup — build, discover, rewrite, verify — and refuses to run without an explicit `PATHS=` because the rewrite is irreversible.

## Build and install the binary

`make build` compiles the CLI to `secretsweep/secretsweep`. To build it by hand, or to place it on your `PATH` so you can launch the TUI from anywhere:

```bash
# Build in place (produces ./secretsweep/secretsweep)
cd secretsweep && go build -o secretsweep .

# Or install to your Go bin directory (usually ~/go/bin, which should be on PATH)
make install          # == cd secretsweep && go install .
```

`go install` places a `secretsweep` binary in `$(go env GOPATH)/bin`. Once that directory is on your `PATH`, launch the TUI from any folder:

```bash
secretsweep ~/code /backups/mirrors     # opens the interactive TUI
```

The binary needs `trivy` and `git-filter-repo` on the `PATH` at runtime.

## Interactive use

Running `secretsweep PATH...` (or `make tui`) opens the TUI:

1. **Discover** — repositories are found under the target paths.
2. **Scan** — Trivy scans every working tree with a coloured spinner, repository progress, running finding count, and a safely masked latest-finding notification.
3. **Review** — findings open in a searchable split pane. Nothing is selected by default:
   - `↑`/`↓` or `j`/`k` — move through the report without losing selection
   - `/` — search by severity, rule, repository, title, or path; `ctrl+u` clears the search
   - `space` — cycle the current finding through **none → replace → delete file**
   - `e` — edit the plain replacement marker (default `REMOVED_API_KEY`)
   - `p` — review the exact cleanup plan
   - `s` — scan full Git history for only the selected secrets
   - `d` — execute a dry-run for the selected plan; nothing is modified
4. **Preview and confirm** — the preview lists every repository-scoped deletion and the global replacement behavior. Continue only after typing `apply` exactly.
5. **Run** — engine output streams into a scrollable viewport; the summary reports what matched, was rewritten, or was skipped.

Selecting **replace** applies that compromised value everywhere it occurs in every discovered repository. Selecting **delete file** removes that repository-relative path from the selected repository's history and still replaces the compromised value everywhere else. Unrecovered findings remain visible for manual review but cannot be selected automatically.

Replacement text must be non-empty, single-line, free of the filter-rule delimiter, and different from every compromised value found during the scan.

## Headless use

```bash
secretsweep --headless ~/code                          # Trivy + full-history scan
secretsweep --headless --action dry-run ~/code         # preview the rewrite
secretsweep --headless --action rewrite --yes ~/code   # rewrite and verify
secretsweep --headless --replacement REVOKED_KEY ~/code # custom safe marker
secretsweep --headless --action none ~/code            # Trivy findings only
secretsweep --headless --key-file keys.txt ~/code      # add history-only keys
```

`--action rewrite` requires `--yes`. Exit status:

| Code | Meaning |
|---|---|
| `0` | no findings / everything clear |
| `2` | usage or environment error |
| `3` | compromised material found (scan or dry-run) |
| `4` | a rewrite was skipped or failed for at least one repository |

## How it works

Trivy redacts secret values in its output, so `secretsweep` recovers the exact key by aligning the redacted match against the raw file line. It then cleans **every recovered key across every discovered repository at once** — so a key spotted in one repository's working tree is also purged from every other repository's history.

The cleanup engine, for each repository selected by the reviewed plan:

- Scans the **full object database** (`git cat-file --batch-all-objects`) — the authoritative check that covers history, annotated tags, commit messages, and unreachable objects, for both working clones and bare/mirror repositories.
- Rewrites with `git filter-repo --replace-text --replace-message --sensitive-data-removal`, replacing every selected key with the reviewed plain marker across all locally available (and, when an `origin` exists, all fetchable) refs. Selected files additionally use `--invert-paths` with validated repository-relative paths.
- **Skips** repositories with uncommitted changes.
- **Verifies** by re-scanning the object database and reachable paths, and reports a failure if any key or selected deleted path remains.
- **Never pushes** — you review and force-push each repository yourself.

Secrets are written only to a `0600` temporary file that is deleted when the run ends, and are always shown masked in the UI.

### Keys that live only in history

Trivy scans working trees, not history. A key present in some working tree is recovered automatically and then purged everywhere. A key that exists **only** in old commits (removed from every working tree) is invisible to Trivy — supply it explicitly with `--key-file` (one exact key per line; blank lines and `#` comments ignored):

```bash
secretsweep --headless --action rewrite --yes --key-file /secure/keys.txt ~/code
```

Protect and then delete that file:

```bash
chmod 600 /secure/keys.txt   # before use
rm -f /secure/keys.txt       # after cleanup and verification
```

## Complete branch coverage with mirror clones

A normal clone may contain only its default branch plus a subset of remote refs. For complete coverage of every branch and tag on the server, create a mirror clone of each affected repository under one folder and point `secretsweep` at it:

```bash
mkdir -p /secure/work/org-cleanup
git clone --mirror YOUR_REPOSITORY_URL /secure/work/org-cleanup/repository-name.git
# repeat for each repository, then:
secretsweep --headless --action dry-run /secure/work/org-cleanup
```

A mirror clone is a bare repository ending in `.git`; `secretsweep` detects mirror, bare, worktree, and ordinary working clones. Refresh an existing mirror before relying on it:

```bash
git -C /secure/work/org-cleanup/repository-name.git remote update --prune
```

## Publish each cleaned repository

Rewrite mode does not push. Inspect each rewritten repository, then force-push when ready:

```bash
git -C /secure/work/org-cleanup/repository-name.git log --oneline --all --decorate -n 20
git -C /secure/work/org-cleanup/repository-name.git remote -v
git -C /secure/work/org-cleanup/repository-name.git push --force --mirror origin
```

`git-filter-repo` may remove a repository's `origin` remote as a safety measure; restore it with `git remote add origin YOUR_REPOSITORY_URL` if needed. Only use `--mirror` from a deliberately created and reviewed mirror clone — it replaces all remote refs. Force-pushing changes commit IDs, so collaborators should delete old clones and re-clone the cleaned repository; existing clones and forks can otherwise reintroduce the compromised history.

## Verify the published result

Delete the local mirror, create a fresh mirror from the server, and scan again:

```bash
rm -rf /secure/work/verification/repository-name.git
git clone --mirror YOUR_REPOSITORY_URL /secure/work/verification/repository-name.git
secretsweep --headless --action scan /secure/work/verification
```

The required result is exit status `0` with every repository clear. This fresh-clone verification proves what the server currently advertises. Use the real HTTPS or SSH URL — a clone from another local path may copy unreachable objects through Git's local-clone optimization and is not an accurate simulation of the server.

## Complete the security cleanup

Rewriting history is necessary but not sufficient. Also:

- Confirm every compromised key is **revoked**, not merely removed from Git.
- Remove keys from pull-request text, issue comments, build logs, releases, and artifacts.
- Follow your Git host's sensitive-data-removal process for cached objects and pull-request refs.
- Store replacement keys in a secret manager or environment variables.
- Add local secret files such as `.env` to `.gitignore` and commit only a placeholder like `.env.example`.
- Enable secret scanning and push protection on the hosting platform.

Provider caches, pull-request views, forks, build logs, releases, backups, and existing clones may still require provider-specific cleanup.

## License

Licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
