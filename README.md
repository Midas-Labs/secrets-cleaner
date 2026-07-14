# Compromised API Key Cleanup

This utility scans Git repositories for compromised API keys, including keys that exist only in earlier commits, branch histories, tags, commit messages, and unreachable local Git objects. It accepts one or more target paths; each path may be a single repository (working clone, worktree, bare, or mirror) or a folder that is searched recursively. After a report-only scan and an optional dry run of the rewrite plan, it can replace every confirmed compromised key across all fetched refs and verify the complete local object database.

`CHANGE_REPORT.md` records the current implementation and verification status. The `archive` folder contains the earlier report snapshot and is retained only for history; it is superseded by the current README and change report.

Revoke or rotate all compromised keys with the API provider before using this tool. Rewriting Git history does not invalidate keys that have already been copied.

Two entry points are provided:

- **`secretsweep`** — an interactive TUI (built with [Bubble Tea](https://github.com/charmbracelet/bubbletea)) that discovers repositories, finds compromised keys automatically with [Trivy](https://trivy.dev) secret scanning, and drives the cleanup engine. No hand-written key inventory needed. See [secretsweep](#secretsweep-trivy-powered-tui) below.
- **`clean-secret-from-repos.sh`** — the cleanup engine, usable directly when you already know the compromised keys (sections 1–8 below).

## secretsweep: Trivy-powered TUI

```bash
brew install trivy go
cd secretsweep && go build -o secretsweep .

# Interactive: discover repos, Trivy-scan them, review findings, clean up
./secretsweep ~/code /backups/mirrors

# Headless (automation / CI)
./secretsweep --headless ~/code                        # Trivy + full-history scan
./secretsweep --headless --action dry-run ~/code       # preview the rewrite
./secretsweep --headless --action rewrite --yes ~/code # rewrite and verify
```

The TUI flow: repositories are discovered (single repos or folders, recursively), Trivy scans every working tree for secrets, findings appear in a table (severity, rule, location, masked value). From there `[s]` scans full Git history for the recovered keys, `[d]` previews the rewrite per repository, and `[r]` rewrites — after typing `rewrite` to confirm. Engine output streams into a scrollable viewport.

How it works: Trivy redacts secret values in its output, so secretsweep recovers the exact key by aligning the redacted match against the raw file line, then feeds all recovered keys to `clean-secret-from-repos.sh` over all repositories — so a key spotted in one repository's working tree is also purged from every other repository's history. Secrets are written only to a `0600` temp file that is deleted when the run ends, and are always shown masked in the UI.

Limitation: Trivy scans working trees, not Git history. A key that exists only in old commits is found by the engine's history scan once recovered from *some* working tree, but a key absent from every working tree must still be supplied by hand via the engine's `--key-file` (sections 1–8 below). Findings whose exact value cannot be recovered are reported for manual review.

## Requirements

- macOS or Linux with Bash and Git
- [`git-filter-repo`](https://github.com/newren/git-filter-repo) for rewrite mode
- Clean working trees in repositories that will be rewritten
- A backup of the repositories and coordination with their collaborators
- Network and repository permissions sufficient to fetch and replace every remote branch

On macOS, install the rewrite dependency with:

```bash
brew install git-filter-repo
```

Make the script executable if needed:

```bash
chmod +x clean-secret-from-repos.sh
```

## 1. Prepare the compromised-key inventory

Create a file outside the repositories being scanned. Each non-empty line may contain an exact key or a masked key pattern:

```text
first-complete-compromised-key
sk_live_abcd**
**wxyz9876
ghp_ABCD**WXYZ
tok2***i72i
**visible-middle**
literal:key**that-really-contains-asterisks
```

The supported forms are:

| Inventory entry | Meaning |
|---|---|
| `complete-key` | Match one exact key |
| `prefix**` | Match a complete token beginning with `prefix` |
| `**suffix` | Match a complete token ending with `suffix` |
| `prefix**suffix` | Match a token with the supplied beginning and ending |
| `prefix***suffix` | Same behavior: any run of two or more asterisks is one mask |
| `**middle**` | Match a token containing the supplied visible middle |
| `literal:key**value` | Treat `**` as literal asterisks instead of a mask |

Every mask must expose at least four characters in total. Each consecutive run of two or more asterisks represents one or more unknown token characters; the number of asterisks does not indicate the hidden key length. A single asterisk is rejected unless the entry starts with `literal:`. Masked token characters are limited to letters, digits, `.`, `_`, `~`, `+`, `/`, `@`, and `-`; supply the complete exact key when the unknown portion contains other characters such as `=` or `:`.

Protect the file while it exists:

```bash
chmod 600 /secure/path/compromised-keys.txt
```

Keys may share the same first or last characters. A masked entry can cover multiple compromised keys, but broader masks increase the risk of matching unrelated tokens. Always review scan results and test against disposable mirrors before rewrite mode.

Do not commit the inventory file. Delete it securely after cleanup and verification.

## 2. Create complete mirror clones

A normal clone may contain only its default branch plus a subset of remote refs. For complete branch coverage, create a mirror clone of every affected repository under one root folder:

```bash
mkdir -p /secure/work/org-cleanup
cd /secure/work/org-cleanup
git clone --mirror YOUR_REPOSITORY_URL repository-name.git
```

Repeat that command for each organization repository being audited. A mirror clone contains all refs advertised by the remote and is a bare repository ending in `.git`; the cleanup script detects both mirror clones and ordinary working clones.

Before relying on a previously created mirror, refresh it:

```bash
git -C /secure/work/org-cleanup/repository-name.git remote update --prune
```

The utility can refresh all configured remotes before its report-only scan by using `--fetch-all`.

## 3. Scan every repository, ref, and object

Preview which repositories a run would cover (no key input needed):

```bash
./clean-secret-from-repos.sh --list /secure/work/org-cleanup
```

Then run the report-only scan:

```bash
./clean-secret-from-repos.sh \
  --scan \
  --fetch-all \
  --key-file /secure/path/compromised-keys.txt \
  /secure/work/org-cleanup
```

Targets can also be a single repository, or any mix of repositories and folders:

```bash
# One repository
./clean-secret-from-repos.sh --scan --key-file keys.txt ~/code/api

# Several repositories and folders in one run (duplicates are scanned once)
./clean-secret-from-repos.sh --scan --key-file keys.txt \
  ~/code/api ~/code/web /secure/work/org-cleanup

# Require every path to be a repository itself (no recursive search)
./clean-secret-from-repos.sh --scan --no-recurse --key-file keys.txt \
  /secure/work/api.git /secure/work/web.git
```

When no path is given, the current directory is used.

The script discovers repositories and reports, for each one:

- Whether a supplied exact key or masked key pattern exists in current tracked files for working clones
- Whether a supplied exact key or masked key pattern exists in any commit reachable from any local ref
- Every infected local or remote-tracking branch ref
- The infected branch count for each repository and the total count
- Whether a supplied key appears anywhere in the local Git object database, including commit messages, annotated tags, and unreachable blobs
- Whether the repository requires cleanup

Scan mode never edits repositories or pushes to remotes.

For one compromised key, a silent prompt is also available:

```bash
./clean-secret-from-repos.sh --scan /path/to/folder-containing-repositories
```

For the reported case, the scan summary should account for the initial 240 infected branches. A different count means the local mirrors or the compromised-key inventory need investigation before rewriting.

## 4. Dry-run the rewrite

Before touching anything, preview exactly what rewrite mode would do:

```bash
./clean-secret-from-repos.sh \
  --dry-run \
  --key-file /secure/path/compromised-keys.txt \
  /secure/work/org-cleanup
```

A dry run performs the full scan and then, for each matching repository, reports whether it would be rewritten or skipped (for example because of uncommitted changes), including the exact `git filter-repo` invocation that rewrite mode would execute. Nothing is modified; the exit status is `3` when compromised material is found, matching scan mode.

## 5. Rewrite all fetched histories

After reviewing the scan and dry run, revoking the keys, and backing up the repositories, run:

```bash
./clean-secret-from-repos.sh \
  --rewrite \
  --key-file /secure/path/compromised-keys.txt \
  /secure/work/org-cleanup
```

Rewrite mode asks for a typed confirmation (`rewrite`) before touching anything. Pass `--yes` for unattended runs; without it, a non-interactive invocation refuses to proceed.

Rewrite mode:

- Replaces every exact key and every complete token matched by a supplied mask with `REMOVED_API_KEY`
- Replaces supplied keys in file contents, commit messages, and annotated tag messages
- Uses `git-filter-repo` sensitive-data-removal mode to perform a mirror-like fetch of all fetchable refs from `origin`
- Rewrites all locally available branches, tags, and refs rather than only the checked-out branch
- Skips repositories with uncommitted changes
- Verifies that no supplied key remains anywhere in the local Git object database
- Does not push any changes

`git-filter-repo` may remove a repository's `origin` remote as a safety measure. Inspect each rewritten repository and restore its remote URL if necessary.

If a repository has no `origin`, the utility cannot fetch missing server refs. It warns, rewrites locally available refs, and performs local verification only.

## 6. Review and publish each cleaned repository

Inside each rewritten mirror, inspect its refs and remote:

```bash
git -C /secure/work/org-cleanup/repository-name.git show-ref
git -C /secure/work/org-cleanup/repository-name.git log --oneline --all --decorate -n 20
git -C /secure/work/org-cleanup/repository-name.git remote -v
```

If `origin` was removed, restore it using the repository's actual URL:

```bash
git -C /secure/work/org-cleanup/repository-name.git remote add origin YOUR_REPOSITORY_URL
```

Coordinate with collaborators before replacing shared history. When ready:

```bash
git -C /secure/work/org-cleanup/repository-name.git push --force --mirror origin
```

Only use `--mirror` from a deliberately created and reviewed mirror clone. It replaces all remote refs represented by the mirror. Force-pushing changes commit IDs; existing clones and forks can reintroduce the compromised history, so collaborators should delete old clones and clone the cleaned repository again.

## 7. Verify the published result

Delete the local mirror, create a new mirror from the server, and run the full scan again:

```bash
rm -rf /secure/work/verification/repository-name.git
git clone --mirror YOUR_REPOSITORY_URL /secure/work/verification/repository-name.git

./clean-secret-from-repos.sh \
  --scan \
  --fetch-all \
  --key-file /secure/path/compromised-keys.txt \
  /secure/work/verification
```

The required result is:

- Zero matching repositories
- Zero infected branches
- `Full Git object database: clear` for every repository
- Command exit status `0`

This fresh-clone verification proves what the server currently advertises to the operator. Hosting-provider pull-request refs, cached views, forks, build logs, releases, and internal retention may still require provider-specific cleanup.

Use the actual HTTPS or SSH server URL for verification. A clone made directly from another local filesystem path may copy unreachable objects through Git's local-clone optimization and is not an accurate simulation of what the server advertises over the network.

## 8. Complete the security cleanup

- Confirm every compromised key is revoked, not merely removed from Git.
- Remove keys from pull-request text, issue comments, build logs, releases, and artifacts where applicable.
- Follow the Git hosting provider's sensitive-data removal process for cached objects and pull-request references.
- Delete the local compromised-key inventory.
- Store replacement keys in a secret manager or environment variables.
- Add local secret files such as `.env` to `.gitignore` and commit only a placeholder such as `.env.example`.
- Enable secret scanning and push protection on the hosting platform.

## Exit and safety behavior

- Invalid arguments, missing files, empty key inventories, or missing rewrite dependencies stop the run.
- Scan and dry-run modes return exit status `3` when compromised material is found and `0` only when every scanned repository is clear.
- Dry-run mode never edits anything; it reports the exact rewrite plan per matching repository.
- Rewrite mode returns exit status `4` if any matching repository is skipped or fails verification.
- Rewrite mode requires a typed confirmation unless `--yes` is supplied, and refuses to run non-interactively without `--yes`.
- Repositories with uncommitted changes are skipped in rewrite mode (reported as "would SKIP" in a dry run).
- The script handles non-bare repositories represented by `.git` directories or worktree pointer files.
- The script also handles bare and mirror repositories whose folders end in `.git`.
- Rewrite mode performs a mirror-like origin fetch when `origin` is configured.
- Verification scans all remaining local blobs, commits, and annotated tag objects, including unreachable objects.
- No remote is modified unless an operator explicitly runs the force-push commands.

Use `./clean-secret-from-repos.sh --help` for the command summary.
