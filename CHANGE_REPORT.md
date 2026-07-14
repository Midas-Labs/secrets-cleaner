# Change report

Status: tested and ready for controlled use on disposable mirrors before organization rollout.

## Current capabilities

- Discovers ordinary, worktree, bare, and mirror Git repositories below one folder.
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
