#!/usr/bin/env bash
set -euo pipefail

VERSION="2.0.0"
SCRIPT_NAME=$(basename "$0")

usage() {
  cat <<EOF
${SCRIPT_NAME} ${VERSION} — find and remove compromised API keys from Git history.

Usage:
  ${SCRIPT_NAME} [OPTIONS] [PATH ...]

Each PATH may be a single Git repository (working clone, worktree, bare, or
mirror) or a folder that is searched recursively for repositories. Several
paths may be mixed freely; duplicates are scanned once. When no PATH is
given, the current directory is used.

Modes (mutually exclusive; default: --scan):
  --scan            Report-only audit of refs and Git objects. Never edits.
  --dry-run         Everything --scan does, plus the exact rewrite plan for
                    each matching repository. Never edits.
  --rewrite         Rewrite matching histories with git-filter-repo and
                    verify every remaining Git object. Asks for typed
                    confirmation unless --yes is given. Never pushes.

Key sources (pick one):
  --key-file FILE   One exact key or mask per non-empty line (format below).
  API_KEY=...       Environment variable holding one exposed key.
  (neither)         Silent interactive prompt for one key.

Options:
  --fetch-all       Refresh all configured remotes and tags before scanning.
  --no-recurse      Require every PATH to be a repository itself; do not
                    search subfolders.
  --list            List the repositories that would be scanned, then exit.
                    Needs no key input.
  -y, --yes         Skip the interactive confirmation in rewrite mode.
  --no-color        Disable colored output (the NO_COLOR environment
                    variable is also honored).
  -V, --version     Print the version and exit.
  -h, --help        Show this help and exit.

Key file format:
  Exact keys and masks such as prefix**, **suffix, or prefix***suffix. Any
  run of 2+ asterisks is one mask covering unknown token characters. Every
  mask must expose at least 4 characters. Use literal:KEY when a key really
  contains asterisks. Blank lines are ignored.

Examples:
  # Audit a single repository
  ${SCRIPT_NAME} --scan ~/code/api

  # Audit several targets at once (repos and folders can be mixed)
  ${SCRIPT_NAME} --key-file keys.txt ~/code/api ~/code/web /backups/mirrors

  # Preview exactly what a rewrite would do, without changing anything
  ${SCRIPT_NAME} --dry-run --key-file keys.txt /secure/work/org-cleanup

  # Rewrite after review (still requires typed confirmation)
  ${SCRIPT_NAME} --rewrite --key-file keys.txt /secure/work/org-cleanup

  # Unattended rewrite of two specific repositories
  ${SCRIPT_NAME} --rewrite --yes --no-recurse --key-file keys.txt \\
    /secure/work/api.git /secure/work/web.git

Exit status:
  0  no compromised material found (or --list / --help / --version)
  2  usage, confirmation, or environment error
  3  scan or dry run found compromised material
  4  rewrite mode skipped or failed at least one matching repository

Rewrite mode never pushes; review each repository before force-pushing.
EOF
}

mode="scan"
mode_flag=""
key_file=""
fetch_all=false
no_recurse=false
list_only=false
assume_yes=false
no_color=false
targets=()

set_mode() {
  if [[ -n $mode_flag && $mode_flag != "$1" ]]; then
    printf 'Conflicting modes: %s and %s\n' "$mode_flag" "$1" >&2
    exit 2
  fi
  mode_flag=$1
  mode=${1#--}
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --scan|--rewrite|--dry-run)
      set_mode "$1"
      shift
      ;;
    --key-file)
      if [[ $# -lt 2 ]]; then
        printf '%s requires a file path.\n' "$1" >&2
        exit 2
      fi
      key_file=$2
      shift 2
      ;;
    --key-file=*)
      key_file=${1#*=}
      shift
      ;;
    --fetch-all)
      fetch_all=true
      shift
      ;;
    --no-recurse)
      no_recurse=true
      shift
      ;;
    --list|--list-repos)
      list_only=true
      shift
      ;;
    -y|--yes)
      assume_yes=true
      shift
      ;;
    --no-color)
      no_color=true
      shift
      ;;
    -V|--version)
      printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        targets+=("$1")
        shift
      done
      ;;
    -*)
      printf 'Unknown option: %s\n' "$1" >&2
      printf 'Run %s --help for usage.\n' "$SCRIPT_NAME" >&2
      exit 2
      ;;
    *)
      targets+=("$1")
      shift
      ;;
  esac
done

if (( ${#targets[@]} == 0 )); then
  targets=(".")
fi

if [[ $no_color == false && -z ${NO_COLOR:-} && -t 1 ]]; then
  c_red=$'\033[31m'
  c_green=$'\033[32m'
  c_yellow=$'\033[33m'
  c_bold=$'\033[1m'
  c_dim=$'\033[2m'
  c_reset=$'\033[0m'
else
  c_red=""
  c_green=""
  c_yellow=""
  c_bold=""
  c_dim=""
  c_reset=""
fi

for target in "${targets[@]}"; do
  if [[ ! -d $target ]]; then
    printf 'Folder does not exist: %s\n' "$target" >&2
    exit 2
  fi
done

if [[ -n $key_file && ! -f $key_file ]]; then
  printf 'Key file does not exist: %s\n' "$key_file" >&2
  exit 2
fi

have_filter_repo=true
if ! command -v git-filter-repo >/dev/null 2>&1; then
  have_filter_repo=false
fi
if [[ $mode == "rewrite" && $have_filter_repo == false ]]; then
  printf 'Rewrite mode requires git-filter-repo. Install it with: brew install git-filter-repo\n' >&2
  exit 1
fi

# --- Repository discovery ---------------------------------------------------

repos=()

add_repo() {
  local candidate=$1 resolved existing
  resolved=$(cd "$candidate" 2>/dev/null && pwd -P) || resolved=$candidate
  for existing in ${repos[@]+"${repos[@]}"}; do
    if [[ $existing == "$resolved" ]]; then
      return 0
    fi
  done
  repos+=("$resolved")
}

path_is_repo() {
  local path=$1
  if [[ -d $path/.git || -f $path/.git ]]; then
    return 0
  fi
  git -C "$path" rev-parse --is-bare-repository 2>/dev/null | grep -qx true
}

discover_repos() {
  local target=$1 git_dir
  while IFS= read -r -d '' git_dir; do
    if [[ -d $git_dir && $(basename "$git_dir") == ".git" ]]; then
      add_repo "${git_dir%/.git}"
    elif [[ -f $git_dir && $(basename "$git_dir") == ".git" ]]; then
      add_repo "${git_dir%/.git}"
    elif git -C "$git_dir" rev-parse --is-bare-repository 2>/dev/null | grep -qx true; then
      add_repo "$git_dir"
    fi
  done < <(find "$target" \( -type d -name .git -o -type f -name .git -o -type d -name '*.git' \) -print0 2>/dev/null)
}

for target in "${targets[@]}"; do
  if path_is_repo "$target"; then
    add_repo "$target"
    if [[ $no_recurse == true ]]; then
      continue
    fi
  elif [[ $no_recurse == true ]]; then
    printf 'Not a Git repository (every PATH must be one with --no-recurse): %s\n' "$target" >&2
    exit 2
  fi
  discover_repos "$target"
done

if (( ${#repos[@]} == 0 )); then
  printf 'No Git repositories found under: %s\n' "${targets[*]}"
  exit 0
fi

if [[ $list_only == true ]]; then
  printf '%d Git repositories found:\n' "${#repos[@]}"
  for repo in "${repos[@]}"; do
    printf '  %s\n' "$repo"
  done
  exit 0
fi

# --- Key pattern loading -----------------------------------------------------

scan_pattern_file=$(mktemp)
replacement_file=$(mktemp)
cleanup() {
  rm -f "$scan_pattern_file" "$replacement_file"
}
trap cleanup EXIT INT TERM
chmod 600 "$scan_pattern_file" "$replacement_file"

# Characters treated as part of an API-key token when expanding masked runs.
# The hyphen must remain last inside this bracket expression.
token_chars='A-Za-z0-9._~+/@-'
token_group="[$token_chars]"

regex_escape() {
  local input=$1 output="" char i=0
  while (( i < ${#input} )); do
    char=${input:i:1}
    case $char in
      '\\'|'.'|'['|']'|'^'|'$'|'*'|'+'|'?'|'{'|'}'|'('|')'|'|')
        output="${output}\\${char}"
        ;;
      *)
        output="${output}${char}"
        ;;
    esac
    ((i += 1))
  done
  printf '%s' "$output"
}

mask_to_regex() {
  local input=$1 output="" char i=0 run_end run_length
  while (( i < ${#input} )); do
    char=${input:i:1}
    if [[ $char == '*' ]]; then
      run_end=$i
      while (( run_end < ${#input} )) && [[ ${input:run_end:1} == '*' ]]; do
        ((run_end += 1))
      done
      run_length=$((run_end - i))
      if (( run_length < 2 )); then
        printf 'Invalid mask with a single *: %s\n' "$input" >&2
        return 1
      fi
      output="${output}${token_group}+"
      i=$run_end
      continue
    fi
    output="${output}$(regex_escape "$char")"
    ((i += 1))
  done
  printf '%s' "$output"
}

add_exact_key() {
  local key=$1 escaped
  if [[ -z $key ]]; then
    printf 'Exact keys cannot be empty.\n' >&2
    return 1
  fi
  escaped=$(regex_escape "$key")
  printf '%s\n' "$escaped" >> "$scan_pattern_file"
  printf 'literal:%s==>REMOVED_API_KEY\n' "$key" >> "$replacement_file"
}

add_masked_key() {
  local mask=$1 visible core
  visible=${mask//\*/}
  if (( ${#visible} < 4 )); then
    printf 'Unsafe mask (expose at least four characters): %s\n' "$mask" >&2
    return 1
  fi
  core=$(mask_to_regex "$mask")
  printf '(^|[^%s])%s($|[^%s])\n' "$token_chars" "$core" "$token_chars" >> "$scan_pattern_file"
  printf 'regex:(?<![%s])%s(?![%s])==>REMOVED_API_KEY\n' "$token_chars" "$core" "$token_chars" >> "$replacement_file"
}

key_count=0
exact_count=0
masked_count=0
if [[ -n $key_file ]]; then
  # Blank lines are ignored. A run of 2+ asterisks denotes one unknown token
  # segment unless the line starts with literal:.
  while IFS= read -r key || [[ -n $key ]]; do
    key=${key%$'\r'}
    [[ -z $key ]] && continue
    if [[ $key == literal:* ]]; then
      add_exact_key "${key#literal:}"
      ((exact_count += 1))
    elif [[ $key == *'**'* ]]; then
      add_masked_key "$key"
      ((masked_count += 1))
    elif [[ $key == *'*'* ]]; then
      printf 'Invalid key pattern with a single *; use ** as a mask or literal: for a real asterisk.\n' >&2
      exit 2
    else
      add_exact_key "$key"
      ((exact_count += 1))
    fi
    ((key_count += 1))
  done < "$key_file"
else
  if [[ -z ${API_KEY:-} ]]; then
    read -r -s -p 'Exposed API key: ' API_KEY
    printf '\n'
  fi
  if [[ -z $API_KEY ]]; then
    printf 'The API key cannot be empty.\n' >&2
    exit 2
  fi
  add_exact_key "$API_KEY"
  key_count=1
  exact_count=1
fi

if (( key_count == 0 )); then
  printf 'No keys were found. Add one exact key or mask per non-empty line.\n' >&2
  exit 2
fi

# --- Run ---------------------------------------------------------------------

case $mode in
  scan) mode_label="scan (report only)" ;;
  dry-run) mode_label="dry run (rewrite preview; nothing is modified)" ;;
  rewrite) mode_label="rewrite" ;;
esac

printf '%sMode:%s %s\n' "$c_bold" "$c_reset" "$mode_label"
printf 'Loaded %d compromised key patterns (%d exact, %d masked).\n' "$key_count" "$exact_count" "$masked_count"
printf 'Found %d Git repositories across %d target path(s).\n\n' "${#repos[@]}" "${#targets[@]}"

if [[ $mode == "dry-run" && $have_filter_repo == false ]]; then
  printf '%sNote:%s git-filter-repo is not installed; --rewrite will fail until you run: brew install git-filter-repo\n\n' \
    "$c_yellow" "$c_reset"
fi

if [[ $mode == "rewrite" && $assume_yes == false ]]; then
  printf '%sRewrite mode permanently rewrites Git history in every matching repository.%s\n' "$c_bold" "$c_reset"
  printf 'Confirm that the exposed keys are revoked and backups exist before continuing.\n'
  if [[ ! -t 0 ]]; then
    printf 'Standard input is not a terminal; re-run with --yes to confirm non-interactively.\n' >&2
    exit 2
  fi
  read -r -p 'Type "rewrite" to continue: ' confirmation
  if [[ $confirmation != "rewrite" ]]; then
    printf 'Aborted; no repository was modified.\n'
    exit 2
  fi
  printf '\n'
fi

matches=0
rewritten=0
skipped=0
would_rewrite=0
would_skip=0
infected_branches_total=0

object_database_has_match() {
  local repo=$1
  local oid type
  while read -r oid type; do
    case $type in
      blob|commit|tag)
        if git -C "$repo" cat-file "$type" "$oid" 2>/dev/null | LC_ALL=C grep -a -E -f "$scan_pattern_file" >/dev/null 2>&1; then
          return 0
        fi
        ;;
    esac
  done < <(git -C "$repo" cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)')
  return 1
}

# Populates filter_args for the given repository. Returns 1 when the
# repository has no origin remote, in which case --no-fetch is included.
build_filter_args() {
  local repo=$1
  filter_args=(--replace-text "$replacement_file" --replace-message "$replacement_file" --sensitive-data-removal --force)
  if ! git -C "$repo" remote get-url origin >/dev/null 2>&1; then
    filter_args+=(--no-fetch)
    return 1
  fi
  return 0
}

repo_index=0
for repo in "${repos[@]}"; do
  ((repo_index += 1))
  printf '%s[%d/%d]%s Repository: %s%s%s\n' \
    "$c_dim" "$repo_index" "${#repos[@]}" "$c_reset" "$c_bold" "$repo" "$c_reset"

  bare=$(git -C "$repo" rev-parse --is-bare-repository 2>/dev/null || printf false)
  if [[ $fetch_all == true ]]; then
    printf '  Refreshing all configured remotes and tags...\n'
    if ! git -C "$repo" fetch --all --prune --tags; then
      printf '  Action: %sSKIPPED%s (fetch failed)\n\n' "$c_yellow" "$c_reset" >&2
      ((skipped += 1))
      continue
    fi
  fi

  current_match=false
  history_match=false
  object_match=false
  infected_commits=$(mktemp)
  chmod 600 "$infected_commits"

  if [[ $bare == true ]]; then
    printf '  Current tracked files: n/a (bare or mirror repository)\n'
  elif git -C "$repo" grep -I -E -f "$scan_pattern_file" -- . >/dev/null 2>&1; then
    current_match=true
    printf '  Current tracked files: %sMATCH%s\n' "$c_red" "$c_reset"
  else
    printf '  Current tracked files: %sclear%s\n' "$c_green" "$c_reset"
  fi

  # Build the set of infected commits once, then map it to every branch ref.
  while IFS= read -r revision; do
    if git -C "$repo" grep -I -E -f "$scan_pattern_file" "$revision" -- . >/dev/null 2>&1 || \
       git -C "$repo" cat-file commit "$revision" 2>/dev/null | LC_ALL=C grep -a -E -f "$scan_pattern_file" >/dev/null 2>&1; then
      history_match=true
      printf '%s\n' "$revision" >> "$infected_commits"
    fi
  done < <(git -C "$repo" rev-list --all)

  if [[ $history_match == true ]]; then
    printf '  Reachable Git history: %sMATCH%s\n' "$c_red" "$c_reset"
  else
    printf '  Reachable Git history: %sclear%s\n' "$c_green" "$c_reset"
  fi

  infected_branches=0
  if [[ -s $infected_commits ]]; then
    while IFS= read -r ref; do
      ref_infected=false
      while IFS= read -r infected_commit; do
        if git -C "$repo" merge-base --is-ancestor "$infected_commit" "$ref" 2>/dev/null; then
          ref_infected=true
          break
        fi
      done < "$infected_commits"
      if [[ $ref_infected == true ]]; then
        printf '    Infected branch: %s\n' "$ref"
        ((infected_branches += 1))
      fi
    done < <(git -C "$repo" for-each-ref --format='%(refname)' refs/heads refs/remotes | grep -v '/HEAD$' || true)
  fi
  ((infected_branches_total += infected_branches))
  printf '  Infected branches: %d\n' "$infected_branches"

  printf '  Full Git object database: scanning...\n'
  if object_database_has_match "$repo"; then
    object_match=true
    printf '  Full Git object database: %sMATCH%s\n' "$c_red" "$c_reset"
  else
    printf '  Full Git object database: %sclear%s\n' "$c_green" "$c_reset"
  fi

  if [[ $current_match == false && $history_match == false && $object_match == false ]]; then
    rm -f "$infected_commits"
    printf '\n'
    continue
  fi

  ((matches += 1))
  if [[ $mode == "scan" ]]; then
    rm -f "$infected_commits"
    printf '  Action: report only\n\n'
    continue
  fi

  if [[ $mode == "dry-run" ]]; then
    rm -f "$infected_commits"
    if [[ $bare != true && -n $(git -C "$repo" status --porcelain) ]]; then
      printf '  Action: %swould SKIP%s (working tree has uncommitted changes)\n\n' "$c_yellow" "$c_reset"
      ((would_skip += 1))
      continue
    fi
    if build_filter_args "$repo"; then
      printf '  Action: %swould rewrite history%s (all fetchable origin refs)\n' "$c_yellow" "$c_reset"
    else
      printf '  Action: %swould rewrite history%s (no origin remote; locally available refs only)\n' "$c_yellow" "$c_reset"
    fi
    printf '    Command: git -C %q filter-repo' "$repo"
    for arg in "${filter_args[@]}"; do
      case $arg in
        "$replacement_file") printf ' <replacement-rules>' ;;
        *) printf ' %q' "$arg" ;;
      esac
    done
    printf '\n    Then: verify every remaining Git object against the key patterns.\n\n'
    ((would_rewrite += 1))
    continue
  fi

  if [[ $bare != true && -n $(git -C "$repo" status --porcelain) ]]; then
    rm -f "$infected_commits"
    printf '  Action: %sSKIPPED%s (working tree has uncommitted changes)\n\n' "$c_yellow" "$c_reset" >&2
    ((skipped += 1))
    continue
  fi

  printf '  Rewriting history...\n'
  if ! build_filter_args "$repo"; then
    printf '  Warning: no origin remote; only locally available refs can be rewritten.\n' >&2
  fi
  if git -C "$repo" filter-repo "${filter_args[@]}"; then
    rm -f "$infected_commits"

    printf '  Verifying every remaining Git object...\n'
    if object_database_has_match "$repo"; then
      printf '  Action: %sFAILED VERIFICATION%s (a supplied key remains in the object database)\n\n' "$c_red" "$c_reset" >&2
      ((skipped += 1))
    else
      printf '  Action: %srewritten and verified%s; inspect before pushing\n\n' "$c_green" "$c_reset"
      ((rewritten += 1))
    fi
  else
    rm -f "$infected_commits"
    printf '  Action: %sFAILED%s\n\n' "$c_red" "$c_reset" >&2
    ((skipped += 1))
  fi
done

if [[ $mode == "dry-run" ]]; then
  printf 'Summary: %d matching repositories, %d infected branches, %d would be rewritten, %d would be skipped\n' \
    "$matches" "$infected_branches_total" "$would_rewrite" "$would_skip"
else
  printf 'Summary: %d matching repositories, %d infected branches, %d rewritten, %d skipped\n' \
    "$matches" "$infected_branches_total" "$rewritten" "$skipped"
fi

if [[ $mode == "scan" ]] && (( matches > 0 )); then
  printf 'Re-run with --dry-run to preview the rewrite, then --rewrite after revoking the exposed keys and backing up your repositories.\n'
  exit 3
fi

if [[ $mode == "dry-run" ]] && (( matches > 0 )); then
  printf 'Dry run only: nothing was modified. Re-run with --rewrite after revoking the exposed keys and backing up your repositories.\n'
  exit 3
fi

if [[ $mode == "rewrite" ]] && (( skipped > 0 )); then
  exit 4
fi
