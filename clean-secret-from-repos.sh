#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  clean-secret-from-repos.sh [--scan|--rewrite] [--fetch-all] --key-file KEYS_FILE ROOT_FOLDER
  API_KEY='one-exposed-key' clean-secret-from-repos.sh [--scan|--rewrite] [--fetch-all] ROOT_FOLDER

Modes:
  --scan       Audit all local refs and Git objects without editing (default).
  --rewrite    Fetch all origin refs, rewrite them, and verify every Git object.

Options:
  --fetch-all  Refresh all configured remotes and tags before a scan.

The script discovers Git repositories recursively. Rewrite mode does not push;
review the results before force-pushing branches and tags yourself.

KEYS_FILE accepts exact keys and masks such as prefix**, **suffix, or prefix***suffix.
Any run of 2+ asterisks is one mask. Expose 4+ characters; use literal:KEY for real asterisks.
For a single key, set API_KEY or omit it to use the silent prompt.
EOF
}

mode="scan"
key_file=""
fetch_all=false
if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    --scan|--rewrite)
      mode="${1#--}"
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
    --fetch-all)
      fetch_all=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

root=$1
if [[ ! -d $root ]]; then
  printf 'Folder does not exist: %s\n' "$root" >&2
  exit 2
fi

if [[ -n $key_file && ! -f $key_file ]]; then
  printf 'Key file does not exist: %s\n' "$key_file" >&2
  exit 2
fi

if [[ $mode == "rewrite" ]] && ! command -v git-filter-repo >/dev/null 2>&1; then
  printf 'Rewrite mode requires git-filter-repo. Install it with: brew install git-filter-repo\n' >&2
  exit 1
fi

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

repos=()
while IFS= read -r -d '' git_dir; do
  if [[ -d $git_dir && $(basename "$git_dir") == ".git" ]]; then
    repos+=("${git_dir%/.git}")
  elif [[ -f $git_dir && $(basename "$git_dir") == ".git" ]]; then
    repos+=("${git_dir%/.git}")
  elif git -C "$git_dir" rev-parse --is-bare-repository 2>/dev/null | grep -qx true; then
    repos+=("$git_dir")
  fi
done < <(find "$root" \( -type d -name .git -o -type f -name .git -o -type d -name '*.git' \) -print0 2>/dev/null)

if (( ${#repos[@]} == 0 )); then
  printf 'No Git repositories found under %s\n' "$root"
  exit 0
fi

printf 'Loaded %d compromised key patterns (%d exact, %d masked).\n' "$key_count" "$exact_count" "$masked_count"
printf 'Found %d Git repositories under %s\n\n' "${#repos[@]}" "$root"
matches=0
rewritten=0
skipped=0
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

for repo in "${repos[@]}"; do
  printf 'Repository: %s\n' "$repo"

  bare=$(git -C "$repo" rev-parse --is-bare-repository 2>/dev/null || printf false)
  if [[ $fetch_all == true ]]; then
    printf '  Refreshing all configured remotes and tags...\n'
    if ! git -C "$repo" fetch --all --prune --tags; then
      printf '  Action: SKIPPED (fetch failed)\n\n' >&2
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
    printf '  Current tracked files: MATCH\n'
  else
    printf '  Current tracked files: clear\n'
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
    history_match=true
    printf '  Reachable Git history: MATCH\n'
  else
    printf '  Reachable Git history: clear\n'
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
    printf '  Full Git object database: MATCH\n'
  else
    printf '  Full Git object database: clear\n'
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

  if [[ $bare != true && -n $(git -C "$repo" status --porcelain) ]]; then
    rm -f "$infected_commits"
    printf '  Action: SKIPPED (working tree has uncommitted changes)\n\n' >&2
    ((skipped += 1))
    continue
  fi

  printf '  Rewriting history...\n'
  filter_args=(--replace-text "$replacement_file" --replace-message "$replacement_file" --sensitive-data-removal --force)
  if ! git -C "$repo" remote get-url origin >/dev/null 2>&1; then
    printf '  Warning: no origin remote; only locally available refs can be rewritten.\n' >&2
    filter_args+=(--no-fetch)
  fi
  if git -C "$repo" filter-repo "${filter_args[@]}"; then
    rm -f "$infected_commits"

    printf '  Verifying every remaining Git object...\n'
    if object_database_has_match "$repo"; then
      printf '  Action: FAILED VERIFICATION (a supplied key remains in the object database)\n\n' >&2
      ((skipped += 1))
    else
      printf '  Action: rewritten and verified; inspect before pushing\n\n'
      ((rewritten += 1))
    fi
  else
    rm -f "$infected_commits"
    printf '  Action: FAILED\n\n' >&2
    ((skipped += 1))
  fi
done

printf 'Summary: %d matching repositories, %d infected branches, %d rewritten, %d skipped\n' \
  "$matches" "$infected_branches_total" "$rewritten" "$skipped"

if [[ $mode == "scan" && $matches -gt 0 ]]; then
  printf 'Re-run with --rewrite only after revoking the exposed key and backing up your repositories.\n'
  exit 3
fi

if [[ $mode == "rewrite" && $skipped -gt 0 ]]; then
  exit 4
fi
