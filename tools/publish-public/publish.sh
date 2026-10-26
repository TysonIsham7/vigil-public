#!/usr/bin/env bash
# Build a sanitized snapshot of a private git ref and, only with --push,
# publish it as one new commit. The private repository is not rewritten.
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'publish-public: run this script with bash\n' >&2
  exit 1
fi
set -euo pipefail
export LC_ALL=C

PP_TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$PP_TOOL_DIR/lib/common.sh"
# shellcheck source=lib/config.sh
. "$PP_TOOL_DIR/lib/config.sh"
# shellcheck source=lib/gitleaks.sh
. "$PP_TOOL_DIR/lib/gitleaks.sh"
# shellcheck source=lib/sanitize.sh
. "$PP_TOOL_DIR/lib/sanitize.sh"
# shellcheck source=lib/scan.sh
. "$PP_TOOL_DIR/lib/scan.sh"

PP_REPO=""
PP_CONFIG=""
PP_REF="HEAD"
PP_PUSH=0
PP_KEEP=0
PP_REPORT_PATH=""
PP_DENYLIST_OVERRIDE=""
PP_MESSAGE_OVERRIDE=""
PP_WORK=""
PP_TREE=""
PP_COMMIT_MESSAGE=""
PP_PARENT=""
PP_COMMIT=""
PP_IDENTICAL=0
PP_FETCH_NOTE=""
PP_SOURCE_SHA=""
PP_STATUS_BEFORE=""
PP_HEAD_BEFORE=""

pp_cleanup() {
  local status=$?
  if [ -n "${PP_WORK:-}" ] && [ -d "$PP_WORK" ]; then
    rm -f "$PP_WORK"/gitleaks-*.json "$PP_WORK"/gitleaks.parsed "$PP_WORK"/deny.out \
      "$PP_WORK"/name.out "$PP_WORK/message/COMMIT_MESSAGE.txt" 2>/dev/null || true
    if [ "$PP_KEEP" -eq 0 ]; then
      rm -rf "$PP_WORK"
    else
      pp_note "kept temp tree at ${PP_WORK}/tree"
    fi
  fi
  exit "$status"
}
trap pp_cleanup EXIT

pp_usage() {
  cat <<'EOF'
usage: publish.sh [--repo DIR] [--config FILE] [--ref REV] [--denylist FILE]
                  [--message TEXT] [--report FILE] [--push] [--keep]

Copy a git ref into a temp directory, apply the repo's publish config, and
scan the result. The default is a dry run: it prints a report and a diff
summary and does not push. Pass --push to send one new commit to the
configured public remote. The private repository is not rewritten, and the
push is not a force push.
EOF
}

pp_need() {
  if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
    pp_die "$1 needs a value"
  fi
  case $2 in
    --*) pp_die "$1 needs a value" ;;
  esac
}

pp_parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --repo)
        pp_need "$@"
        PP_REPO=$2
        shift 2
        ;;
      --config)
        pp_need "$@"
        PP_CONFIG=$2
        shift 2
        ;;
      --ref)
        pp_need "$@"
        PP_REF=$2
        shift 2
        ;;
      --denylist)
        pp_need "$@"
        PP_DENYLIST_OVERRIDE=$2
        shift 2
        ;;
      --message)
        pp_need "$@"
        PP_MESSAGE_OVERRIDE=$2
        shift 2
        ;;
      --report)
        pp_need "$@"
        PP_REPORT_PATH=$2
        shift 2
        ;;
      --push)
        PP_PUSH=1
        shift
        ;;
      --keep)
        PP_KEEP=1
        shift
        ;;
      --dry-run)
        PP_PUSH=0
        shift
        ;;
      -h | --help)
        pp_usage
        exit 0
        ;;
      *)
        pp_die "unknown argument: $1"
        ;;
    esac
  done
}

pp_refuse_same_repo() {
  local origin src_git path="" dest_git
  origin=$(git -C "$PP_REPO" remote get-url origin 2>/dev/null || true)
  if [ -n "$origin" ] && [ "$(pp_slug "$origin")" = "$(pp_slug "$PP_REMOTE")" ]; then
    pp_die "public_remote is this repository. Refusing."
  fi
  src_git=$(git -C "$PP_REPO" rev-parse --absolute-git-dir)
  case $PP_REMOTE in
    file://*) path=${PP_REMOTE#file://} ;;
    /* | ./* | ../*) path=$PP_REMOTE ;;
  esac
  if [ -n "$path" ] && [ -e "$path" ]; then
    dest_git=$(git -C "$path" rev-parse --absolute-git-dir 2>/dev/null \
      || git --git-dir="$path" rev-parse --absolute-git-dir 2>/dev/null || true)
    if [ -n "$dest_git" ] && [ "$dest_git" = "$src_git" ]; then
      pp_die "public_remote points at this repository. Refusing."
    fi
  fi
}

pp_resolve_denylist() {
  if [ -n "$PP_DENYLIST_OVERRIDE" ]; then
    case $PP_DENYLIST_OVERRIDE in
      /*) PP_DENYLIST_FILE=$PP_DENYLIST_OVERRIDE ;;
      *) PP_DENYLIST_FILE=$PP_REPO/$PP_DENYLIST_OVERRIDE ;;
    esac
    return 0
  fi
  case $PP_DENYLIST_REL in
    /*) PP_DENYLIST_FILE=$PP_DENYLIST_REL ;;
    *) PP_DENYLIST_FILE=$PP_REPO/$PP_DENYLIST_REL ;;
  esac
}

pp_resolve_gitleaks_config() {
  PP_GITLEAKS_CONFIG_PATH=""
  local rel=$PP_GITLEAKS_CONFIG
  if [ -z "$rel" ] && [ -f "$PP_REPO/.gitleaks.toml" ]; then
    rel=.gitleaks.toml
  fi
  [ -n "$rel" ] || return 0
  case $rel in
    /*) PP_GITLEAKS_CONFIG_PATH=$rel ;;
    *) PP_GITLEAKS_CONFIG_PATH=$PP_REPO/$rel ;;
  esac
  [ -f "$PP_GITLEAKS_CONFIG_PATH" ] || pp_die "gitleaks config not found: ${rel}"
}

pp_assert_source_unchanged() {
  local head status
  head=$(git -C "$PP_REPO" rev-parse HEAD)
  status=$(git -C "$PP_REPO" status --porcelain)
  if [ "$head" != "$PP_HEAD_BEFORE" ] || [ "$status" != "$PP_STATUS_BEFORE" ]; then
    pp_die "internal error: the private repository changed"
  fi
}

pp_prepare_commit() {
  git -C "$PP_TREE" -c core.hooksPath=/dev/null init -q
  git -C "$PP_TREE" -c core.hooksPath=/dev/null symbolic-ref HEAD "refs/heads/${PP_BRANCH}"
  git -C "$PP_TREE" config core.autocrlf false
  git -C "$PP_TREE" config core.safecrlf false
  git -C "$PP_TREE" config commit.gpgsign false
  git -C "$PP_TREE" config core.hooksPath /dev/null
  git -C "$PP_TREE" config user.name "$PP_AUTHOR_NAME"
  git -C "$PP_TREE" config user.email "$PP_AUTHOR_EMAIL"
  git -C "$PP_TREE" -c core.hooksPath=/dev/null add -A
  PP_TREE_OID=$(git -C "$PP_TREE" -c core.hooksPath=/dev/null write-tree)
}

pp_read_public() {
  local err=$PP_WORK/remote.err out=$PP_WORK/remote.out st
  PP_PARENT=""
  PP_FETCH_NOTE=""
  set +e
  git -C "$PP_TREE" -c core.hooksPath=/dev/null ls-remote --heads "$PP_REMOTE" "$PP_BRANCH" >"$out" 2>"$err"
  st=$?
  set -e
  if [ "$st" -ne 0 ]; then
    PP_FETCH_NOTE=$(pp_redact_text < "$err" || true)
    return 1
  fi
  if [ ! -s "$out" ]; then
    PP_FETCH_NOTE="public branch is empty"
    return 0
  fi
  set +e
  git -C "$PP_TREE" -c core.hooksPath=/dev/null fetch --no-tags "$PP_REMOTE" \
    "+refs/heads/${PP_BRANCH}:refs/remotes/public/${PP_BRANCH}" >"$PP_WORK/fetch.out" 2>"$err"
  st=$?
  set -e
  if [ "$st" -ne 0 ]; then
    PP_FETCH_NOTE=$(pp_redact_text < "$err" || true)
    return 1
  fi
  PP_PARENT=$(git -C "$PP_TREE" rev-parse "refs/remotes/public/${PP_BRANCH}")
  return 0
}

pp_make_commit() {
  local args old
  PP_IDENTICAL=0
  if [ -n "$PP_PARENT" ]; then
    old=$(git -C "$PP_TREE" rev-parse "${PP_PARENT}^{tree}")
    if [ "$old" = "$PP_TREE_OID" ]; then
      PP_IDENTICAL=1
      PP_COMMIT=$PP_PARENT
      return 0
    fi
  fi
  args=(commit-tree "$PP_TREE_OID" -m "$PP_COMMIT_MESSAGE")
  if [ -n "$PP_PARENT" ]; then
    args=(commit-tree "$PP_TREE_OID" -p "$PP_PARENT" -m "$PP_COMMIT_MESSAGE")
  fi
  PP_COMMIT=$(
    GIT_AUTHOR_NAME="$PP_AUTHOR_NAME" \
      GIT_AUTHOR_EMAIL="$PP_AUTHOR_EMAIL" \
      GIT_COMMITTER_NAME="$PP_AUTHOR_NAME" \
      GIT_COMMITTER_EMAIL="$PP_AUTHOR_EMAIL" \
      git -C "$PP_TREE" -c core.hooksPath=/dev/null "${args[@]}"
  )
  git -C "$PP_TREE" -c core.hooksPath=/dev/null update-ref "refs/heads/${PP_BRANCH}" "$PP_COMMIT"
  git -C "$PP_TREE" -c core.hooksPath=/dev/null symbolic-ref HEAD "refs/heads/${PP_BRANCH}"
  local an ae cn ce
  an=$(git -C "$PP_TREE" log -1 --format='%an' "$PP_COMMIT")
  ae=$(git -C "$PP_TREE" log -1 --format='%ae' "$PP_COMMIT")
  cn=$(git -C "$PP_TREE" log -1 --format='%cn' "$PP_COMMIT")
  ce=$(git -C "$PP_TREE" log -1 --format='%ce' "$PP_COMMIT")
  if [ "$an" != "$PP_AUTHOR_NAME" ] || [ "$ae" != "$PP_AUTHOR_EMAIL" ] \
    || [ "$cn" != "$PP_AUTHOR_NAME" ] || [ "$ce" != "$PP_AUTHOR_EMAIL" ]; then
    pp_die "commit author does not match the config. Nothing was pushed."
  fi
}

pp_push_commit() {
  local err=$PP_WORK/push.err st
  set +e
  git -C "$PP_TREE" -c core.hooksPath=/dev/null -c push.default=simple \
    push "$PP_REMOTE" "refs/heads/${PP_BRANCH}:refs/heads/${PP_BRANCH}" >"$PP_WORK/push.out" 2>"$err"
  st=$?
  set -e
  if [ "$st" -ne 0 ]; then
    pp_redact_text < "$err" >&2 || true
    pp_die "push was rejected. The remote was not force-updated."
  fi
}

pp_cap_file() {
  local file=$1 limit=$2 total
  [ -f "$file" ] || return 0
  total=$(wc -l < "$file" | tr -d ' ')
  head -n "$limit" "$file"
  if [ "$total" -gt "$limit" ]; then
    printf '... %s more\n' "$((total - limit))"
  fi
}

pp_write_report() {
  local report=$PP_WORK/report.txt files mode="dry-run"
  if [ "$PP_PUSH" -eq 1 ]; then
    mode=push
  fi
  files=$(find "$PP_TREE" -type f ! -path '*/.git/*' | wc -l | tr -d ' ')
  {
    printf 'publish-public report\n'
    printf 'mode: %s\n' "$mode"
    printf 'source: %s\n' "$PP_REPO"
    printf 'ref: %s %s\n' "$PP_REF" "$PP_SOURCE_SHA"
    printf 'public_remote: %s\n' "$PP_REMOTE"
    printf 'public_branch: %s\n' "$PP_BRANCH"
    printf 'author: %s <%s>\n' "$PP_AUTHOR_NAME" "$PP_AUTHOR_EMAIL"
    if [ "$PP_HITS" -gt 0 ]; then
      printf 'commit_message: withheld because the scan failed\n'
    else
      printf 'commit_message: %s\n' "$PP_COMMIT_MESSAGE"
    fi
    printf 'gitleaks: %s\n' "$PP_GITLEAKS_VERSION"
    printf 'denylist: %s (%s rules)\n' "$PP_DENYLIST_FILE" "${#PP_DENY_KIND[@]}"
    printf 'files_in_snapshot: %s\n' "$files"
    printf 'dropped:\n'
    if [ -s "$PP_DROPPED_LIST" ]; then
      sort -u "$PP_DROPPED_LIST" > "$PP_WORK/dropped.sorted"
      pp_cap_file "$PP_WORK/dropped.sorted" 200
    else
      printf '  (none)\n'
    fi
    printf 'replacements:\n'
    if [ -s "$PP_REPLACED_LIST" ]; then
      awk -F '\t' '{ count[$1] += $2 } END { for (path in count) printf "%s\t%s\n", path, count[path] }' \
        "$PP_REPLACED_LIST" | sort > "$PP_WORK/replaced.sorted"
      pp_cap_file "$PP_WORK/replaced.sorted" 200
    else
      printf '  (none)\n'
    fi
    if [ -s "$PP_CONVERTED_LIST" ]; then
      printf 'utf16_converted:\n'
      pp_cap_file "$PP_CONVERTED_LIST" 50
    fi
    printf 'scan_hits: %s\n' "$PP_HITS"
    if [ -s "$PP_HIT_LOG" ]; then
      cat "$PP_HIT_LOG"
    fi
    if [ "$PP_HITS" -eq 0 ]; then
      printf 'diff:\n'
      if [ -n "$PP_FETCH_NOTE" ] && [ -z "$PP_PARENT" ] && [ "$PP_FETCH_NOTE" != "public branch is empty" ]; then
        printf 'public branch was not read; content diff omitted\n'
        printf '%s\n' "$PP_FETCH_NOTE"
      elif [ "${PP_IDENTICAL:-0}" -eq 1 ]; then
        printf 'sanitized tree matches the public branch\n'
      elif [ -z "$PP_PARENT" ]; then
        printf 'public branch is empty; this would be the first commit (%s files)\n' "$files"
      else
        git -C "$PP_TREE" --no-pager diff --stat "$PP_PARENT" "$PP_COMMIT" > "$PP_WORK/diff.stat" || true
        pp_cap_file "$PP_WORK/diff.stat" 200
        printf 'name-status:\n'
        git -C "$PP_TREE" --no-pager diff --name-status "$PP_PARENT" "$PP_COMMIT" > "$PP_WORK/diff.names" || true
        pp_cap_file "$PP_WORK/diff.names" 200
      fi
      if [ -n "${PP_COMMIT:-}" ] && [ "${PP_IDENTICAL:-0}" -eq 0 ]; then
        printf 'local_commit: %s\n' "$PP_COMMIT"
      fi
    fi
    if [ "$PP_HITS" -gt 0 ]; then
      printf 'result: scan failed. Nothing was pushed.\n'
    elif [ "${PP_IDENTICAL:-0}" -eq 1 ]; then
      printf 'result: public branch already has this tree. Nothing was pushed.\n'
    elif [ "$PP_PUSH" -eq 1 ]; then
      printf 'result: pushed %s to %s %s\n' "$PP_COMMIT" "$PP_REMOTE" "$PP_BRANCH"
    else
      printf 'result: dry-run ok. Nothing was pushed.\n'
    fi
  } > "$report"
  cat "$report"
  if [ -n "$PP_REPORT_PATH" ]; then
    mkdir -p "$(dirname -- "$PP_REPORT_PATH")"
    cp "$report" "$PP_REPORT_PATH"
  fi
}

pp_main() {
  pp_parse_args "$@"
  if [ -z "$PP_REPO" ]; then
    PP_REPO=$(git rev-parse --show-toplevel)
  fi
  PP_REPO=$(CDPATH= cd -- "$PP_REPO" && pwd)
  git -C "$PP_REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || pp_die "not a git repository: ${PP_REPO}"
  if [ -z "$PP_CONFIG" ]; then
    PP_CONFIG=$PP_REPO/.publish-public.yml
  fi
  local overlay=$PP_REPO/.publish-public.local.yml
  if [ ! -f "$overlay" ]; then
    overlay=""
  fi
  pp_load_config "$PP_CONFIG" "$overlay"
  if [ -n "$PP_MESSAGE_OVERRIDE" ]; then
    PP_MESSAGE=$PP_MESSAGE_OVERRIDE
  fi
  PP_COMMIT_MESSAGE=$PP_MESSAGE
  [ -n "$PP_COMMIT_MESSAGE" ] || pp_die "commit message is empty"
  pp_resolve_denylist
  pp_resolve_gitleaks_config
  pp_refuse_same_repo
  pp_load_denylist "$PP_DENYLIST_FILE"
  PP_HEAD_BEFORE=$(git -C "$PP_REPO" rev-parse HEAD)
  PP_STATUS_BEFORE=$(git -C "$PP_REPO" status --porcelain)
  PP_SOURCE_SHA=$(git -C "$PP_REPO" rev-parse --verify "${PP_REF}^{commit}") \
    || pp_die "ref not found: ${PP_REF}"

  PP_WORK=$(mktemp -d "${TMPDIR:-/tmp}/publish-public.XXXXXX")
  PP_TREE=$PP_WORK/tree
  PP_DROPPED_LIST=$PP_WORK/dropped.txt
  PP_REPLACED_LIST=$PP_WORK/replaced.txt
  PP_CONVERTED_LIST=$PP_WORK/converted.txt
  PP_HIT_LOG=$PP_WORK/hits.txt
  : > "$PP_DROPPED_LIST"
  : > "$PP_REPLACED_LIST"
  : > "$PP_CONVERTED_LIST"
  : > "$PP_HIT_LOG"

  pp_extract_tree
  pp_drop_external_symlinks
  pp_apply_drops
  pp_normalize_encoding
  pp_apply_replacements
  pp_scan_all
  pp_assert_source_unchanged

  if [ "$PP_HITS" -gt 0 ]; then
    pp_write_report
    pp_note "scan failed (${PP_HITS} hits). Nothing was pushed."
    exit 1
  fi

  pp_prepare_commit
  if ! pp_read_public; then
    if [ "$PP_PUSH" -eq 1 ]; then
      pp_note "${PP_FETCH_NOTE:-public branch was not read}"
      pp_die "refusing to push because the public branch could not be read. Nothing was pushed."
    fi
  fi
  pp_make_commit
  if [ "$PP_IDENTICAL" -eq 1 ]; then
    pp_write_report
    pp_note "public branch already has this tree. Nothing was pushed."
    pp_assert_source_unchanged
    exit 0
  fi
  if [ "$PP_PUSH" -eq 1 ]; then
    pp_push_commit
  fi
  pp_write_report
  pp_assert_source_unchanged
  if [ "$PP_PUSH" -eq 1 ]; then
    pp_note "pushed ${PP_COMMIT}"
  else
    pp_note "dry-run ok. Nothing was pushed."
  fi
}

pp_main "$@"
