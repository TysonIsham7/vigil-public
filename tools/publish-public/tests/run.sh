#!/usr/bin/env bash
# Scan/fail tests for publish-public. Secrets are generated at runtime.
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'run these tests with bash\n' >&2
  exit 1
fi
set -euo pipefail
export LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
PUBLISH=$ROOT/tools/publish-public/publish.sh
CONFIG=$ROOT/.publish-public.yml
SAMPLE=$ROOT/tools/publish-public/examples/vigil.publish-public.yml
TMP=$(mktemp -d "${TMPDIR:-/tmp}/publish-public-tests.XXXXXX")
export PUBLISH_PUBLIC_CACHE=$TMP/cache
PASS=0
FAIL=0

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

die() {
  printf 'FAIL %s\n' "$1" >&2
  FAIL=$((FAIL + 1))
  CASE_FAIL=1
}

ok() {
  if [ "${CASE_FAIL:-0}" -ne 0 ]; then
    CASE_FAIL=0
    return 0
  fi
  printf 'ok %s\n' "$1"
  PASS=$((PASS + 1))
}

field() {
  local key=$1 file=$2 line
  line=$(grep -E "^${key}:" "$file" | head -n 1)
  line=${line#*:}
  line=${line#"${line%%[![:space:]]*}"}
  line=${line%"${line##*[![:space:]]}"}
  case $line in
    \"*\") line=${line#\"}; line=${line%\"} ;;
    \'*\') line=${line#\'}; line=${line%\'} ;;
  esac
  printf '%s' "$line"
}

AUTHOR_NAME=$(field author_name "$CONFIG")
AUTHOR_EMAIL=$(field author_email "$CONFIG")

git_init() {
  local dir=$1
  if ! git init -q -b main "$dir" 2>/dev/null; then
    git init -q "$dir"
    git -C "$dir" symbolic-ref HEAD refs/heads/main
  fi
}

git_init_bare() {
  local dir=$1
  if ! git init -q --bare -b main "$dir" 2>/dev/null; then
    git init -q --bare "$dir"
    git --git-dir="$dir" symbolic-ref HEAD refs/heads/main
  fi
}

commit_fixture() {
  local dir=$1 message=$2 top
  [ -d "$dir/.git" ] || {
    printf 'fixture %s is not its own git repo\n' "$dir" >&2
    exit 1
  }
  top=$(git -C "$dir" rev-parse --show-toplevel)
  if [ "$top" = "$ROOT" ]; then
    printf 'refusing to commit the repository under test\n' >&2
    exit 1
  fi
  git -C "$dir" add -A
  git -C "$dir" -c commit.gpgsign=false -c user.name=Fixture -c user.email=fixture@example.com \
    commit -q -m "$message"
}

write_base_config() {
  local file=$1 remote=$2
  cat > "$file" <<EOF
public_remote: ${remote}
public_branch: main
commit_message: "Publish sanitized snapshot"
author_name: "${AUTHOR_NAME}"
author_email: "${AUTHOR_EMAIL}"
denylist: .publish-public.denylist
builtin_drops: true
drop:
  - private-notes.md
EOF
}

run_publish() {
  local repo=$1
  shift
  set +e
  PUBLISH_OUT=$(bash "$PUBLISH" --repo "$repo" "$@" 2>&1)
  PUBLISH_STATUS=$?
  set -e
}

assert_status() {
  local want=$1 name=$2
  if [ "$PUBLISH_STATUS" -ne "$want" ]; then
    printf '%s\n' "$PUBLISH_OUT" | head -n 40 >&2
    die "$name (exit $PUBLISH_STATUS, wanted $want)"
    return 1
  fi
  return 0
}

assert_absent() {
  local needle=$1 name=$2
  if printf '%s\n' "$PUBLISH_OUT" | grep -F -q -- "$needle"; then
    die "$name leaked a raw match into the output"
    return 1
  fi
  return 0
}

bare_head() {
  git --git-dir="$1" rev-parse --verify HEAD 2>/dev/null || true
}

# The tool's own shell must not contain the configured name tokens.
check_shell_names() {
  local word file hit=0
  local words=$AUTHOR_NAME
  words=$(printf '%s' "$words" | tr -s '[:space:]' '\n')
  while IFS= read -r word; do
    [ "${#word}" -ge 3 ] || continue
    while IFS= read -r file; do
      if grep -F -i -q -- "$word" "$file"; then
        printf 'name token in %s\n' "$file" >&2
        hit=1
      fi
    done < <(find "$ROOT/tools/publish-public" -type f -name '*.sh')
  done <<EOF
$words
$AUTHOR_NAME
EOF
  if [ "$hit" -ne 0 ]; then
    die "shell sources contain a name token"
  else
    ok "shell sources omit name tokens"
  fi
}

if ! diff -q "$CONFIG" "$SAMPLE" >/dev/null; then
  die "vigil config and the sample copy differ"
else
  ok "vigil config matches the sample"
fi

check_shell_names

# 1. Literal denylist hit: masked file:line, no push.
test_literal() {
  local src=$TMP/literal bare=$TMP/literal.git secret
  git_init "$src"
  git_init_bare "$bare"
  secret="pp-literal-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  printf 'hello %s\n' "$secret" > "$src/leak.txt"
  printf 'keep\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf 'literal %s\n' "$secret" > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src"
  assert_status 1 "literal denylist" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'leak.txt:1: denylist literal matched ' \
    || die "literal denylist did not print file:line"
  assert_absent "$secret" "literal denylist" || return 0
  if [ -n "$(bare_head "$bare")" ]; then
    die "literal denylist pushed"
  else
    ok "literal denylist fails closed"
  fi
}

# 2. Regex denylist hit.
test_regex() {
  local src=$TMP/regex bare=$TMP/regex.git
  local live
  git_init "$src"
  git_init_bare "$bare"
  live="vg_live_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  printf 'prefix %s\n' "$live" > "$src/leak.txt"
  printf 'ok\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf 'regex %s\n' 'vg_live_[A-Za-z0-9_-]{8,}' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src"
  assert_status 1 "regex denylist" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'leak.txt:1: denylist regex matched ' \
    || die "regex denylist did not print file:line"
  assert_absent "$live" "regex denylist" || return 0
  if [ -n "$(bare_head "$bare")" ]; then
    die "regex denylist pushed"
  else
    ok "regex denylist fails closed"
  fi
}

# 3. Commit message hit. The report must not echo the message.
test_message() {
  local src=$TMP/message bare=$TMP/message.git secret
  git_init "$src"
  git_init_bare "$bare"
  secret="pp-message-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  printf 'clean\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf 'literal %s\n' "$secret" > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src" --message "ship ${secret}"
  assert_status 1 "commit message" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'COMMIT_MESSAGE:1: denylist literal matched ' \
    || die "commit message hit missing"
  assert_absent "$secret" "commit message" || return 0
  if [ -n "$(bare_head "$bare")" ]; then
    die "commit message hit pushed"
  else
    ok "commit message hit fails closed"
  fi
}

# 4. Author name in Swift fails. The same name in LICENSE is not source.
test_name_in_code() {
  local src=$TMP/name bare=$TMP/name.git
  git_init "$src"
  git_init_bare "$bare"
  printf 'let label = "%s"\n' "$AUTHOR_NAME" > "$src/Person.swift"
  printf 'Copyright (c) 2026 %s\n' "$AUTHOR_NAME" > "$src/LICENSE"
  printf 'ok\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf '# no literals\n' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src"
  assert_status 1 "name in code" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'Person.swift:1: author name in code matched ' \
    || die "name in code was not reported"
  local hit
  hit=$(printf '%s\n' "$PUBLISH_OUT" | grep 'author name in code' || true)
  if printf '%s\n' "$hit" | grep -F -q -- "$AUTHOR_NAME"; then
    die "name hit was not masked"
  fi
  if [ -n "$(bare_head "$bare")" ]; then
    die "name in code pushed"
  else
    ok "name in code fails closed"
  fi
}

# 5. Clean tree: dry-run does not push; --push adds one commit; a second release adds another.
test_push_local() {
  local src=$TMP/push bare=$TMP/push.git head1 head2 name email sig count
  git_init "$src"
  git_init_bare "$bare"
  printf 'Copyright (c) 2026 %s\n' "$AUTHOR_NAME" > "$src/LICENSE"
  printf 'hello\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf '# no literals\n' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  local before
  before=$(git -C "$src" rev-parse HEAD)
  run_publish "$src"
  assert_status 0 "dry-run" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'Nothing was pushed' || die "dry-run did not say it skipped the push"
  if [ -n "$(bare_head "$bare")" ]; then
    die "dry-run pushed"
    return 0
  fi
  if [ "$(git -C "$src" rev-parse HEAD)" != "$before" ]; then
    die "dry-run changed the source HEAD"
    return 0
  fi
  run_publish "$src" --push
  assert_status 0 "push" || return 0
  head1=$(bare_head "$bare")
  [ -n "$head1" ] || die "push did not create a commit"
  name=$(git --git-dir="$bare" log -1 --format='%an')
  email=$(git --git-dir="$bare" log -1 --format='%ae')
  sig=$(git --git-dir="$bare" log -1 --format='%G?')
  [ "$name" = "$AUTHOR_NAME" ] || die "author name was not taken from the config"
  [ "$email" = "$AUTHOR_EMAIL" ] || die "author email was not taken from the config"
  [ "$sig" = "N" ] || die "published commit was signed"
  printf 'more\n' >> "$src/README.md"
  commit_fixture "$src" second
  run_publish "$src" --push
  assert_status 0 "second push" || return 0
  count=$(git --git-dir="$bare" rev-list --count HEAD)
  head2=$(bare_head "$bare")
  [ "$count" = "2" ] || die "expected one new commit per release, got $count"
  [ "$head2" != "$head1" ] || die "second release did not move the branch"
  local parent
  parent=$(git --git-dir="$bare" rev-parse HEAD^)
  [ "$parent" = "$head1" ] || die "second commit is not stacked on the first"
  ok "dry-run then two local commits"
}

# 6. gitleaks rejects a generated token that is not on the denylist.
test_gitleaks() {
  local src=$TMP/gitleaks bare=$TMP/gitleaks.git token alphabet out i idx bytes
  git_init "$src"
  git_init_bare "$bare"
  alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  out=""
  bytes=$(od -An -N48 -tu1 /dev/urandom | tr -s ' ')
  for i in $bytes; do
    idx=$((i % 62))
    out="${out}${alphabet:idx:1}"
  done
  token="ghp_${out:0:36}"
  printf 'token=%s\n' "$token" > "$src/leak.txt"
  printf 'ok\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf '# no literals\n' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src"
  assert_status 1 "gitleaks" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'leak.txt:1: gitleaks github-pat matched ' \
    || die "gitleaks hit was not reported"
  assert_absent "$token" "gitleaks" || return 0
  if [ -n "$(bare_head "$bare")" ]; then
    die "gitleaks hit pushed"
  else
    ok "gitleaks fails closed"
  fi
}

# 7. Replacement removes a team id before the denylist runs. The report omits it.
test_replace() {
  local src=$TMP/replace bare=$TMP/replace.git team=ABCD12EFGH blob
  git_init "$src"
  git_init_bare "$bare"
  printf 'DEVELOPMENT_TEAM = %s;\nCODE_SIGN_STYLE = Automatic;\n' "$team" > "$src/App.pbxproj"
  printf '%s\n' $'see /Users/localuser/Desktop and C:\\Users\\localuser\\Desktop' > "$src/Notes.txt"
  printf 'mail founder@private.test\n' > "$src/Contact.txt"
  printf 'device iPhone16,2 on a MacBook Pro\n' > "$src/Device.txt"
  printf 'ok\n' > "$src/README.md"
  cat > "$src/.publish-public.yml" <<EOF
public_remote: file://${bare}
public_branch: main
commit_message: "Publish sanitized snapshot"
author_name: "${AUTHOR_NAME}"
author_email: "${AUTHOR_EMAIL}"
denylist: .publish-public.denylist
builtin_drops: true
replacements:
  - pattern: 'DEVELOPMENT_TEAM = [A-Z0-9]{10}'
    to: 'DEVELOPMENT_TEAM = XXXXXXXXXX'
    skip_if_match: 'XXXXXXXXXX'
  - pattern: 'CODE_SIGN_STYLE = Automatic;'
    to: 'CODE_SIGN_STYLE = Manual;'
  - pattern: '/Users/[A-Za-z0-9._-]+'
    to: '/Users/example'
    skip_if_match: '^/Users/example$'
  - pattern: 'C:\\\\Users\\\\[A-Za-z0-9._-]+'
    to: 'C:\\Users\\example'
    skip_if_match: '^C:\\\\Users\\\\example$'
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'
    to: 'user@example.com'
    skip_if_match: '@(example\\.com|example\\.org|users\\.noreply\\.github\\.com)$'
  - pattern: 'MacBook( Pro| Air)?'
    to: 'Mac'
  - pattern: 'iPhone[0-9]+,[0-9]+'
    to: 'iPhone'
EOF
  printf 'literal %s\n' "$team" > "$src/.publish-public.denylist"
  printf 'Business Name\n' > "$src/Biz.txt"
  cat > "$src/.publish-public.local.yml" <<'EOF'
replacements:
  - from: "Business Name"
    to: "Example Company"
EOF
  commit_fixture "$src" init
  # The local overlay is untracked and must not be published.
  run_publish "$src" --push
  assert_status 0 "replacement push" || return 0
  assert_absent "$team" "replacement report" || return 0
  blob=$(git --git-dir="$bare" grep -n -h . HEAD -- App.pbxproj Notes.txt Contact.txt Device.txt Biz.txt || true)
  printf '%s\n' "$blob" | grep -q 'DEVELOPMENT_TEAM = XXXXXXXXXX' || die "team id was not rewritten"
  printf '%s\n' "$blob" | grep -q 'CODE_SIGN_STYLE = Manual' || die "signing style was not rewritten"
  printf '%s\n' "$blob" | grep -q '/Users/example' || die "home path was not rewritten"
  printf '%s\n' "$blob" | grep -q 'user@example.com' || die "email was not rewritten"
  printf '%s\n' "$blob" | grep -q 'iPhone' || die "device model was not rewritten"
  printf '%s\n' "$blob" | grep -q 'Example Company' || die "local overlay replacement was not applied"
  if printf '%s\n' "$blob" | grep -F -q -- "$team"; then
    die "team id survived into the published tree"
  fi
  if git --git-dir="$bare" ls-tree -r --name-only HEAD | grep -q 'publish-public.local.yml'; then
    die "local overlay was published"
  fi
  if git --git-dir="$bare" ls-tree -r --name-only HEAD | grep -q 'publish-public.denylist'; then
    die "denylist was published"
  fi
  ok "replacements run before the scan"
}

# 8. Uncommitted worktree secrets are not part of the snapshot, and the worktree stays dirty.
test_worktree() {
  local src=$TMP/work bare=$TMP/work.git secret before
  git_init "$src"
  git_init_bare "$bare"
  printf 'clean\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf '# no literals\n' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  secret="pp-dirty-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s\n' "$secret" >> "$src/README.md"
  printf 'literal %s\n' "$secret" > "$src/.publish-public.denylist"
  before=$(git -C "$src" status --porcelain)
  run_publish "$src" --push
  assert_status 0 "dirty worktree" || return 0
  if git --git-dir="$bare" grep -F -q -- "$secret" HEAD; then
    die "uncommitted text was published"
  fi
  if [ "$(git -C "$src" status --porcelain)" != "$before" ]; then
    die "source worktree status changed"
  fi
  if ! grep -F -q -- "$secret" "$src/README.md"; then
    die "source worktree file was edited"
  fi
  ok "uncommitted text stays private"
}

# 9. Missing denylist and a remote that is the source repo both refuse.
test_refuse() {
  local src=$TMP/refuse bare=$TMP/refuse.git
  git_init "$src"
  git_init_bare "$bare"
  printf 'ok\n' > "$src/README.md"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  commit_fixture "$src" init
  run_publish "$src"
  assert_status 1 "missing denylist" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'denylist not found' || die "missing denylist was not explained"
  if [ -n "$(bare_head "$bare")" ]; then
    die "missing denylist pushed"
    return 0
  fi
  local gitdir
  gitdir=$(git -C "$src" rev-parse --absolute-git-dir)
  cat > "$src/.publish-public.yml" <<EOF
public_remote: ${gitdir}
public_branch: main
commit_message: "Publish sanitized snapshot"
author_name: "${AUTHOR_NAME}"
author_email: "${AUTHOR_EMAIL}"
denylist: .publish-public.denylist
EOF
  printf '# no literals\n' > "$src/.publish-public.denylist"
  run_publish "$src" --push
  assert_status 1 "same repo" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'this repository' || die "same-repo remote was not refused"
  ok "missing denylist and same-repo remote are refused"
}

# 10. Dropped paths do not ship, and a tracked private note is removed.
test_drop() {
  local src=$TMP/drop bare=$TMP/drop.git
  git_init "$src"
  git_init_bare "$bare"
  printf 'secret brief\n' > "$src/private-notes.md"
  printf 'ok\n' > "$src/README.md"
  mkdir -p "$src/App.xcodeproj/xcuserdata/person"
  printf 'state\n' > "$src/App.xcodeproj/xcuserdata/person/UserInterfaceState.xcuserstate"
  write_base_config "$src/.publish-public.yml" "file://${bare}"
  printf '# no literals\n' > "$src/.publish-public.denylist"
  commit_fixture "$src" init
  run_publish "$src" --push
  assert_status 0 "drop" || return 0
  if git --git-dir="$bare" ls-tree -r --name-only HEAD | grep -q 'private-notes.md'; then
    die "configured drop was published"
  fi
  if git --git-dir="$bare" ls-tree -r --name-only HEAD | grep -q 'xcuserdata'; then
    die "xcuserdata was published"
  fi
  ok "configured and built-in paths are dropped"
}

test_literal
test_regex
test_message
test_name_in_code
test_push_local
test_gitleaks
test_replace
test_worktree
test_refuse
test_drop

# Vigil dry run. This reads the public mirror and does not push.
vigil_dry_run() {
  local deny=$TMP/vigil.denylist report=$TMP/vigil-report.txt head before
  cp "$ROOT/tools/publish-public/examples/denylist.example" "$deny"
  head=$(git -C "$ROOT" rev-parse HEAD)
  before=$(git -C "$ROOT" status --porcelain)
  run_publish "$ROOT" --denylist "$deny" --report "$report"
  assert_status 0 "vigil dry-run" || return 0
  printf '%s\n' "$PUBLISH_OUT" | grep -q 'Nothing was pushed' || die "vigil dry-run did not stay local"
  [ "$(git -C "$ROOT" rev-parse HEAD)" = "$head" ] || die "vigil dry-run moved HEAD"
  [ "$(git -C "$ROOT" status --porcelain)" = "$before" ] || die "vigil dry-run changed the worktree"
  if [ ! -s "$report" ]; then
    die "vigil dry-run wrote no report"
  fi
  ok "vigil dry-run"
}

if git -C "$ROOT" cat-file -e HEAD:tools/publish-public/publish.sh 2>/dev/null; then
  vigil_dry_run
else
  printf 'skip vigil dry-run until the tool is in HEAD\n'
fi

printf 'passed %s, failed %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
