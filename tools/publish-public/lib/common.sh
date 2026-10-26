# Shared helpers. Sourced by publish.sh. Requires bash 3.2 or newer.

pp_die() {
  printf 'publish-public: %s\n' "$1" >&2
  exit 1
}

pp_note() {
  printf 'publish-public: %s\n' "$1" >&2
}

pp_mask() {
  # Print a masked copy of $1. Short values are fully hidden.
  local s=$1
  local n=${#s}
  local stars i
  if [ "$n" -le 6 ]; then
    printf '****'
    return 0
  fi
  stars=$((n - 2))
  if [ "$stars" -gt 6 ]; then
    stars=6
  fi
  printf '%s' "${s:0:1}"
  i=0
  while [ "$i" -lt "$stars" ]; do
    printf '*'
    i=$((i + 1))
  done
  printf '%s' "${s:n-1:1}"
}

pp_redact_text() {
  # Hide credential material that git may echo from URL rewrites.
  sed -E \
    -e 's#x-access-token:[^@[:space:]]+#x-access-token:REDACTED#g' \
    -e 's#ghp_[A-Za-z0-9]+#ghp_REDACTED#g' \
    -e 's#github_pat_[A-Za-z0-9_]+#github_pat_REDACTED#g'
}

pp_rel() {
  local root=$1 abs=$2
  case $abs in
    "$root"/*) printf '%s' "${abs#"$root"/}" ;;
    *) printf '%s' "$abs" ;;
  esac
}

pp_reject_dotdot() {
  case $1 in
    ..|../*|*/../*|*/..) return 0 ;;
    *) return 1 ;;
  esac
}

# Convert a small glob (**, *, ?) to an anchored ERE.
pp_glob_to_ere() {
  local glob=$1
  local i=0 n=${#glob} c next out=""
  while [ "$i" -lt "$n" ]; do
    c=${glob:i:1}
    if [ "$c" = "*" ]; then
      next=${glob:i+1:1}
      if [ "$next" = "*" ]; then
        i=$((i + 2))
        if [ "${glob:i:1}" = "/" ]; then
          out="${out}(.*/)?"
          i=$((i + 1))
        else
          out="${out}.*"
        fi
      else
        out="${out}[^/]*"
        i=$((i + 1))
      fi
    elif [ "$c" = "?" ]; then
      out="${out}[^/]"
      i=$((i + 1))
    else
      case $c in
        "." | "\\" | "(" | ")" | "|" | "+" | "{" | "}" | "^" | "$" | "[" | "]")
          out="${out}\\${c}"
          ;;
        *)
          out="${out}${c}"
          ;;
      esac
      i=$((i + 1))
    fi
  done
  printf '^%s$' "$out"
}

pp_glob_match() {
  local path=$1 glob=$2 ere
  ere=$(pp_glob_to_ere "$glob")
  [[ $path =~ $ere ]]
}

pp_globs_match() {
  # $1 path, remaining args are globs. Newline-separated globs may be passed as $2.
  local path=$1 globs=$2 glob
  [ -n "$globs" ] || return 1
  local oldifs=$IFS
  IFS='
'
  for glob in $globs; do
    [ -n "$glob" ] || continue
    if pp_glob_match "$path" "$glob"; then
      IFS=$oldifs
      return 0
    fi
  done
  IFS=$oldifs
  return 1
}

pp_path_or_ancestor_matches() {
  local path=$1 globs=$2
  local cursor=$path
  while true; do
    if pp_globs_match "$cursor" "$globs"; then
      return 0
    fi
    case $cursor in
      */*) cursor=${cursor%/*} ;;
      *) break ;;
    esac
  done
  return 1
}

pp_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

pp_basename_lower() {
  pp_lower "$(basename -- "$1")"
}

pp_is_license_path() {
  case $(pp_basename_lower "$1") in
    license | license.md | license.txt | license.rst | copying | copying.md | copying.txt | licence | licence.md | licence.txt)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

pp_file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%OLp' "$1"
  fi
}

pp_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

pp_slug() {
  local u=$1
  u=${u%.git}
  u=${u%/}
  case $u in
    *://*) u=${u#*://} ;;
  esac
  u=${u#*@}
  pp_lower "$u"
}

pp_join_nl() {
  # Append $2 to the newline-separated list in the variable named by $1.
  local name=$1 value=$2 cur
  eval "cur=\${$name-}"
  if [ -z "$cur" ]; then
    eval "$name=\$value"
  else
    eval "$name=\$cur\$'\\n'\$value"
  fi
}
