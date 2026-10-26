# Denylist, author-name, and gitleaks scans. Hits are printed masked.

PP_HITS=0
PP_DEFAULT_CODE_EXTS="swift m mm h c cc cpp hpp hh js jsx mjs cjs ts tsx py rb go rs java kt kts cs php sh bash zsh pl lua scala sql metal pbxproj xcconfig plist ent entitlements strings"

pp_record_hit() {
  local path=$1 line=$2 rule=$3 raw=$4 masked
  masked=$(pp_mask "$raw")
  PP_HITS=$((PP_HITS + 1))
  if [ "$PP_HITS" -le 200 ]; then
    printf '%s:%s: %s matched %s\n' "$path" "$line" "$rule" "$masked" >&2
    printf '%s:%s: %s matched %s\n' "$path" "$line" "$rule" "$masked" >> "$PP_HIT_LOG"
  fi
}

pp_load_denylist() {
  local file=$1 line lineno=0 kind pat
  [ -f "$file" ] || pp_die "denylist not found: ${file}
Copy tools/publish-public/examples/denylist.example and add the private strings that must not ship.
Nothing was pushed."
  PP_DENY_KIND=()
  PP_DENY_PAT=()
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line=${line%$'\r'}
    case $line in
      "" | \#*) continue ;;
      [[:space:]]\#*) continue ;;
    esac
    case $line in
      "literal "*)
        kind=literal
        pat=${line#"literal "}
        ;;
      "regex "*)
        kind=regex
        pat=${line#"regex "}
        ;;
      *)
        kind=literal
        pat=$(pp_trim "$line")
        ;;
    esac
    case $pat in
      *$'\n'*) pp_die "denylist line ${lineno} contains a newline" ;;
    esac
    if [ "${#pat}" -lt 4 ]; then
      pp_die "denylist line ${lineno} is shorter than 4 characters"
    fi
    PP_DENY_KIND+=("$kind")
    PP_DENY_PAT+=("$pat")
  done < "$file"
}

pp_allow_globs() {
  local joined="" item
  if [ "${#PP_ALLOW_ITEMS[@]}" -eq 0 ]; then
    printf ''
    return 0
  fi
  for item in "${PP_ALLOW_ITEMS[@]}"; do
    joined="${joined}${item}"$'\n'
  done
  printf '%s' "$joined"
}

pp_scan_denylist_root() {
  local root=$1 label=$2
  local n=${#PP_DENY_KIND[@]} i allow=""
  [ "$n" -gt 0 ] || return 0
  if [ "$label" = "tree" ]; then
    allow=$(pp_allow_globs)
  fi
  for ((i = 0; i < n; i++)); do
    pp_scan_denylist_rule "$i" "$root" "$label" "$allow"
  done
}

pp_scan_denylist_rule() {
  local i=$1 root=$2 label=$3 allow=$4
  local kind=${PP_DENY_KIND[$i]} pat=${PP_DENY_PAT[$i]}
  local out=$PP_WORK/deny.out err=$PP_WORK/deny.err st hit file rest line match rel
  set +e
  if [ "$kind" = "literal" ]; then
    grep -a -n -o -F -r -e "$pat" -- "$root" >"$out" 2>"$err"
  else
    grep -a -n -o -E -r -e "$pat" -- "$root" >"$out" 2>"$err"
  fi
  st=$?
  set -e
  if [ "$st" -eq 2 ]; then
    pp_die "denylist rule ${i} was rejected by grep. Nothing was pushed."
  fi
  if [ "$st" -eq 1 ]; then
    return 0
  fi
  if [ "$st" -ne 0 ]; then
    pp_die "denylist scan failed. Nothing was pushed."
  fi
  while IFS= read -r hit || [ -n "$hit" ]; do
    [ -n "$hit" ] || continue
    file=${hit%%:*}
    rest=${hit#*:}
    line=${rest%%:*}
    match=${rest#*:}
    case $file in
      "$root"/*) rel=$(pp_rel "$root" "$file") ;;
      *) rel=$file ;;
    esac
    if [ "$label" = "message" ]; then
      rel=COMMIT_MESSAGE
    elif [ -n "$allow" ] && pp_path_or_ancestor_matches "$rel" "$allow"; then
      continue
    fi
    pp_record_hit "$rel" "$line" "denylist ${kind}" "$match"
  done < "$out"
  rm -f "$out"
}

pp_code_extensions() {
  if [ "${#PP_CODE_EXT_ITEMS[@]}" -gt 0 ]; then
    local item joined=""
    for item in "${PP_CODE_EXT_ITEMS[@]}"; do
      joined="${joined} $(pp_lower "$item")"
    done
    printf '%s' "$joined"
  else
    printf '%s' "$PP_DEFAULT_CODE_EXTS"
  fi
}

pp_is_code_rel() {
  local rel=$1 ext list
  if pp_is_license_path "$rel"; then
    return 1
  fi
  if [ "${#PP_NAME_ALLOW_ITEMS[@]}" -gt 0 ]; then
    local globs="" item
    for item in "${PP_NAME_ALLOW_ITEMS[@]}"; do
      globs="${globs}${item}"$'\n'
    done
    if pp_globs_match "$rel" "$globs"; then
      return 1
    fi
  fi
  ext=$(pp_lower "${rel##*.}")
  list=$(pp_code_extensions)
  case " $list " in
    *" $ext "*) return 0 ;;
    *) return 1 ;;
  esac
}

pp_scan_names() {
  local n=${#PP_NAME_TOKEN_ITEMS[@]}
  [ "$n" -gt 0 ] || return 0
  local file rel token out st hit line match
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    rel=$(pp_rel "$PP_TREE" "$file")
    pp_is_code_rel "$rel" || continue
    if pp_file_has_nul "$file"; then
      continue
    fi
    local t
    for ((t = 0; t < n; t++)); do
      token=${PP_NAME_TOKEN_ITEMS[$t]}
      out=$PP_WORK/name.out
      set +e
      grep -a -n -o -F -i -e "$token" -- "$file" >"$out"
      st=$?
      set -e
      [ "$st" -eq 0 ] || continue
      while IFS= read -r hit || [ -n "$hit" ]; do
        [ -n "$hit" ] || continue
        line=${hit%%:*}
        match=${hit#*:}
        pp_record_hit "$rel" "$line" "author name in code" "$match"
      done < "$out"
    done
  done < <(find "$PP_TREE" -type f)
}

pp_parse_gitleaks_report() {
  local report=$1 source=$2 parsed=$PP_WORK/gitleaks.parsed
  PP_GITLEAKS_PARSED=0
  [ -s "$report" ] || return 0
  awk '
    function qval(line,    i, n, c, out, esc) {
      i = index(line, ":")
      if (i == 0) return ""
      line = substr(line, i + 1)
      sub(/^[[:space:]]*/, "", line)
      if (substr(line, 1, 1) != "\"") {
        sub(/[,[:space:]]*$/, "", line)
        return line
      }
      out = ""
      n = length(line)
      i = 2
      while (i <= n) {
        c = substr(line, i, 1)
        if (esc) {
          if (c == "n") out = out "\n"
          else if (c == "t") out = out "\t"
          else if (c == "r") out = out "\r"
          else out = out c
          esc = 0
        } else if (c == "\\") {
          esc = 1
        } else if (c == "\"") {
          break
        } else {
          out = out c
        }
        i++
      }
      return out
    }
    /^[[:space:]]*"RuleID":/ { rule = qval($0); next }
    /^[[:space:]]*"StartLine":/ { line = qval($0); next }
    /^[[:space:]]*"File":/ { file = qval($0); next }
    /^[[:space:]]*"Secret":/ { secret = qval($0); next }
    /^[[:space:]]*"Match":/ { if (secret == "") secret = qval($0); next }
    /^[[:space:]]*}/ {
      if (file != "") {
        if (line == "" || line == "0") line = "1"
        if (secret == "") secret = rule
        printf "%s\034%s\034%s\034%s\n", file, line, rule, secret
      }
      file = ""; line = ""; rule = ""; secret = ""
    }
  ' "$report" > "$parsed"
  local rec file line rule secret rel
  while IFS= read -r rec || [ -n "$rec" ]; do
    [ -n "$rec" ] || continue
    file=${rec%%$'\034'*}
    rec=${rec#*$'\034'}
    line=${rec%%$'\034'*}
    rec=${rec#*$'\034'}
    rule=${rec%%$'\034'*}
    secret=${rec#*$'\034'}
    case $file in
      "$source"/*) rel=$(pp_rel "$source" "$file") ;;
      *) rel=$file ;;
    esac
    case $rel in
      COMMIT_MESSAGE.txt | */COMMIT_MESSAGE.txt) rel=COMMIT_MESSAGE ;;
    esac
    PP_GITLEAKS_PARSED=$((PP_GITLEAKS_PARSED + 1))
    pp_record_hit "$rel" "$line" "gitleaks ${rule}" "$secret"
  done < "$parsed"
  rm -f "$parsed" "$report"
}

pp_run_gitleaks() {
  local source=$1 label=$2
  local bin report st config=""
  bin=$(pp_gitleaks_bin)
  report=$PP_WORK/gitleaks-${label}.json
  if [ -n "${PP_GITLEAKS_CONFIG_PATH:-}" ]; then
    config=$PP_GITLEAKS_CONFIG_PATH
  fi
  set +e
  if [ -n "$config" ]; then
    "$bin" detect --no-git --source "$source" --config "$config" \
      --no-banner --no-color --log-level error \
      --report-format json --report-path "$report" --exit-code 1 \
      >"$PP_WORK/gitleaks.out" 2>"$PP_WORK/gitleaks.err"
  else
    "$bin" detect --no-git --source "$source" \
      --no-banner --no-color --log-level error \
      --report-format json --report-path "$report" --exit-code 1 \
      >"$PP_WORK/gitleaks.out" 2>"$PP_WORK/gitleaks.err"
  fi
  st=$?
  set -e
  if [ -f "$report" ]; then
    chmod 600 "$report" 2>/dev/null || true
  fi
  if [ "$st" -eq 0 ]; then
    rm -f "$report"
    return 0
  fi
  if [ "$st" -ne 1 ]; then
    pp_redact_text < "$PP_WORK/gitleaks.err" >&2 || true
    rm -f "$report"
    pp_die "gitleaks failed to run. Nothing was pushed."
  fi
  pp_parse_gitleaks_report "$report" "$source"
  if [ "${PP_GITLEAKS_PARSED:-0}" -eq 0 ]; then
    pp_record_hit "GITLEAKS" "1" "gitleaks" "report"
    rm -f "$report"
  fi
}

pp_prepare_message_dir() {
  PP_MESSAGE_DIR=$PP_WORK/message
  mkdir -p "$PP_MESSAGE_DIR"
  printf '%s\n' "$PP_COMMIT_MESSAGE" > "$PP_MESSAGE_DIR/COMMIT_MESSAGE.txt"
  chmod 600 "$PP_MESSAGE_DIR/COMMIT_MESSAGE.txt"
}

pp_scan_all() {
  : > "$PP_HIT_LOG"
  PP_HITS=0
  pp_prepare_message_dir
  pp_scan_denylist_root "$PP_TREE" "tree"
  pp_scan_denylist_root "$PP_MESSAGE_DIR" "message"
  pp_scan_names
  pp_run_gitleaks "$PP_TREE" "tree"
  pp_run_gitleaks "$PP_MESSAGE_DIR" "message"
  rm -f "$PP_MESSAGE_DIR/COMMIT_MESSAGE.txt"
  if [ "$PP_HITS" -gt 200 ]; then
    printf 'publish-public: %s more hits not shown\n' "$((PP_HITS - 200))" >&2
  fi
}
