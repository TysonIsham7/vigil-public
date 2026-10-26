# Copy a git ref into the temp tree, then drop and rewrite paths there.

PP_BUILTIN_GLOBS="$(printf '%s\n' \
  '**/.env' \
  '**/.env.*' \
  '**/*.p12' \
  '**/*.pfx' \
  '**/*.p8' \
  '**/*.mobileprovision' \
  '**/*.provisionprofile' \
  '**/*.xcuserstate' \
  '**/xcuserdata' \
  '**/.DS_Store' \
  '**/id_rsa' \
  '**/id_rsa.pub' \
  '**/id_ed25519' \
  '**/id_ed25519.pub')"

pp_extract_tree() {
  mkdir -p "$PP_TREE"
  git -C "$PP_REPO" archive --format=tar "$PP_REF" | tar -x -C "$PP_TREE"
}

pp_drop_external_symlinks() {
  local link target rel
  [ -d "$PP_TREE" ] || return 0
  while IFS= read -r link; do
    [ -n "$link" ] || continue
    target=$(readlink -- "$link" || readlink "$link" || true)
    case $target in
      /* | .. | ../* | */.. | */../*)
        rel=$(pp_rel "$PP_TREE" "$link")
        rm -f -- "$link"
        printf '%s\n' "$rel" >> "$PP_DROPPED_LIST"
        ;;
    esac
  done < <(find "$PP_TREE" -type l)
}

pp_explicit_drop_globs() {
  local joined="" item
  if [ "${#PP_DROP_ITEMS[@]}" -eq 0 ]; then
    printf ''
    return 0
  fi
  for item in "${PP_DROP_ITEMS[@]}"; do
    joined="${joined}${item}"$'\n'
  done
  printf '%s' "$joined"
}

pp_should_drop_rel() {
  local rel=$1 base globs
  base=$(basename -- "$rel")
  case $base in
    .publish-public.denylist | .publish-public.local.yml) return 0 ;;
  esac
  case $rel in
    "$PP_DENYLIST_REL" | "$PP_DENYLIST_REL"/*) return 0 ;;
  esac
  globs=$(pp_explicit_drop_globs)
  if [ -n "$globs" ] && pp_path_or_ancestor_matches "$rel" "$globs"; then
    return 0
  fi
  if [ "$PP_BUILTIN_DROPS" = "true" ] && [ "$base" != ".env.example" ]; then
    if pp_path_or_ancestor_matches "$rel" "$PP_BUILTIN_GLOBS"; then
      return 0
    fi
  fi
  return 1
}

pp_apply_drops() {
  local item target
  if [ "${#PP_DROP_ITEMS[@]}" -gt 0 ]; then
    for item in "${PP_DROP_ITEMS[@]}"; do
      case $item in
        *'*'* | *'?'*) continue ;;
      esac
      if pp_reject_dotdot "$item"; then
        pp_die "drop path must stay inside the tree"
      fi
      target=$PP_TREE/$item
      if [ -e "$target" ] || [ -L "$target" ]; then
        case $target in
          "$PP_TREE"/*) ;;
          *) pp_die "refusing to delete outside the temp tree" ;;
        esac
        if [ -L "$target" ]; then
          rm -f -- "$target"
        elif [ -d "$target" ]; then
          find "$target" -depth -delete
        else
          rm -f -- "$target"
        fi
        printf '%s\n' "$item" >> "$PP_DROPPED_LIST"
      fi
    done
  fi
  local file rel
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    rel=$(pp_rel "$PP_TREE" "$file")
    if pp_should_drop_rel "$rel"; then
      case $file in
        "$PP_TREE"/*) ;;
        *) pp_die "refusing to delete outside the temp tree" ;;
      esac
      rm -f -- "$file"
      printf '%s\n' "$rel" >> "$PP_DROPPED_LIST"
    fi
  done < <(find "$PP_TREE" \( -type f -o -type l \))
}

pp_normalize_encoding() {
  : > "$PP_CONVERTED_LIST"
  local file rel sig tmp
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    sig=$(od -An -t x1 -N 2 -- "$file" 2>/dev/null | tr -d ' \n' || true)
    case $sig in
      fffe | feff) ;;
      *) continue ;;
    esac
    rel=$(pp_rel "$PP_TREE" "$file")
    tmp=$PP_WORK/utf8-body
    if [ "$sig" = "fffe" ]; then
      iconv -f UTF-16LE -t UTF-8 -- "$file" > "$tmp" || pp_die "could not decode UTF-16 text"
    else
      iconv -f UTF-16BE -t UTF-8 -- "$file" > "$tmp" || pp_die "could not decode UTF-16 text"
    fi
    mv "$tmp" "$file"
    printf '%s\n' "$rel" >> "$PP_CONVERTED_LIST"
  done < <(find "$PP_TREE" -type f)
}

pp_skip_replacement_path() {
  local rel=$1
  case $rel in
    .publish-public.yml | */.publish-public.yml) return 0 ;;
    .publish-public.local.yml | */.publish-public.local.yml) return 0 ;;
    .publish-public.denylist | */.publish-public.denylist) return 0 ;;
    tools/publish-public | tools/publish-public/*) return 0 ;;
  esac
  return 1
}

pp_rule_wants_file() {
  local i=$1 rel=$2
  if pp_skip_replacement_path "$rel"; then
    return 1
  fi
  local paths=${PP_R_PATHS[$i]-} skips=${PP_R_SKIP_PATHS[$i]-}
  if [ -n "$paths" ]; then
    pp_globs_match "$rel" "$paths" || return 1
  fi
  if [ -n "$skips" ] && pp_path_or_ancestor_matches "$rel" "$skips"; then
    return 1
  fi
  return 0
}

pp_file_has_nul() {
  local orig new
  orig=$(wc -c < "$1" | tr -d ' ')
  new=$(tr -d '\000' < "$1" | wc -c | tr -d ' ')
  [ "$orig" != "$new" ]
}

pp_index_of() {
  local hay=$1 needle=$2
  local n=${#needle} h=${#hay} i=0
  if [ "$n" -eq 0 ]; then
    printf -- '-1'
    return 0
  fi
  while [ $((i + n)) -le "$h" ]; do
    if [ "${hay:i:n}" = "$needle" ]; then
      printf '%s' "$i"
      return 0
    fi
    i=$((i + 1))
  done
  printf -- '-1'
}

pp_expand_backrefs() {
  local repl=$1
  local out="" i=0 n=${#repl} c nxt
  while [ "$i" -lt "$n" ]; do
    c=${repl:i:1}
    if [ "$c" = "\\" ] && [ $((i + 1)) -lt "$n" ]; then
      nxt=${repl:i+1:1}
      case $nxt in
        0) out="${out}${PP_M0-}" ;;
        1) out="${out}${PP_M1-}" ;;
        2) out="${out}${PP_M2-}" ;;
        3) out="${out}${PP_M3-}" ;;
        4) out="${out}${PP_M4-}" ;;
        5) out="${out}${PP_M5-}" ;;
        6) out="${out}${PP_M6-}" ;;
        7) out="${out}${PP_M7-}" ;;
        8) out="${out}${PP_M8-}" ;;
        9) out="${out}${PP_M9-}" ;;
        \\) out="${out}\\" ;;
        *) out="${out}${nxt}" ;;
      esac
      i=$((i + 2))
    else
      out="${out}${c}"
      i=$((i + 1))
    fi
  done
  printf '%s' "$out"
}

pp_save_rematch() {
  PP_M0=${BASH_REMATCH[0]-}
  PP_M1=${BASH_REMATCH[1]-}
  PP_M2=${BASH_REMATCH[2]-}
  PP_M3=${BASH_REMATCH[3]-}
  PP_M4=${BASH_REMATCH[4]-}
  PP_M5=${BASH_REMATCH[5]-}
  PP_M6=${BASH_REMATCH[6]-}
  PP_M7=${BASH_REMATCH[7]-}
  PP_M8=${BASH_REMATCH[8]-}
  PP_M9=${BASH_REMATCH[9]-}
}

pp_replace_literal_line() {
  local line=$1 from=$2 to=$3 skip=$4
  PP_LINE_REPLACEMENTS=0
  if [ -n "$skip" ]; then
    local sre=$skip
    if [[ $from =~ $sre ]]; then
      printf '%s' "$line"
      return 0
    fi
  fi
  local out="" rest=$line idx count=0
  while true; do
    idx=$(pp_index_of "$rest" "$from")
    if [ "$idx" = "-1" ]; then
      out="${out}${rest}"
      break
    fi
    out="${out}${rest:0:idx}${to}"
    rest=${rest:idx+${#from}}
    count=$((count + 1))
  done
  PP_LINE_REPLACEMENTS=$count
  printf '%s' "$out"
}

pp_replace_regex_line() {
  local line=$1 pattern=$2 to=$3 skip=$4
  local out="" count=0
  PP_LINE_REPLACEMENTS=0
  while [ -n "$line" ]; do
    local re=$pattern
    if [[ $line =~ $re ]]; then
      pp_save_rematch
      local matched=$PP_M0
      if [ -z "$matched" ]; then
        out="${out}${line:0:1}"
        line=${line:1}
        continue
      fi
      local idx
      idx=$(pp_index_of "$line" "$matched")
      if [ "$idx" = "-1" ]; then
        out="${out}${line}"
        break
      fi
      local use=$matched
      local skipped=0
      if [ -n "$skip" ]; then
        local sre=$skip
        if [[ $matched =~ $sre ]]; then
          skipped=1
        fi
      fi
      if [ "$skipped" -eq 0 ]; then
        use=$(pp_expand_backrefs "$to")
        if [ "$use" != "$matched" ]; then
          count=$((count + 1))
        fi
      fi
      out="${out}${line:0:idx}${use}"
      line=${line:idx+${#matched}}
    else
      out="${out}${line}"
      break
    fi
  done
  PP_LINE_REPLACEMENTS=$count
  printf '%s' "$out"
}

pp_replace_line() {
  local line=$1 kind=$2 find=$3 to=$4 skip=$5
  if [ "$kind" = "from" ]; then
    pp_replace_literal_line "$line" "$find" "$to" "$skip"
  else
    pp_replace_regex_line "$line" "$find" "$to" "$skip"
  fi
}

pp_file_ends_with_newline() {
  local size last
  size=$(wc -c < "$1" | tr -d ' ')
  [ "$size" -gt 0 ] || return 1
  last=$(od -An -t x1 -N 1 -j $((size - 1)) -- "$1" 2>/dev/null | tr -d ' \n' || true)
  [ "$last" = "0a" ]
}

pp_record_replacement() {
  printf '%s\t%s\n' "$1" "$2" >> "$PP_REPLACED_LIST"
}

pp_replace_in_file() {
  local file=$1 rel=$2 kind=$3 find=$4 to=$5 skip=$6
  local tmp mode count=0 line result had_nl=0
  mode=$(pp_file_mode "$file")
  if pp_file_ends_with_newline "$file"; then
    had_nl=1
  fi
  tmp=$PP_WORK/replace-body
  : > "$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    pp_replace_line "$line" "$kind" "$find" "$to" "$skip"
    printf '\n'
    count=$((count + PP_LINE_REPLACEMENTS))
  done < "$file" > "$tmp"
  if [ "$had_nl" -eq 0 ]; then
    local size
    size=$(wc -c < "$tmp" | tr -d ' ')
    if [ "$size" -gt 0 ]; then
      dd if="$tmp" of="$PP_WORK/replace-stripped" bs=1 count=$((size - 1)) 2>/dev/null
      mv "$PP_WORK/replace-stripped" "$tmp"
    fi
  fi
  if [ "$count" -gt 0 ]; then
    mv "$tmp" "$file"
    chmod "$mode" "$file" 2>/dev/null || chmod "0${mode}" "$file" 2>/dev/null || true
    pp_record_replacement "$rel" "$count"
  else
    rm -f "$tmp"
  fi
}

pp_grep_status() {
  # Run grep. Return 0 on match, 1 on no match, die on a broken pattern.
  local st
  set +e
  "$@" >"$PP_WORK/grep-rule.out" 2>"$PP_WORK/grep-rule.err"
  st=$?
  set -e
  if [ "$st" -eq 2 ]; then
    pp_die "a replacement or denylist pattern was rejected by grep"
  fi
  if [ "$st" -ne 0 ] && [ "$st" -ne 1 ]; then
    pp_die "grep failed during sanitize"
  fi
  return "$st"
}

pp_apply_one_rule() {
  local i=$1
  local kind=${PP_R_KIND[$i]}
  local find=${PP_R_FIND[$i]}
  local to=${PP_R_TO[$i]}
  local skip=${PP_R_SKIP[$i]-}
  local file rel st
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    rel=$(pp_rel "$PP_TREE" "$file")
    pp_rule_wants_file "$i" "$rel" || continue
    if pp_file_has_nul "$file"; then
      continue
    fi
    if [ "$kind" = "from" ]; then
      if ! pp_grep_status grep -a -F -q -e "$find" -- "$file"; then
        continue
      fi
    else
      if ! pp_grep_status grep -a -E -q -e "$find" -- "$file"; then
        continue
      fi
    fi
    pp_replace_in_file "$file" "$rel" "$kind" "$find" "$to" "$skip"
  done < <(find "$PP_TREE" -type f)
}

pp_apply_replacements() {
  : > "$PP_REPLACED_LIST"
  local n=${#PP_R_KIND[@]} i
  [ "$n" -gt 0 ] || return 0
  for ((i = 0; i < n; i++)); do
    pp_apply_one_rule "$i"
  done
}
