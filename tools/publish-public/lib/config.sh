# Restricted YAML reader for .publish-public.yml.
# Supports comments, scalars, lists of strings, and one level of maps
# (the replacements list) whose values may themselves be lists.

PP_REMOTE=""
PP_BRANCH=""
PP_MESSAGE=""
PP_AUTHOR_NAME=""
PP_AUTHOR_EMAIL=""
PP_DENYLIST_REL=""
PP_GITLEAKS_CONFIG=""
PP_GITLEAKS_VERSION=""
PP_BUILTIN_DROPS=""

PP_DROP_ITEMS=()
PP_ALLOW_ITEMS=()
PP_NAME_TOKEN_ITEMS=()
PP_NAME_ALLOW_ITEMS=()
PP_CODE_EXT_ITEMS=()

PP_R_KIND=()
PP_R_FIND=()
PP_R_TO=()
PP_R_SKIP=()
PP_R_PATHS=()
PP_R_SKIP_PATHS=()

pp_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

pp_unquote_value() {
  local raw
  raw=$(pp_trim "$1")
  local out="" i=0 n c
  if [ -z "$raw" ]; then
    printf ''
    return 0
  fi
  local q=${raw:0:1}
  if [ "$q" = "'" ]; then
    raw=${raw:1}
    while [ -n "$raw" ]; do
      case $raw in
        \'\'*)
          out="${out}'"
          raw=${raw:2}
          ;;
        \'*)
          raw=${raw:1}
          break
          ;;
        *)
          out="${out}${raw:0:1}"
          raw=${raw:1}
          ;;
      esac
    done
    printf '%s' "$out"
    return 0
  fi
  if [ "$q" = '"' ]; then
    raw=${raw:1}
    while [ -n "$raw" ]; do
      c=${raw:0:1}
      if [ "$c" = "\\" ]; then
        local nxt=${raw:1:1}
        case $nxt in
          n) out="${out}
" ;;
          t) out="${out}	" ;;
          \\ | \" | /) out="${out}${nxt}" ;;
          *) out="${out}${nxt}" ;;
        esac
        raw=${raw:2}
        continue
      fi
      if [ "$c" = '"' ]; then
        break
      fi
      out="${out}${c}"
      raw=${raw:1}
    done
    printf '%s' "$out"
    return 0
  fi
  # Unquoted. Drop a trailing comment introduced by whitespace.
  local comment
  comment=$(printf '%s\n' "$raw" | sed -n 's/[[:space:]]#.*//p')
  if [ -n "$comment" ] || printf '%s' "$raw" | grep -q '[[:space:]]#'; then
    raw=$(printf '%s' "$raw" | sed 's/[[:space:]]#.*$//')
    raw=$(pp_trim "$raw")
  fi
  printf '%s' "$raw"
}

pp_split_key_value() {
  # Sets PP_KV_KEY and PP_KV_VAL. Values may be empty, so this does not print them.
  local content=$1
  local key val
  case $content in
    *:*)
      key=$(pp_trim "${content%%:*}")
      val=${content#*:}
      ;;
    *)
      pp_die "expected key: value near: ${content}"
      ;;
  esac
  case $key in
    "" | *[!A-Za-z0-9_-]*)
      pp_die "invalid config key: ${key}"
      ;;
  esac
  PP_KV_KEY=$key
  PP_KV_VAL=$(pp_unquote_value "$val")
}

pp_set_scalar() {
  local key=$1 val=$2
  case $key in
    public_remote) PP_REMOTE=$val ;;
    public_branch) PP_BRANCH=$val ;;
    commit_message) PP_MESSAGE=$val ;;
    author_name) PP_AUTHOR_NAME=$val ;;
    author_email) PP_AUTHOR_EMAIL=$val ;;
    denylist) PP_DENYLIST_REL=$val ;;
    gitleaks_config) PP_GITLEAKS_CONFIG=$val ;;
    gitleaks_version) PP_GITLEAKS_VERSION=$val ;;
    builtin_drops) PP_BUILTIN_DROPS=$val ;;
    *)
      pp_die "unknown config key: ${key}"
      ;;
  esac
}

pp_list_name_for() {
  case $1 in
    drop) printf 'drop' ;;
    denylist_allow) printf 'allow' ;;
    name_tokens) printf 'tokens' ;;
    name_allow) printf 'nameallow' ;;
    code_extensions) printf 'ext' ;;
    *) return 1 ;;
  esac
}

pp_append_simple() {
  local section=$1 item=$2
  case $section in
    drop) PP_DROP_ITEMS+=("$item") ;;
    denylist_allow) PP_ALLOW_ITEMS+=("$item") ;;
    name_tokens) PP_NAME_TOKEN_ITEMS+=("$item") ;;
    name_allow) PP_NAME_ALLOW_ITEMS+=("$item") ;;
    code_extensions) PP_CODE_EXT_ITEMS+=("$item") ;;
    *) pp_die "not a list: ${section}" ;;
  esac
}

pp_new_replacement() {
  PP_R_KIND+=("")
  PP_R_FIND+=("")
  PP_R_TO+=("")
  PP_R_SKIP+=("")
  PP_R_PATHS+=("")
  PP_R_SKIP_PATHS+=("")
  PP_R_INDEX=$((${#PP_R_KIND[@]} - 1))
  PP_R_HAVE_TO=0
}

pp_set_repl_field() {
  local key=$1 val=$2
  local i=$PP_R_INDEX
  case $key in
    from)
      PP_R_KIND[i]="from"
      PP_R_FIND[i]=$val
      ;;
    pattern)
      PP_R_KIND[i]="pattern"
      PP_R_FIND[i]=$val
      ;;
    to)
      PP_R_TO[i]=$val
      PP_R_HAVE_TO=1
      ;;
    skip_if_match)
      PP_R_SKIP[i]=$val
      ;;
    paths | skip_paths)
      if [ -n "$val" ]; then
        pp_die "${key} must be a list, not a scalar"
      fi
      ;;
    *)
      pp_die "unknown replacement field: ${key}"
      ;;
  esac
}

pp_append_repl_list() {
  local field=$1 item=$2
  local i=$PP_R_INDEX
  case $field in
    paths)
      if [ -z "${PP_R_PATHS[$i]}" ]; then
        PP_R_PATHS[$i]=$item
      else
        PP_R_PATHS[$i]=${PP_R_PATHS[$i]}$'\n'$item
      fi
      ;;
    skip_paths)
      if [ -z "${PP_R_SKIP_PATHS[$i]}" ]; then
        PP_R_SKIP_PATHS[$i]=$item
      else
        PP_R_SKIP_PATHS[$i]=${PP_R_SKIP_PATHS[$i]}$'\n'$item
      fi
      ;;
    *) pp_die "not a replacement list: ${field}" ;;
  esac
}

pp_parse_config_file() {
  local file=$1
  [ -f "$file" ] || pp_die "config not found: ${file}"
  local line indent content section="" repl_field="" lineno=0
  local in_repl=0
  PP_R_INDEX=-1
  PP_R_HAVE_TO=0
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line=${line%$'\r'}
    case $line in
      "" | \#*) continue ;;
    esac
    case $line in
      *[![:space:]]*) ;;
      *) continue ;;
    esac
    indent=0
    while [ "${line:indent:1}" = " " ]; do
      indent=$((indent + 1))
    done
    case $line in
      *"$'\t'"*) pp_die "${file}:${lineno}: tabs are not allowed in the config" ;;
    esac
    if printf '%s' "$line" | grep -q $'\t'; then
      pp_die "${file}:${lineno}: tabs are not allowed in the config"
    fi
    content=${line:indent}
    case $content in
      \#*) continue ;;
    esac

    if [ "$indent" -eq 0 ]; then
      if [ "$in_repl" -eq 1 ] && [ "$PP_R_HAVE_TO" -eq 0 ]; then
        pp_die "${file}:${lineno}: replacement is missing to:"
      fi
      in_repl=0
      repl_field=""
      local key val
      pp_split_key_value "$content"
      key=$PP_KV_KEY
      val=$PP_KV_VAL
      if [ -z "$val" ]; then
        section=$key
        case $section in
          drop | denylist_allow | name_tokens | name_allow | code_extensions | replacements) ;;
          *) pp_die "${file}:${lineno}: unknown section ${section}" ;;
        esac
      else
        section=""
        pp_set_scalar "$key" "$val"
      fi
      continue
    fi

    if [ -z "$section" ]; then
      pp_die "${file}:${lineno}: indented line outside a section"
    fi

    if [ "$section" = "replacements" ]; then
      if [ "$indent" -eq 2 ] && [ "${content:0:2}" = "- " ]; then
        if [ "$in_repl" -eq 1 ] && [ "$PP_R_HAVE_TO" -eq 0 ]; then
          pp_die "${file}:${lineno}: replacement is missing to:"
        fi
        pp_new_replacement
        in_repl=1
        repl_field=""
        local item_body key val
        item_body=${content:2}
        pp_split_key_value "$item_body"
        key=$PP_KV_KEY
        val=$PP_KV_VAL
        pp_set_repl_field "$key" "$val"
        if [ -z "$val" ] && [ "$key" != "to" ]; then
          repl_field=$key
        else
          repl_field=""
        fi
        continue
      fi
      if [ "$in_repl" -eq 0 ]; then
        pp_die "${file}:${lineno}: expected a replacement item"
      fi
      if [ "${content:0:2}" = "- " ]; then
        [ -n "$repl_field" ] || pp_die "${file}:${lineno}: list item is not under paths or skip_paths"
        pp_append_repl_list "$repl_field" "$(pp_unquote_value "${content:2}")"
        continue
      fi
      local key val
      pp_split_key_value "$content"
      key=$PP_KV_KEY
      val=$PP_KV_VAL
      pp_set_repl_field "$key" "$val"
      if [ -z "$val" ] && [ "$key" != "to" ]; then
        repl_field=$key
      else
        repl_field=""
      fi
      continue
    fi

    if [ "${content:0:2}" != "- " ]; then
      pp_die "${file}:${lineno}: expected a list item under ${section}"
    fi
    pp_append_simple "$section" "$(pp_unquote_value "${content:2}")"
  done < "$file"

  if [ "$in_repl" -eq 1 ] && [ "$PP_R_HAVE_TO" -eq 0 ]; then
    pp_die "${file}: replacement is missing to:"
  fi
}

pp_finish_config() {
  [ -n "$PP_REMOTE" ] || pp_die "config is missing public_remote"
  [ -n "$PP_AUTHOR_NAME" ] || pp_die "config is missing author_name"
  [ -n "$PP_AUTHOR_EMAIL" ] || pp_die "config is missing author_email"
  case $PP_AUTHOR_EMAIL in
    *@*) ;;
    *) pp_die "author_email is not an email address" ;;
  esac
  case $PP_REMOTE in
    -*) pp_die "public_remote must not start with a dash" ;;
  esac
  [ -n "$PP_BRANCH" ] || PP_BRANCH=main
  case $PP_BRANCH in
    *[!A-Za-z0-9._/-]* | -* | */*/*/*/* | ../* | */../* | */.. | ..)
      pp_die "public_branch is not a single branch name"
      ;;
  esac
  case $PP_BRANCH in
    *..* | *@\{*) pp_die "public_branch is not a single branch name" ;;
  esac
  [ -n "$PP_MESSAGE" ] || PP_MESSAGE="Publish sanitized snapshot"
  [ -n "$PP_DENYLIST_REL" ] || PP_DENYLIST_REL=".publish-public.denylist"
  [ -n "$PP_GITLEAKS_VERSION" ] || PP_GITLEAKS_VERSION="8.30.1"
  [ -n "$PP_BUILTIN_DROPS" ] || PP_BUILTIN_DROPS="true"
  case $PP_BUILTIN_DROPS in
    true | false) ;;
    *) pp_die "builtin_drops must be true or false" ;;
  esac

  if [ "${#PP_NAME_TOKEN_ITEMS[@]}" -eq 0 ]; then
    PP_NAME_TOKEN_ITEMS+=("$PP_AUTHOR_NAME")
    local rest=$PP_AUTHOR_NAME word
    rest=$(printf '%s' "$rest" | tr -s '[:space:]' ' ')
    local oldifs=$IFS
    IFS=' '
    for word in $rest; do
      [ "${#word}" -ge 3 ] || continue
      if [ "$word" != "$PP_AUTHOR_NAME" ]; then
        PP_NAME_TOKEN_ITEMS+=("$word")
      fi
    done
    IFS=$oldifs
  fi

  local i
  if [ "${#PP_R_KIND[@]}" -gt 0 ]; then
    for ((i = 0; i < ${#PP_R_KIND[@]}; i++)); do
      [ -n "${PP_R_KIND[$i]}" ] || pp_die "replacement is missing from: or pattern:"
      [ -n "${PP_R_FIND[$i]}" ] || pp_die "replacement pattern is empty"
    done
  fi
}

pp_load_config() {
  local base=$1 overlay=$2
  pp_parse_config_file "$base"
  if [ -n "$overlay" ] && [ -f "$overlay" ]; then
    pp_parse_config_file "$overlay"
  fi
  pp_finish_config
}
