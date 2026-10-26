# Download a pinned gitleaks binary and verify the release tarball.

pp_gitleaks_asset() {
  local ver=$1 os arch
  os=$(uname -s)
  arch=$(uname -m)
  case "${os}-${arch}" in
    Darwin-arm64) printf 'gitleaks_%s_darwin_arm64.tar.gz' "$ver" ;;
    Darwin-x86_64) printf 'gitleaks_%s_darwin_x64.tar.gz' "$ver" ;;
    Linux-x86_64 | Linux-amd64) printf 'gitleaks_%s_linux_x64.tar.gz' "$ver" ;;
    Linux-aarch64 | Linux-arm64) printf 'gitleaks_%s_linux_arm64.tar.gz' "$ver" ;;
    *) pp_die "no pinned gitleaks build for ${os} ${arch}" ;;
  esac
}

pp_gitleaks_expected() {
  local ver=$1 asset=$2 sums line
  sums=$PP_TOOL_DIR/checksums/gitleaks-${ver}.sha256
  [ -f "$sums" ] || pp_die "no checksum file for gitleaks ${ver}"
  line=$(awk -v asset="$asset" '$2 == asset { print $1; exit }' "$sums")
  [ -n "$line" ] || pp_die "checksum file has no entry for ${asset}"
  printf '%s' "$line"
}

pp_gitleaks_download() {
  local url=$1 dest=$2
  mkdir -p "$(dirname -- "$dest")"
  curl -fsSL --retry 3 --retry-delay 1 -o "${dest}.partial" "$url" \
    || pp_die "failed to download gitleaks"
  mv "${dest}.partial" "$dest"
}

pp_gitleaks_bin() {
  local ver=$PP_GITLEAKS_VERSION
  local asset expected cache_dir tarball bin got reported url
  asset=$(pp_gitleaks_asset "$ver")
  expected=$(pp_gitleaks_expected "$ver" "$asset")
  cache_dir=${PUBLISH_PUBLIC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/publish-public}
  mkdir -p "$cache_dir"
  tarball=$cache_dir/$asset
  url="https://github.com/gitleaks/gitleaks/releases/download/v${ver}/${asset}"
  if [ ! -f "$tarball" ]; then
    pp_note "downloading gitleaks ${ver} (${asset})"
    pp_gitleaks_download "$url" "$tarball"
  fi
  got=$(pp_sha256 "$tarball")
  if [ "$got" != "$expected" ]; then
    rm -f "$tarball"
    pp_note "cached gitleaks tarball did not match the pinned checksum; downloading again"
    pp_gitleaks_download "$url" "$tarball"
    got=$(pp_sha256 "$tarball")
    if [ "$got" != "$expected" ]; then
      rm -f "$tarball"
      pp_die "gitleaks checksum mismatch for ${asset}"
    fi
  fi
  bin=$cache_dir/${asset%.tar.gz}/gitleaks
  if [ ! -x "$bin" ]; then
    mkdir -p "$(dirname -- "$bin")"
    tar -xzf "$tarball" -C "$(dirname -- "$bin")" gitleaks
    chmod 755 "$bin"
  fi
  reported=$("$bin" version 2>/dev/null || true)
  case $reported in
    "$ver" | *" $ver" | *"$ver"*) ;;
    *) pp_die "gitleaks reported '${reported}', wanted ${ver}" ;;
  esac
  printf '%s' "$bin"
}
