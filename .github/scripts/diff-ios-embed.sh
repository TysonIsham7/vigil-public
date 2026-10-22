#!/bin/bash
# Compare a built Vigil iOS appex with a fresh safari-web-extension-converter
# project. Records validator, plist, and codesign results. Does not edit the repo.
#
# Usage: diff-ios-embed.sh <unsigned-derived-data> <signed-derived-data> <report>
# Bash 3.2 compatible. macOS only. Exits 0 after writing the report.

set -u

UNSIGNED_DD="${1:-}"
SIGNED_DD="${2:-}"
REPORT="${3:-ios-embed-report.txt}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=""
TOOL=""
PASSED=""
VIGIL_PLIST=""
TEMPLATE_PLIST=""

cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

: >"$REPORT"

say() {
  printf '%s\n' "$*" | tee -a "$REPORT"
}

scrub() {
  sed -E \
    -e 's/(TeamIdentifier=)[^[:space:]]+/\1REDACTED/g' \
    -e 's/(Authority=).*/\1REDACTED/g' \
    -e 's/(DEVELOPMENT_TEAM = ).*/\1REDACTED/g' \
    -e 's/(Signing Identity:).*/\1 REDACTED/g'
}

find_tool() {
  local candidate
  candidate=""
  if candidate=$(xcrun --find embeddedBinaryValidationUtility 2>/dev/null); then
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      TOOL="$candidate"
      return 0
    fi
  fi
  candidate=$(find /Applications/Xcode.app \( -name embeddedBinaryValidationUtility -o -name builtin-embeddedBinaryValidationUtility \) 2>/dev/null | head -n 1)
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    TOOL="$candidate"
  fi
}

product_root() {
  local dd="$1"
  if [ -z "$dd" ] || [ ! -d "$dd/Build/Products" ]; then
    return 0
  fi
  find "$dd/Build/Products" -type d -name 'Debug-iphonesimulator' 2>/dev/null | head -n 1
}

note_pass() {
  local name="$1"
  local code="$2"
  if [ "$code" -eq 0 ]; then
    PASSED="$PASSED $name"
  fi
}

run_tool() {
  local name="$1"
  shift
  local out code
  out=$("$TOOL" "$@" 2>&1)
  code=$?
  printf '%s\n' "$out" | scrub | tee -a "$REPORT"
  say "PROBE $name exit=$code"
  note_pass "$name" "$code"
}

probe() {
  local name="$1"
  local appex="$2"
  local host="$3"
  if [ -z "$TOOL" ]; then
    say "PROBE $name exit=no-tool"
    return 0
  fi
  if [ ! -d "$appex" ]; then
    say "PROBE $name exit=missing-appex"
    return 0
  fi
  if [ ! -f "$host" ]; then
    say "PROBE $name exit=missing-host"
    return 0
  fi
  run_tool "$name" "$appex" -info-plist-path "$host"
  run_tool "$name-cert" "$appex" -signing-cert - -info-plist-path "$host"
  run_tool "$name-shallow" "$appex" -shallow-bundle -info-plist-path "$host"
}

describe_bundle() {
  local label="$1"
  local bundle="$2"
  local plist executable binary code
  say "LIST $label"
  if [ ! -d "$bundle" ]; then
    say "LIST $label missing"
    return 0
  fi
  find "$bundle" \( -type f -o -type l -o -type d \) | sed "s|$bundle|.|" | sort | tee -a "$REPORT"
  find "$bundle" -type l -print | tee -a "$REPORT"
  plist="$bundle/Info.plist"
  if [ -f "$bundle/Contents/Info.plist" ] && [ ! -f "$plist" ]; then
    plist="$bundle/Contents/Info.plist"
  fi
  if [ ! -f "$plist" ]; then
    say "PLIST $label missing"
    return 0
  fi
  say "---- PLIST-HEADER $label"
  od -An -tx1 -N 16 "$plist" | tee -a "$REPORT"
  plutil -lint "$plist" 2>&1 | tee -a "$REPORT"
  plutil -p "$plist" 2>&1 | scrub | tee -a "$REPORT"
  codesign --verify --strict --verbose=4 "$bundle" >"$WORK/verify.txt" 2>&1
  code=$?
  scrub <"$WORK/verify.txt" | tee -a "$REPORT"
  say "VERIFY $label exit=$code"
  codesign -dvvv "$bundle" >"$WORK/codesign-dv.txt" 2>&1
  scrub <"$WORK/codesign-dv.txt" | tee -a "$REPORT"
  executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$plist" 2>/dev/null || true)
  binary="$bundle/$executable"
  if [ ! -f "$binary" ] && [ -n "$executable" ] && [ -f "$bundle/Contents/MacOS/$executable" ]; then
    binary="$bundle/Contents/MacOS/$executable"
  fi
  if [ -n "$executable" ] && [ -f "$binary" ]; then
    file "$binary" 2>&1 | tee -a "$REPORT"
    if command -v vtool >/dev/null 2>&1; then
      vtool -show-build "$binary" 2>&1 | tee -a "$REPORT"
    fi
  fi
  if [ "$label" = "signed-embedded" ] || [ "$label" = "unsigned-embedded" ]; then
    VIGIL_PLIST="$plist"
  fi
  if [ "$label" = "template-embedded" ] || [ "$label" = "template-standalone" ]; then
    if [ -z "$TEMPLATE_PLIST" ]; then
      TEMPLATE_PLIST="$plist"
    fi
  fi
}

settings_for() {
  local label="$1"
  local project="$2"
  local target="$3"
  local out key value team
  say "---- SETTING $label target=$target"
  out=$(xcodebuild -project "$project" -target "$target" -configuration Debug -sdk iphonesimulator -showBuildSettings 2>/dev/null || true)
  for key in \
    PRODUCT_NAME PRODUCT_MODULE_NAME FULL_PRODUCT_NAME WRAPPER_NAME WRAPPER_EXTENSION \
    CONTENTS_FOLDER_PATH INFOPLIST_FILE INFOPLIST_PATH INFOPLIST_OUTPUT_FORMAT \
    GENERATE_INFOPLIST_FILE PRODUCT_BUNDLE_PACKAGE_TYPE EXECUTABLE_NAME EXECUTABLE_PATH \
    EXECUTABLE_FOLDER_PATH UNLOCALIZED_RESOURCES_FOLDER_PATH ENABLE_DEBUG_DYLIB ENABLE_PREVIEWS \
    CODE_SIGN_ENTITLEMENTS CODE_SIGN_STYLE CODE_SIGN_IDENTITY IPHONEOS_DEPLOYMENT_TARGET \
    TARGETED_DEVICE_FAMILY SDKROOT SUPPORTED_PLATFORMS SKIP_INSTALL APPLICATION_EXTENSION_API_ONLY \
    DEFINES_MODULE PRODUCT_BUNDLE_IDENTIFIER MARKETING_VERSION CURRENT_PROJECT_VERSION \
    DEPLOYMENT_LOCATION INSTALL_PATH PACKAGE_TYPE DEVELOPMENT_LANGUAGE CODE_SIGNING_ALLOWED \
    CODE_SIGNING_REQUIRED AD_HOC_CODE_SIGNING_ALLOWED
  do
    value=$(printf '%s\n' "$out" | awk -v k="$key" '$1 == k { sub(/^[^=]*= */, ""); print; exit }')
    if [ -n "$value" ]; then
      say "SETTING $label $key=$value"
    else
      say "SETTING $label $key=(unset)"
    fi
  done
  team=$(printf '%s\n' "$out" | awk '$1 == "DEVELOPMENT_TEAM" { sub(/^[^=]*= */, ""); print; exit }')
  case "$team" in
    "") say "SETTING $label DEVELOPMENT_TEAM=(empty)" ;;
    XXXXXXXXXX) say "SETTING $label DEVELOPMENT_TEAM=placeholder" ;;
    *) say "SETTING $label DEVELOPMENT_TEAM=set" ;;
  esac
}

copy_bundle() {
  rm -rf "$2"
  ditto "$1" "$2"
}

mutate_and_probe() {
  local name="$1"
  local source="$2"
  local host="$3"
  local mode="$4"
  local dest="$WORK/$name.appex"
  local code
  copy_bundle "$source" "$dest"
  case "$mode" in
    resign)
      codesign --force --sign - --timestamp=none "$dest" >"$WORK/codesign.txt" 2>&1
      ;;
    xml-resign)
      plutil -convert xml1 "$dest/Info.plist"
      codesign --force --sign - --timestamp=none "$dest" >"$WORK/codesign.txt" 2>&1
      ;;
    strip-signature)
      rm -rf "$dest/_CodeSignature"
      printf '%s\n' "signature removed" >"$WORK/codesign.txt"
      ;;
    contents-plist)
      mkdir -p "$dest/Contents"
      cp "$dest/Info.plist" "$dest/Contents/Info.plist"
      codesign --force --sign - --timestamp=none "$dest" >"$WORK/codesign.txt" 2>&1
      ;;
    development-region)
      /usr/libexec/PlistBuddy -c 'Add :CFBundleDevelopmentRegion string en' "$dest/Info.plist" >/dev/null 2>&1 || \
        /usr/libexec/PlistBuddy -c 'Set :CFBundleDevelopmentRegion en' "$dest/Info.plist"
      codesign --force --sign - --timestamp=none "$dest" >"$WORK/codesign.txt" 2>&1
      ;;
    pkginfo)
      printf 'XPC!????' >"$dest/PkgInfo"
      codesign --force --sign - --timestamp=none "$dest" >"$WORK/codesign.txt" 2>&1
      ;;
    contents-plist-nosign)
      mkdir -p "$dest/Contents"
      cp "$dest/Info.plist" "$dest/Contents/Info.plist"
      printf '%s\n' "copied Info.plist to Contents without signing" >"$WORK/codesign.txt"
      ;;
    rename-resources)
      if [ -d "$dest/Resources" ]; then
        mv "$dest/Resources" "$dest/WebResources"
      fi
      printf '%s\n' "renamed Resources" >"$WORK/codesign.txt"
      ;;
    drop-resources)
      rm -rf "$dest/Resources"
      printf '%s\n' "removed Resources" >"$WORK/codesign.txt"
      ;;
  esac
  code=$?
  say "MUTATE $name codesign exit=$code"
  scrub <"$WORK/codesign.txt" | tee -a "$REPORT"
  probe "$name" "$dest" "$host"
}

json_list() {
  local project="$1"
  local kind="$2"
  xcodebuild -list -json -project "$project" >"$WORK/list.json" 2>"$WORK/list.err" || true
  python3 - "$WORK/list.json" "$kind" <<'PY'
import json, sys
path, kind = sys.argv[1], sys.argv[2]
raw = open(path, encoding="utf-8", errors="replace").read()
start = raw.find("{")
if start < 0:
    sys.exit(0)
data = json.loads(raw[start:])
proj = data.get("project") or data.get("workspace") or {}
for item in proj.get(kind) or []:
    print(item)
PY
}

pick_ios_name() {
  local choice
  choice=$(printf '%s\n' "$1" | grep -E -i 'iOS|iPhone' | head -n 1)
  if [ -z "$choice" ]; then
    choice=$(printf '%s\n' "$1" | head -n 1)
  fi
  printf '%s\n' "$choice"
}

build_template() {
  local ext="$WORK/min-ext"
  local out="$WORK/template-src"
  local converter log code project schemes scheme dd build_log products app appex embedded host target
  mkdir -p "$ext"
  printf '%s\n' '/* template */' >"$ext/background.js"
  cat >"$ext/manifest.json" <<'EOF'
{
  "manifest_version": 3,
  "name": "Template",
  "version": "1.0",
  "description": "Template",
  "background": {
    "scripts": ["background.js"]
  }
}
EOF
  converter=""
  if converter=$(xcrun --find safari-web-extension-converter 2>/dev/null); then
    :
  fi
  if [ -z "$converter" ] && [ -x /usr/bin/safari-web-extension-converter ]; then
    converter=/usr/bin/safari-web-extension-converter
  fi
  if [ -z "$converter" ]; then
    say "CONCLUSION template=no-converter"
    return 0
  fi
  say "TOOL converter=$converter"
  "$converter" --help >"$WORK/converter-help.txt" 2>&1 || true
  head -n 60 "$WORK/converter-help.txt" | tee -a "$REPORT"
  log=$("$converter" "$ext" \
    --project-location "$out" \
    --app-name Template \
    --bundle-identifier com.example.template \
    --swift \
    --ios-only \
    --copy-resources \
    --no-open \
    --no-prompt \
    --force 2>&1)
  code=$?
  printf '%s\n' "$log" | scrub | tee -a "$REPORT"
  say "CONVERTER exit=$code"
  if [ "$code" -ne 0 ]; then
    rm -rf "$out"
    mkdir -p "$out"
    log=$("$converter" "$ext" \
      --project-location "$out" \
      --app-name Template \
      --bundle-identifier com.example.template \
      --swift \
      --no-open \
      --no-prompt \
      --force 2>&1)
    code=$?
    printf '%s\n' "$log" | scrub | tee -a "$REPORT"
    say "CONVERTER fallback exit=$code"
  fi
  project=$(find "$out" -name '*.xcodeproj' -type d | head -n 1)
  if [ -z "$project" ]; then
    say "CONCLUSION template=no-project"
    return 0
  fi
  say "TEMPLATE project=$(basename "$project")"
  schemes=$(json_list "$project" schemes)
  say "TEMPLATE schemes follow"
  printf '%s\n' "$schemes" | tee -a "$REPORT"
  scheme=$(pick_ios_name "$schemes")
  if [ -z "$scheme" ]; then
    say "CONCLUSION template=no-scheme"
    return 0
  fi
  say "TEMPLATE scheme=$scheme"
  dd="$WORK/template-dd"
  build_log=$(xcodebuild -project "$project" -scheme "$scheme" -configuration Debug \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$dd" \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY=- \
    CODE_SIGNING_ALLOWED=YES \
    AD_HOC_CODE_SIGNING_ALLOWED=YES \
    DEVELOPMENT_TEAM= \
    build 2>&1)
  code=$?
  printf '%s\n' "$build_log" | scrub | tail -n 60 | tee -a "$REPORT"
  printf '%s\n' "$build_log" | scrub | grep -E 'error:|ValidateEmbedded|Couldn' | tee -a "$REPORT" || true
  say "TEMPLATE build exit=$code"
  products=$(find "$dd/Build/Products" -type d -name 'Debug-iphonesimulator' 2>/dev/null | head -n 1)
  if [ -z "$products" ]; then
    say "CONCLUSION template=no-products"
    return 0
  fi
  app=$(find "$products" -type d -name '*.app' ! -path '*/PlugIns/*' | head -n 1)
  appex=$(find "$products" -type d -name '*.appex' | awk '!/PlugIns/ { print; exit }')
  embedded=$(find "$products" -path '*/PlugIns/*.appex' -type d | head -n 1)
  host=""
  if [ -n "$app" ] && [ -f "$app/Info.plist" ]; then
    host="$app/Info.plist"
  fi
  say "TEMPLATE app=$(basename "${app:-missing}") embedded=$(basename "${embedded:-missing}")"
  if [ -n "$appex" ]; then
    describe_bundle template-standalone "$appex"
  fi
  if [ -n "$embedded" ]; then
    describe_bundle template-embedded "$embedded"
  fi
  if [ -n "$host" ] && [ -n "$appex" ]; then
    probe template-standalone "$appex" "$host"
  fi
  if [ -n "$host" ] && [ -n "$embedded" ]; then
    probe template-embedded "$embedded" "$host"
  fi
  target=$(json_list "$project" targets)
  target=$(pick_ios_name "$(printf '%s\n' "$target" | grep -E -i 'Extension')")
  if [ -n "$target" ]; then
    settings_for template "$project" "$target"
  fi
  TEMPLATE_HOST="$host"
  TEMPLATE_APPEX="${embedded:-$appex}"
}

compare_plists() {
  if [ -z "$VIGIL_PLIST" ] || [ -z "$TEMPLATE_PLIST" ]; then
    say "PLIST-KEYS vigil=${VIGIL_PLIST:-missing} template=${TEMPLATE_PLIST:-missing}"
    return 0
  fi
  python3 - "$VIGIL_PLIST" "$TEMPLATE_PLIST" <<'PY' | tee -a "$REPORT"
import json, subprocess, sys

def load(path):
    out = subprocess.check_output(["plutil", "-convert", "json", "-o", "-", path])
    return json.loads(out)

def leaves(value, prefix=""):
    found = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            found.update(leaves(child, path))
    else:
        found[prefix] = value
    return found

vigil = leaves(load(sys.argv[1]))
template = leaves(load(sys.argv[2]))
only_vigil = sorted(set(vigil) - set(template))
only_template = sorted(set(template) - set(vigil))
differ = sorted(key for key in set(vigil) & set(template) if vigil[key] != template[key])
print("PLIST-KEYS only-vigil " + (", ".join(only_vigil) if only_vigil else "(none)"))
print("PLIST-KEYS only-template " + (", ".join(only_template) if only_template else "(none)"))
print("PLIST-KEYS differ " + (", ".join(differ) if differ else "(none)"))
PY
}

say "XCODE $(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
say "XCODE select $(xcode-select -p 2>/dev/null)"
sw_vers 2>/dev/null | tee -a "$REPORT"
find_tool
say "TOOL ${TOOL:-missing}"
if [ -n "$TOOL" ]; then
  say "---- TOOL help"
  "$TOOL" -help >"$REPORT.tool" 2>&1 || true
  "$TOOL" >>"$REPORT.tool" 2>&1 || true
  head -n 40 "$REPORT.tool" | tee -a "$REPORT"
  say "---- TOOL strings"
  strings -a "$TOOL" | grep -E -i 'shallow|dictionary|info-plist|Info\.plist|usage|Couldn' | head -n 40 | tee -a "$REPORT" || true
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/vigil-embed.XXXXXX")

settings_for vigil "$ROOT/apps/safari/Vigil.xcodeproj" "Vigil iOS Extension"
settings_for vigil-app "$ROOT/apps/safari/Vigil.xcodeproj" "Vigil iOS"

probe_tree() {
  local label="$1"
  local dd="$2"
  local products appex embedded app host
  products=$(product_root "$dd")
  say "PROBE tree $label products=${products:-missing}"
  if [ -z "$products" ]; then
    return 0
  fi
  appex=$(find "$products" -type d -name 'VigilIOSExtension.appex' | awk '!/PlugIns/ { print; exit }')
  embedded=$(find "$products" -path '*/PlugIns/VigilIOSExtension.appex' -type d | head -n 1)
  app=$(find "$products" -type d -name 'VigilIOS.app' | head -n 1)
  host=""
  if [ -n "$app" ] && [ -f "$app/Info.plist" ]; then
    host="$app/Info.plist"
    describe_bundle "$label-host" "$app"
  fi
  if [ -n "$appex" ]; then
    describe_bundle "$label-standalone" "$appex"
  fi
  if [ -n "$embedded" ]; then
    describe_bundle "$label-embedded" "$embedded"
  fi
  if [ -n "$host" ] && [ -n "$appex" ]; then
    probe "$label-standalone" "$appex" "$host"
  fi
  if [ -n "$host" ] && [ -n "$embedded" ]; then
    probe "$label-embedded" "$embedded" "$host"
  fi
  VIGIL_HOST="$host"
  VIGIL_STANDALONE="$appex"
  VIGIL_EMBEDDED="$embedded"
}

VIGIL_HOST=""
VIGIL_STANDALONE=""
VIGIL_EMBEDDED=""
TEMPLATE_HOST=""
TEMPLATE_APPEX=""

probe_tree unsigned "$UNSIGNED_DD"
UNSIGNED_HOST="$VIGIL_HOST"
UNSIGNED_STANDALONE="$VIGIL_STANDALONE"
UNSIGNED_EMBEDDED="$VIGIL_EMBEDDED"

VIGIL_HOST=""
VIGIL_STANDALONE=""
VIGIL_EMBEDDED=""
probe_tree signed "$SIGNED_DD"

SOURCE=""
HOST=""
if [ -n "$VIGIL_EMBEDDED" ] && [ -n "$VIGIL_HOST" ]; then
  SOURCE="$VIGIL_EMBEDDED"
  HOST="$VIGIL_HOST"
elif [ -n "$UNSIGNED_EMBEDDED" ] && [ -n "$UNSIGNED_HOST" ]; then
  SOURCE="$UNSIGNED_EMBEDDED"
  HOST="$UNSIGNED_HOST"
elif [ -n "$UNSIGNED_STANDALONE" ] && [ -n "$UNSIGNED_HOST" ]; then
  SOURCE="$UNSIGNED_STANDALONE"
  HOST="$UNSIGNED_HOST"
fi

if [ -n "$SOURCE" ] && [ -n "$HOST" ]; then
  mutate_and_probe vigil-contents-nosign "$SOURCE" "$HOST" contents-plist-nosign
  mutate_and_probe vigil-rename-resources "$SOURCE" "$HOST" rename-resources
  mutate_and_probe vigil-drop-resources "$SOURCE" "$HOST" drop-resources
  mutate_and_probe vigil-resign "$SOURCE" "$HOST" resign
  mutate_and_probe vigil-xml-resign "$SOURCE" "$HOST" xml-resign
  mutate_and_probe vigil-strip-signature "$SOURCE" "$HOST" strip-signature
  mutate_and_probe vigil-contents-plist "$SOURCE" "$HOST" contents-plist
  mutate_and_probe vigil-development-region "$SOURCE" "$HOST" development-region
  mutate_and_probe vigil-pkginfo "$SOURCE" "$HOST" pkginfo
else
  say "PROBE mutations exit=no-vigil-product"
fi

build_template
compare_plists

if [ -n "${TEMPLATE_HOST:-}" ] && [ -n "$SOURCE" ]; then
  probe vigil-appex-template-host "$SOURCE" "$TEMPLATE_HOST"
fi
if [ -n "$HOST" ] && [ -n "${TEMPLATE_APPEX:-}" ]; then
  probe template-appex-vigil-host "$TEMPLATE_APPEX" "$HOST"
fi

if [ -n "$PASSED" ]; then
  say "CONCLUSION passed:$PASSED"
else
  say "CONCLUSION passed: none"
fi
say "CONCLUSION source=${SOURCE:-missing}"
exit 0
