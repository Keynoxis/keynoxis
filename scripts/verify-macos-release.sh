#!/usr/bin/env bash

set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
app_bundle=${1:-"$project_root/src-tauri/target/release/bundle/macos/Keynoxis.app"}
dmg_bundle=${2:-}
expected_macos=${KEYNOXIS_MINIMUM_MACOS:-26.0}
require_distribution=${KEYNOXIS_REQUIRE_DISTRIBUTION_SIGNATURE:-0}

fail() {
  echo "release verification failed: $*" >&2
  exit 1
}

test -d "$app_bundle" || fail "app bundle not found: $app_bundle"

plutil -lint "$app_bundle/Contents/Info.plist" >/dev/null
bundle_macos=$(plutil -extract LSMinimumSystemVersion raw "$app_bundle/Contents/Info.plist")
test "$bundle_macos" = "$expected_macos" || fail "Info.plist requires macOS $bundle_macos, expected $expected_macos"

codesign --verify --deep --strict --verbose=4 "$app_bundle"

main_executable="$app_bundle/Contents/MacOS/keynoxis"
binaries=("$main_executable")
while IFS= read -r binary_file; do
  binaries+=("$binary_file")
done < <(find "$app_bundle/Contents/Frameworks" -type f -name '*.dylib' -print | sort)

if test "$require_distribution" = "1"; then
  app_signature_details=$(codesign -dvvv "$app_bundle" 2>&1)
  grep -q '^Authority=Developer ID Application:' <<<"$app_signature_details" || fail "app bundle is not signed with Developer ID Application"
  grep -q 'flags=.*runtime' <<<"$app_signature_details" || fail "app bundle does not enable hardened runtime"
  grep -q '^Timestamp=' <<<"$app_signature_details" || fail "app bundle has no secure timestamp"
  grep -Eq '^TeamIdentifier=.+$' <<<"$app_signature_details" || fail "app bundle has no Team ID"
  grep -q '^TeamIdentifier=not set$' <<<"$app_signature_details" && fail "app bundle has no Team ID"
fi

for binary_file in "${binaries[@]}"; do
  test -f "$binary_file" || fail "signed binary not found: $binary_file"
  codesign --verify --strict --verbose=2 "$binary_file"

  binary_macos=$(otool -l "$binary_file" | awk '
    /cmd LC_BUILD_VERSION/ { in_build_version = 1; next }
    in_build_version && $1 == "minos" { print $2; exit }
  ')
  test "$binary_macos" = "$expected_macos" || fail "$(basename "$binary_file") requires macOS $binary_macos, expected $expected_macos"

  if test "$require_distribution" = "1"; then
    signature_details=$(codesign -dvvv "$binary_file" 2>&1)
    grep -q '^Authority=Developer ID Application:' <<<"$signature_details" || fail "$(basename "$binary_file") is not signed with Developer ID Application"
    if test "$binary_file" = "$main_executable"; then
      grep -q 'flags=.*runtime' <<<"$signature_details" || fail "$(basename "$binary_file") does not enable hardened runtime"
    fi
    grep -q '^Timestamp=' <<<"$signature_details" || fail "$(basename "$binary_file") has no secure timestamp"
    grep -Eq '^TeamIdentifier=.+$' <<<"$signature_details" || fail "$(basename "$binary_file") has no Team ID"
    grep -q '^TeamIdentifier=not set$' <<<"$signature_details" && fail "$(basename "$binary_file") has no Team ID"
  fi
done

entitlements=$(codesign -d --entitlements :- "$app_bundle" 2>/dev/null || true)
grep -q 'com.apple.security.get-task-allow' <<<"$entitlements" && fail "shipping entitlements contain get-task-allow"

if test "$require_distribution" = "1"; then
  xcrun stapler validate "$app_bundle"
  spctl --assess --type execute --verbose=4 "$app_bundle"
  if command -v syspolicy_check >/dev/null 2>&1; then
    syspolicy_check distribution "$app_bundle"
  fi
fi

if test -n "$dmg_bundle"; then
  test -f "$dmg_bundle" || fail "DMG not found: $dmg_bundle"
  hdiutil verify "$dmg_bundle"
  if test "$require_distribution" = "1"; then
    xcrun stapler validate "$dmg_bundle"
  fi
fi

echo "release verification passed for $app_bundle"
