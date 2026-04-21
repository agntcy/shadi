#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${ROOT}/docs/install.sh"
TARGET="x86_64-unknown-linux-gnu"
DOWNLOADS_ROOT=""
INSTALL_DIR=""
TEST_TMP_DIR=""

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TEST_TMP_DIR" && -d "$TEST_TMP_DIR" ]]; then
    rm -rf "$TEST_TMP_DIR"
  fi
}

make_stub_binary() {
  local path="$1"
  local version="$2"

  cat > "$path" <<EOF
#!/usr/bin/env bash
printf 'shadictl %s\n' '${version}'
EOF
  chmod +x "$path"
}

package_release() {
  local version="$1"
  local checksum_mode="$2"
  local tag="agntcy-shadi-cli-v${version}"
  local release_dir="${DOWNLOADS_ROOT}/${tag}"
  local stub_binary="${TEST_TMP_DIR}/stub-${version}-shadictl"
  local archive_name="shadictl-v${version}-${TARGET}.tar.gz"
  local checksum_name="${archive_name}.sha256"

  mkdir -p "$release_dir"
  make_stub_binary "$stub_binary" "$version"

  python3 "${ROOT}/scripts/package_shadictl_release.py" \
    --binary "$stub_binary" \
    --target "$TARGET" \
    --version "$version" \
    --output-dir "$release_dir" \
    >/dev/null

  if [[ "$checksum_mode" == "bad" ]]; then
    printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' "$archive_name" > "${release_dir}/${checksum_name}"
  fi
}

assert_installed_version() {
  local expected="$1"
  local binary_path="${INSTALL_DIR}/shadictl"

  [[ -x "$binary_path" ]] || fail "expected installed binary at ${binary_path}"

  local output
  output="$($binary_path)"
  [[ "$output" == "shadictl ${expected}" ]] || fail "expected installed version ${expected}, got: ${output}"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || fail "installer validation only runs on Linux"

  bash -n "$INSTALLER"

  TEST_TMP_DIR="$(mktemp -d)"
  trap cleanup EXIT

  DOWNLOADS_ROOT="${TEST_TMP_DIR}/downloads"
  INSTALL_DIR="${TEST_TMP_DIR}/bin"
  mkdir -p "$DOWNLOADS_ROOT" "$INSTALL_DIR"

  package_release "9.9.9" "good"
  package_release "9.9.10" "good"
  package_release "9.9.11" "bad"

  local latest_api_json="${TEST_TMP_DIR}/latest.json"
  cat > "$latest_api_json" <<'EOF'
{"tag_name":"agntcy-shadi-cli-v9.9.9"}
EOF

  env \
    SHADI_INSTALL_DIR="$INSTALL_DIR" \
    SHADI_RELEASE_API_URL="file://${latest_api_json}" \
    SHADI_RELEASE_DOWNLOAD_BASE_URL="file://${DOWNLOADS_ROOT}" \
    bash "$INSTALLER"

  assert_installed_version "9.9.9"

  env \
    SHADI_VERSION="9.9.10" \
    SHADI_INSTALL_DIR="$INSTALL_DIR" \
    SHADI_RELEASE_DOWNLOAD_BASE_URL="file://${DOWNLOADS_ROOT}" \
    bash "$INSTALLER"

  assert_installed_version "9.9.10"

  if env \
    SHADI_VERSION="9.9.11" \
    SHADI_INSTALL_DIR="$INSTALL_DIR" \
    SHADI_RELEASE_DOWNLOAD_BASE_URL="file://${DOWNLOADS_ROOT}" \
    bash "$INSTALLER"; then
    fail "installer succeeded unexpectedly for a corrupted checksum"
  fi

  assert_installed_version "9.9.10"

  printf 'installer validation passed\n'
}

main "$@"