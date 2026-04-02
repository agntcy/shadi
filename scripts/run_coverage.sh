#!/usr/bin/env bash
set -euo pipefail

mode="${1:-lcov}"
python_bin="${2:-${PYO3_PYTHON:-python3.12}}"
rustflags_value="${3:-${RUSTFLAGS:-}}"

mkdir -p coverage

llvm_sysroot="$(rustc --print sysroot)"
llvm_host="$(rustc -Vv | awk '/host/ {print $2}')"
llvm_brew="$(brew --prefix llvm 2>/dev/null || true)"
llvm_brew_versioned="$(brew --prefix llvm@21 2>/dev/null || true)"

resolve_tool() {
  local tool_name="$1"
  local current_path

  current_path="$(command -v "$tool_name" || true)"
  if [[ -n "$current_path" ]]; then
    echo "$current_path"
    return 0
  fi

  if [[ -x "$llvm_brew/bin/$tool_name" ]]; then
    echo "$llvm_brew/bin/$tool_name"
    return 0
  fi

  if [[ -x "$llvm_brew_versioned/bin/$tool_name" ]]; then
    echo "$llvm_brew_versioned/bin/$tool_name"
    return 0
  fi

  echo "$llvm_sysroot/lib/rustlib/$llvm_host/bin/$tool_name"
}

llvm_cov="$(resolve_tool llvm-cov)"
llvm_profdata="$(resolve_tool llvm-profdata)"

# On macOS, auto-resolve OPENSSL_DIR via Homebrew if not already set.
# On Linux, point to the system prefix where libssl-dev installs.
# (Windows sets it in CI via GITHUB_ENV.)
if [[ -z "${OPENSSL_DIR:-}" ]]; then
  case "$(uname)" in
    Darwin)
      for ossl_keg in "openssl@3" "openssl@1.1" "openssl"; do
        if keg_path="$(brew --prefix "$ossl_keg" 2>/dev/null)"; then
          export OPENSSL_DIR="$keg_path"
          break
        fi
      done
      ;;
    Linux)
      if [[ -d /usr/include/openssl ]]; then
        export OPENSSL_DIR=/usr
      fi
      ;;
  esac
fi

case "$mode" in
  lcov)
    format_args=(--lcov --output-path coverage/lcov.info)
    ;;
  html)
    format_args=(--html --output-dir coverage/html)
    ;;
  *)
    echo "unsupported coverage mode: $mode (expected 'lcov' or 'html')" >&2
    exit 2
    ;;
esac

SHADI_KEYCHAIN_TESTS="${SHADI_KEYCHAIN_TESTS:-1}" \
PYO3_PYTHON="$python_bin" \
RUSTFLAGS="$rustflags_value" \
LLVM_COV="$llvm_cov" \
LLVM_PROFDATA="$llvm_profdata" \
cargo llvm-cov --workspace --tests --features coverage "${format_args[@]}" --no-default-ignore-filename-regex --ignore-filename-regex "/rustc-[^/]+/" -- --test-threads=1

if [[ "$mode" == "lcov" ]]; then
  if command -v lcov >/dev/null 2>&1; then
    lcov --summary coverage/lcov.info
  else
    echo "lcov not found; skipping coverage summary"
  fi
fi
