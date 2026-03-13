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
cargo llvm-cov --workspace --features coverage "${format_args[@]}" --ignore-filename-regex "/rustc-[^/]+/"

if [[ "$mode" == "lcov" ]]; then
  if command -v lcov >/dev/null 2>&1; then
    lcov --summary coverage/lcov.info
  else
    echo "lcov not found; skipping coverage summary"
  fi
fi
