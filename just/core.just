[group('core')]
[doc('Build the Rust workspace and local Python extension artifacts.')]
build:
  {{ if os() == "windows" {
    "$env:PYO3_PYTHON = \"" + python312 + "\"; cargo build"
  } else if os() == "macos" {
    "PYO3_PYTHON=\"" + python312 + "\" RUSTFLAGS=\"-C link-arg=-undefined -C link-arg=dynamic_lookup\" cargo build && cp target/debug/libshadi.dylib .venv/lib/python3.12/site-packages/shadi/shadi.cpython-312-darwin.so && codesign --sign - --force .venv/lib/python3.12/site-packages/shadi/shadi.cpython-312-darwin.so"
  } else {
    "PYO3_PYTHON=\"" + python312 + "\" cargo build"
  } }}

[group('core')]
[doc('Compatibility alias for Windows users; runs the shared build recipe.')]
windows-build: build

[group('core')]
[doc('Compatibility alias for Windows users; runs the shared test recipe.')]
windows-test: test

[group('core')]
[doc('Run the Rust workspace test suite with the correct Python toolchain.')]
test:
  {{ if os() == "windows" {
    "$env:PYO3_PYTHON = \"" + python312 + "\"; cargo test --workspace"
  } else if python_rustflags != "" {
    "PYO3_PYTHON=\"" + python312 + "\" RUSTFLAGS=\"" + python_rustflags + "\" cargo test --workspace"
  } else {
    "PYO3_PYTHON=\"" + python312 + "\" cargo test --workspace"
  } }}

[group('core')]
[doc('Run Clippy across all targets and features.')]
lint:
  {{ if os() == "windows" {
    "$env:PYO3_PYTHON = \"" + python312 + "\"; cargo clippy --all-targets --all-features"
  } else if os() == "macos" {
    "PYO3_PYTHON=\"" + python312 + "\" RUSTFLAGS=\"-C link-arg=-undefined -C link-arg=dynamic_lookup\" cargo clippy --all-targets --all-features"
  } else {
    "PYO3_PYTHON=\"" + python312 + "\" cargo clippy --all-targets --all-features"
  } }}

[group('core')]
[doc('Remove Cargo build artifacts.')]
clean:
  cargo clean

[group('core')]
[doc('Generate LCOV coverage output for the workspace.')]
coverage:
  {{ if os() == "windows" {
    ".\\scripts\\run_coverage.ps1 -Mode lcov -PythonBin \"" + python312 + "\" -RustflagsValue \"" + python_rustflags + "\""
  } else {
    "SHADI_KEYCHAIN_TESTS=1 scripts/run_coverage.sh lcov \"" + python312 + "\" \"" + python_rustflags + "\""
  } }}

[group('core')]
[doc('Generate HTML coverage output for the workspace.')]
coverage-html:
  {{ if os() == "windows" {
    ".\\scripts\\run_coverage.ps1 -Mode html -PythonBin \"" + python312 + "\" -RustflagsValue \"" + python_rustflags + "\""
  } else {
    "SHADI_KEYCHAIN_TESTS=1 scripts/run_coverage.sh html \"" + python312 + "\" \"" + python_rustflags + "\""
  } }}

[group('core')]
[doc('Run the Windows integration-oriented Cargo tests.')]
windows-integration:
  $env:PYO3_PYTHON = "{{python312}}"; $env:SHADI_WINDOWS_INTEGRATION = "1"; cargo test --workspace

[group('docs')]
[doc('Build the MkDocs site locally.')]
docs-build:
  mkdocs build

[group('docs')]
[doc('Serve the MkDocs site locally.')]
docs-serve:
  mkdocs serve

[group('profiles')]
[doc('Print the strict built-in security profile.')]
secure-profile-strict:
  cargo run -p shadictl -- --profile strict --print-policy

[group('profiles')]
[doc('Print the balanced built-in security profile.')]
secure-profile-balanced:
  cargo run -p shadictl -- --profile balanced --print-policy

[group('profiles')]
[doc('Print the connected built-in security profile.')]
secure-profile-connected:
  cargo run -p shadictl -- --profile connected --print-policy