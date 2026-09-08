# Changelog - AGNTCY SHADI

All notable changes to this project will be documented in this file.

Per-crate changelogs live alongside each crate; this file collects the
workspace-wide view of each release.

## [Unreleased]

## 2026-09-03

### Added

- *(sandbox)* add cargo-fuzz targets for the control protocol ([#203](https://github.com/agntcy/shadi/pull/203))

### Fixed

- *(agentbridge)* Ctrl-C hang and orphaned child process on listener shutdown ([#189](https://github.com/agntcy/shadi/pull/189))

### Other

- *(deps)* update github actions ([#188](https://github.com/agntcy/shadi/pull/188))
- *(sandbox)* move the control-socket client into shadi_sandbox ([#200](https://github.com/agntcy/shadi/pull/200))
- update Cargo.lock dependencies

## 2026-08-26

### Added

- *(slim)* move to SLIM 2.3 ([#175](https://github.com/agntcy/shadi/pull/175))
- *(telemetry)* move to OpenTelemetry 0.32 ([#173](https://github.com/agntcy/shadi/pull/173))

### Fixed

- *(deps)* update rust crate pyo3 to 0.29 [security] ([#168](https://github.com/agntcy/shadi/pull/168))
- *(deps)* update rust crate rand to 0.9 [security] ([#169](https://github.com/agntcy/shadi/pull/169))
- *(memory)* vendor OpenSSL into SQLCipher on Windows ([#176](https://github.com/agntcy/shadi/pull/176))

## 2026-08-20

### Added

- *(desktop)* frictionless SSH onboarding, no env vars required ([#143](https://github.com/agntcy/shadi/pull/143))

## 2026-08-14

### Added

- *(agentbridge)* require SHADI sandbox enforcement for remote listeners ([#130](https://github.com/agntcy/shadi/pull/130))
- *(identity)* root human and agent DIDs in an SSH Ed25519 key ([#142](https://github.com/agntcy/shadi/pull/142))

### Fixed

- *(policy)* keep accepted control-socket connections blocking ([#149](https://github.com/agntcy/shadi/pull/149))

### Other

- update Cargo.lock dependencies

## 2026-07-28

### Added

- *(release)* distribute agentbridge like shadictl ([#110](https://github.com/agntcy/shadi/pull/110))

### Other

- update agentbridge READMEs for general-purpose framing ([#108](https://github.com/agntcy/shadi/pull/108))

## 2026-07-27

### Added

- *(agentbridge)* require DID auth for coding agents, drop shared secret ([#98](https://github.com/agntcy/shadi/pull/98))
- *(agentbridge,shadictl)* discover SLIM group members via Agent Directory ([#101](https://github.com/agntcy/shadi/pull/101))
- *(identity)* DID identity & admission building blocks for SLIM v2 ([#94](https://github.com/agntcy/shadi/pull/94))
- *(identity)* route remaining create_app sites through DID auth + moderator role UX ([#95](https://github.com/agntcy/shadi/pull/95))
- *(slim)* DID agent-group demo + A2A Collaborate group messaging ([#96](https://github.com/agntcy/shadi/pull/96))
- *(slim)* [**breaking**] migrate SHADI onto SLIM v2 ([#91](https://github.com/agntcy/shadi/pull/91))

### Fixed

- *(slim)* adopt #1869 MLS fix; drop require_header_mac workaround ([#93](https://github.com/agntcy/shadi/pull/93))

## 2026-07-11

### Added

- *(agentbridge)* CLI coding-agent interconnect with MAS coordination over SLIM A2A ([#89](https://github.com/agntcy/shadi/pull/89))
- add WinGet distribution support for Windows installs of `shadictl`

## 2026-04-20

### Changed

- migrate the SHADI A2A wrapper to the official `a2aproject/a2a-rs` SDK
- switch `shadictl` A2A commands to the official `a2aproject/a2a-rs` SDK through `shadi_a2a`

### Other

- adopt official A2A SDK and enable release-plz publish ([#67](https://github.com/agntcy/shadi/pull/67))
- update Cargo.lock dependencies
- update Rust dependency versions ([#79](https://github.com/agntcy/shadi/pull/79))

## 2026-04-08

### Added

- *(a2a)* add SHADI A2A support over SLIMRPC ([#64](https://github.com/agntcy/shadi/pull/64))

## 2026-04-07

### Added

- *(a2a)* initial A2A channel support over SLIMRPC ([#55](https://github.com/agntcy/shadi/issues/55))
- *(agent_secrets)* add 1Password as optional secret store backend ([#5](https://github.com/agntcy/shadi/pull/5))
- *(demo)* add Rust demo bot and pitch README ([#58](https://github.com/agntcy/shadi/pull/58))
- *(dir)* agent directory integration via dirctl (closes #53) ([#54](https://github.com/agntcy/shadi/pull/54))
- *(presets)* make all policy presets cross-platform (macOS, Linux, Windows) ([#52](https://github.com/agntcy/shadi/pull/52))
- *(sandbox)* add dynamic policy update via control socket ([#32](https://github.com/agntcy/shadi/pull/32))
- *(sandbox)* implement Linux sandbox using Landlock LSM ([#37](https://github.com/agntcy/shadi/pull/37))
- *(sandbox)* macOS sandbox hardening ([#40](https://github.com/agntcy/shadi/pull/40))
- *(shadictl)* add config/policy introspection commands ([#17](https://github.com/agntcy/shadi/pull/17))
- *(shadictl)* add git snapshot artifacts ([#10](https://github.com/agntcy/shadi/pull/10))
- *(shadictl)* add interactive shell with REPL (issue #39) ([#44](https://github.com/agntcy/shadi/pull/44))
- *(shadictl)* improve interactive shell UX ([#47](https://github.com/agntcy/shadi/pull/47))
- *(shell)* named sessions with --name flag ([#50](https://github.com/agntcy/shadi/pull/50))
- *(slim)* add native shell support and stdio bridge ([#57](https://github.com/agntcy/shadi/pull/57))
- *(windows)* harden trusted-secret and ACL path controls (issue #35) ([#41](https://github.com/agntcy/shadi/pull/41))
- *(windows)* persist ACL rollback journals for crash recovery ([#42](https://github.com/agntcy/shadi/pull/42))
- Add SHADI implementation ([#2](https://github.com/agntcy/shadi/pull/2))
- add CLI policy presets for safe autonomous usage ([#48](https://github.com/agntcy/shadi/pull/48))
- add core telemetry and trace tooling ([#14](https://github.com/agntcy/shadi/pull/14))

### Fixed

- *(windows)* harden ACL rollback journal tamper resistance ([#43](https://github.com/agntcy/shadi/pull/43))

### Other

- *(release)* adopt release-plz publishing ([#61](https://github.com/agntcy/shadi/pull/61))
- *(shadictl)* consolidate subcommands and modularize CLI ([#15](https://github.com/agntcy/shadi/pull/15))
- *(windows)* split sandbox setup into testable units ([#25](https://github.com/agntcy/shadi/pull/25))
- Implement trusted secret delivery hardening ([#30](https://github.com/agntcy/shadi/pull/30))
