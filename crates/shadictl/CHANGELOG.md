# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.3...agntcy-shadi-cli-v0.1.4) - 2026-08-14

### Added

- *(identity)* root human and agent DIDs in an SSH Ed25519 key ([#142](https://github.com/agntcy/shadi/pull/142))

### Fixed

- *(policy)* keep accepted control-socket connections blocking ([#149](https://github.com/agntcy/shadi/pull/149))

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.2...agntcy-shadi-cli-v0.1.3) - 2026-07-28

### Other

- updated the following local packages: agntcy-agentbridge

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.1...agntcy-shadi-cli-v0.1.2) - 2026-07-11

### Added

- *(agentbridge)* CLI coding-agent interconnect with MAS coordination over SLIM A2A ([#89](https://github.com/agntcy/shadi/pull/89))

### Added

- add WinGet distribution support for Windows installs of `shadictl`

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.0...agntcy-shadi-cli-v0.1.1) - 2026-04-20

### Other

- adopt official A2A SDK and enable release-plz publish ([#67](https://github.com/agntcy/shadi/pull/67))

### Changed

- switch `shadictl` A2A commands to the official `a2aproject/a2a-rs` SDK through `shadi_a2a`

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-shadi-cli-v0.1.0) - 2026-04-07

### Added

- *(demo)* add Rust demo bot and pitch README ([#58](https://github.com/agntcy/shadi/pull/58))
- *(slim)* add native shell support and stdio bridge ([#57](https://github.com/agntcy/shadi/pull/57))
- *(dir)* agent directory integration via dirctl (closes #53) ([#54](https://github.com/agntcy/shadi/pull/54))
- *(presets)* make all policy presets cross-platform (macOS, Linux, Windows) ([#52](https://github.com/agntcy/shadi/pull/52))
- *(shell)* named sessions with --name flag ([#50](https://github.com/agntcy/shadi/pull/50))
- add CLI policy presets for safe autonomous usage ([#48](https://github.com/agntcy/shadi/pull/48))
- *(shadictl)* improve interactive shell UX ([#47](https://github.com/agntcy/shadi/pull/47))
- *(shadictl)* add interactive shell with REPL (issue #39) ([#44](https://github.com/agntcy/shadi/pull/44))
- *(windows)* harden trusted-secret and ACL path controls (issue #35) ([#41](https://github.com/agntcy/shadi/pull/41))
- *(sandbox)* macOS sandbox hardening ([#40](https://github.com/agntcy/shadi/pull/40))
- *(sandbox)* implement Linux sandbox using Landlock LSM ([#37](https://github.com/agntcy/shadi/pull/37))
- *(sandbox)* add dynamic policy update via control socket ([#32](https://github.com/agntcy/shadi/pull/32))
- *(shadictl)* add config/policy introspection commands ([#17](https://github.com/agntcy/shadi/pull/17))
- add core telemetry and trace tooling ([#14](https://github.com/agntcy/shadi/pull/14))
- *(shadictl)* add git snapshot artifacts ([#10](https://github.com/agntcy/shadi/pull/10))
- *(agent_secrets)* add 1Password as optional secret store backend ([#5](https://github.com/agntcy/shadi/pull/5))
- Add SHADI implementation ([#2](https://github.com/agntcy/shadi/pull/2))

### Other

- *(release)* adopt release-plz publishing ([#61](https://github.com/agntcy/shadi/pull/61))
- Implement trusted secret delivery hardening ([#30](https://github.com/agntcy/shadi/pull/30))
- *(windows)* split sandbox setup into testable units ([#25](https://github.com/agntcy/shadi/pull/25))
- *(shadictl)* consolidate subcommands and modularize CLI ([#15](https://github.com/agntcy/shadi/pull/15))
