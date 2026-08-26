# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.1.1...agntcy-shadi-sandbox-v0.1.2) - 2026-08-26

### Fixed

- *(deps)* update rust crate rand to 0.9 [security] ([#169](https://github.com/agntcy/shadi/pull/169))

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.1.0...agntcy-shadi-sandbox-v0.1.1) - 2026-08-14

### Added

- *(agentbridge)* require SHADI sandbox enforcement for remote listeners ([#130](https://github.com/agntcy/shadi/pull/130))

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-shadi-sandbox-v0.1.0) - 2026-04-07

### Added

- *(slim)* add native shell support and stdio bridge ([#57](https://github.com/agntcy/shadi/pull/57))
- add CLI policy presets for safe autonomous usage ([#48](https://github.com/agntcy/shadi/pull/48))
- *(shadictl)* improve interactive shell UX ([#47](https://github.com/agntcy/shadi/pull/47))
- *(windows)* persist ACL rollback journals for crash recovery ([#42](https://github.com/agntcy/shadi/pull/42))
- *(windows)* harden trusted-secret and ACL path controls (issue #35) ([#41](https://github.com/agntcy/shadi/pull/41))
- *(sandbox)* macOS sandbox hardening ([#40](https://github.com/agntcy/shadi/pull/40))
- *(sandbox)* implement Linux sandbox using Landlock LSM ([#37](https://github.com/agntcy/shadi/pull/37))
- *(sandbox)* add dynamic policy update via control socket ([#32](https://github.com/agntcy/shadi/pull/32))
- add core telemetry and trace tooling ([#14](https://github.com/agntcy/shadi/pull/14))
- *(agent_secrets)* add 1Password as optional secret store backend ([#5](https://github.com/agntcy/shadi/pull/5))
- Add SHADI implementation ([#2](https://github.com/agntcy/shadi/pull/2))

### Fixed

- *(windows)* harden ACL rollback journal tamper resistance ([#43](https://github.com/agntcy/shadi/pull/43))

### Other

- *(release)* adopt release-plz publishing ([#61](https://github.com/agntcy/shadi/pull/61))
- Implement trusted secret delivery hardening ([#30](https://github.com/agntcy/shadi/pull/30))
- *(windows)* split sandbox setup into testable units ([#25](https://github.com/agntcy/shadi/pull/25))
- *(shadictl)* consolidate subcommands and modularize CLI ([#15](https://github.com/agntcy/shadi/pull/15))
