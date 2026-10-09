# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.2.1...agntcy-shadi-sandbox-v0.3.0) - 2026-10-09

### Added

- *(sandbox)* speak HTTP on the --watch-policy proxy port ([#439](https://github.com/agntcy/shadi/pull/439))

### Fixed

- *(sandbox)* [**breaking**] enforce the port in --watch-policy allow-list entries ([#438](https://github.com/agntcy/shadi/pull/438))
- *(sandbox)* give each Windows sandbox its own AppContainer and revoke only its grants ([#433](https://github.com/agntcy/shadi/pull/433))
- *(sandbox)* check the kernel, not env vars, before calling a sandbox enforced ([#392](https://github.com/agntcy/shadi/pull/392))
- *(sandbox)* enforce --net-allow per port in the kernel ([#391](https://github.com/agntcy/shadi/pull/391))

## [0.2.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.2.0...agntcy-shadi-sandbox-v0.2.1) - 2026-09-30

### Added

- *(sandbox)* bound proxy connections and finish the SOCKS5 fuzzing ([#290](https://github.com/agntcy/shadi/pull/290))

### Fixed

- *(sandbox)* list a denied path once in the policy description ([#314](https://github.com/agntcy/shadi/pull/314))
- *(sandbox)* bind the ACL journal HMAC to its field boundary ([#310](https://github.com/agntcy/shadi/pull/310))
- *(sandbox)* deduplicate resolved policy paths and network destinations ([#302](https://github.com/agntcy/shadi/pull/302)) ([#303](https://github.com/agntcy/shadi/pull/303))
- *(shadi_py)* default sandbox policies to the minimal platform profile ([#299](https://github.com/agntcy/shadi/pull/299))

### Other

- *(agentbridge)* fuzz the stdio response and member spec parsers ([#307](https://github.com/agntcy/shadi/pull/307))
- *(sandbox)* fuzz resolve_session_socket ([#291](https://github.com/agntcy/shadi/pull/291))
- *(sandbox)* hold the port lock in every test that binds one ([#289](https://github.com/agntcy/shadi/pull/289))

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.1.4...agntcy-shadi-sandbox-v0.2.0) - 2026-09-15

### Added

- *(sandbox)* make platform defaults deniable ([#242](https://github.com/agntcy/shadi/pull/242))

### Other

- *(sandbox)* fuzz Seatbelt profile generation ([#252](https://github.com/agntcy/shadi/pull/252))
- *(sandbox)* fuzz policy-patch apply and cap control lines ([#251](https://github.com/agntcy/shadi/pull/251))

## [0.1.4](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.1.3...agntcy-shadi-sandbox-v0.1.4) - 2026-09-09

### Added

- *(a2a)* add pluggable unicast bindings beside SLIM ([#233](https://github.com/agntcy/shadi/pull/233))
- *(agentbridge)* add harness skill and JSON register profiles ([#226](https://github.com/agntcy/shadi/pull/226))
- *(agentbridge)* prove agent DID and ship native handoff ([#215](https://github.com/agntcy/shadi/pull/215))

### Fixed

- *(deps)* update patch and minor ([#223](https://github.com/agntcy/shadi/pull/223))

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-shadi-sandbox-v0.1.2...agntcy-shadi-sandbox-v0.1.3) - 2026-09-03

### Added

- *(sandbox)* add cargo-fuzz targets for the control protocol ([#203](https://github.com/agntcy/shadi/pull/203))

### Other

- *(sandbox)* move the control-socket client into shadi_sandbox ([#200](https://github.com/agntcy/shadi/pull/200))

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
