# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.4.0...agntcy-agentbridge-v0.4.1) - 2026-10-09

### Added

- *(desktop)* add the Agent Directory panel ([#453](https://github.com/agntcy/shadi/pull/453))

## [0.4.0](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.3.0...agntcy-agentbridge-v0.4.0) - 2026-10-09

### Added

- *(desktop)* own the rooms you moderate, and approve who joins ([#428](https://github.com/agntcy/shadi/pull/428))
- *(agentbridge)* let agents ask a channel's owner over A2A ([#426](https://github.com/agntcy/shadi/pull/426))
- *(agentbridge)* decide channel requests by the owner's standing rules ([#425](https://github.com/agntcy/shadi/pull/425))
- *(mas)* [**breaking**] agents derive the update rule in ASSEMBLY and apply it themselves in CONVERGE ([#412](https://github.com/agntcy/shadi/pull/412))

## [0.3.0](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.2.1...agntcy-agentbridge-v0.3.0) - 2026-09-30

### Fixed

- *(agentbridge)* stop exec'ing generated scripts in the session tests ([#324](https://github.com/agntcy/shadi/pull/324))
- *(agentbridge)* key harness sessions by A2A contextId ([#306](https://github.com/agntcy/shadi/pull/306))
- *(agentbridge)* serialize every env-mutating test on one lock ([#311](https://github.com/agntcy/shadi/pull/311))
- *(agentbridge)* terminate every child on shutdown, not just the newest ([#281](https://github.com/agntcy/shadi/pull/281))
- *(agentbridge)* stop claude --add-dir from swallowing the prompt ([#275](https://github.com/agntcy/shadi/pull/275))

### Other

- *(agentbridge)* fuzz the stdio response and member spec parsers ([#307](https://github.com/agntcy/shadi/pull/307))

## [0.2.1](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.2.0...agntcy-agentbridge-v0.2.1) - 2026-09-15

### Added

- *(mas)* add ASSEMBLY and CONVERGE group protocol ([#240](https://github.com/agntcy/shadi/pull/240))

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.5...agntcy-agentbridge-v0.2.0) - 2026-09-09

### Added

- *(a2a)* add pluggable unicast bindings beside SLIM ([#233](https://github.com/agntcy/shadi/pull/233))
- *(agentbridge)* add Goose and OpenCode profile adapters ([#232](https://github.com/agntcy/shadi/pull/232))
- *(agentbridge)* add harness skill and JSON register profiles ([#226](https://github.com/agntcy/shadi/pull/226))
- *(agentbridge)* implement list --local via register leases ([#221](https://github.com/agntcy/shadi/pull/221))
- *(agentbridge)* prove agent DID and ship native handoff ([#215](https://github.com/agntcy/shadi/pull/215))

### Other

- *(demos)* introduce the sample run without the dated header ([#229](https://github.com/agntcy/shadi/pull/229))

## [0.1.5](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.4...agntcy-agentbridge-v0.1.5) - 2026-09-03

### Fixed

- *(agentbridge)* Ctrl-C hang and orphaned child process on listener shutdown ([#189](https://github.com/agntcy/shadi/pull/189))

## [0.1.4](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.3...agntcy-agentbridge-v0.1.4) - 2026-08-26

### Other

- updated the following local packages: agntcy-shadi-mas

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.2...agntcy-agentbridge-v0.1.3) - 2026-08-20

### Other

- updated the following local packages: agntcy-shadi-mas

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.1...agntcy-agentbridge-v0.1.2) - 2026-08-14

### Other

- updated the following local packages: agntcy-shadi-mas

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-v0.1.0...agntcy-agentbridge-v0.1.1) - 2026-07-28

### Added

- *(release)* distribute agentbridge like shadictl ([#110](https://github.com/agntcy/shadi/pull/110))

### Other

- update agentbridge READMEs for general-purpose framing ([#108](https://github.com/agntcy/shadi/pull/108))

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-agentbridge-v0.1.0) - 2026-07-11

### Added

- *(agentbridge)* CLI coding-agent interconnect with MAS coordination over SLIM A2A ([#89](https://github.com/agntcy/shadi/pull/89))
