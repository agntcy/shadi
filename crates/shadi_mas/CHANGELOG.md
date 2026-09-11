# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.2.0...agntcy-shadi-mas-v0.3.0) - 2026-09-11

### Added

- *(mas)* add ASSEMBLY and CONVERGE group protocol ([#240](https://github.com/agntcy/shadi/pull/240))

### Changed

- Crate README now matches the tree and points at
  [SHADI MAS](../../docs/content/shadi-mas.md). Dropped example binaries
  and adapter names that are not in this crate. Distinguished
  `shadi_mas` from `slim_mas`.

### Added

- `PreferenceEngine` applies the synchronous Jacobi preference step on
  epoch-tagged `ScalarProposal` values and rejects stale or replayed
  announcements. This is not a median vote.
- ASSEMBLY (`AssemblySession`) and CONVERGE (`ConvergeController`,
  `CascadeEngine`, `ResourceEngine`). See
  [ASSEMBLY and CONVERGE](../../docs/content/assembly-converge.md).
  ASSEMBLY may name classes beyond the implemented examples; `Unmapped`
  does not run a solver. Paper CONVERGE engines apply the class update
  after a full epoch and halt on STOP, plateau, or the class horizon.
  `DevelopmentEngine` is CONVERGE for a code artifact.

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.1.5...agntcy-shadi-mas-v0.2.0) - 2026-09-09

### Added

- *(a2a)* add pluggable unicast bindings beside SLIM ([#233](https://github.com/agntcy/shadi/pull/233))
- *(agentbridge)* prove agent DID and ship native handoff ([#215](https://github.com/agntcy/shadi/pull/215))

## [0.1.5](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.1.4...agntcy-shadi-mas-v0.1.5) - 2026-09-03

### Other

- updated the following local packages: agntcy-shadi-agent-transport-slim, agntcy-shadi-a2a

## [0.1.4](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.1.3...agntcy-shadi-mas-v0.1.4) - 2026-08-26

### Added

- *(slim)* move to SLIM 2.3 ([#175](https://github.com/agntcy/shadi/pull/175))

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.1.2...agntcy-shadi-mas-v0.1.3) - 2026-08-20

### Other

- updated the following local packages: agntcy-shadi-agent-secrets, agntcy-shadi-identity, agntcy-shadi-agent-transport-slim, agntcy-shadi-a2a

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-mas-v0.1.1...agntcy-shadi-mas-v0.1.2) - 2026-08-14

### Other

- updated the following local packages: agntcy-shadi-identity, agntcy-shadi-agent-transport-slim

## [0.1.1](https://github.com/agntcy/shadi/releases/tag/agntcy-shadi-mas-v0.1.1) - 2026-07-11

### Added

- *(agentbridge)* CLI coding-agent interconnect with MAS coordination over SLIM A2A ([#89](https://github.com/agntcy/shadi/pull/89))
