# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-agent-transport-slim-v0.2.1...agntcy-shadi-agent-transport-slim-v0.2.2) - 2026-08-20

### Other

- updated the following local packages: agntcy-shadi-agent-secrets, agntcy-shadi-identity

## [0.2.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-agent-transport-slim-v0.2.0...agntcy-shadi-agent-transport-slim-v0.2.1) - 2026-08-14

### Other

- update Cargo.lock dependencies

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-agent-transport-slim-v0.1.2...agntcy-shadi-agent-transport-slim-v0.2.0) - 2026-07-27

### Added

- *(identity)* route remaining create_app sites through DID auth + moderator role UX ([#95](https://github.com/agntcy/shadi/pull/95))
- *(identity)* DID identity & admission building blocks for SLIM v2 ([#94](https://github.com/agntcy/shadi/pull/94))
- *(slim)* [**breaking**] migrate SHADI onto SLIM v2 ([#91](https://github.com/agntcy/shadi/pull/91))

### Fixed

- *(slim)* adopt #1869 MLS fix; drop require_header_mac workaround ([#93](https://github.com/agntcy/shadi/pull/93))

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-agent-transport-slim-v0.1.1...agntcy-shadi-agent-transport-slim-v0.1.2) - 2026-04-20

### Other

- update Cargo.lock dependencies

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-agent-transport-slim-v0.1.0...agntcy-shadi-agent-transport-slim-v0.1.1) - 2026-04-08

### Added

- *(a2a)* add SHADI A2A support over SLIMRPC ([#64](https://github.com/agntcy/shadi/pull/64))

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-shadi-agent-transport-slim-v0.1.0) - 2026-04-07

### Added

- *(slim)* add native shell support and stdio bridge ([#57](https://github.com/agntcy/shadi/pull/57))
- Add SHADI implementation ([#2](https://github.com/agntcy/shadi/pull/2))

### Other

- *(release)* adopt release-plz publishing ([#61](https://github.com/agntcy/shadi/pull/61))
