# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-shadi-a2a-v0.1.2...agntcy-shadi-a2a-v0.1.3) - 2026-08-20

### Other

- updated the following local packages: agntcy-shadi-agent-secrets

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-a2a-v0.1.1...agntcy-shadi-a2a-v0.1.2) - 2026-07-27

### Added

- *(slim)* DID agent-group demo + A2A Collaborate group messaging ([#96](https://github.com/agntcy/shadi/pull/96))
- *(identity)* DID identity & admission building blocks for SLIM v2 ([#94](https://github.com/agntcy/shadi/pull/94))
- *(slim)* [**breaking**] migrate SHADI onto SLIM v2 ([#91](https://github.com/agntcy/shadi/pull/91))

### Fixed

- *(slim)* adopt #1869 MLS fix; drop require_header_mac workaround ([#93](https://github.com/agntcy/shadi/pull/93))

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-a2a-v0.1.0...agntcy-shadi-a2a-v0.1.1) - 2026-04-20

### Other

- adopt official A2A SDK and enable release-plz publish ([#67](https://github.com/agntcy/shadi/pull/67))

### Changed

- migrate the SHADI A2A wrapper to the official `a2aproject/a2a-rs` SDK

## [0.1.0] - 2026-04-07

### Added

- *(a2a)* initial A2A channel support over SLIMRPC ([#55](https://github.com/agntcy/shadi/issues/55))
