# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.3.0...agntcy-shadi-identity-v0.4.0) - 2026-10-16

### Added

- *(identity)* [**breaking**] sign channel-manager create and delete requests ([#471](https://github.com/agntcy/shadi/pull/471))
- *(agentbridge)* [**breaking**] let the owner's standing rules decide removals ([#446](https://github.com/agntcy/shadi/pull/446))

### Other

- *(deps)* move to SLIM 3.4.3, the A2A 0.4.2 set and rustls 0.23.46 ([#498](https://github.com/agntcy/shadi/pull/498))
- *(deps)* move to SLIM 3.4.1 and a2a-slimrpc 0.3.3 ([#489](https://github.com/agntcy/shadi/pull/489))
- *(deps)* [**breaking**] move to SLIM 3.2.1, a2a-slimrpc 0.3 and OpenTelemetry 0.33 ([#465](https://github.com/agntcy/shadi/pull/465))
- *(deps)* move to SLIM 3.1 ([#443](https://github.com/agntcy/shadi/pull/443))
- *(identity)* move the did:key document and OpenPGP key helpers into shadi_identity ([#450](https://github.com/agntcy/shadi/pull/450))

## [0.3.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.2.2...agntcy-shadi-identity-v0.3.0) - 2026-10-09

### Added

- *(identity)* sign and verify channel grants ([#424](https://github.com/agntcy/shadi/pull/424))
- *(slim)* [**breaking**] move to SLIM 3.0.1 and the 0.4 A2A SDK ([#423](https://github.com/agntcy/shadi/pull/423))
- *(slim)* connect to a remote node with a bearer token ([#418](https://github.com/agntcy/shadi/pull/418))
- *(shadi-identity)* add trust anchors ([#389](https://github.com/agntcy/shadi/pull/389))

## [0.2.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.2.1...agntcy-shadi-identity-v0.2.2) - 2026-09-30

### Added

- *(agentbridge)* verify the human binding at admission ([#327](https://github.com/agntcy/shadi/pull/327))
- *(identity)* add human-to-agent binding certificates ([#321](https://github.com/agntcy/shadi/pull/321))

### Fixed

- *(deps)* pin agntcy-slim-persistence and unblock releases ([#339](https://github.com/agntcy/shadi/pull/339))

### Other

- *(identity)* pin that DID credentials are minted per call ([#315](https://github.com/agntcy/shadi/pull/315))

## [0.2.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.2.0...agntcy-shadi-identity-v0.2.1) - 2026-09-15

### Other

- *(sandbox)* fuzz Seatbelt profile generation ([#252](https://github.com/agntcy/shadi/pull/252))

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.1.3...agntcy-shadi-identity-v0.2.0) - 2026-09-09

### Added

- *(agentbridge)* prove agent DID and ship native handoff ([#215](https://github.com/agntcy/shadi/pull/215))

### Fixed

- *(deps)* update patch and minor ([#223](https://github.com/agntcy/shadi/pull/223))

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.1.2...agntcy-shadi-identity-v0.1.3) - 2026-08-26

### Added

- *(slim)* move to SLIM 2.3 ([#175](https://github.com/agntcy/shadi/pull/175))

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.1.1...agntcy-shadi-identity-v0.1.2) - 2026-08-20

### Added

- *(desktop)* frictionless SSH onboarding, no env vars required ([#143](https://github.com/agntcy/shadi/pull/143))

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-identity-v0.1.0...agntcy-shadi-identity-v0.1.1) - 2026-08-14

### Added

- *(identity)* root human and agent DIDs in an SSH Ed25519 key ([#142](https://github.com/agntcy/shadi/pull/142))

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-shadi-identity-v0.1.0) - 2026-07-27

### Added

- *(agentbridge)* require DID auth for coding agents, drop shared secret ([#98](https://github.com/agntcy/shadi/pull/98))
- *(identity)* route remaining create_app sites through DID auth + moderator role UX ([#95](https://github.com/agntcy/shadi/pull/95))
- *(identity)* DID identity & admission building blocks for SLIM v2 ([#94](https://github.com/agntcy/shadi/pull/94))
