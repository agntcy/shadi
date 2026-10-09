# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.8...agntcy-agentbridge-cli-v0.2.0) - 2026-10-09

### Added

- *(agentbridge)* let agents ask a channel's owner over A2A ([#426](https://github.com/agntcy/shadi/pull/426))
- *(slim)* [**breaking**] move to SLIM 3.0.1 and the 0.4 A2A SDK ([#423](https://github.com/agntcy/shadi/pull/423))
- *(mas)* [**breaking**] agents derive the update rule in ASSEMBLY and apply it themselves in CONVERGE ([#412](https://github.com/agntcy/shadi/pull/412))
- *(slim)* connect to a remote node with a bearer token ([#418](https://github.com/agntcy/shadi/pull/418))
- *(a2a)* capture A2A prompts and replies in traces only on opt-in ([#411](https://github.com/agntcy/shadi/pull/411))
- *(a2a)* carry W3C trace context in A2A message metadata ([#406](https://github.com/agntcy/shadi/pull/406))
- *(agentbridge)* trace each A2A request, with its decisions as span events ([#404](https://github.com/agntcy/shadi/pull/404))
- *(agentbridge)* pass every outbound A2A message through one egress check ([#402](https://github.com/agntcy/shadi/pull/402))
- *(agentbridge)* export OpenTelemetry traces from every command ([#403](https://github.com/agntcy/shadi/pull/403))

### Fixed

- *(agentbridge)* key a listener's admission decisions on a local id ([#422](https://github.com/agntcy/shadi/pull/422))
- *(mas)* return rejected and failed A2A replies as errors ([#394](https://github.com/agntcy/shadi/pull/394))
- *(sandbox)* check the kernel, not env vars, before calling a sandbox enforced ([#392](https://github.com/agntcy/shadi/pull/392))
- *(sandbox)* enforce --net-allow per port in the kernel ([#391](https://github.com/agntcy/shadi/pull/391))

## [0.1.8](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.7...agntcy-agentbridge-cli-v0.1.8) - 2026-09-30

### Added

- *(agentbridge)* add --session and --report to coordinate ([#330](https://github.com/agntcy/shadi/pull/330))
- *(agentbridge)* verify the human binding at admission ([#327](https://github.com/agntcy/shadi/pull/327))
- *(agentbridge)* serve the agent card at the well-known path ([#287](https://github.com/agntcy/shadi/pull/287))

### Fixed

- *(deps)* pin agntcy-slim-persistence and unblock releases ([#339](https://github.com/agntcy/shadi/pull/339))
- *(agentbridge)* key harness sessions by A2A contextId ([#306](https://github.com/agntcy/shadi/pull/306))
- *(agentbridge)* park and reject as real tasks the client can fetch ([#293](https://github.com/agntcy/shadi/pull/293))

### Other

- *(agentbridge)* serialise the TLS tests against each other ([#288](https://github.com/agntcy/shadi/pull/288))

## [0.1.7](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.6...agntcy-agentbridge-cli-v0.1.7) - 2026-09-15

### Added

- *(mas)* add ASSEMBLY and CONVERGE group protocol ([#240](https://github.com/agntcy/shadi/pull/240))
- *(agentbridge)* add --verbose to register for full A2A request/response text ([#239](https://github.com/agntcy/shadi/pull/239))

### Fixed

- *(deps)* drop rustls-pemfile ([#236](https://github.com/agntcy/shadi/pull/236))

## [0.1.6](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.5...agntcy-agentbridge-cli-v0.1.6) - 2026-09-09

### Added

- *(a2a)* add pluggable unicast bindings beside SLIM ([#233](https://github.com/agntcy/shadi/pull/233))
- *(agentbridge)* add Goose and OpenCode profile adapters ([#232](https://github.com/agntcy/shadi/pull/232))
- *(agentbridge)* add harness skill and JSON register profiles ([#226](https://github.com/agntcy/shadi/pull/226))
- *(agentbridge)* implement list --local via register leases ([#221](https://github.com/agntcy/shadi/pull/221))
- *(agentbridge)* prove agent DID and ship native handoff ([#215](https://github.com/agntcy/shadi/pull/215))

## [0.1.5](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.4...agntcy-agentbridge-cli-v0.1.5) - 2026-09-03

### Fixed

- *(agentbridge)* Ctrl-C hang and orphaned child process on listener shutdown ([#189](https://github.com/agntcy/shadi/pull/189))

## [0.1.4](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.3...agntcy-agentbridge-cli-v0.1.4) - 2026-08-26

### Added

- *(slim)* move to SLIM 2.3 ([#175](https://github.com/agntcy/shadi/pull/175))

## [0.1.3](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.2...agntcy-agentbridge-cli-v0.1.3) - 2026-08-20

### Other

- updated the following local packages: agntcy-shadi-agent-secrets, agntcy-shadi-identity, agntcy-shadi-a2a, agntcy-shadi-mas, agntcy-agentbridge

## [0.1.2](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.1...agntcy-agentbridge-cli-v0.1.2) - 2026-08-14

### Added

- *(agentbridge)* require SHADI sandbox enforcement for remote listeners ([#130](https://github.com/agntcy/shadi/pull/130))

## [0.1.1](https://github.com/agntcy/shadi/compare/agntcy-agentbridge-cli-v0.1.0...agntcy-agentbridge-cli-v0.1.1) - 2026-07-28

### Added

- *(release)* distribute agentbridge like shadictl ([#110](https://github.com/agntcy/shadi/pull/110))

### Other

- update agentbridge READMEs for general-purpose framing ([#108](https://github.com/agntcy/shadi/pull/108))

## [0.1.0](https://github.com/agntcy/shadi/releases/tag/agntcy-agentbridge-cli-v0.1.0) - 2026-07-11

### Added

- *(agentbridge)* CLI coding-agent interconnect with MAS coordination over SLIM A2A ([#89](https://github.com/agntcy/shadi/pull/89))
