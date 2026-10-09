# Changelog - AGNTCY SHADI

All notable changes to this project will be documented in this file.

Per-crate changelogs live alongside each crate; this file collects the
workspace-wide view of each release.

## [Unreleased]

## [0.2.1](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.2.0...agntcy-shadi-cli-v0.2.1) - 2026-10-09

### Added

- *(desktop)* add the Agent Directory panel ([#453](https://github.com/agntcy/shadi/pull/453))

### Fixed

- *(shadictl)* let derive-agent-identity skip the secret store ([#445](https://github.com/agntcy/shadi/pull/445))

### Other

- *(identity)* move the did:key document and OpenPGP key helpers into shadi_identity ([#450](https://github.com/agntcy/shadi/pull/450))

## [0.2.0](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.11...agntcy-shadi-cli-v0.2.0) - 2026-10-09

### Added

- *(sandbox)* speak HTTP on the --watch-policy proxy port ([#439](https://github.com/agntcy/shadi/pull/439))
- *(slim)* [**breaking**] move to SLIM 3.0.1 and the 0.4 A2A SDK ([#423](https://github.com/agntcy/shadi/pull/423))
- *(slim)* connect to a remote node with a bearer token ([#418](https://github.com/agntcy/shadi/pull/418))
- *(desktop)* own the rooms you moderate, and approve who joins ([#428](https://github.com/agntcy/shadi/pull/428))
- *(agentbridge)* let agents ask a channel's owner over A2A ([#426](https://github.com/agntcy/shadi/pull/426))
- *(agentbridge)* decide channel requests by the owner's standing rules ([#425](https://github.com/agntcy/shadi/pull/425))
- *(mas)* [**breaking**] agents derive the update rule in ASSEMBLY and apply it themselves in CONVERGE ([#412](https://github.com/agntcy/shadi/pull/412))
- *(a2a)* capture A2A prompts and replies in traces only on opt-in ([#411](https://github.com/agntcy/shadi/pull/411))
- *(a2a)* carry W3C trace context in A2A message metadata ([#406](https://github.com/agntcy/shadi/pull/406))
- *(agentbridge)* trace each A2A request, with its decisions as span events ([#404](https://github.com/agntcy/shadi/pull/404))
- *(agentbridge)* pass every outbound A2A message through one egress check ([#402](https://github.com/agntcy/shadi/pull/402))
- *(agentbridge)* export OpenTelemetry traces from every command ([#403](https://github.com/agntcy/shadi/pull/403))
- *(a2a)* let verifiers check each request, and the live adapter take a policy ([#405](https://github.com/agntcy/shadi/pull/405))
- *(identity)* sign and verify channel grants ([#424](https://github.com/agntcy/shadi/pull/424))
- *(shadi-identity)* add trust anchors ([#389](https://github.com/agntcy/shadi/pull/389))

### Fixed

- *(sandbox)* [**breaking**] enforce the port in --watch-policy allow-list entries ([#438](https://github.com/agntcy/shadi/pull/438))
- *(shadictl)* refuse get-secret inside a sandbox, and to a terminal without --reveal ([#410](https://github.com/agntcy/shadi/pull/410))
- *(shadictl)* rename the secret-named CLI variants that CodeQL treats as secrets ([#409](https://github.com/agntcy/shadi/pull/409))
- *(agentbridge)* key a listener's admission decisions on a local id ([#422](https://github.com/agntcy/shadi/pull/422))
- *(mas)* return rejected and failed A2A replies as errors ([#394](https://github.com/agntcy/shadi/pull/394))
- *(sandbox)* check the kernel, not env vars, before calling a sandbox enforced ([#392](https://github.com/agntcy/shadi/pull/392))
- *(sandbox)* enforce --net-allow per port in the kernel ([#391](https://github.com/agntcy/shadi/pull/391))
- *(mas)* send the destination DID over SLIM; listeners without a matching DID now reject ([#395](https://github.com/agntcy/shadi/pull/395))
- *(mas)* bound SLIM connect attempts in the live A2A adapter ([#393](https://github.com/agntcy/shadi/pull/393))
- *(sandbox)* give each Windows sandbox its own AppContainer and revoke only its grants ([#433](https://github.com/agntcy/shadi/pull/433))

## [0.1.11](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.10...agntcy-shadi-cli-v0.1.11) - 2026-09-30

### Added

- *(shadictl)* report trusted-secret rules over the control socket ([#305](https://github.com/agntcy/shadi/pull/305))
- *(agentbridge)* add --session and --report to coordinate ([#330](https://github.com/agntcy/shadi/pull/330))
- *(agentbridge)* verify the human binding at admission ([#327](https://github.com/agntcy/shadi/pull/327))
- *(agentbridge)* serve the agent card at the well-known path ([#287](https://github.com/agntcy/shadi/pull/287))
- *(identity)* add human-to-agent binding certificates ([#321](https://github.com/agntcy/shadi/pull/321))
- *(sandbox)* bound proxy connections and finish the SOCKS5 fuzzing ([#290](https://github.com/agntcy/shadi/pull/290))

### Fixed

- *(deps)* pin agntcy-slim-persistence and unblock releases ([#339](https://github.com/agntcy/shadi/pull/339))
- *(agent_secrets)* stop listing secrets whose keychain item is gone ([#331](https://github.com/agntcy/shadi/pull/331))
- *(agent_secrets)* remove unused secret policy ([#325](https://github.com/agntcy/shadi/pull/325))
- *(agentbridge)* stop exec'ing generated scripts in the session tests ([#324](https://github.com/agntcy/shadi/pull/324))
- *(agentbridge)* key harness sessions by A2A contextId ([#306](https://github.com/agntcy/shadi/pull/306))
- *(agentbridge)* serialize every env-mutating test on one lock ([#311](https://github.com/agntcy/shadi/pull/311))
- *(agentbridge)* terminate every child on shutdown, not just the newest ([#281](https://github.com/agntcy/shadi/pull/281))
- *(agentbridge)* stop claude --add-dir from swallowing the prompt ([#275](https://github.com/agntcy/shadi/pull/275))
- *(agentbridge)* park and reject as real tasks the client can fetch ([#293](https://github.com/agntcy/shadi/pull/293))
- *(mas)* scale the cascade demand series with the chain, and expose gamma ([#332](https://github.com/agntcy/shadi/pull/332))
- *(shadi_mas)* scan every line for the ASSEMBLY CLASS marker ([#308](https://github.com/agntcy/shadi/pull/308))
- *(shadi_py)* default sandbox policies to the minimal platform profile ([#299](https://github.com/agntcy/shadi/pull/299))
- *(sandbox)* list a denied path once in the policy description ([#314](https://github.com/agntcy/shadi/pull/314))
- *(sandbox)* bind the ACL journal HMAC to its field boundary ([#310](https://github.com/agntcy/shadi/pull/310))
- *(sandbox)* deduplicate resolved policy paths and network destinations ([#302](https://github.com/agntcy/shadi/pull/302)) ([#303](https://github.com/agntcy/shadi/pull/303))

### Other

- *(agent_secrets)* fuzz the secret mapping parser ([#309](https://github.com/agntcy/shadi/pull/309))
- *(agentbridge)* fuzz the stdio response and member spec parsers ([#307](https://github.com/agntcy/shadi/pull/307))
- *(agentbridge)* serialise the TLS tests against each other ([#288](https://github.com/agntcy/shadi/pull/288))
- *(identity)* pin that DID credentials are minted per call ([#315](https://github.com/agntcy/shadi/pull/315))
- Fix/pyo3 0.29 build ([#268](https://github.com/agntcy/shadi/pull/268))
- *(sandbox)* fuzz resolve_session_socket ([#291](https://github.com/agntcy/shadi/pull/291))
- *(sandbox)* hold the port lock in every test that binds one ([#289](https://github.com/agntcy/shadi/pull/289))

## [0.1.10](https://github.com/agntcy/shadi/compare/agntcy-shadi-cli-v0.1.9...agntcy-shadi-cli-v0.1.10) - 2026-09-15

### Other

- generate the root CHANGELOG with release-plz ([#272](https://github.com/agntcy/shadi/pull/272))

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
