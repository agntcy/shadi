# Tauri IPC command contract

Closes [agntcy/shadi#114](https://github.com/agntcy/shadi/issues/114).

This is the frontend/backend contract every panel issue (`#115`-`#121`) builds
against. It exists so frontend and backend work can proceed in parallel
without churn: the request/response shapes below should not need to change
when a panel replaces its module's stubs with real calls into the
corresponding SHADI crate.

**Scope**: signatures and types. Implementing them is each panel issue's job,
not this one's — `agentbridge.rs` (#120) and `slim.rs` (#118) are real; the
remaining modules still return `not_implemented(<panel-issue>)`. Where a panel's
implementation had to extend its own signatures, this document follows it rather
than the other way round.

## Conventions

- **Errors are `String`.** Tauri requires command errors to be serializable;
  a plain message is enough at this layer — no error-code taxonomy yet. If a
  panel's implementation needs richer error handling (e.g. distinguishing
  "not found" from "permission denied" in the UI), add a typed error enum
  in that panel's own PR rather than widening this contract speculatively.
- **One module per panel**, named to match: `sandbox.rs` (#115), `policy.rs`
  (#116), `identity.rs` (#117, secrets included), `slim.rs` (#118), `dir.rs`
  (#119), `agentbridge.rs` (#120), `trace_memory.rs` (#121, both included
  since they share one CLI-side gate — see below).
- **Async by default.** Every command is `async fn`, even though the stubs
  don't await anything — real implementations will call into blocking SHADI
  APIs (subprocess I/O, keychain access, SLIM connections) and should do that
  work via `tauri::async_runtime::spawn_blocking` rather than block Tauri's
  async executor.
- **Sessions are identified by socket path**, not an opaque handle. The
  sandbox/policy commands all take a `socket_path: String` — the same
  identifier `shadictl shell`'s `/attach` and `/sessions` already use — so a
  panel can hold a list of sessions from `sandbox_list_sessions` and pass one
  straight back into `policy_query`/`sandbox_status` without a separate
  "open a handle" step.
- **Secret values never round-trip further than they have to.** `secret_get`
  returns the raw value (the panel needs it to display it), but
  `secret_list_keychain` returns key names only, and `memory_search`/
  `memory_list` return entry metadata without `payload` — only `memory_get`
  populates that field. Panels must not log or persist values returned by
  these commands outside of React state. See
  [`docs/content/security.md`](https://github.com/agntcy/shadi/blob/main/docs/content/security.md)
  for the secret-delivery model this must not weaken.
- **Streaming uses Tauri events, not long-lived return values.**
  `agentbridge_coordinate` is the one command whose real implementation runs
  for multiple rounds. Rather than returning a `Vec` of every round only at
  the end, it emits `CoordinateRoundEvent` on the `coordinate:round` event
  (see `COORDINATE_ROUND_EVENT` in `agentbridge.rs`) as each round completes,
  and the command's return value is only the final result. The frontend must
  call `listen("coordinate:round", ...)` *before* invoking the command, or it
  will miss early rounds.
- **Some commands are stateful, and that state is the panel's own.** `slim.rs`
  is the one module backed by Tauri managed state (`SlimState`), because a SLIM
  node and its group sessions outlive a single command. It deliberately does
  *not* mirror `shadictl shell`'s single-active-session model: the shell deletes
  the previous group when you create or join another, which makes a rooms
  overview impossible. So `slim_group_list`/`slim_group_roster`/
  `slim_group_remove_member`/`slim_group_forget` have no CLI equivalent to
  mirror — the first two read that state, and the last two mutate it.
- **Known rooms outlive the process; their sessions do not.** Room metadata
  (channel, role, roster) is persisted, so `slim_group_list` returns rooms from
  earlier launches with `connected: false`. A disconnected room's roster is
  readable, but `slim_group_invite`/`slim_group_remove_member` require a live
  session and fail with a rejoin hint — panels should gate those controls on
  `connected` rather than only on `role`. Sessions and credentials are never
  written to disk; a `did:key` is a public key, so the stored roster holds no
  secrets. See agntcy/shadi#138.
- **Tagged unions over mutually-exclusive optional fields.** The CLI models
  "secret ref xor file path" as two `Option<T>` args with `conflicts_with`/
  `required_unless_present` clap attributes — that's a clap ergonomics
  pattern, not a good IPC shape. `HumanKeySource` in `identity.rs` is a
  `#[serde(tag = "kind")]` enum instead, so invalid combinations aren't
  representable at all.

## Command index

| Module | Commands | CLI/shell equivalent |
|---|---|---|
| `sandbox.rs` | `sandbox_launch`, `sandbox_list_sessions`, `sandbox_attach`, `sandbox_detach`, `sandbox_kill`, `sandbox_status` | `shadictl <flags> -- <cmd>`, shell `/sessions` `/attach` `/detach` `/kill` `/status` |
| `policy.rs` | `policy_query`, `policy_patch`, `policy_explain`, `policy_diff`, `policy_profiles` | shell `/policy query\|patch\|explain\|diff`, `--profile` |
| `identity.rs` | `identity_did_from_gpg`, `identity_did_from_github`, `identity_derive_agent`, `identity_verify_agent`, `secret_get`, `secret_put_key`, `secret_list_keychain`, `secret_backend_status` | `shadictl did-from-gpg\|did-from-github\|derive-agent-identity\|verify-agent-identity\|get-secret\|put-key`, `--list-keychain` |
| `slim.rs` | `slim_node_start`, `slim_node_status`, `slim_group_create`, `slim_group_invite`, `slim_group_join`, `slim_group_list`, `slim_group_roster`, `slim_group_remove_member`, `slim_group_forget`, `slim_controller_list_connections`, `slim_controller_list_routes` | shell `/slim start-node\|create-group\|invite\|join\|controller`; the room-list/roster/remove/forget commands have no CLI equivalent (see below) |
| `dir.rs` | `dir_search`, `dir_pull`, `dir_info`, `dir_register` | `shadictl dir search\|pull\|info`, `agentbridge register --dir-publish` |
| `agentbridge.rs` | `agentbridge_list_adapters`, `agentbridge_handoff`, `agentbridge_delegate`, `agentbridge_coordinate` | `agentbridge list\|handoff\|delegate\|coordinate` |
| `trace_memory.rs` | `trace_list`, `trace_summary`, `memory_get`, `memory_search`, `memory_list` | `shadictl trace list\|summary`, `shadictl memory get\|search\|list` |

Full request/response types are in each module — they're the source of
truth; this table is a map, not a copy.

## What's deliberately not here

- **The embedded terminal (#122)** doesn't need any of these commands — it
  spawns `shadictl shell` as a real subprocess/PTY and talks to it over
  stdin/stdout, not Tauri IPC.
- **Onboarding (#123)** composes `identity_derive_agent` and
  `secret_backend_status` from this contract; it doesn't need new commands
  of its own.
