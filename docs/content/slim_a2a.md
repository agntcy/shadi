# SLIM and A2A

SHADI carries [A2A](https://a2a-protocol.org/) traffic over the SLIM data
plane instead of raw HTTP: SLIM provides the authenticated, encrypted
transport (mTLS, and MLS between group members), and A2A provides the
conversation semantics (tasks, messages, streaming).

SHADI's A2A wrapper (`shadi_a2a`) is built on the official Rust SDK from
[`a2aproject/a2a-rs`](https://github.com/a2aproject/a2a-rs) — its core
protocol, client, server, and SLIMRPC bindings — with SHADI's outbound
verifier gate kept in front of the transport, and its own DID-based identity
model underneath.

## Point-to-point: `a2a-send` / `a2a-echo-peer`

For one-to-one A2A requests, `shadictl slim a2a-send` sends a unary or
streaming request over SLIMRPC to a single peer, and `shadictl slim
a2a-echo-peer` serves one as a task-backed listener. See the [CLI
Reference](cli.md#shadictl-slim-shadictl-slim) for exact flags and examples.

This is also the transport [agentbridge](agentbridge.md) uses to let CLI
coding agents (Claude Code, Codex, Copilot, Cursor Agent, and others) delegate
tasks to each other one-on-one.

## Group messaging: `a2a-collaborate`

`shadictl slim a2a-collaborate` broadcasts one A2A `Message` to every other
member of a SLIM group channel and streams back everyone else's messages —
the SLIMRPC `Collaborate` RPC, with each reply tagged by sender
(`metadata["slim-src"]`). Every member both sends its own message and listens
for everyone else's in the same call, so the mesh is a genuine many-to-many:
every agent reaches every other agent directly, not just moderator to
members.

```bash
cargo run -p agntcy-shadi-cli -- slim a2a-collaborate \
  --agent-id claude-code \
  --peer-agent-ids codex,copilot,cursor-agent,avatar \
  --message "Hi, I am claude-code — reporting in" \
  --timeout-seconds 15
```

`a2a-collaborate` assumes the group channel already exists and its members
have already subscribed — see the next section for how a group is actually
formed and admitted.

## Secure agent groups: identity, moderator role, and admission

Group membership itself is managed through `shadictl`'s interactive shell,
not the one-shot CLI above:

| Shell command | Effect |
|---|---|
| `/slim create <org/namespace/app>` | Creates a channel; the caller becomes its **moderator**. |
| `/slim invite <org/namespace/app>` | Moderator-only: invites a participant into the channel. |
| `/slim join <org/namespace/app> [--timeout SECONDS]` | Blocks until invited; caller becomes a **participant**. |
| `/slim whoami` | Prints agent name, auth mode, role, and (under DID auth) the derived agent DID and human DID. |

Every member authenticates with its own `did:key` rather than a shared
secret. In the reference demo, every agent's DID is HKDF-derived from one
human root key, so the group can tell which human every agent belongs to —
`whoami` surfaces both the agent DID and that shared human DID. Admission is
enforced by DID allow-list: the moderator's `create`/`invite` control
messages carry its DID-JWT, and each participant verifies that JWT against
the allow-list before replying, so a non-member DID is dropped. The
allow-list itself is evaluated separately by `shadictl slim-mas` — see the
[CLI Reference](cli.md#shadictl-slim-mas-shadictl-slim-mas) for
`list-groups`/`list-members`/`validate`/`admit`.

For a full worked example — moderator + four coding-agent CLIs, DID
admission, an A2A Collaborate roll call, and real task delegation via
agentbridge — see the [Secure Agent Group Demo](demos/did-agent-group.md).

## Intended security properties

1. SLIM session setup verifies agent identity (DID/VC), not a shared secret.
2. Group admission is enforced against an explicit per-agent DID allow-list.
3. MLS provides content confidentiality between group members.
4. Secrets are accessed only after verification succeeds.

## Next steps

- Walk through a full multi-agent example in the [Secure Agent Group Demo](demos/did-agent-group.md).
- See how a group's membership can be discovered instead of hand-named in the [Agent Directory Discovery Demo](demos/dir-group-discovery.md).
- See how agentbridge uses this transport to interconnect agents — coding CLIs today, any A2A-speaking agent in general — in [AgentBridge](agentbridge.md).
- Look up exact flags in the [CLI Reference](cli.md).
