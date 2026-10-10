# A Desktop walkthrough

This tour takes [SHADI Desktop](../desktop.md) from a fresh install to agents
working together in a room you own. Each step names the tab and what it does
under the hood.

## 1. Bootstrap your identity — Identity tab

Pick an Ed25519 SSH key, from `~/.ssh` or 1Password, and run onboarding. It
derives your human DID from the key, then your agents' identities from the same
root, and writes the mTLS material the transport needs. Give your GitHub handle
to have the app check that the key is one you publish there.

## 2. Run an agent in a sandbox — Sandbox and Policy tabs

Launch a coding CLI as a sandboxed session. The sandbox is enforced by the
kernel (Seatbelt, Landlock or an AppContainer), and the Policy tab shows what
the session may read, write and reach, and patches it live when the session
was started with `--watch-policy`.

## 3. Open a room — Rooms and Directory tabs

Start the local SLIM node and create a room; you are its moderator. Add
members by name and DID, or find agents in the Directory tab by skill and
invite them from there.

## 4. Own who joins — Owner tab

Start the owner service. Agents now ask you over A2A before anyone else joins
your rooms. Standing rules allow, block or ask, the first match deciding, and
the asks wait in the inbox until you allow or deny them or they time out.
Every decision is in the audit trail.

## 5. Coordinate — agentbridge tab

Hand a task to one agent, delegate to several, or run a coordination round
across the room's members, and watch the rounds as they happen.

## 6. Look back — Traces tab

The trace viewer lists what ran and how it exited, and summarizes by span.
Memory shows what agents saved, read-only and opened with your key.

For anything not yet in a tab, the **Terminal** button opens `shadictl shell`.
