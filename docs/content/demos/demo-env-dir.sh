# Shared environment for the Agent Directory discovery demo
# (docs/content/demos/dir-group-discovery.md). Source this in EVERY terminal:
#   source docs/content/demos/demo-env-dir.sh
#
# Unlike demo-env.sh (docs/content/demos/did-agent-group.md), this file
# deliberately does NOT set SLIM_MEMBER_DIDS for the moderator — the whole
# point of this demo is that `shadictl slim create-group` resolves the
# group's trust set from Agent Directory discovery instead of a hand-written
# allow-list. Each *member* terminal still needs the moderator's own DID in
# its own SLIM_MEMBER_DIDS to admit the moderator's invite — export it
# per-terminal as shown in the demo.
#
# All DIDs below are HKDF-derived from SLIM_HUMAN_SEED (salt
# "shadi-agent-derive") with the agent names avatar / copilot / codex /
# claude-code, so they are deterministic for this seed. Re-derive with
# `/slim whoami` per agent if you change the seed.

export SHADI_SLIM_AUTH=did                         # select DID-JWT admission
export SLIM_HUMAN_SEED="shadi-dir-demo-human-root-secret"

export SHADI_TMP_DIR="${SHADI_TMP_DIR:-/tmp/shadi-dir-demo}"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47660}"

# One transport cert is fine for the demo — identity is the DID, not the TLS CN.
export SLIM_TLS_CERT="$SHADI_TMP_DIR/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$SHADI_TMP_DIR/shadi-slim-mtls/client-avatar.key"

# The local `dirctl daemon` instance every dirctl/agentbridge/shadictl call
# in this demo talks to (see the Prerequisites section for how to start it).
export SHADI_DIR_SERVER=127.0.0.1:8888

unset SLIM_MEMBER_DIDS
