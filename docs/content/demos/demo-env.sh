# Shared environment for the DID agent-group demo (docs/content/demos/did-agent-group.md).
# Source this in EVERY terminal:  source docs/content/demos/demo-env.sh
#
# All five member DIDs below are HKDF-derived from SLIM_HUMAN_SEED (salt
# "shadi-agent-derive") with the agent names avatar / claude-code / codex /
# copilot / cursor-agent, so they are deterministic for this seed. Change the seed
# and they all change — re-derive with `/slim whoami` per agent (see the doc).

export SHADI_SLIM_AUTH=did                         # select DID-JWT admission
export SLIM_HUMAN_SEED="shadi-demo-human-root-secret"
export SLIM_HUMAN_DID="did:key:z6MkhVTmZLk7g6zRXm8DF2u2Y5b2WCkC75n16xuoJDN1X4Bp"

export SHADI_TMP_DIR="${SHADI_TMP_DIR:-/tmp/shadi-did-demo}"
mkdir -p "$SHADI_TMP_DIR"
# Resolve to the real path (macOS /tmp is a symlink to /private/tmp) so it
# matches exactly what shadictl's sandbox --read/--write policy resolves to —
# Seatbelt's subpath rules don't match a path accessed through the /tmp
# symlink if the rule was generated for the canonicalized /private/tmp form.
export SHADI_TMP_DIR="$(cd "$SHADI_TMP_DIR" && pwd -P)"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47560}"

# One transport cert is fine for the demo — identity is the DID, not the TLS CN.
export SLIM_TLS_CERT="$SHADI_TMP_DIR/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$SHADI_TMP_DIR/shadi-slim-mtls/client-avatar.key"

# Allow-list = the DID of every member (moderator avatar + 4 coding-agent CLIs).
export SLIM_MEMBER_DIDS="\
did:key:z6Mkix7tAk25UD8f4Uy7tTxn1FAErhGZ7rfifBgrvdKgzM82,\
did:key:z6MkhRuJgsaipjWB6No8RUGD4P7fnn8qGBZKK5C5zGJjPZa1,\
did:key:z6MkmaFFysqqMsE1q5M6E7LDuoJMaSBv3PkNHz5SwwwnuGr6,\
did:key:z6MkmJUcT1F6BK21nQv1C2zo46gJJA9hsMGnbdpiN2LrMnwT,\
did:key:z6MktdzQzm171sAoRZc6cCUPDa8XWxaG8Bi6R3Y4ohP7qS5Q"
