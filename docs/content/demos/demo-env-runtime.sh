# Shared environment for the runtime discovery demo
# (docs/content/demos/dir-runtime-discovery.md). Source this in EVERY terminal.
export SHADI_SLIM_AUTH=did                         # select DID-JWT admission
export SLIM_HUMAN_SEED="shadi-runtime-demo-human-root-secret"
# The only DID the demo agents accept tasks from: the "avatar" agent derived
# from the seed above (what `agentbridge delegate` signs as). Re-derive with
# `/slim whoami` if you change the seed.
export SLIM_MEMBER_DIDS="did:key:z6Mkf19ViBaFJEbgVNY9oWqED71Wnr4kYLQiwvYbtEnEGHJC"

# The demo's working state: each run's harness configuration
# (agentbridge-record/), the registry of local listeners (agentbridge-local/)
# and the harnesses' work directory (work/). Agent terminals grant it to the
# sandbox with --allow "$SHADI_TMP_DIR".
export SHADI_TMP_DIR="${SHADI_TMP_DIR:-/tmp/shadi-runtime-demo}"
mkdir -p "$SHADI_TMP_DIR/work"
# The real path: the sandbox's rules don't match paths through the /tmp symlink.
export SHADI_TMP_DIR="$(cd "$SHADI_TMP_DIR" && pwd -P)"

# dirctl with runtime discovery, for you and for agentbridge inside the sandbox
export DIRCTL="${DIRCTL:-$HOME/go/bin/dirctl-dev}"
export SHADI_DIRCTL_BINARY="$DIRCTL"
export DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888

# The stand-in harness and its profile
export PATH="$PWD/target/debug:$PWD/examples/agentbridge-container:$PATH"
export AGENTBRIDGE_PROFILES_DIR="$PWD/examples/agentbridge-container/profiles"
