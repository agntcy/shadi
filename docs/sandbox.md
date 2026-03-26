# SHADI Sandbox (MVP)

SHADI includes a kernel-enforced sandbox launcher to run agent processes with a
restricted capability set.

- **Linux**: Landlock LSM (kernel 5.13+) for filesystem isolation, with network
  filtering on ABI V4+ (kernel 5.19+). `PR_SET_NO_NEW_PRIVS` prevents privilege
  escalation through setuid binaries.
- **macOS**: Seatbelt sandbox APIs (`sandbox_init`).
- **Windows**: AppContainer + ACL-based allowlists with optional network
  capability toggles, plus Job Objects to ensure child processes are terminated
  with the parent.

## CLI

```bash
cargo run -p shadictl -- \
  --allow . \
  --net-block \
  -- \
  ./your-agent --arg value
```

### Portable launcher profiles (no shell wrapper)

`shadictl` now has a built-in policy profile model so you can launch securely
without platform-specific Bash/PowerShell wrappers:

```bash
cargo run -p shadictl -- --profile strict -- -- ./your-agent
```

Profiles:
- `strict`: local workspace only, network blocked.
- `balanced` (default): workspace access with network blocked.
- `connected`: workspace access with network allowed.

On macOS and Linux, all built-in profiles now resolve through the minimal platform
profile by default. On macOS this uses a minimal Seatbelt profile; on Linux the
Landlock backend supplies its own `DEFAULT_READ_PATHS` (e.g. `/usr`, `/lib`,
`/etc`, `/proc/self`). That keeps the runtime allowances needed to start common
tooling, but stops adding an implicit root read allowlist for `balanced` and
`connected`. Add explicit `--read` or `--allow` paths when a workload needs
extra filesystem access beyond the workspace.

### Starter profile matrix

Use this matrix as a baseline when selecting a profile:

| Workload | Recommended profile | Why |
| --- | --- | --- |
| Local processing agent (no network calls) | `strict` | Smallest blast radius and full network block. |
| Typical development agent (reads toolchain/system paths) | `balanced` | Keeps network off while allowing common runtime reads. |
| API-integrated agent (GitHub/LLM calls) | `connected` | Enables network while keeping filesystem policy centralized. |

Then tighten with explicit path flags (`--allow`, `--read`, `--write`) and only open command exceptions with `--allow-command` when strictly required.

Print the resolved profile policy:

```bash
cargo run -p shadictl -- --profile balanced --print-policy
```

The printed policy now includes `platform_profile`, which is `minimal` on
macOS and Linux for the built-in launcher profiles.

### JSON Policy

You can pass a JSON policy file to avoid long CLI arguments:

```json
{
  "allow": ["."],
  "read": ["/opt/homebrew"],
  "write": ["./output"],
  "net_block": true,
  "net_allow": ["api.github.com", "127.0.0.1"],
  "allow_command": ["rm"],
  "block_command": ["curl"],
  "process_inject_keychain": [
    {
      "program": "/Users/example/bin/secops-agent",
      "key": "secops/api-token",
      "env": "SECOPS_TOKEN"
    }
  ],
  "process_trusted_secret": [
    {
      "program": "/Users/example/bin/avatar-agent",
      "key": "avatar/session-key",
      "name": "avatar-session",
      "fd_env": "AVATAR_SESSION_FD"
    }
  ],
  "process_secret_policy": [
    {
      "program": "/Users/example/bin/secops-agent",
      "secret": "secops/github_token",
      "actions": ["delegate-to-child"],
      "children": ["/usr/bin/curl"],
      "name": "github-token",
      "fd_env": "GITHUB_TOKEN_FD"
    }
  ]
}
```

Run it with:

```bash
cargo run -p shadictl -- --policy ./sandbox.json -- ./your-agent
```

CLI flags override policy file settings. Paths are canonicalized before use.
Profile defaults are applied first, then policy file values, then CLI flags.
Process-scoped secret rules are matched against the exact resolved executable
path for the launched command, so a shared policy file can carry secrets for
multiple entrypoints without making them ambient to every run.
On Unix/macOS, trusted-secret delivery now uses a brokered one-shot fetch path
instead of an inherited secret-bearing FD, which reduces relay risk when a
matched process execs into a different executable before consuming the secret.
For delegated child delivery, SHADI also adds only the temporary runtime
allowances needed for the broker endpoint and, on macOS, local Unix sockets.

### Flags
- `--policy FILE`: Load policy settings from a JSON file.
- `--profile PROFILE`: Built-in launcher profile (`strict`, `balanced`, `connected`).
- `--allow PATH`: Allow read+write under the path.
- `--read PATH`: Allow read-only access under the path.
- `--write PATH`: Allow write access under the path.
- `--net-block`: Block network access.
- `--allow-command CMD`: Override default command blocklist.
- `--inject-keychain KEY=ENV`: Read a keychain secret and inject it as an env var before sandboxing.
- `--trusted-secret KEY=NAME`: Configure direct trusted-secret delivery.
- `--trusted-secret-exec NAME=PROGRAM`: Bind a trusted secret to an exact executable.
- `--trusted-secret-fd-env NAME=ENV`: Set the endpoint env name for a trusted secret mapping.
- `--git-snapshot`: Capture before/after Git state for the current working tree.
- `--git-snapshot-dir DIR`: Override the default snapshot root at `${SHADI_TMP_DIR:-./.tmp}/git-snapshots`.
- `--git-snapshot-untracked`: Include an explicit untracked-file inventory in the artifact.

`net_allow` is honored by the Python sandbox runner. It injects a `sitecustomize.py` hook that blocks connections outside the allowlist (best-effort; not OS-enforced).

## Git-backed snapshots

`shadictl` can optionally capture a read-only Git snapshot around the sandboxed
run. This is useful when you want an audit artifact for file changes without
auto-committing anything or asking downstream tooling to reconstruct Git state
from scratch.

Enable it explicitly:

```bash
cargo run -p shadictl -- \
  --allow . \
  --git-snapshot \
  --git-snapshot-untracked \
  -- \
  ./your-agent
```

What gets captured:

- repository detection based on the current working directory
- discovery of nested Git repositories under the sandbox working directory
- pre-run and post-run `HEAD`
- `git status --porcelain=v1 --untracked-files=all`
- `git diff --binary`
- optional untracked inventory via `git ls-files --others --exclude-standard`
- a derived comparison block so operators can tell whether `HEAD`, status,
  diff, or untracked state changed
- SHA-256 hashes for the captured Git payloads and a combined state hash

Artifact layout:

- `${SHADI_TMP_DIR:-./.tmp}/git-snapshots/runs/<artifact_id>/snapshot.json`
- `${SHADI_TMP_DIR:-./.tmp}/git-snapshots/latest.json`

This feature is opt-in by design. SHADI does not capture snapshots unless you
pass `--git-snapshot`, and the first implementation remains Git-read-only.

Nested Git repos are handled explicitly. The artifact keeps the original
top-level `git.*` fields for the primary repo rooted at the sandbox working
directory, and adds `git.repositories` for per-repo records when additional Git
repos exist below that directory. This prevents false negatives in workflows
where an agent changes another repo under the same workspace.

Example: a SecOps agent may clone, pull, or commit inside a remediation target
repo under its working folder. In that case the outer repo can remain clean,
but the nested repo entry will still show the change through its own
`comparison` block and will increment `git.changed_repositories`.

### Key utilities
`shadictl` also manages OpenPGP keys and agent DIDs without invoking OS `gpg`:

```bash
cargo run -p shadictl -- \
  put-key --key human/gpg --in /path/to/human-secret.asc

cargo run -p shadictl -- \
  derive-agent-did --secret human/gpg --name agent-a --prefix agents
```

## Secret delivery modes

SHADI supports three different secret-delivery modes at launch time:

- explicit env disclosure via `--inject-keychain` or `process_inject_keychain`
- process-scoped direct trusted delivery via `process_trusted_secret`
- delegated child delivery via `process_secret_policy`

### Explicit disclosure

Keychain access is often restricted inside a sandbox. You can still read a
secret before sandboxing and inject it as an environment variable when direct
disclosure is intentional:

```bash
cargo run -p shadictl -- \
  --allow . \
  --read / \
  --net-block \
  --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
  -- \
  uv run agents/secops/secops.py
```

### Trusted delivery

`process_trusted_secret` is the compatibility bridge between env disclosure and
full delegated policy. It scopes the trusted secret to the exact launched
executable and exposes a protocol-specific endpoint env instead of a broad
ambient env var.

On Unix/macOS this is a one-shot broker fetch path protected by:

- exact executable matching
- process identity verification
- launch-scoped nonce presentation
- one-shot consumption semantics

On Windows, direct trusted-secret delivery remains a compatibility handle path.

### Delegated child delivery

`process_secret_policy` adds action-based secret rules. The implemented secure
path today is `delegate-to-child` on Unix/macOS:

- the parent process is allowed to request delivery to a specific child tool
- the parent does not receive the secret value itself
- SHADI verifies the child executable, optional child SHA-256 constraint, and nonce
- the child receives the secret directly as the final authorized consumer

## Dynamic Policy Updates

`shadictl` supports runtime policy updates for long-running sandboxed workloads.
When launched with `--watch-policy`, an `AF_UNIX` control socket is created so
external callers can query and patch the effective policy without restarting the
agent process.  The same Unix-domain socket protocol is used on all platforms:

| Platform | Socket path |
| --- | --- |
| macOS / Linux | `$TMPDIR/shadi-ctl-<pid>.sock` |
| Windows (10 1803+) | `%TEMP%\shadi-ctl-<pid>.sock` |

Windows 10 version 1803 and later support `AF_UNIX` natively.  The
[`uds_windows`](https://crates.io/crates/uds_windows) crate provides the
binding so the control channel implementation is shared across all platforms
with no TCP fallback.

### Enabling the control socket

```bash
cargo run -p shadictl -- --watch-policy --profile balanced -- ./your-agent
```

On startup, `shadictl` prints the control socket path to stderr:

```
control socket: /tmp/shadi-ctl-12345.sock
```

### Querying the current policy

```bash
cargo run -p shadictl -- policy query --socket /tmp/shadi-ctl-12345.sock
```

### Sending a policy patch

From the CLI:

```bash
cargo run -p shadictl -- policy patch \
  --socket /tmp/shadi-ctl-12345.sock \
  --add-allow-command npm \
  --add-block-command curl \
  --add-read /opt/new-tool
```

From a JSON patch file:

```json
{
  "add_allow_command": ["npm"],
  "add_block_command": ["curl"],
  "add_read": ["/opt/new-tool"],
  "add_net_allow": ["registry.npmjs.org"]
}
```

```bash
cargo run -p shadictl -- policy patch \
  --socket /tmp/shadi-ctl-12345.sock \
  --patch-file ./patch.json
```

### Patch axis status

Each axis of a policy patch returns one of:

| Status | Meaning |
| --- | --- |
| `applied` | Change took effect immediately (command allow/block lists). |
| `pending_restart` | Change is staged but requires a process restart to take effect (filesystem paths, network rules). |
| `unchanged` | No change was requested for this axis. |
| `rejected` | The change was invalid or denied. |

### Platform limitations

macOS Seatbelt profiles are compiled once at process launch via `sandbox_init`.
Filesystem and network rules **cannot** be widened at runtime. These axes are
staged (reported as `pending_restart`) and require relaunching the agent with
the updated policy to take effect.

Command allow/block lists are enforced in user space by `shadictl` and can
always be updated immediately.

### Process group cleanup (macOS / Linux)

On macOS and Linux, the sandboxed child process is placed in its own process
group via `setsid()` in `pre_exec`. When `SandboxedChild::kill()` is called,
SHADI sends `SIGKILL` to the entire process group using `killpg()`, ensuring
that any grandchild processes spawned by the agent are also terminated. This
mirrors the Windows Job-object pattern (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).

### Mach IPC hardening (macOS)

In **Minimal** Seatbelt profile mode, `mach-lookup` is restricted to an
essential-services allowlist rather than being blanket-allowed. Only the Mach
services required for basic process execution, DNS resolution, Security
framework operations, system logging, and CF preferences are permitted.

In **Compatibility** mode, `mach-lookup` remains unrestricted to support
third-party tools (1Password CLI, `gh`, `git` credential helpers, etc.) that
communicate with background daemons via Mach IPC.

Network filtering on macOS remains all-or-nothing because Seatbelt does not
support domain-level or port-level allowlists. `net_blocked` disables all TCP/IP;
Unix-domain sockets can still be selectively allowed.

## Notes
- This is an MVP and uses a conservative Seatbelt profile. System paths required
  to execute processes are allowed for read access.
- On macOS, the built-in launcher profiles use the minimal Seatbelt platform
  profile by default; broader read allowances should be granted explicitly.
- Command blocking is enforced before launch in the CLI.
- Git snapshots are metadata capture only. They do not commit, stage, or rewrite Git history.
- On macOS, policy paths are resolved to absolute paths before Seatbelt rules are emitted; relative subpaths are not reliable enforcement inputs.
- The demo launchers may still pre-read secrets outside the sandbox when a workload requires explicit disclosure or when the optional 1Password backend cannot be accessed safely inside the sandbox.
- Windows: ACL allowlists are applied to the specified paths for the AppContainer
  SID and automatically reverted when the sandboxed process exits. SHADI now
  journals the original DACLs to disk before mutation and will replay any stale
  rollback journals on the next Windows sandbox startup if a prior process
  crashed before cleanup. Journal files are stored in a restricted directory
  (owner + SYSTEM only) and each entry is HMAC-SHA256 authenticated with
  a per-session key; tampered or unsigned journals are rejected on recovery.
  Network access is controlled by AppContainer capabilities.

### Sandbox boundary guidance

Use the sandbox as the security boundary, not application-level path deny rules.
Path-matching controls are useful for operator ergonomics, but they are weaker
than OS-enforced policy because the agent can reason about alternate paths and
wrappers. SHADI resolves and applies the effective sandbox policy before launch,
which is the property you should rely on for enforcement.

## Windows integration test

The Windows AppContainer sandbox has an opt-in integration test. Run it on
Windows with:

```bash
SHADI_WINDOWS_INTEGRATION=1 cargo test -p shadi_sandbox
```

Or via Just:

```bash
just windows-integration
```
