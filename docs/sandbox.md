# SHADI Sandbox (MVP)

SHADI includes a kernel-enforced sandbox launcher to run agent processes with a
restricted capability set. The initial implementation targets macOS using the
Seatbelt sandbox APIs. Windows uses AppContainer + ACL-based allowlists with
optional network capability toggles, plus Job Objects to ensure child processes
are terminated with the parent.

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
- `balanced` (default): workspace + system reads, network blocked.
- `connected`: workspace + system reads, network allowed.

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
  "block_command": ["curl"]
}
```

Run it with:

```bash
cargo run -p shadictl -- --policy ./sandbox.json -- ./your-agent
```

CLI flags override policy file settings. Paths are canonicalized before use.
Profile defaults are applied first, then policy file values, then CLI flags.

### Flags
- `--policy FILE`: Load policy settings from a JSON file.
- `--profile PROFILE`: Built-in launcher profile (`strict`, `balanced`, `connected`).
- `--allow PATH`: Allow read+write under the path.
- `--read PATH`: Allow read-only access under the path.
- `--write PATH`: Allow write access under the path.
- `--net-block`: Block network access.
- `--allow-command CMD`: Override default command blocklist.
- `--inject-keychain KEY=ENV`: Read a keychain secret and inject it as an env var before sandboxing.

`net_allow` is honored by the Python sandbox runner. It injects a `sitecustomize.py` hook that blocks connections outside the allowlist (best-effort; not OS-enforced).

### Key utilities
`shadictl` also manages OpenPGP keys and agent DIDs without invoking OS `gpg`:

```bash
cargo run -p shadictl -- \
  put-key --key human/gpg --in /path/to/human-secret.asc

cargo run -p shadictl -- \
  derive-agent-did --secret human/gpg --name agent-a --prefix agents
```

## Brokered secrets

Keychain access is often restricted inside a sandbox. You can broker secrets by
reading them before sandboxing and injecting them as environment variables:

```bash
cargo run -p shadictl -- \
  --allow . \
  --read / \
  --net-block \
  --inject-keychain tourist_api_key=SHADI_BROKER_SECRET \
  -- \
  uv run agents/secops/secops.py
```

## Notes
- This is an MVP and uses a conservative Seatbelt profile. System paths required
  to execute processes are allowed for read access.
- Command blocking is enforced before launch in the CLI.
- Windows: ACL allowlists are applied to the specified paths for the AppContainer
  SID and automatically reverted when the sandboxed process exits. Network
  access is controlled by AppContainer capabilities.

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
