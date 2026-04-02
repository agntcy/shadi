# SHADI Interactive Shell Demo

This walkthrough demonstrates how to use `shadictl shell` to inspect and
manage a sandboxed agent process in real time.

## Prerequisites

```bash
cargo build -p shadictl
cargo build -p shadi_demo_bot
```

Rust shell ticker:

```bash
cargo run -p shadi_demo_bot -- shell-ticker
```

## Step 1 — Launch a demo agent in the sandbox

Open a terminal and run:

```bash
cargo run -p shadictl -- \
    --policy examples/shell_demo/policy.json \
    --watch-policy \
    -- bash examples/shell_demo/demo_agent.sh
```

You should see output like:

```
control socket: /tmp/shadi-ctl-12345.sock
[demo-agent] starting — press Ctrl-C to stop
[demo-agent] pid=12345
[demo-agent] http probe=http://example.com/
[demo-agent] tcp  probe=1.1.1.1:80
[demo-agent] probe file=/private/etc/hosts
[demo-agent] tick    1  14:30:00
[demo-agent] http probe           rc=97  (no output)
[demo-agent] tcp probe            rc=97  tcp_rc=97
[demo-agent] file probe           rc=1   head: /private/etc/hosts: Operation not permitted
[demo-agent] delete probe         rc=1   rm: /tmp/shadi-demo-marker: Operation not permitted
```

`rc=97` is `CURLE_PROXY` — the SOCKS5 proxy replied with REP=0x02 "connection not allowed",
meaning the destination is not in the `net_allow` list.

Note the **control socket** path printed to stderr — you can use it to
attach directly, or let the shell discover it automatically.

Leave this running.

## Step 2 — Open the interactive shell

In a **second terminal**:

```bash
cargo run -p shadictl -- shell
```

You'll see the SHADI banner and prompt:

```
+------------------------------------------------------------------------+
| [DEFENSE] SHADI                                                        |
|                                                                        |
| Sandbox Hardening for AI Developer Infrastructure  v0.1.0              |
| type '/help' for commands, '/exit' to quit, '<cmd> --help' for details |
+------------------------------------------------------------------------+

shadi>
```

## Step 3 — Discover and attach to the running session

```
shadi> /sessions
found 1 session(s):
  /tmp/shadi-ctl-12345.sock (reachable)

shadi> /attach /tmp/shadi-ctl-12345.sock
attached to /tmp/shadi-ctl-12345.sock

shadi(shadi-ctl-12345)>
```

The prompt changes to show you're connected.

## Step 4 — Inspect the sandbox policy

```
shadi(shadi-ctl-12345)> /status
session: attached
socket:  /tmp/shadi-ctl-12345.sock
policy:  connected (query ok)

shadi(shadi-ctl-12345)> /policy query
{
  "allow_command": [],
  "allow_read": ["/path/to/project", "/usr/local", "/usr/bin", ...],
  "block_command": ["rm", "sudo", "curl", "wget", ...],
  "net_blocked": true,
  ...
}
```

## Step 5 — Patch the policy at runtime

The demo agent is intentionally noisy: every tick it tries three things:

- a TCP connect probe to `1.1.1.1:80` to show network enforcement
- `head /private/etc/hosts` (macOS) or `head /etc/hosts` (Linux) to show blocked file reads
- `rm -f /tmp/shadi-demo-marker` to show blocked command execution

This lets you demonstrate both immediate and restart-gated policy changes.

First, observe that all probes are blocked: network probes return `rc=97` (proxy denies),
the file probe returns `Operation not permitted`, and the delete probe is blocked by command policy.

### Patch network policy without restarting the process

SHADI routes all outbound TCP through a loopback SOCKS5 proxy and checks the
hostname **before DNS resolution**. A `--add-net-allow` patch updates the
proxy's allowlist live — the child process never restarts:

Allow the HTTP probe target by hostname:

```
shadi(shadi-ctl-12345)> /policy patch --force --add-net-allow example.com
{
  "accepted": true,
  "network": "applied",
  "pending_restart": []
}
```

After the next tick, `http probe rc=0 http_code=200` will appear — no restart.

Allow the TCP probe target by IP:

```
shadi(shadi-ctl-12345)> /policy patch --force --add-net-allow 1.1.1.1
```

After the next tick, `tcp probe rc=0 tcp_rc=0` will appear — still no restart.

Show an immediate command-policy change:

```
shadi(shadi-ctl-12345)> /policy patch --force --remove-block-command rm
{
  "accepted": true,
  "filesystem": "unchanged",
  "commands": "applied",
  "network": "unchanged",
  "message": "patch applied",
  "pending_restart": []
}
```

After the next tick, the delete probe should no longer fail with `Operation not permitted`.

Then stage a file-read allowance for restart:

```
shadi(shadi-ctl-12345)> /policy patch --force --add-read /private/etc
```

On Linux, use `/etc` instead. After you restart the demo agent, the file probe should succeed.

The existing patch UX is still available for dry-run and interactive confirmation:

```
shadi(shadi-ctl-12345)> /policy patch --add-allow-command npm
patch to apply:
{
  "add_allow_command": ["npm"],
  ...
}
apply this patch? [y/N] y
{
  "accepted": true,
  "filesystem": "unchanged",
  "commands": "applied",
  "network": "unchanged",
  "message": "patch applied",
  "pending_restart": []
}
```

Preview without sending (`--dry-run`):

```
shadi(shadi-ctl-12345)> /policy patch --dry-run --add-read /opt/tools
dry-run: the following patch would be applied:
{
  "add_read": ["/opt/tools"],
  ...
}
```

Add a filesystem path (requires process restart):

```
shadi(shadi-ctl-12345)> /policy patch --force --add-read /opt/tools
{
  "accepted": true,
  "filesystem": "pending_restart",
  "commands": "unchanged",
  "network": "unchanged",
  "message": "patch accepted; filesystem require process restart to take effect",
  "pending_restart": ["filesystem"]
}
```

## Step 6 — Inspect local configuration

```
shadi(shadi-ctl-12345)> /config
{
  "effective_policy": { ... },
  "profile": "balanced",
  ...
}

shadi(shadi-ctl-12345)> /policy explain
{
  "effective_policy": { ... },
  "sources": {
    "cli_overrides": { ... },
    "policy_file": { ... },
    "profile": { "name": "balanced", ... }
  }
}

shadi(shadi-ctl-12345)> /policy diff profile:strict
{
  "against": "profile:strict",
  "diff": { ... }
}
```

## Step 7 — Detach and exit

```
shadi(shadi-ctl-12345)> /detach
detached

shadi> /exit
```

Then press **Ctrl-C** in the first terminal to stop the demo agent.

## Available commands

shadi> /sessions                          # discover the running socket
shadi> /attach /var/folders/.../shadi-ctl-<PID>.sock

shadi(shadi-ctl-...)> /h                  # alias for /help
shadi(shadi-ctl-...)> /policy patch --help   # per-command help

shadi(shadi-ctl-...)> /policy patch --dry-run --add-allow-command npm
# previews JSON without sending

shadi(shadi-ctl-...)> /policy patch --add-allow-command npm
# shows confirmation prompt: apply this patch? [y/N]

shadi(shadi-ctl-...)> /policy patch --force --add-read /opt/tools
# skips prompt, returns pretty-printed JSON response

shadi(shadi-ctl-...)> /history --limit 5  # new command
shadi(shadi-ctl-...)> /s                  # alias for /status
shadi(shadi-ctl-...)> /q                  # alias for /exit| Command | Aliases | Description |
|---------|---------|-------------|
| `/help [cmd]` | `/h` | Show all commands, or detailed help for one |
| `/status` | `/s` | Show current session status |
| `/attach <path>` | | Attach to a running sandbox session |
| `/detach` | | Detach from the current session |
| `/sessions` | | Discover running SHADI control sockets |
| `/config` | | Show effective runtime configuration |
| `/policy query` | | Query the attached session's policy |
| `/policy patch` | | Patch the policy (see flags below) |
| `/policy explain` | | Explain resolved policy and sources |
| `/policy diff` | | Diff against a baseline profile |
| `/trace list` | | List recent trace entries |
| `/trace summary` | | Summarize traces by span name |
| `/history` | | Show command history |
| `/clear` | | Clear the screen |
| `/exit` | `/q`, `/quit` | Exit the shell |

Type `<cmd> --help` for per-command usage, e.g. `/policy patch --help`.

### Policy patch flags

```
--add-read PATH
--add-write PATH
--add-allow PATH
--add-allow-command CMD
--remove-allow-command CMD
--add-block-command CMD
--remove-block-command CMD
--add-net-allow DEST
--remove-net-allow DEST
--force           skip confirmation prompt
--dry-run         preview patch JSON without applying
```

## Files

| File | Purpose |
|------|---------|
| `demo_agent.sh` | Bash demo agent with blocked command, network, and file probes |
| `../shadi_demo_bot` | Rust shell ticker plus a full SHADI feature bot with sandbox, memory, secrets, and SLIM checks |
| `policy.json` | Demo policy: read-only /usr, network blocked, dangerous commands blocked |
