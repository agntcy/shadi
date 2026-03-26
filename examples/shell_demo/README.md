# SHADI Interactive Shell Demo

This walkthrough demonstrates how to use `shadictl shell` to inspect and
manage a sandboxed agent process in real time.

## Prerequisites

```bash
cargo build -p shadictl
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
[demo-agent] tick    1  14:30:00
[demo-agent] tick    2  14:30:03
```

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
  ____  _   _   /^\  ____ ___ 
 / ___|| | | | /(_)\ |  _ \_ _|
 \___ \| |_| || |_| || | | | |
  ___) |  _  | \   / | |_| | |
 |____/|_| |_|  \_/  |____/___|

  Sandbox Hardening for AI Developer Infrastructure  v0.1.0
  type '/help' for commands, '/exit' to quit, '<cmd> --help' for details

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

Unblock a command (interactive confirmation prompt; pass `--force` to skip):

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

Apply without prompt (`--force`):

```
shadi(shadi-ctl-12345)> /policy patch --force --add-allow-command npm
{
  "accepted": true,
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
  "message": "patch accepted; filesystem require process restart",
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
| `demo_agent.sh` | Bash ticker (runs inside Minimal sandbox profile) |
| `demo_agent.py` | Python ticker (needs `--read ~/.pyenv` on macOS with pyenv) |
| `policy.json` | Demo policy: read-only /usr, network blocked, dangerous commands blocked |
