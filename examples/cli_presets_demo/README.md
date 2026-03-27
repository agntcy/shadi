# SHADI CLI Preset Demos

How to run `codex` and `copilot` under SHADI sandboxing with the
provided policy presets.

## Prerequisites

```bash
cargo build -p shadictl
npm install -g @openai/codex      # for the codex demo
npm install -g @github/copilot-cli  # for the copilot demo
```

---

## Codex

### Launch

> **`--watch-policy` is required** for `shadi shell` to discover the session.
> Without it no control socket is created and the session is invisible.

```bash
cargo run -p shadictl -- \
    --watch-policy \
    --policy policies/presets/codex.json \
    --read ~/.nvm \
    --allow ~/.codex \
    -- codex
```

On successful launch you will see:

```
network proxy (DNS-name enforcement gate): 127.0.0.1:<port>
control socket: /var/folders/…/shadi-ctl-<pid>.sock
```

### Attach from another terminal

```bash
cargo run -p shadictl -- shell
# then inside the shell:
/sessions      # lists the running session
/attach /var/folders/…/shadi-ctl-<pid>.sock
/status
```

### What the preset enforces

| Axis | Behaviour |
|---|---|
| Write paths | workspace (`.`) only |
| Network | `api.openai.com` via SOCKS5 proxy; all other hosts blocked |
| Blocked commands | `curl`, `wget`, `nc`, `netcat` |

---

## Copilot CLI

### Launch

```bash
cargo run -p shadictl -- \
    --watch-policy \
    --policy policies/presets/copilot-cli.json \
    --read ~/.nvm \
    --allow ~/.config/gh \
    -- copilot
```

### What the preset enforces

| Axis | Behaviour |
|---|---|
| Write paths | workspace (`.`) only |
| Network | `api.github.com`, `copilot-proxy.githubusercontent.com` via SOCKS5 proxy |
| Blocked commands | `curl`, `wget`, `nc`, `netcat` |

---

## Patching policy live (no restart)

With `--watch-policy` you can update net-allow entries at runtime.
Open a second terminal while the agent is running:

```bash
# Allow an extra network destination
cargo run -p shadictl -- policy patch --add-net-allow example.com

# Remove it again
cargo run -p shadictl -- policy patch --remove-net-allow example.com
```
