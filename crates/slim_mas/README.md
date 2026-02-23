# slim_mas

SLIM Multi-Agent System (MAS) moderator for SHADI.

This crate provides a minimal group registry and admission control for SLIM
participants using DIDs.

## Config (mas.toml)
```toml
[mas]
default_group = "secops-team"

[groups.secops-team]
moderator_did = "did:key:..."
members = [
  { did = "did:key:...", role = "human" },
  { did = "did:key:...", role = "agent" }
]
```

## CLI
```bash
cargo run -p slim_mas -- list-groups
cargo run -p slim_mas -- list-members --group secops-team
cargo run -p slim_mas -- admit --group secops-team --did did:key:... --role human
```
