# SHADI

Secure Host Agentic AI Dynamic Instantiation (SHADI) is a host runtime designed
for autonomous, multi-agent systems running on end devices. It is critical in
this setting because agents are long-lived, operate with real credentials, and
run on machines that can access sensitive local data. SHADI reduces the blast
radius of mistakes or compromise by enforcing identity checks, secrets access
gating, and OS-level restrictions.

### Why it matters on end devices

- **Least-privilege execution**: sandbox policies limit filesystem and network access.
- **Verified identity**: agents must pass DID/VC checks before touching secrets.
- **Local secrets hygiene**: secrets live in OS keystores and are zeroized in memory.
- **Secure agent-to-agent transport**: MLS-backed messaging protects content in transit.
- **Durable local memory**: SQLCipher-backed storage keeps contexts and long-term memory secure at rest.

### What SHADI provides

- Secure secrets storage for agents across platforms.
- OpenPGP key ingestion and DID derivation via `shadictl` (no OS `gpg` dependency).
- MLS-backed secure agent messaging via SLIM/A2A integration.
- Kernel-enforced sandboxing for agent processes.
- Encrypted local memory via SQLCipher.
- Python bindings for secrets, SQLCipher memory, and sandbox execution.
- A SecOps agent for security monitoring and reporting.

Use the navigation to find setup, security, CLI, and integration details.
