import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./OnboardingPanel.css";

interface SshKeyCandidate {
  path: string;
  comment: string | null;
  encrypted: boolean;
  human_did: string | null;
}

interface AgentIdentity {
  agent_name: string;
  did: string;
}

interface TrustedHuman {
  github_handle: string;
  human_did: string;
}

interface BootstrapStatus {
  ready: boolean;
  human_did: string | null;
  github_handle: string | null;
  agents: AgentIdentity[];
  local_agent: string | null;
  endpoint: string;
  mtls_ready: boolean;
  trusted: TrustedHuman[];
  seed_stored: boolean;
}

const DEFAULT_AGENTS = "avatar, claude-code, codex";

function Did({ value }: { value: string }) {
  return <code className="ob-did">{value}</code>;
}

export function OnboardingPanel() {
  const [status, setStatus] = useState<BootstrapStatus | null>(null);
  const [keys, setKeys] = useState<SshKeyCandidate[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [passphrase, setPassphrase] = useState("");
  const [agentNames, setAgentNames] = useState(DEFAULT_AGENTS);
  const [handle, setHandle] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [trustHandle, setTrustHandle] = useState("");
  const [trustError, setTrustError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, k] = await Promise.all([
        invoke<BootstrapStatus>("identity_status"),
        invoke<SshKeyCandidate[]>("identity_discover_ssh_keys"),
      ]);
      setStatus(s);
      setKeys(k);
      setSelected((prev) => prev || k[0]?.path || "");
      setEndpoint((prev) => prev || s.endpoint);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const chosen = keys.find((k) => k.path === selected);
  const names = agentNames
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  async function onBootstrap() {
    setBusy(true);
    setError(null);
    try {
      const next = await invoke<BootstrapStatus>("identity_bootstrap", {
        request: {
          key_path: selected,
          passphrase: passphrase || null,
          agent_names: names,
          local_agent: names[0],
          endpoint: endpoint || null,
          github_handle: handle.trim().replace(/^@/, "") || null,
        },
      });
      setStatus(next);
      setPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onTrust() {
    setBusy(true);
    setTrustError(null);
    try {
      const trusted = await invoke<TrustedHuman[]>("identity_trust_github_handle", {
        handle: trustHandle,
      });
      setStatus((s) => (s ? { ...s, trusted } : s));
      setTrustHandle("");
    } catch (e) {
      setTrustError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onUntrust(h: string) {
    setBusy(true);
    setTrustError(null);
    try {
      const trusted = await invoke<TrustedHuman[]>("identity_untrust_github_handle", {
        handle: h,
      });
      setStatus((s) => (s ? { ...s, trusted } : s));
    } catch (e) {
      setTrustError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="ob-panel">
      <section className="ob-card">
        <h2>Identity</h2>
        {status?.ready ? (
          <>
            <p className="ob-row">
              <span className="ob-ok">ready</span>
              <span className="ob-muted">
                mTLS {status.mtls_ready ? "generated" : "missing"} · root{" "}
                {status.seed_stored ? "in secret store" : "missing"} · {status.endpoint}
              </span>
            </p>
            <p>
              Human <Did value={status.human_did!} />
              {status.github_handle && (
                <span className="ob-verified"> verified as @{status.github_handle}</span>
              )}
            </p>
            <table className="ob-table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>DID</th>
                </tr>
              </thead>
              <tbody>
                {status.agents.map((a) => (
                  <tr key={a.agent_name}>
                    <td>
                      {a.agent_name}
                      {a.agent_name === status.local_agent && (
                        <span className="ob-tag">this app</span>
                      )}
                    </td>
                    <td>
                      <Did value={a.did} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="ob-muted ob-note">
              Re-running below re-derives from the same key and leaves existing
              certificates alone.
            </p>
          </>
        ) : (
          <p className="ob-muted ob-note">
            Not set up yet. Pick an SSH Ed25519 key below: its public half becomes
            your human DID, its private half derives one DID per agent. mTLS
            material and the derivation root are created for you, so no
            environment variables are needed.
          </p>
        )}
      </section>

      <section className="ob-card">
        <h2>{status?.ready ? "Re-run setup" : "Set up"}</h2>
        {keys.length === 0 ? (
          <>
            <p className="ob-muted">
              No Ed25519 SSH key found in <code>~/.ssh</code>. Create one with{" "}
              <code>ssh-keygen -t ed25519</code>, then Refresh. Only{" "}
              <code>ssh-ed25519</code> works — RSA and hardware (FIDO) keys
              cannot root a derivation.
            </p>
            <div className="ob-row">
              <button onClick={refresh} disabled={busy}>
                Refresh
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="ob-row">
              <select
                className="ob-input"
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
              >
                {keys.map((k) => (
                  <option key={k.path} value={k.path}>
                    {k.path}
                    {k.comment ? ` (${k.comment})` : ""}
                    {k.encrypted ? " — encrypted" : ""}
                  </option>
                ))}
              </select>
            </div>
            {chosen?.human_did && (
              <p className="ob-muted">
                Human DID would be <Did value={chosen.human_did} />
              </p>
            )}
            {chosen?.encrypted && (
              <div className="ob-row">
                <input
                  className="ob-input"
                  type="password"
                  placeholder="Key passphrase"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>
            )}
            <div className="ob-row">
              <input
                className="ob-input"
                placeholder="Agents to derive, comma-separated"
                value={agentNames}
                onChange={(e) => setAgentNames(e.target.value)}
              />
            </div>
            <div className="ob-row">
              <input
                className="ob-input"
                placeholder="GitHub handle (optional — verifies the key is published there)"
                value={handle}
                onChange={(e) => setHandle(e.target.value)}
              />
              <input
                className="ob-input ob-input-narrow"
                placeholder="SLIM endpoint"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
              />
            </div>
            <div className="ob-row">
              <button
                onClick={onBootstrap}
                disabled={busy || !selected || names.length === 0}
              >
                {busy ? "Setting up…" : status?.ready ? "Re-run" : "Set up identity"}
              </button>
              <button onClick={refresh} disabled={busy}>
                Refresh
              </button>
              {names.length > 0 && (
                <span className="ob-muted">
                  this app will act as <strong>{names[0]}</strong>
                </span>
              )}
            </div>
          </>
        )}
        {error && <p className="ob-error">{error}</p>}
      </section>

      <section className="ob-card">
        <h2>Trusted people</h2>
        <p className="ob-muted ob-note">
          Name a GitHub account instead of pasting a DID: their published{" "}
          <code>ssh-ed25519</code> key gives their human DID. This records who you
          accept — their agents' DIDs derive from their private key, so admitting
          those still needs the DIDs they share with you (agntcy/shadi#141).
        </p>
        <div className="ob-row">
          <input
            className="ob-input"
            placeholder="GitHub handle, e.g. octocat"
            value={trustHandle}
            onChange={(e) => setTrustHandle(e.target.value)}
          />
          <button onClick={onTrust} disabled={busy || !trustHandle.trim()}>
            {busy ? "Checking…" : "Trust handle"}
          </button>
        </div>
        {trustError && <p className="ob-error">{trustError}</p>}
        {status && status.trusted.length > 0 ? (
          <table className="ob-table">
            <thead>
              <tr>
                <th>Handle</th>
                <th>Human DID</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {status.trusted.map((t) => (
                <tr key={t.github_handle}>
                  <td>@{t.github_handle}</td>
                  <td>
                    <Did value={t.human_did} />
                  </td>
                  <td>
                    <button
                      className="ob-small"
                      onClick={() => onUntrust(t.github_handle)}
                      disabled={busy}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="ob-muted">Nobody trusted yet.</p>
        )}
      </section>
    </div>
  );
}
