import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./SandboxPanel.css";

interface SandboxSession {
  name: string;
  session_id: string;
  pid: number | null;
  launched_here: boolean;
}

interface SandboxStatus {
  session: SandboxSession;
  running: boolean;
  uptime_secs: number | null;
  command: string[];
  rss_bytes: number | null;
}

const PROFILES = ["strict", "balanced", "connected"] as const;
type Profile = (typeof PROFILES)[number];

/// What each profile grants, shown next to the picker so the choice is not a
/// guess. Mirrors SandboxProfile::defaults in shadi_sandbox.
const PROFILE_SUMMARY: Record<Profile, string> = {
  strict: "Working directory only, network off",
  balanced: "Working directory writable, wider reads, network off",
  connected: "Balanced, network on",
};

/// Sessions are polled rather than pushed: the control socket answers one
/// request per connection and has no subscribe verb.
const REFRESH_MS = 4000;

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sb-error">{message}</p>;
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ${seconds % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function formatBytes(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`;
}

function LaunchSection({ onLaunched }: { onLaunched: () => void }) {
  const [command, setCommand] = useState("");
  const [sessionName, setSessionName] = useState("");
  const [profile, setProfile] = useState<Profile>("balanced");
  const [allow, setAllow] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onLaunch() {
    const argv = command.trim().split(/\s+/).filter(Boolean);
    if (argv.length === 0) {
      setError("Enter a command to run.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await invoke<SandboxSession>("sandbox_launch", {
        request: {
          command: argv,
          session_name: sessionName.trim() || null,
          policy: {
            allow: allow.trim() ? allow.split(",").map((p) => p.trim()).filter(Boolean) : [],
            read: [],
            write: [],
            net_block: false,
            net_allow: [],
            profile,
          },
        },
      });
      setCommand("");
      setSessionName("");
      onLaunched();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sb-card">
      <h2>Launch a sandboxed process</h2>
      <label className="sb-field">
        <span>Command</span>
        <input
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          placeholder="npm test"
        />
      </label>
      <div className="sb-row">
        <label className="sb-field">
          <span>Profile</span>
          <select value={profile} onChange={(e) => setProfile(e.target.value as Profile)}>
            {PROFILES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label className="sb-field">
          <span>Session name (optional)</span>
          <input
            value={sessionName}
            onChange={(e) => setSessionName(e.target.value)}
            placeholder="derived from the pid"
          />
        </label>
      </div>
      <p className="sb-hint">{PROFILE_SUMMARY[profile]}</p>
      <label className="sb-field">
        <span>Extra read+write paths (comma separated)</span>
        <input value={allow} onChange={(e) => setAllow(e.target.value)} placeholder="/tmp/work" />
      </label>
      <button onClick={onLaunch} disabled={busy}>
        {busy ? "Launching…" : "Launch"}
      </button>
      <ErrorText message={error} />
    </section>
  );
}

function StatusSection({
  status,
  onDetach,
  onKill,
}: {
  status: SandboxStatus;
  onDetach: () => void;
  onKill: () => void;
}) {
  const { session } = status;
  return (
    <section className="sb-card">
      <h2>{session.name}</h2>
      <dl className="sb-status">
        <dt>State</dt>
        <dd>
          <span className={status.running ? "sb-pill sb-pill-live" : "sb-pill sb-pill-stopped"}>
            {status.running ? "running" : "stopped"}
          </span>
        </dd>
        <dt>Origin</dt>
        <dd>{session.launched_here ? "launched here" : "discovered"}</dd>
        {session.pid !== null && (
          <>
            <dt>PID</dt>
            <dd>{session.pid}</dd>
          </>
        )}
        {status.uptime_secs !== null && (
          <>
            <dt>Uptime</dt>
            <dd>{formatUptime(status.uptime_secs)}</dd>
          </>
        )}
        {status.rss_bytes !== null && (
          <>
            <dt>Memory</dt>
            <dd>{formatBytes(status.rss_bytes)}</dd>
          </>
        )}
        {status.command.length > 0 && (
          <>
            <dt>Command</dt>
            <dd>
              <code>{status.command.join(" ")}</code>
            </dd>
          </>
        )}
        <dt>Endpoint</dt>
        <dd>
          <code className="sb-endpoint">{session.session_id}</code>
        </dd>
      </dl>
      {!session.launched_here && (
        <p className="sb-hint">
          Started outside this app, so its command line and uptime are not available — a control
          socket does not report them.
        </p>
      )}
      <div className="sb-actions">
        <button onClick={onDetach}>Detach</button>
        <button className="sb-danger" onClick={onKill}>
          Kill
        </button>
      </div>
    </section>
  );
}

export function SandboxPanel() {
  const [sessions, setSessions] = useState<SandboxSession[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [status, setStatus] = useState<SandboxStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSessions(await invoke<SandboxSession[]>("sandbox_list_sessions"));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  // Keep the open session's status fresh, and drop the selection if it goes.
  useEffect(() => {
    if (selected === null) {
      setStatus(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const next = await invoke<SandboxStatus>("sandbox_status", { sessionId: selected });
        if (!cancelled) setStatus(next);
      } catch {
        if (!cancelled) {
          setStatus(null);
          setSelected(null);
        }
      }
    };
    poll();
    const timer = setInterval(poll, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [selected]);

  async function onAttach(sessionId: string) {
    setError(null);
    try {
      setStatus(await invoke<SandboxStatus>("sandbox_attach", { sessionId }));
      setSelected(sessionId);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onDetach() {
    if (selected === null) return;
    try {
      await invoke("sandbox_detach", { sessionId: selected });
    } catch (e) {
      setError(String(e));
    }
    setSelected(null);
  }

  async function onKill(sessionId: string) {
    setError(null);
    try {
      await invoke("sandbox_kill", { sessionId });
      if (selected === sessionId) setSelected(null);
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="sb-panel">
      <LaunchSection onLaunched={refresh} />

      <section className="sb-card">
        <h2>Sessions</h2>
        {sessions.length === 0 ? (
          <p className="sb-hint">
            No sandbox sessions running. Launch one above, or start one elsewhere with{" "}
            <code>shadictl --watch-policy</code> and it will appear here.
          </p>
        ) : (
          <ul className="sb-sessions">
            {sessions.map((s) => (
              <li key={s.session_id} className={s.session_id === selected ? "sb-selected" : ""}>
                <div className="sb-session-id">
                  <strong>{s.name}</strong>
                  <span className="sb-tag">{s.launched_here ? "launched here" : "discovered"}</span>
                  {s.pid !== null && <span className="sb-tag">pid {s.pid}</span>}
                </div>
                <div className="sb-actions">
                  <button onClick={() => onAttach(s.session_id)}>Attach</button>
                  <button className="sb-danger" onClick={() => onKill(s.session_id)}>
                    Kill
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
        <ErrorText message={error} />
      </section>

      {status !== null && (
        <StatusSection status={status} onDetach={onDetach} onKill={() => onKill(status.session.session_id)} />
      )}
    </div>
  );
}
