import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./SlimRoomsPanel.css";
import "./OwnerPanel.css";

// The channel owner (agntcy/shadi#421): the rooms this Desktop moderates are
// the human's. Agents ask over A2A to let someone in; standing rules decide
// most requests and the rest wait here.

interface OwnerStatus {
  running: boolean;
  owner_did: string | null;
  service: string | null;
  channels: string[];
}

interface InviteRequest {
  channel: string;
  invitee_name: string;
  invitee_did: string | null;
  action: "add" | "delete";
  requester: string;
  requester_human_did: string | null;
}

interface PendingAsk {
  id: number;
  request: InviteRequest;
  asked_at: number;
  expires_at: number;
}

interface AuditEntry {
  at: number;
  outcome: string;
  by: string;
  index?: number;
  channel: string;
  invitee_name: string;
  action: "add" | "delete";
  requester: string;
}

function describe(request: { action: string; invitee_name: string }): string {
  return `${request.action === "delete" ? "Remove" : "Let in"} ${request.invitee_name}`;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sl-error">{message}</p>;
}

function useNow(): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const timer = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

function StatusSection({
  status,
  onStart,
  busy,
}: {
  status: OwnerStatus | null;
  onStart: () => void;
  busy: boolean;
}) {
  return (
    <section className="sl-card">
      <h2>Channel owner</h2>
      <div className="sl-row">
        <span className={`sl-dot ${status?.running ? "sl-dot-on" : "sl-dot-off"}`} />
        <span>{status?.running ? `Serving requests at ${status.service}` : "Not serving requests"}</span>
        {!status?.running && (
          <button onClick={onStart} disabled={busy}>
            {busy ? "Starting…" : "Start"}
          </button>
        )}
      </div>
      {status?.owner_did && (
        <p className="sl-muted">
          Owner <span className="sl-did">{status.owner_did}</span>
        </p>
      )}
      <p className="sl-muted">
        {status && status.channels.length > 0
          ? `Rooms you own: ${status.channels.join(", ")}`
          : "You own no rooms yet. Create one in the Rooms tab."}
      </p>
    </section>
  );
}

function InboxSection({ running }: { running: boolean }) {
  const [asks, setAsks] = useState<PendingAsk[]>([]);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();

  const refresh = useCallback(async () => {
    if (!running) return;
    try {
      setAsks(await invoke<PendingAsk[]>("owner_pending"));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [running]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [refresh]);

  async function decide(command: "owner_approve" | "owner_deny", askId: number) {
    setError(null);
    try {
      await invoke(command, { askId });
    } catch (e) {
      setError(String(e));
    }
    refresh();
  }

  return (
    <section className="sl-card">
      <h2>Waiting for you</h2>
      <ErrorText message={error} />
      {asks.length === 0 ? (
        <p className="sl-muted">No requests are waiting.</p>
      ) : (
        <table className="sl-table">
          <thead>
            <tr>
              <th>Room</th>
              <th>Request</th>
              <th>Asked by</th>
              <th>Denied in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {asks.map((ask) => (
              <tr key={ask.id}>
                <td>{ask.request.channel}</td>
                <td>{describe(ask.request)}</td>
                <td className="sl-did">{ask.request.requester}</td>
                <td>{Math.max(0, ask.expires_at - now)}s</td>
                <td className="ow-actions">
                  <button onClick={() => decide("owner_approve", ask.id)}>Allow</button>
                  <button onClick={() => decide("owner_deny", ask.id)}>Deny</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function RulesSection() {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    invoke<string>("owner_policy_get")
      .then(setText)
      .catch((e) => setError(String(e)));
  }, []);

  async function onSave() {
    setError(null);
    setSaved(false);
    try {
      await invoke("owner_policy_set", { policy: text });
      setSaved(true);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Standing rules</h2>
      <p className="sl-muted">
        The first matching rule decides; with none, <code>default</code> does
        (ask when omitted). Rules match on <code>channel</code>, <code>invitee</code>,{" "}
        <code>requested_by</code>, <code>requested_by_human</code> and <code>action</code>{" "}
        (<code>add</code> or <code>delete</code>; a rule without one decides only additions).
      </p>
      <textarea
        className="ow-rules"
        value={text}
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          setSaved(false);
        }}
      />
      <div className="sl-row">
        <button onClick={onSave}>Save</button>
        {saved && <span className="sl-muted">Saved.</span>}
      </div>
      <ErrorText message={error} />
    </section>
  );
}

function AuditSection() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setEntries(await invoke<AuditEntry[]>("owner_audit"));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <section className="sl-card">
      <h2>Audit trail</h2>
      <ErrorText message={error} />
      {entries.length === 0 ? (
        <p className="sl-muted">No decisions yet.</p>
      ) : (
        <table className="sl-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Outcome</th>
              <th>Decided by</th>
              <th>Room</th>
              <th>Request</th>
              <th>Asked by</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i}>
                <td>{new Date(e.at * 1000).toLocaleString()}</td>
                <td>{e.outcome}</td>
                <td>{e.by === "rule" ? `rule ${e.index}` : e.by.replace("_", " ")}</td>
                <td>{e.channel}</td>
                <td>{describe(e)}</td>
                <td className="sl-did">{e.requester}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function OwnerPanel() {
  const [status, setStatus] = useState<OwnerStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    invoke<OwnerStatus>("owner_status")
      .then(setStatus)
      .catch((e) => setError(String(e)));
  }, []);

  async function onStart() {
    setBusy(true);
    setError(null);
    try {
      setStatus(await invoke<OwnerStatus>("owner_start"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="sl-panel">
      <StatusSection status={status} onStart={onStart} busy={busy} />
      <ErrorText message={error} />
      <InboxSection running={status?.running ?? false} />
      <RulesSection />
      <AuditSection />
    </div>
  );
}
