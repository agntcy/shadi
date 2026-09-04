import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./PolicyPanel.css";

interface LivePolicySnapshot {
  allow_read: string[];
  allow_write: string[];
  net_allow: string[];
  net_blocked: boolean;
  allow_command: string[];
  block_command: string[];
  staged_read: string[];
  staged_write: string[];
  staged_allow: string[];
  net_allow_live: string[] | null;
}

interface PolicyPatch {
  add_allow: string[];
  add_read: string[];
  add_write: string[];
  add_allow_command: string[];
  remove_allow_command: string[];
  add_block_command: string[];
  remove_block_command: string[];
  add_net_allow: string[];
  remove_net_allow: string[];
}

interface PatchAxisStatus {
  // "applied" | "unchanged" | "pending_restart" | "rejected", but the panel
  // only needs to display it, never branch on a specific value.
  [key: string]: unknown;
}

interface PolicyPatchResponse {
  accepted: boolean;
  filesystem: PatchAxisStatus;
  commands: PatchAxisStatus;
  network: PatchAxisStatus;
  message: string;
  pending_restart: string[];
}

const EMPTY_PATCH: PolicyPatch = {
  add_allow: [],
  add_read: [],
  add_write: [],
  add_allow_command: [],
  remove_allow_command: [],
  add_block_command: [],
  remove_block_command: [],
  add_net_allow: [],
  remove_net_allow: [],
};

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function axisLabel(status: PatchAxisStatus | undefined): string {
  if (!status) return "—";
  const value = Object.values(status)[0] ?? status;
  return typeof value === "string" ? value : JSON.stringify(value);
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="pl-error">{message}</p>;
}

function PolicyList({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="pl-list">
      <span className="pl-list-label">{label}</span>
      {items.length === 0 ? (
        <span className="pl-empty">none</span>
      ) : (
        <ul>
          {items.map((item) => (
            <li key={item}>
              <code>{item}</code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SnapshotView({ snapshot }: { snapshot: LivePolicySnapshot }) {
  return (
    <section className="pl-card">
      <h2>Effective policy</h2>
      <div className="pl-grid">
        <PolicyList label="Read" items={snapshot.allow_read} />
        <PolicyList label="Write" items={snapshot.allow_write} />
        <PolicyList label="Allowed commands" items={snapshot.allow_command} />
        <PolicyList label="Blocked commands" items={snapshot.block_command} />
        <PolicyList
          label={`Network allow (${snapshot.net_blocked ? "blocked by default" : "open by default"})`}
          items={snapshot.net_allow}
        />
        {snapshot.net_allow_live !== null && (
          <PolicyList label="Network allow (live proxy)" items={snapshot.net_allow_live} />
        )}
      </div>
      {(snapshot.staged_read.length > 0 ||
        snapshot.staged_write.length > 0 ||
        snapshot.staged_allow.length > 0) && (
        <div className="pl-staged">
          <h3>Staged, pending restart</h3>
          <div className="pl-grid">
            <PolicyList label="Read" items={snapshot.staged_read} />
            <PolicyList label="Write" items={snapshot.staged_write} />
            <PolicyList label="Allow" items={snapshot.staged_allow} />
          </div>
        </div>
      )}
    </section>
  );
}

function PatchForm({
  onSubmit,
  busy,
}: {
  onSubmit: (patch: PolicyPatch) => void;
  busy: boolean;
}) {
  const [addAllow, setAddAllow] = useState("");
  const [addRead, setAddRead] = useState("");
  const [addWrite, setAddWrite] = useState("");
  const [addNetAllow, setAddNetAllow] = useState("");
  const [addAllowCommand, setAddAllowCommand] = useState("");
  const [addBlockCommand, setAddBlockCommand] = useState("");

  function submit() {
    onSubmit({
      ...EMPTY_PATCH,
      add_allow: splitList(addAllow),
      add_read: splitList(addRead),
      add_write: splitList(addWrite),
      add_net_allow: splitList(addNetAllow),
      add_allow_command: splitList(addAllowCommand),
      add_block_command: splitList(addBlockCommand),
    });
    setAddAllow("");
    setAddRead("");
    setAddWrite("");
    setAddNetAllow("");
    setAddAllowCommand("");
    setAddBlockCommand("");
  }

  const hasInput =
    [addAllow, addRead, addWrite, addNetAllow, addAllowCommand, addBlockCommand].some(
      (s) => s.trim().length > 0,
    );

  return (
    <section className="pl-card">
      <h2>Patch</h2>
      <p className="pl-hint">
        Adds to the running session's policy. Filesystem changes here are usually staged until
        the sandboxed process restarts; network and command changes can take effect immediately —
        the response below says which.
      </p>
      <div className="pl-grid">
        <label className="pl-field">
          <span>Add read+write paths</span>
          <input value={addAllow} onChange={(e) => setAddAllow(e.target.value)} placeholder="/tmp/work" />
        </label>
        <label className="pl-field">
          <span>Add read-only paths</span>
          <input value={addRead} onChange={(e) => setAddRead(e.target.value)} />
        </label>
        <label className="pl-field">
          <span>Add write-only paths</span>
          <input value={addWrite} onChange={(e) => setAddWrite(e.target.value)} />
        </label>
        <label className="pl-field">
          <span>Add network allow (hosts)</span>
          <input
            value={addNetAllow}
            onChange={(e) => setAddNetAllow(e.target.value)}
            placeholder="api.example.com"
          />
        </label>
        <label className="pl-field">
          <span>Add allowed commands</span>
          <input value={addAllowCommand} onChange={(e) => setAddAllowCommand(e.target.value)} />
        </label>
        <label className="pl-field">
          <span>Add blocked commands</span>
          <input value={addBlockCommand} onChange={(e) => setAddBlockCommand(e.target.value)} />
        </label>
      </div>
      <button onClick={submit} disabled={busy || !hasInput}>
        {busy ? "Applying…" : "Apply patch"}
      </button>
    </section>
  );
}

function PatchResultView({ result }: { result: PolicyPatchResponse }) {
  return (
    <section className="pl-card">
      <h2>Patch result</h2>
      <p className={result.accepted ? "pl-accepted" : "pl-rejected"}>
        {result.accepted ? "Accepted" : "Rejected"}
        {result.message ? ` — ${result.message}` : ""}
      </p>
      <dl className="pl-axes">
        <dt>Filesystem</dt>
        <dd>{axisLabel(result.filesystem)}</dd>
        <dt>Commands</dt>
        <dd>{axisLabel(result.commands)}</dd>
        <dt>Network</dt>
        <dd>{axisLabel(result.network)}</dd>
      </dl>
      {result.pending_restart.length > 0 && (
        <p className="pl-hint">Needs a restart to take effect: {result.pending_restart.join(", ")}</p>
      )}
    </section>
  );
}

export function PolicyPanel() {
  const [sessionId, setSessionId] = useState("");
  const [attached, setAttached] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<LivePolicySnapshot | null>(null);
  const [patchResult, setPatchResult] = useState<PolicyPatchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async (socketPath: string) => {
    try {
      setSnapshot(await invoke<LivePolicySnapshot>("policy_query", { socketPath }));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (attached === null) return;
    refresh(attached);
    const timer = setInterval(() => refresh(attached), 4000);
    return () => clearInterval(timer);
  }, [attached, refresh]);

  async function onAttach() {
    const trimmed = sessionId.trim();
    if (!trimmed) {
      setError("Enter a session name or socket path.");
      return;
    }
    setError(null);
    setPatchResult(null);
    setAttached(trimmed);
  }

  async function onPatch(patch: PolicyPatch) {
    if (attached === null) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<PolicyPatchResponse>("policy_patch", {
        socketPath: attached,
        patch,
      });
      setPatchResult(result);
      await refresh(attached);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pl-panel">
      <section className="pl-card">
        <h2>Attach</h2>
        <p className="pl-hint">
          Same session name or socket path as the Sandbox tab — a session started with{" "}
          <code>shadictl --watch-policy</code> exposes one; a session launched from the Sandbox
          tab does not, since serving a control socket is shadictl's job.
        </p>
        <div className="pl-row">
          <input
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            placeholder="myagent, or /tmp/shadi-ctl-myagent.sock"
          />
          <button onClick={onAttach}>Attach</button>
        </div>
        <ErrorText message={error} />
      </section>

      {snapshot !== null && <SnapshotView snapshot={snapshot} />}
      {attached !== null && <PatchForm onSubmit={onPatch} busy={busy} />}
      {patchResult !== null && <PatchResultView result={patchResult} />}
    </div>
  );
}
