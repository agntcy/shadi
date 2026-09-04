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

interface PolicyDescription {
  allow: string[];
  read: string[];
  write: string[];
  net_block: boolean;
  net_allow: string[];
  platform_profile: string;
  allow_command: string[];
  block_command: string[];
}

interface PolicyInputs {
  profile: string | null;
  policy_file: string | null;
  allow: string[];
  read: string[];
  write: string[];
  net_block: boolean;
  net_allow: string[];
  allow_command: string[];
}

interface PolicyExplanation {
  effective: PolicyDescription;
  sources: {
    profile: string;
    profile_defaults: { allow: string[]; read: string[]; write: string[]; net_block: boolean };
    policy_file: { path: string; values: Record<string, unknown> } | null;
    overrides: {
      allow: string[];
      read: string[];
      write: string[];
      net_block: boolean;
      net_allow: string[];
      allow_command: string[];
    };
  };
  live: LivePolicySnapshot | null;
}

interface PolicyFieldDiff {
  field: string;
  current: string[];
  baseline: string[];
}

interface PolicyDiffResult {
  equivalent: boolean;
  changed: PolicyFieldDiff[];
}

const PROFILES = ["strict", "balanced", "connected"] as const;

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

function ResolveSection({ attached }: { attached: string | null }) {
  const [profile, setProfile] = useState<string>("balanced");
  const [policyFile, setPolicyFile] = useState("");
  const [allow, setAllow] = useState("");
  const [read, setRead] = useState("");
  const [write, setWrite] = useState("");
  const [netBlock, setNetBlock] = useState(false);
  const [netAllow, setNetAllow] = useState("");
  const [baseline, setBaseline] = useState<string>("strict");
  const [explanation, setExplanation] = useState<PolicyExplanation | null>(null);
  const [diff, setDiff] = useState<PolicyDiffResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function currentInputs(): PolicyInputs {
    return {
      profile,
      policy_file: policyFile.trim() || null,
      allow: splitList(allow),
      read: splitList(read),
      write: splitList(write),
      net_block: netBlock,
      net_allow: splitList(netAllow),
      allow_command: [],
    };
  }

  async function run(what: "explain" | "diff") {
    setBusy(true);
    setError(null);
    try {
      if (what === "explain") {
        setDiff(null);
        setExplanation(
          await invoke<PolicyExplanation>("policy_explain", {
            inputs: currentInputs(),
            socketPath: attached,
          }),
        );
      } else {
        setExplanation(null);
        setDiff(
          await invoke<PolicyDiffResult>("policy_diff", {
            inputs: currentInputs(),
            baselineProfile: baseline,
          }),
        );
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="pl-card">
        <h2>Resolve from inputs</h2>
        <p className="pl-hint">
          What a profile, a policy file and these paths resolve to — answered without a running
          session, so you can check a policy before launching anything.
          {attached !== null && " The attached session's live policy is shown alongside it."}
        </p>
        <div className="pl-grid">
          <label className="pl-field">
            <span>Profile</span>
            <select value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
          <label className="pl-field">
            <span>Policy file (optional)</span>
            <input
              value={policyFile}
              onChange={(e) => setPolicyFile(e.target.value)}
              placeholder="/path/to/policy.json"
            />
          </label>
          <label className="pl-field">
            <span>Read+write paths</span>
            <input value={allow} onChange={(e) => setAllow(e.target.value)} placeholder="/tmp/work" />
          </label>
          <label className="pl-field">
            <span>Read-only paths</span>
            <input value={read} onChange={(e) => setRead(e.target.value)} />
          </label>
          <label className="pl-field">
            <span>Write-only paths</span>
            <input value={write} onChange={(e) => setWrite(e.target.value)} />
          </label>
          <label className="pl-field">
            <span>Network allow (hosts)</span>
            <input value={netAllow} onChange={(e) => setNetAllow(e.target.value)} />
          </label>
        </div>
        <label className="pl-check">
          <input type="checkbox" checked={netBlock} onChange={(e) => setNetBlock(e.target.checked)} />
          <span>Block network regardless of the profile</span>
        </label>
        <div className="pl-row">
          <button onClick={() => run("explain")} disabled={busy}>
            Explain
          </button>
          <button onClick={() => run("diff")} disabled={busy}>
            Diff against
          </button>
          <select value={baseline} onChange={(e) => setBaseline(e.target.value)}>
            {PROFILES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>
        <ErrorText message={error} />
      </section>

      {explanation !== null && <ExplanationView explanation={explanation} />}
      {diff !== null && <DiffView diff={diff} baseline={baseline} />}
    </>
  );
}

function ExplanationView({ explanation }: { explanation: PolicyExplanation }) {
  const { effective, sources, live } = explanation;
  return (
    <section className="pl-card">
      <h2>Effective policy</h2>
      <div className="pl-grid">
        <PolicyList label="Read+write" items={effective.allow} />
        <PolicyList label="Read-only" items={effective.read} />
        <PolicyList label="Write-only" items={effective.write} />
        <PolicyList
          label={`Network allow (${effective.net_block ? "blocked by default" : "open by default"})`}
          items={effective.net_allow}
        />
        <PolicyList label="Allowed commands" items={effective.allow_command} />
        <PolicyList label="Blocked commands" items={effective.block_command} />
      </div>
      <p className="pl-hint">Platform sandbox profile: {effective.platform_profile}</p>

      <div className="pl-staged">
        <h3>Where it came from</h3>
        <div className="pl-grid">
          <PolicyList
            label={`Profile "${sources.profile}" grants`}
            items={[
              ...sources.profile_defaults.allow,
              ...sources.profile_defaults.read,
              ...sources.profile_defaults.write,
            ]}
          />
          <PolicyList
            label={sources.policy_file ? `File ${sources.policy_file.path}` : "Policy file"}
            items={sources.policy_file ? [JSON.stringify(sources.policy_file.values)] : []}
          />
          <PolicyList
            label="Your overrides"
            items={[
              ...sources.overrides.allow,
              ...sources.overrides.read,
              ...sources.overrides.write,
              ...sources.overrides.net_allow,
            ]}
          />
        </div>
      </div>

      {live !== null && (
        <div className="pl-staged">
          <h3>The attached session right now</h3>
          <p className="pl-hint">
            A session patched since it started will differ from the resolved policy above.
          </p>
          <div className="pl-grid">
            <PolicyList label="Read" items={live.allow_read} />
            <PolicyList label="Write" items={live.allow_write} />
            <PolicyList label="Network allow" items={live.net_allow} />
          </div>
        </div>
      )}
    </section>
  );
}

function DiffView({ diff, baseline }: { diff: PolicyDiffResult; baseline: string }) {
  return (
    <section className="pl-card">
      <h2>Diff against {baseline}</h2>
      {diff.equivalent ? (
        <p className="pl-accepted">Identical to the {baseline} profile.</p>
      ) : (
        <div className="pl-grid">
          {diff.changed.map((field) => (
            <div key={field.field} className="pl-list">
              <span className="pl-list-label">{field.field}</span>
              <PolicyList label="this policy" items={field.current} />
              <PolicyList label={baseline} items={field.baseline} />
            </div>
          ))}
        </div>
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
      <ResolveSection attached={attached} />
    </div>
  );
}
