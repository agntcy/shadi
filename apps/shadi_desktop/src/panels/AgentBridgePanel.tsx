import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { explicitMemberSpec, slimAgentSpec, useRooms } from "../shared/rooms";
import type { SlimGroupInfo } from "../shared/rooms";
import "./AgentBridgePanel.css";

interface AdapterInfo {
  agent_id: string;
  tool: string;
  endpoint: string | null;
}

interface ContextPacketSummary {
  id: string;
  source_agent: string;
  conversation_messages: number;
  artifacts: number;
}

interface DelegateResult {
  response: string;
  elapsed_ms: number;
}

interface CoordinateRoundEvent {
  round: number;
  agent: string;
  kind: string;
  summary: string;
}

interface CoordinateResult {
  winning_agent: string | null;
  artifact: string | null;
  applied: number;
  finalized: number;
  rejected: number;
  deferred: number;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="ab-error">{message}</p>;
}

/// Admits a discovered adapter into a room without retyping its DID or
/// endpoint (agntcy/shadi#135). `agentbridge_list_adapters` already returns
/// `{agent_id, tool: did, endpoint}`, so this builds the `explicit:` spec from
/// what's in hand — no second Directory round-trip — and passes
/// `kind: "agent"` so the invite isn't mislabelled human by the spec-prefix
/// default.
function AddToRoom({ adapter }: { adapter: AdapterInfo }) {
  const { rooms, refresh } = useRooms();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const moderated = rooms.filter((r) => r.role === "moderator");

  async function add(channel: string) {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      await invoke<SlimGroupInfo>("slim_group_invite", {
        channel,
        memberSpec: explicitMemberSpec(
          adapter.agent_id,
          adapter.tool,
          adapter.endpoint,
        ),
        dirServer: null,
        kind: "agent",
      });
      setDone(channel);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (moderated.length === 0) {
    return <span className="ab-hint">no moderated room</span>;
  }

  return (
    <>
      <select
        className="ab-select"
        disabled={busy}
        value=""
        onChange={(e) => {
          if (e.target.value) add(e.target.value);
        }}
      >
        <option value="">{busy ? "Adding…" : "Add to…"}</option>
        {moderated.map((r) => (
          <option key={r.channel} value={r.channel}>
            {r.channel}
          </option>
        ))}
      </select>
      {done && <span className="ab-ok"> ✓ {done}</span>}
      {error && <span className="ab-error"> {error}</span>}
    </>
  );
}

function AdapterList() {
  const [dirServer, setDirServer] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [localOnly, setLocalOnly] = useState(false);
  const [adapters, setAdapters] = useState<AdapterInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onList() {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<AdapterInfo[]>("agentbridge_list_adapters", {
        localOnly,
        dirServer,
        ghToken: ghToken || null,
      });
      setAdapters(result);
    } catch (e) {
      setError(String(e));
      setAdapters(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="ab-card">
      <h2>Adapters</h2>
      <div className="ab-row">
        <label>
          <input
            type="checkbox"
            checked={localOnly}
            onChange={(e) => setLocalOnly(e.target.checked)}
          />
          Local only
        </label>
        <input
          className="ab-input"
          placeholder="DIR server address"
          value={dirServer}
          onChange={(e) => setDirServer(e.target.value)}
          disabled={localOnly}
        />
        <input
          className="ab-input"
          placeholder="GitHub token (optional)"
          type="password"
          value={ghToken}
          onChange={(e) => setGhToken(e.target.value)}
          disabled={localOnly}
        />
        <button onClick={onList} disabled={loading}>
          {loading ? "Listing…" : "List adapters"}
        </button>
      </div>
      <ErrorText message={error} />
      {adapters && (
        <table className="ab-table">
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Tool / DID</th>
              <th>Endpoint</th>
              <th>Add to room</th>
            </tr>
          </thead>
          <tbody>
            {adapters.map((a) => (
              <tr key={a.agent_id}>
                <td>{a.agent_id}</td>
                <td className="ab-did">{a.tool}</td>
                <td>{a.endpoint ?? "—"}</td>
                <td>
                  <AddToRoom adapter={a} />
                </td>
              </tr>
            ))}
            {adapters.length === 0 && (
              <tr>
                <td colSpan={4}>No adapters found.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}

function HandoffForm() {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [savePath, setSavePath] = useState("");
  const [summary, setSummary] = useState<ContextPacketSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onHandoff() {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<ContextPacketSummary>("agentbridge_handoff", {
        from,
        to,
        savePath: savePath || null,
      });
      setSummary(result);
    } catch (e) {
      setError(String(e));
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="ab-card">
      <h2>Handoff</h2>
      <div className="ab-row">
        <input
          className="ab-input"
          placeholder="From command (generic-stdio source)"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />
        <input
          className="ab-input"
          placeholder="To command (generic-stdio destination)"
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />
      </div>
      <div className="ab-row">
        <input
          className="ab-input"
          placeholder="Save path (optional)"
          value={savePath}
          onChange={(e) => setSavePath(e.target.value)}
        />
        <button onClick={onHandoff} disabled={loading || !from || !to}>
          {loading ? "Handing off…" : "Hand off context"}
        </button>
      </div>
      <ErrorText message={error} />
      {summary && (
        <ul className="ab-summary">
          <li>Packet ID: {summary.id}</li>
          <li>Source agent: {summary.source_agent}</li>
          <li>Conversation messages: {summary.conversation_messages}</li>
          <li>Artifacts: {summary.artifacts}</li>
        </ul>
      )}
    </section>
  );
}

function DelegateForm() {
  const [prompt, setPrompt] = useState("");
  const [to, setTo] = useState("");
  const [agentId, setAgentId] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [result, setResult] = useState<DelegateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onDelegate() {
    setLoading(true);
    setError(null);
    try {
      const res = await invoke<DelegateResult>("agentbridge_delegate", {
        prompt,
        to,
        agentId,
        endpoint,
      });
      setResult(res);
    } catch (e) {
      setError(String(e));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="ab-card">
      <h2>Delegate</h2>
      <p className="ab-hint ab-note">
        Sends one prompt to one peer and shows the reply — a manual probe, not
        the room's ongoing conversation.
      </p>
      <textarea
        className="ab-textarea"
        placeholder="Prompt"
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
      />
      <div className="ab-row">
        <input
          className="ab-input"
          placeholder="To (peer agent ID)"
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />
        <input
          className="ab-input"
          placeholder="Local agent ID"
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
        />
        <input
          className="ab-input"
          placeholder="SLIM endpoint"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
        />
        <button onClick={onDelegate} disabled={loading || !prompt || !to}>
          {loading ? "Delegating…" : "Delegate"}
        </button>
      </div>
      <ErrorText message={error} />
      {result && (
        <div className="ab-response">
          <p className="ab-response-meta">{result.elapsed_ms}ms</p>
          <pre>{result.response}</pre>
        </div>
      )}
    </section>
  );
}

function CoordinateVisualizer() {
  // Prefilled with a runnable demo default — matches
  // examples/agentbridge_demo's own goal, and works with zero extra
  // infra (no SLIM node, no DID setup) as long as the listed CLIs are
  // installed locally.
  const [goal, setGoal] = useState(
    "Write fibonacci(n: u64) -> u64 with memoization and doctest",
  );
  const [agentSpecs, setAgentSpecs] = useState("claude-code, codex, copilot");
  const [quorum, setQuorum] = useState(2);
  const [maxRounds, setMaxRounds] = useState(3);
  const [requireHuman, setRequireHuman] = useState(false);
  const [slimEndpoint, setSlimEndpoint] = useState("");
  const [rounds, setRounds] = useState<CoordinateRoundEvent[]>([]);
  const [result, setResult] = useState<CoordinateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const roundsEndRef = useRef<HTMLDivElement | null>(null);
  const { rooms } = useRooms();

  useEffect(() => {
    roundsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [rounds]);

  /// Replace the free-typed specs with this room's agent members
  /// (agntcy/shadi#135). Humans are skipped — they participate through their
  /// own harness, not as a coordination tool endpoint.
  function applyRoomRoster(channel: string) {
    const room = rooms.find((r) => r.channel === channel);
    if (!room) return;
    const specs = room.members
      .filter((m) => m.kind !== "human")
      .map(slimAgentSpec);
    if (specs.length === 0) {
      setError(`room ${channel} has no agent members to coordinate`);
      return;
    }
    setError(null);
    setAgentSpecs(specs.join(", "));
    setQuorum(Math.min(quorum, specs.length));
  }

  async function onCoordinate() {
    setRunning(true);
    setError(null);
    setResult(null);
    setRounds([]);

    // Subscribe before invoking so early rounds from a fast-running
    // coordination aren't dropped — per the ipc-contract streaming
    // convention, missing this ordering silently loses events.
    const unlisten = await listen<CoordinateRoundEvent>(
      "coordinate:round",
      (event) => {
        setRounds((prev) => [...prev, event.payload]);
      },
    );

    try {
      const specs = agentSpecs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await invoke<CoordinateResult>("agentbridge_coordinate", {
        request: {
          goal,
          agent_specs: specs,
          quorum,
          max_rounds: maxRounds,
          require_human: requireHuman,
          slim_endpoint: slimEndpoint,
        },
      });
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      unlisten();
      setRunning(false);
    }
  }

  return (
    <section className="ab-card">
      <h2>Coordinate</h2>
      <p className="ab-hint ab-note">
        A manual, operator-triggered run for test-driving a set of agents. The
        sustained exchange between room members happens over SLIM via each
        member's own harness, continuously — not by re-clicking here.
      </p>
      <textarea
        className="ab-textarea"
        placeholder="Goal"
        value={goal}
        onChange={(e) => setGoal(e.target.value)}
      />
      <div className="ab-row">
        <input
          className="ab-input ab-input-wide"
          placeholder="Agent specs, comma-separated (claude-code, codex, slim:agent-x)"
          value={agentSpecs}
          onChange={(e) => setAgentSpecs(e.target.value)}
        />
        {rooms.length > 0 && (
          <select
            className="ab-select"
            value=""
            onChange={(e) => {
              if (e.target.value) applyRoomRoster(e.target.value);
            }}
          >
            <option value="">Use room roster…</option>
            {rooms.map((r) => (
              <option key={r.channel} value={r.channel}>
                {r.channel} ({r.members.filter((m) => m.kind !== "human").length}{" "}
                agents)
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="ab-row">
        <label>
          Quorum
          <input
            className="ab-input ab-input-narrow"
            type="number"
            min={1}
            value={quorum}
            onChange={(e) => setQuorum(Number(e.target.value))}
          />
        </label>
        <label>
          Max rounds
          <input
            className="ab-input ab-input-narrow"
            type="number"
            min={1}
            value={maxRounds}
            onChange={(e) => setMaxRounds(Number(e.target.value))}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={requireHuman}
            onChange={(e) => setRequireHuman(e.target.checked)}
          />
          Require human
        </label>
        <input
          className="ab-input"
          placeholder="SLIM endpoint (for bare slim: specs)"
          value={slimEndpoint}
          onChange={(e) => setSlimEndpoint(e.target.value)}
        />
      </div>
      <button onClick={onCoordinate} disabled={running || !goal || !agentSpecs}>
        {running ? "Coordinating…" : "Start coordination"}
      </button>
      <ErrorText message={error} />

      {rounds.length > 0 && (
        <div className="ab-timeline">
          {rounds.map((r, i) => (
            <div key={i} className={`ab-round ab-round-${r.kind}`}>
              <span className="ab-round-epoch">R{r.round}</span>
              <span className="ab-round-agent">{r.agent}</span>
              <span className="ab-round-kind">{r.kind}</span>
              <span className="ab-round-summary">{r.summary}</span>
            </div>
          ))}
          <div ref={roundsEndRef} />
        </div>
      )}

      {result && (
        <div className="ab-result">
          <p>
            <strong>Winner:</strong> {result.winning_agent ?? "none"}
          </p>
          <p className="ab-response-meta">
            applied {result.applied} · finalized {result.finalized} · rejected{" "}
            {result.rejected} · deferred {result.deferred}
          </p>
          {result.artifact && <pre>{result.artifact}</pre>}
        </div>
      )}
    </section>
  );
}

export function AgentBridgePanel() {
  return (
    <div className="ab-panel">
      <AdapterList />
      <HandoffForm />
      <DelegateForm />
      <CoordinateVisualizer />
    </div>
  );
}
