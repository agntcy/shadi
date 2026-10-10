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

interface ChannelManagerConfig {
  endpoint: string;
  name: string;
  ca_file: string | null;
}

interface ChannelManagerSetup {
  config: ChannelManagerConfig | null;
  owner_did: string | null;
  api_auth: string | null;
}

interface ManagedRoom {
  channel: string;
  expires_at: number | null;
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

function ManagedRoomRow({ room, onChanged }: { room: ManagedRoom; onChanged: () => void }) {
  const [participants, setParticipants] = useState<string[] | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setParticipants(await invoke<string[]>("channel_manager_participants", { channel: room.channel }));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

  async function setPresent(participant: string, present: boolean) {
    setError(null);
    try {
      await invoke("channel_manager_participant_set", { channel: room.channel, participant, present });
      if (present) setName("");
      await load();
    } catch (e) {
      setError(String(e));
    }
  }

  async function remove() {
    setError(null);
    try {
      await invoke("channel_manager_room_delete", { channel: room.channel });
      onChanged();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="sl-room">
      <div className="sl-room-head">
        <strong>{room.channel}</strong>
        {room.expires_at && (
          <span className="sl-muted">expires {new Date(room.expires_at * 1000).toLocaleString()}</span>
        )}
        <button onClick={load}>{participants ? "Refresh" : "Participants"}</button>
        <button onClick={remove}>Delete</button>
      </div>
      <ErrorText message={error} />
      {participants && (
        <>
          <ul className="sl-roster">
            {participants.length === 0 && <li className="sl-muted">No participants.</li>}
            {participants.map((p) => (
              <li key={p}>
                {p} <button onClick={() => setPresent(p, false)}>Remove</button>
              </li>
            ))}
          </ul>
          <div className="sl-row">
            <input
              className="sl-input"
              placeholder="Participant: org/ns/app"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <button onClick={() => setPresent(name, true)} disabled={!name}>
              Add
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ChannelManagerSection({ running }: { running: boolean }) {
  const [setup, setSetup] = useState<ChannelManagerSetup | null>(null);
  const [endpoint, setEndpoint] = useState("");
  const [name, setName] = useState("");
  const [caFile, setCaFile] = useState("");
  const [rooms, setRooms] = useState<ManagedRoom[]>([]);
  const [channel, setChannel] = useState("");
  const [ttl, setTtl] = useState("");
  const [error, setError] = useState<string | null>(null);

  const loadRooms = useCallback(async () => {
    try {
      setRooms(await invoke<ManagedRoom[]>("channel_manager_rooms"));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const loadSetup = useCallback(async () => {
    try {
      const next = await invoke<ChannelManagerSetup>("channel_manager_setup");
      setSetup(next);
      setEndpoint(next.config?.endpoint ?? "");
      setName(next.config?.name ?? "");
      setCaFile(next.config?.ca_file ?? "");
      if (next.config) await loadRooms();
    } catch (e) {
      setError(String(e));
    }
  }, [loadRooms]);

  useEffect(() => {
    loadSetup();
  }, [loadSetup]);

  async function save(clear: boolean) {
    setError(null);
    try {
      const config = clear ? null : { endpoint, name, ca_file: caFile || null };
      await invoke("channel_manager_configure", { config });
      await loadSetup();
      if (clear) setRooms([]);
    } catch (e) {
      setError(String(e));
    }
  }

  async function create() {
    setError(null);
    try {
      const ttlSeconds = ttl ? Number(ttl) : null;
      await invoke("channel_manager_room_create", { channel, ttlSeconds });
      setChannel("");
      setTtl("");
      await loadRooms();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Channel manager</h2>
      <p className="sl-muted">
        With a SLIM channel manager, rooms are created through it and it moderates them. You stay
        their owner: it asks the owner service here before letting anyone else add or remove a
        participant. Without one, the Rooms tab moderates rooms itself.
      </p>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="API endpoint, e.g. http://127.0.0.1:10356"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="Its local-name, e.g. agntcy/ns/channel-manager"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="CA file (https only)"
          value={caFile}
          onChange={(e) => setCaFile(e.target.value)}
        />
        <button onClick={() => save(false)} disabled={!endpoint || !name}>
          Save
        </button>
        {setup?.config && <button onClick={() => save(true)}>Clear</button>}
      </div>
      <ErrorText message={error} />
      {setup?.api_auth && (
        <details>
          <summary className="sl-muted">The channel manager&apos;s api-server.auth for this owner</summary>
          <p className="sl-muted">
            It verifies tokens signed with the owner key, so it records{" "}
            <span className="sl-did">{setup.owner_did}</span> as the owner of the rooms created here.
          </p>
          <textarea className="ow-rules" readOnly value={setup.api_auth} />
        </details>
      )}
      {setup?.config && (
        <>
          <div className="sl-row">
            <input
              className="sl-input"
              placeholder="New room: org/ns/room"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
            />
            <input
              className="sl-input sl-input-narrow"
              placeholder="TTL seconds"
              value={ttl}
              onChange={(e) => setTtl(e.target.value.replace(/[^0-9]/g, ""))}
            />
            <button onClick={create} disabled={!channel || !running}>
              Create
            </button>
            <button onClick={loadRooms}>Refresh</button>
          </div>
          {!running && <p className="sl-muted">Start the owner service to create rooms.</p>}
          {rooms.length === 0 ? (
            <p className="sl-muted">The channel manager lists no rooms you own.</p>
          ) : (
            rooms.map((room) => <ManagedRoomRow key={room.channel} room={room} onChanged={loadRooms} />)
          )}
        </>
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
      <ChannelManagerSection running={status?.running ?? false} />
      <RulesSection />
      <AuditSection />
    </div>
  );
}
