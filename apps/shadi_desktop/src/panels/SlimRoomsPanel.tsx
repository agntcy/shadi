import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./SlimRoomsPanel.css";

interface SlimNodeStatus {
  running: boolean;
  endpoint: string | null;
}

interface SlimGroupMember {
  name: string;
  did: string;
  endpoint: string | null;
  kind: string;
}

interface SlimGroupInfo {
  channel: string;
  role: string;
  members: SlimGroupMember[];
}

interface SlimConnection {
  id: string;
  endpoint: string;
}

interface SlimRoute {
  destination: string;
  via: string;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sl-error">{message}</p>;
}

function NodeSection() {
  const [status, setStatus] = useState<SlimNodeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setStatus(await invoke<SlimNodeStatus>("slim_node_status"));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onStart() {
    setBusy(true);
    setError(null);
    try {
      setStatus(await invoke<SlimNodeStatus>("slim_node_start"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sl-card">
      <h2>SLIM node</h2>
      <div className="sl-row">
        <span className={`sl-dot ${status?.running ? "sl-dot-on" : "sl-dot-off"}`} />
        <span>
          {status?.running ? "running" : "stopped"}
          {status?.endpoint ? ` · ${status.endpoint}` : ""}
        </span>
        <button onClick={onStart} disabled={busy || status?.running}>
          {busy ? "Starting…" : "Start node"}
        </button>
        <button onClick={refresh} disabled={busy}>
          Refresh
        </button>
      </div>
      <ErrorText message={error} />
    </section>
  );
}

function Roster({
  room,
  onRemoved,
}: {
  room: SlimGroupInfo;
  onRemoved: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);

  async function onRemove(memberName: string) {
    setRemoving(memberName);
    setError(null);
    try {
      await invoke<SlimGroupInfo>("slim_group_remove_member", {
        channel: room.channel,
        memberName,
      });
      onRemoved();
    } catch (e) {
      setError(String(e));
    } finally {
      setRemoving(null);
    }
  }

  const isModerator = room.role === "moderator";

  return (
    <div className="sl-roster">
      <ErrorText message={error} />
      {room.members.length === 0 ? (
        <p className="sl-muted">No members yet.</p>
      ) : (
        <table className="sl-table">
          <thead>
            <tr>
              <th />
              <th>Member</th>
              <th>DID</th>
              <th>Endpoint</th>
              {isModerator && <th />}
            </tr>
          </thead>
          <tbody>
            {room.members.map((m) => (
              <tr key={m.name}>
                <td>
                  <span className={`sl-kind sl-kind-${m.kind}`}>
                    {m.kind === "human" ? "human" : "agent"}
                  </span>
                </td>
                <td>{m.name}</td>
                <td className="sl-did">{m.did || "—"}</td>
                <td>{m.endpoint ?? "—"}</td>
                {isModerator && (
                  <td>
                    <button
                      className="sl-remove"
                      onClick={() => onRemove(m.name)}
                      disabled={removing === m.name}
                    >
                      {removing === m.name ? "Removing…" : "Remove"}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RoomCard({ room, onChanged }: { room: SlimGroupInfo; onChanged: () => void }) {
  const [memberSpec, setMemberSpec] = useState("");
  const [dirServer, setDirServer] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onInvite() {
    setBusy(true);
    setError(null);
    try {
      await invoke<SlimGroupInfo>("slim_group_invite", {
        channel: room.channel,
        memberSpec,
        dirServer: dirServer || null,
      });
      setMemberSpec("");
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="sl-room">
      <div className="sl-room-head">
        <strong>{room.channel}</strong>
        <span className={`sl-role sl-role-${room.role}`}>{room.role}</span>
        <span className="sl-muted">
          {room.members.length} member{room.members.length === 1 ? "" : "s"}
        </span>
        <button onClick={onChanged}>Refresh roster</button>
      </div>

      <Roster room={room} onRemoved={onChanged} />

      {room.role === "moderator" && (
        <div className="sl-row sl-invite">
          <input
            className="sl-input"
            placeholder="Member: skill:… | did:… | explicit:name=did | org/ns/app"
            value={memberSpec}
            onChange={(e) => setMemberSpec(e.target.value)}
          />
          <input
            className="sl-input"
            placeholder="DIR server (for skill:/did: specs)"
            value={dirServer}
            onChange={(e) => setDirServer(e.target.value)}
          />
          <button onClick={onInvite} disabled={busy || !memberSpec}>
            {busy ? "Inviting…" : "Invite"}
          </button>
        </div>
      )}
      <ErrorText message={error} />
    </div>
  );
}

function RoomsSection() {
  const [rooms, setRooms] = useState<SlimGroupInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [channel, setChannel] = useState("");
  const [memberSpecs, setMemberSpecs] = useState("");
  const [dirServer, setDirServer] = useState("");
  const [busy, setBusy] = useState(false);
  const [joinChannel, setJoinChannel] = useState("");
  const [joinTimeout, setJoinTimeout] = useState(30);

  const refresh = useCallback(async () => {
    try {
      setRooms(await invoke<SlimGroupInfo[]>("slim_group_list"));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onCreate() {
    setBusy(true);
    setError(null);
    try {
      await invoke<SlimGroupInfo>("slim_group_create", {
        channel,
        memberSpecs: memberSpecs
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        dirServer,
      });
      setChannel("");
      setMemberSpecs("");
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onJoin() {
    setBusy(true);
    setError(null);
    try {
      await invoke<SlimGroupInfo>("slim_group_join", {
        channel: joinChannel,
        timeoutSecs: joinTimeout,
      });
      setJoinChannel("");
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sl-card">
      <h2>Rooms</h2>
      <p className="sl-muted sl-note">
        Rooms are live SLIM sessions this app is joined to — the list is empty on
        a fresh launch until you create or join one. Messaging between members
        happens over SLIM via each member's own harness; this panel administers
        membership.
      </p>

      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="New room channel (org/ns/app)"
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="Members, comma-separated (skill:… , explicit:name=did)"
          value={memberSpecs}
          onChange={(e) => setMemberSpecs(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="DIR server"
          value={dirServer}
          onChange={(e) => setDirServer(e.target.value)}
        />
        <button onClick={onCreate} disabled={busy || !channel}>
          Create room
        </button>
      </div>

      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Join existing channel (org/ns/app)"
          value={joinChannel}
          onChange={(e) => setJoinChannel(e.target.value)}
        />
        <label>
          Timeout
          <input
            className="sl-input sl-input-narrow"
            type="number"
            min={1}
            value={joinTimeout}
            onChange={(e) => setJoinTimeout(Number(e.target.value))}
          />
        </label>
        <button onClick={onJoin} disabled={busy || !joinChannel}>
          Join room
        </button>
        <button onClick={refresh} disabled={busy}>
          Refresh rooms
        </button>
      </div>

      <ErrorText message={error} />

      {rooms.length === 0 ? (
        <p className="sl-muted">Not in any room.</p>
      ) : (
        rooms.map((room) => (
          <RoomCard key={room.channel} room={room} onChanged={refresh} />
        ))
      )}
    </section>
  );
}

function ControllerSection() {
  const [endpoint, setEndpoint] = useState("");
  const [connections, setConnections] = useState<SlimConnection[] | null>(null);
  const [routes, setRoutes] = useState<SlimRoute[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load(kind: "connections" | "routes") {
    setBusy(true);
    setError(null);
    try {
      if (kind === "connections") {
        setConnections(
          await invoke<SlimConnection[]>("slim_controller_list_connections", {
            endpoint,
          }),
        );
      } else {
        setRoutes(
          await invoke<SlimRoute[]>("slim_controller_list_routes", { endpoint }),
        );
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="sl-card">
      <h2>Controller</h2>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Controller endpoint"
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
        />
        <button onClick={() => load("connections")} disabled={busy || !endpoint}>
          List connections
        </button>
        <button onClick={() => load("routes")} disabled={busy || !endpoint}>
          List routes
        </button>
      </div>
      <ErrorText message={error} />
      {connections && (
        <table className="sl-table">
          <thead>
            <tr>
              <th>Connection</th>
              <th>Link</th>
            </tr>
          </thead>
          <tbody>
            {connections.length === 0 ? (
              <tr>
                <td colSpan={2}>No connections.</td>
              </tr>
            ) : (
              connections.map((c) => (
                <tr key={c.id}>
                  <td>{c.id}</td>
                  <td>{c.endpoint || "—"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}
      {routes && (
        <table className="sl-table">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Via</th>
            </tr>
          </thead>
          <tbody>
            {routes.length === 0 ? (
              <tr>
                <td colSpan={2}>No routes.</td>
              </tr>
            ) : (
              routes.map((r, i) => (
                <tr key={`${r.destination}-${r.via}-${i}`}>
                  <td>{r.destination}</td>
                  <td>{r.via}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function SlimRoomsPanel() {
  return (
    <div className="sl-panel">
      <NodeSection />
      <RoomsSection />
      <ControllerSection />
    </div>
  );
}
