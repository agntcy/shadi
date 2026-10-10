import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useRooms } from "../shared/rooms";
import "./SlimRoomsPanel.css";
import "./OwnerPanel.css";

// The Agent Directory (agntcy/shadi#119): `shadictl dir search|pull` and
// `agentbridge register --dir-publish`, through dirctl. A found agent can be
// invited into one of your rooms by its DID.

interface DirRecordSummary {
  cid: string;
  name: string;
  did: string | null;
  skills: string[];
  record_json: string;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sl-error">{message}</p>;
}

function RecordRow({ record, dirServer }: { record: DirRecordSummary; dirServer: string }) {
  const { rooms, refresh } = useRooms();
  const moderated = rooms.filter((r) => r.role === "moderator" && r.connected);
  const [room, setRoom] = useState("");
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function invite() {
    setError(null);
    setNote(null);
    try {
      await invoke("slim_group_invite", {
        channel: room,
        memberSpec: `did:${record.did}`,
        dirServer,
        kind: "agent",
      });
      setNote(`Invited into ${room}.`);
      refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="sl-room">
      <div className="sl-room-head">
        <strong>{record.name}</strong>
        <span className="sl-muted">{record.skills.join(", ")}</span>
        <button onClick={() => setOpen(!open)}>{open ? "Hide record" : "Record"}</button>
      </div>
      <p className="sl-muted">
        {record.did ? <span className="sl-did">{record.did}</span> : "no DID"} · CID{" "}
        <span className="sl-did">{record.cid}</span>
      </p>
      {record.did && (
        <div className="sl-row">
          <select value={room} onChange={(e) => setRoom(e.target.value)}>
            <option value="">Invite into…</option>
            {moderated.map((r) => (
              <option key={r.channel} value={r.channel}>
                {r.channel}
              </option>
            ))}
          </select>
          <button onClick={invite} disabled={!room}>
            Invite
          </button>
          {moderated.length === 0 && <span className="sl-muted">Moderate a connected room to invite.</span>}
          {note && <span className="sl-muted">{note}</span>}
        </div>
      )}
      <ErrorText message={error} />
      {open && <textarea className="ow-rules" readOnly value={record.record_json} />}
    </div>
  );
}

export function DirPanel() {
  const [dirServer, setDirServer] = useState("");
  const [query, setQuery] = useState("");
  const [cid, setCid] = useState("");
  const [records, setRecords] = useState<DirRecordSummary[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [card, setCard] = useState("");
  const [did, setDid] = useState("");
  const [published, setPublished] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(fetch: () => Promise<DirRecordSummary[]>) {
    setBusy(true);
    setError(null);
    try {
      setRecords(await fetch());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function publish() {
    setError(null);
    setPublished(null);
    try {
      const published = await invoke<string>("dir_register", {
        agentCardJson: card,
        dirServer,
        did: did || null,
      });
      setPublished(published);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="sl-panel">
      <section className="sl-card">
        <h2>Agent Directory</h2>
        <p className="sl-muted">Through dirctl, which must be installed. GITHUB_TOKEN authenticates if set.</p>
        <div className="sl-row">
          <input
            className="sl-input"
            placeholder="DIR server, e.g. localhost:8888"
            value={dirServer}
            onChange={(e) => setDirServer(e.target.value)}
          />
        </div>
        <div className="sl-row">
          <input
            className="sl-input"
            placeholder="Skill, or an agent's did:key"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button
            onClick={() =>
              run(() => invoke<DirRecordSummary[]>("dir_search", { query, dirServer, limit: 20 }))
            }
            disabled={busy || !query || !dirServer}
          >
            {busy ? "Searching…" : "Search"}
          </button>
          <input className="sl-input" placeholder="CID" value={cid} onChange={(e) => setCid(e.target.value)} />
          <button
            onClick={() => run(async () => [await invoke<DirRecordSummary>("dir_pull", { cid, dirServer })])}
            disabled={busy || !cid || !dirServer}
          >
            Pull
          </button>
        </div>
        <ErrorText message={error} />
        {records &&
          (records.length === 0 ? (
            <p className="sl-muted">No records found.</p>
          ) : (
            records.map((r) => <RecordRow key={r.cid} record={r} dirServer={dirServer} />)
          ))}
      </section>
      <section className="sl-card">
        <h2>Publish an AgentCard</h2>
        <p className="sl-muted">
          The card becomes a record whose author is the DID, so <code>did:</code> searches and room invites find
          it.
        </p>
        <textarea
          className="ow-rules"
          placeholder='{"name": "my-agent", "skills": [...], "supportedInterfaces": [...]}'
          value={card}
          spellCheck={false}
          onChange={(e) => setCard(e.target.value)}
        />
        <div className="sl-row">
          <input
            className="sl-input"
            placeholder="Agent did:key (author)"
            value={did}
            onChange={(e) => setDid(e.target.value)}
          />
          <button onClick={publish} disabled={!card || !dirServer}>
            Publish
          </button>
          {published && (
            <span className="sl-muted">
              Published as <span className="sl-did">{published}</span>
            </span>
          )}
        </div>
      </section>
    </div>
  );
}
