import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./SlimRoomsPanel.css";
import "./OwnerPanel.css";

// Traces and memory (agntcy/shadi#121): `shadictl trace list|summary` and
// `shadictl memory list|search|get`. Memory opens only with the key
// `shadictl memory` uses, read from the secret store.

interface TraceEntry {
  name: string | null;
  command: string | null;
  exit_code: number | null;
  timestamp: string | null;
  raw: string;
}

interface TraceSummaryEntry {
  span_name: string;
  count: number;
}

interface MemoryEntry {
  id: number;
  scope: string;
  entry_key: string;
  created_at: string;
  payload: string | null;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sl-error">{message}</p>;
}

function TraceSection() {
  const [file, setFile] = useState("");
  const [name, setName] = useState("");
  const [command, setCommand] = useState("");
  const [entries, setEntries] = useState<TraceEntry[] | null>(null);
  const [summary, setSummary] = useState<TraceSummaryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function list() {
    setError(null);
    setSummary(null);
    try {
      setEntries(
        await invoke<TraceEntry[]>("trace_list", {
          file: file || null,
          limit: 200,
          name: name || null,
          command: command || null,
          exitCode: null,
        }),
      );
    } catch (e) {
      setError(String(e));
    }
  }

  async function summarize() {
    setError(null);
    setEntries(null);
    try {
      setSummary(await invoke<TraceSummaryEntry[]>("trace_summary", { file: file || null, limit: 1000 }));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Traces</h2>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Trace file (SHADI_OTEL_FILE when empty)"
          value={file}
          onChange={(e) => setFile(e.target.value)}
        />
        <input className="sl-input sl-input-narrow" placeholder="Span" value={name} onChange={(e) => setName(e.target.value)} />
        <input
          className="sl-input sl-input-narrow"
          placeholder="Command"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
        />
        <button onClick={list}>List</button>
        <button onClick={summarize}>Summary</button>
      </div>
      <ErrorText message={error} />
      {summary && (
        <table className="sl-table">
          <thead>
            <tr>
              <th>Span</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {summary.map((s) => (
              <tr key={s.span_name}>
                <td>{s.span_name}</td>
                <td>{s.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {entries &&
        (entries.length === 0 ? (
          <p className="sl-muted">No matching lines.</p>
        ) : (
          <table className="sl-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Span</th>
                <th>Command</th>
                <th>Exit</th>
              </tr>
            </thead>
            <tbody>
              {entries
                .slice()
                .reverse()
                .map((e, i) => (
                  <tr key={i} title={e.raw}>
                    <td>{e.timestamp ?? ""}</td>
                    <td>{e.name ?? <span className="sl-muted">(not JSON)</span>}</td>
                    <td>{e.command ?? ""}</td>
                    <td>{e.exit_code ?? ""}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        ))}
    </section>
  );
}

function MemorySection() {
  const [db, setDb] = useState("");
  const [scope, setScope] = useState("");
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<MemoryEntry[] | null>(null);
  const [opened, setOpened] = useState<MemoryEntry | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setError(null);
    setOpened(null);
    try {
      setEntries(
        query
          ? await invoke<MemoryEntry[]>("memory_search", { db: db || null, scope: scope || null, query, limit: 100 })
          : await invoke<MemoryEntry[]>("memory_list", { db: db || null, scope: scope || null, limit: 100 }),
      );
    } catch (e) {
      setError(String(e));
    }
  }

  async function read(entry: MemoryEntry) {
    setError(null);
    try {
      setOpened(
        await invoke<MemoryEntry | null>("memory_get", {
          db: db || null,
          scope: entry.scope,
          entryKey: entry.entry_key,
        }),
      );
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Memory</h2>
      <p className="sl-muted">Read-only. The database opens with the key in the secret store, as for the CLI.</p>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Database (SHADI_MEMORY_DB when empty)"
          value={db}
          onChange={(e) => setDb(e.target.value)}
        />
        <input className="sl-input sl-input-narrow" placeholder="Scope" value={scope} onChange={(e) => setScope(e.target.value)} />
        <input className="sl-input sl-input-narrow" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
        <button onClick={load}>{query ? "Search" : "List"}</button>
      </div>
      <ErrorText message={error} />
      {entries &&
        (entries.length === 0 ? (
          <p className="sl-muted">No entries.</p>
        ) : (
          <table className="sl-table">
            <thead>
              <tr>
                <th>Scope</th>
                <th>Key</th>
                <th>Saved</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td>{e.scope}</td>
                  <td>{e.entry_key}</td>
                  <td>{e.created_at}</td>
                  <td>
                    <button onClick={() => read(e)}>Open</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
      {opened && (
        <>
          <p className="sl-muted">
            {opened.scope} / {opened.entry_key}
          </p>
          <textarea className="ow-rules" readOnly value={opened.payload ?? ""} />
        </>
      )}
    </section>
  );
}

export function TracePanel() {
  return (
    <div className="sl-panel">
      <TraceSection />
      <MemorySection />
    </div>
  );
}
