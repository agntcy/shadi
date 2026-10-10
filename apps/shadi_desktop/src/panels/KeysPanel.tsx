import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./SlimRoomsPanel.css";
import "./OwnerPanel.css";

// Identity tools and the secret store (agntcy/shadi#117): what `did-from-gpg`,
// `did-from-github`, `derive-agent-identity`, `verify-agent-identity`,
// `put-key` and `--list-keychain` do. No secret value ever reaches this page:
// the store is browsed by key name and checked for presence only.

type HumanKeySource = { kind: "secret_ref"; key: string } | { kind: "file"; path: string };

interface DidDocument {
  did: string;
  document_json: string;
}

interface AgentIdentity {
  agent_name: string;
  did: string;
}

interface VerifyResult {
  matches: boolean;
  expected_did: string;
  stored_did: string | null;
  human_binding_ok: boolean | null;
}

interface SecretBackend {
  kind: "keychain";
  platform: string;
}

function ErrorText({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="sl-error">{message}</p>;
}

async function pickFile(title: string): Promise<string | null> {
  const picked = await open({ multiple: false, directory: false, title });
  return typeof picked === "string" ? picked : null;
}

/// A human key, from a file or a secret-store entry.
function SourcePicker({
  source,
  onChange,
}: {
  source: HumanKeySource;
  onChange: (source: HumanKeySource) => void;
}) {
  return (
    <div className="sl-row">
      <select
        value={source.kind}
        onChange={(e) =>
          onChange(e.target.value === "file" ? { kind: "file", path: "" } : { kind: "secret_ref", key: "" })
        }
      >
        <option value="file">File</option>
        <option value="secret_ref">Secret store</option>
      </select>
      {source.kind === "file" ? (
        <>
          <input
            className="sl-input"
            placeholder="Key file"
            value={source.path}
            onChange={(e) => onChange({ kind: "file", path: e.target.value })}
          />
          <button
            onClick={async () => {
              const path = await pickFile("Choose a key file");
              if (path) onChange({ kind: "file", path });
            }}
          >
            Browse…
          </button>
        </>
      ) : (
        <input
          className="sl-input"
          placeholder="Secret name, e.g. human/gpg"
          value={source.key}
          onChange={(e) => onChange({ kind: "secret_ref", key: e.target.value })}
        />
      )}
    </div>
  );
}

function sourceReady(source: HumanKeySource): boolean {
  return source.kind === "file" ? source.path !== "" : source.key !== "";
}

function DidSection() {
  const [source, setSource] = useState<HumanKeySource>({ kind: "file", path: "" });
  const [handle, setHandle] = useState("");
  const [doc, setDoc] = useState<DidDocument | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(command: string, args: Record<string, unknown>) {
    setError(null);
    setDoc(null);
    try {
      setDoc(await invoke<DidDocument>(command, args));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>DID from a public key</h2>
      <p className="sl-muted">The did:key for an OpenPGP Ed25519 key, or for the SSH key a GitHub user publishes.</p>
      <SourcePicker source={source} onChange={setSource} />
      <div className="sl-row">
        <button onClick={() => run("identity_did_from_gpg", { source })} disabled={!sourceReady(source)}>
          From GPG key
        </button>
        <input
          className="sl-input"
          placeholder="GitHub handle"
          value={handle}
          onChange={(e) => setHandle(e.target.value)}
        />
        <button onClick={() => run("identity_did_from_github", { username: handle })} disabled={!handle}>
          From GitHub
        </button>
      </div>
      <ErrorText message={error} />
      {doc && (
        <>
          <p>
            <span className="sl-did">{doc.did}</span>
          </p>
          <textarea className="ow-rules" readOnly value={doc.document_json} />
        </>
      )}
    </section>
  );
}

function AgentSection() {
  const [source, setSource] = useState<HumanKeySource>({ kind: "file", path: "" });
  const [names, setNames] = useState("");
  const [humanDidKey, setHumanDidKey] = useState("");
  const [requireBinding, setRequireBinding] = useState(false);
  const [derived, setDerived] = useState<AgentIdentity[]>([]);
  const [verified, setVerified] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const agentNames = names
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  async function derive() {
    setError(null);
    setVerified(null);
    try {
      setDerived(
        await invoke<AgentIdentity[]>("identity_derive_agent", {
          source,
          agentNames,
          humanDidKey: humanDidKey || null,
        }),
      );
    } catch (e) {
      setError(String(e));
    }
  }

  async function verify() {
    setError(null);
    setDerived([]);
    try {
      setVerified(
        await invoke<VerifyResult>("identity_verify_agent", {
          source,
          agentName: agentNames[0],
          requireHumanBinding: requireBinding,
        }),
      );
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Agent identities</h2>
      <p className="sl-muted">
        Derive agents from a human key into <code>agent_keys/&lt;name&gt;/</code>, or check that what is stored
        there still derives from it.
      </p>
      <SourcePicker source={source} onChange={setSource} />
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Agent names, comma-separated"
          value={names}
          onChange={(e) => setNames(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="Human DID secret (optional binding)"
          value={humanDidKey}
          onChange={(e) => setHumanDidKey(e.target.value)}
        />
      </div>
      <div className="sl-row">
        <button onClick={derive} disabled={!sourceReady(source) || agentNames.length === 0}>
          Derive and store
        </button>
        <button onClick={verify} disabled={!sourceReady(source) || agentNames.length !== 1}>
          Verify
        </button>
        <label className="sl-muted">
          <input type="checkbox" checked={requireBinding} onChange={(e) => setRequireBinding(e.target.checked)} />{" "}
          require a human binding
        </label>
      </div>
      <ErrorText message={error} />
      {derived.length > 0 && (
        <table className="sl-table">
          <tbody>
            {derived.map((a) => (
              <tr key={a.agent_name}>
                <td>{a.agent_name}</td>
                <td className="sl-did">{a.did}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {verified && (
        <p className={verified.matches ? "sl-muted" : "sl-error"}>
          {verified.matches ? "Matches" : "Does not match"}: expects{" "}
          <span className="sl-did">{verified.expected_did}</span>, stored{" "}
          <span className="sl-did">{verified.stored_did ?? "nothing"}</span>
          {verified.human_binding_ok !== null &&
            (verified.human_binding_ok ? "; human binding present" : "; no valid human binding")}
        </p>
      )}
    </section>
  );
}

function SecretStoreSection() {
  const [backend, setBackend] = useState<SecretBackend | null>(null);
  const [prefix, setPrefix] = useState("");
  const [keys, setKeys] = useState<string[] | null>(null);
  const [probe, setProbe] = useState("");
  const [probeResult, setProbeResult] = useState<string | null>(null);
  const [storeName, setStoreName] = useState("");
  const [storePath, setStorePath] = useState("");
  const [stored, setStored] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<SecretBackend>("secret_backend_status")
      .then(setBackend)
      .catch((e) => setError(String(e)));
  }, []);

  const list = useCallback(async () => {
    setError(null);
    try {
      const entries = await invoke<{ key: string }[]>("secret_list_keychain", { prefix: prefix || null });
      setKeys(entries.map((e) => e.key));
    } catch (e) {
      setError(String(e));
    }
  }, [prefix]);

  async function check() {
    setError(null);
    try {
      const exists = await invoke<boolean>("secret_exists", { key: probe });
      setProbeResult(`${probe} ${exists ? "is stored" : "is not stored"}`);
    } catch (e) {
      setError(String(e));
    }
  }

  async function store() {
    setError(null);
    setStored(null);
    try {
      await invoke("secret_put_key", { key: storeName, openpgpKeyPath: storePath });
      setStored(`Stored ${storeName}.`);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="sl-card">
      <h2>Secret store</h2>
      <p className="sl-muted">
        {backend ? `Backed by the ${backend.platform}.` : "…"} Values never leave the store for this page.
      </p>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Prefix, e.g. agent_keys/"
          value={prefix}
          onChange={(e) => setPrefix(e.target.value)}
        />
        <button onClick={list}>List keys</button>
      </div>
      {keys &&
        (keys.length === 0 ? (
          <p className="sl-muted">No keys{prefix ? ` under ${prefix}` : ""}.</p>
        ) : (
          <ul className="sl-roster">
            {keys.map((k) => (
              <li key={k}>{k}</li>
            ))}
          </ul>
        ))}
      <div className="sl-row">
        <input className="sl-input" placeholder="Key name" value={probe} onChange={(e) => setProbe(e.target.value)} />
        <button onClick={check} disabled={!probe}>
          Is it stored?
        </button>
        {probeResult && <span className="sl-muted">{probeResult}</span>}
      </div>
      <div className="sl-row">
        <input
          className="sl-input"
          placeholder="Store as, e.g. human/gpg"
          value={storeName}
          onChange={(e) => setStoreName(e.target.value)}
        />
        <input
          className="sl-input"
          placeholder="OpenPGP key file"
          value={storePath}
          onChange={(e) => setStorePath(e.target.value)}
        />
        <button
          onClick={async () => {
            const path = await pickFile("Choose an OpenPGP key");
            if (path) setStorePath(path);
          }}
        >
          Browse…
        </button>
        <button onClick={store} disabled={!storeName || !storePath}>
          Store
        </button>
      </div>
      {stored && <p className="sl-muted">{stored}</p>}
      <ErrorText message={error} />
    </section>
  );
}

export function KeysPanel() {
  return (
    <div className="sl-panel">
      <SecretStoreSection />
      <DidSection />
      <AgentSection />
    </div>
  );
}
