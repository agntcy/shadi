import { useEffect, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./TerminalPane.css";

// The escape hatch (agntcy/shadi#122): the real `shadictl shell` in a pty,
// for anything the panels don't cover yet.

type TerminalEvent = { kind: "output"; data: string } | { kind: "exit"; code: number | null };

export function TerminalPane() {
  const host = useRef<HTMLDivElement>(null);
  const [exited, setExited] = useState<number | null | undefined>(undefined);
  const [session, setSession] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!host.current) return;
    const term = new Terminal({ convertEol: false, cursorBlink: true, fontSize: 13 });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current);
    fit.fit();

    let id: number | null = null;
    let closed = false;
    const events = new Channel<TerminalEvent>();
    events.onmessage = (event) => {
      if (event.kind === "output") term.write(event.data);
      else setExited(event.code);
    };
    setExited(undefined);
    setError(null);
    invoke<number>("terminal_open", { args: [], cols: term.cols, rows: term.rows, onEvent: events })
      .then((opened) => {
        id = opened;
        if (closed) invoke("terminal_close", { id: opened });
      })
      .catch((e) => setError(String(e)));

    const input = term.onData((data) => {
      if (id !== null) invoke("terminal_write", { id, data }).catch(() => {});
    });
    const resized = term.onResize(({ cols, rows }) => {
      if (id !== null) invoke("terminal_resize", { id, cols, rows }).catch(() => {});
    });
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(host.current);

    return () => {
      closed = true;
      observer.disconnect();
      input.dispose();
      resized.dispose();
      if (id !== null) invoke("terminal_close", { id });
      term.dispose();
    };
  }, [session]);

  return (
    <div className="term-pane">
      <div className="term-bar">
        <span>shadictl shell</span>
        {exited !== undefined && <span className="term-exit">exited{exited !== null ? ` (${exited})` : ""}</span>}
        {error && <span className="term-error">{error}</span>}
        <button onClick={() => setSession(session + 1)}>Restart</button>
      </div>
      <div className="term-host" ref={host} />
    </div>
  );
}
