import { useState } from "react";
import "./App.css";
import { AgentBridgePanel } from "./panels/AgentBridgePanel";
import { SlimRoomsPanel } from "./panels/SlimRoomsPanel";
import { RoomsProvider } from "./shared/rooms";

const TABS = [
  { id: "rooms", label: "Rooms", render: () => <SlimRoomsPanel /> },
  { id: "agentbridge", label: "agentbridge", render: () => <AgentBridgePanel /> },
] as const;

function App() {
  const [active, setActive] = useState<string>(TABS[0].id);
  const tab = TABS.find((t) => t.id === active) ?? TABS[0];

  return (
    // Rooms are shared across both panels (#135), so the provider wraps both
    // and survives tab switches — a room admitted in one tab is immediately
    // visible in the other.
    <RoomsProvider>
      <main className="container">
        <h1>SHADI Desktop</h1>
        <nav className="tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={t.id === active ? "tab tab-active" : "tab"}
              onClick={() => setActive(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        {tab.render()}
      </main>
    </RoomsProvider>
  );
}

export default App;
