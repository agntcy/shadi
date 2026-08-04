import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";

export interface SlimGroupMember {
  name: string;
  did: string;
  endpoint: string | null;
  kind: string;
}

export interface SlimGroupInfo {
  channel: string;
  role: string;
  members: SlimGroupMember[];
}

/**
 * Rooms are shared across panels (agntcy/shadi#135): the agentbridge panel
 * needs them to admit a discovered adapter into a room and to source
 * coordination agent specs from a roster, while the SLIM panel administers
 * them. Keeping one copy here avoids the two panels drifting out of sync
 * after an invite or a removal.
 */
interface RoomsContextValue {
  rooms: SlimGroupInfo[];
  error: string | null;
  refresh: () => Promise<void>;
}

const RoomsContext = createContext<RoomsContextValue | null>(null);

export function RoomsProvider({ children }: { children: ReactNode }) {
  const [rooms, setRooms] = useState<SlimGroupInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  // Refreshes are fired from several places at once — the mount effect, and
  // each invite/create/join/remove. Adding two adapters in quick succession
  // starts two overlapping `slim_group_list` calls, so responses have to be
  // ordered: an older one landing last would drop a just-admitted room from
  // both panels until something refreshed again.
  const latestRefresh = useRef(0);

  const refresh = useCallback(async () => {
    const version = ++latestRefresh.current;
    try {
      const next = await invoke<SlimGroupInfo[]>("slim_group_list");
      if (version !== latestRefresh.current) return;
      setRooms(next);
      setError(null);
    } catch (e) {
      if (version !== latestRefresh.current) return;
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const value = useMemo(
    () => ({ rooms, error, refresh }),
    [rooms, error, refresh],
  );
  return <RoomsContext.Provider value={value}>{children}</RoomsContext.Provider>;
}

export function useRooms(): RoomsContextValue {
  const ctx = useContext(RoomsContext);
  if (!ctx) throw new Error("useRooms must be used inside a RoomsProvider");
  return ctx;
}

/**
 * The `explicit:<name>=<did>[@<endpoint>]` spec that admits an
 * already-resolved candidate without a second Directory round-trip.
 *
 * This is the only place the format is built; the Rust side just consumes it.
 * `frontend_explicit_spec_format_resolves_without_a_directory` in
 * `commands/slim.rs` pins the exact shape — update it alongside this.
 */
export function explicitMemberSpec(
  name: string,
  did: string,
  endpoint: string | null,
): string {
  return endpoint ? `explicit:${name}=${did}@${endpoint}` : `explicit:${name}=${did}`;
}

/**
 * The `slim:<agent-id>[@host:port]` spec `agentbridge coordinate` expects for
 * a remote member, derived from a room roster entry.
 */
export function slimAgentSpec(member: SlimGroupMember): string {
  return member.endpoint
    ? `slim:${member.name}@${member.endpoint}`
    : `slim:${member.name}`;
}
