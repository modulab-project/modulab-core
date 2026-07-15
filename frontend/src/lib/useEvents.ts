import { useEffect, useRef } from "react";
import { eventsUrl } from "./api";

// Mirrors backend/internal/notify.Event's JSON shape exactly (Type/Data
// with `json:"type"`/`json:"data,omitempty"`) - keep both in sync. data
// is typed unknown rather than per-event-type, since this hook is shared
// across every event the backend might ever publish - callers narrow it
// themselves based on type (see AppShell.tsx's "user.pending" handler and
// Pending.tsx's "user.approved" handler for the two that exist today).
export interface ServerEvent {
  type: string;
  data?: unknown;
}

// Subscribes to GET /v1/events (spec section 3.5) for as long as enabled is
// true, calling onEvent for every message received. Reconnection on a
// dropped connection is handled by the browser's EventSource
// implementation itself (automatic retry with backoff) - this hook only
// opens/closes the connection as enabled flips, nothing more.
//
// Used to be gated on a session token (string | null) that this hook
// attached to the EventSource URL as ?token=... - now that the session
// lives in an httpOnly cookie the browser sends automatically (see
// backend/internal/auth/events.go's EventsHandler and lib/api.ts's
// eventsUrl), there is no token value left for this hook to hold or pass
// along, only "should a connection be open right now or not".
//
// onEvent is read through a ref rather than depended on directly in the
// effect below, so passing a fresh inline arrow function on every render
// (the common case for both current call sites) does not tear down and
// reopen the EventSource on every render - only an actual enabled change
// does that.
export function useNotificationEvents(enabled: boolean, onEvent: (event: ServerEvent) => void): void {
  const onEventRef = useRef(onEvent);
  // Assigning a ref during render is flagged by react-hooks/refs (React
  // Compiler treats it as a side effect); moving it into its own
  // dependency-free effect keeps the "always call the latest onEvent"
  // behavior (this effect re-runs on every commit, always before the
  // EventSource effect below could fire onEventRef.current) without
  // touching the ref during render.
  useEffect(() => {
    onEventRef.current = onEvent;
  });

  useEffect(() => {
    if (!enabled) {
      return;
    }
    const source = new EventSource(eventsUrl());
    source.onmessage = (e) => {
      try {
        onEventRef.current(JSON.parse(e.data) as ServerEvent);
      } catch {
        // Malformed payload - ignored rather than thrown. The heartbeat
        // comment lines the backend also sends (": heartbeat\n\n") never
        // reach onmessage at all per the SSE spec, so this branch is only
        // ever hit by something that actually claimed to be a data event
        // but wasn't valid JSON.
      }
    };
    return () => source.close();
  }, [enabled]);
}
