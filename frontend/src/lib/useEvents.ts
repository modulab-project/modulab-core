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

// Subscribes to GET /v1/events (spec section 3.5) for as long as token is
// non-null, calling onEvent for every message received. Reconnection on a
// dropped connection is handled by the browser's EventSource
// implementation itself (automatic retry with backoff) - this hook only
// opens/closes the connection as token appears, disappears, or changes,
// nothing more.
//
// onEvent is read through a ref rather than depended on directly in the
// effect below, so passing a fresh inline arrow function on every render
// (the common case for both current call sites) does not tear down and
// reopen the EventSource on every render - only an actual token change
// does that.
export function useNotificationEvents(token: string | null, onEvent: (event: ServerEvent) => void): void {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    if (!token) {
      return;
    }
    const source = new EventSource(eventsUrl(token));
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
  }, [token]);
}
