import { useEffect, useState } from "react";

// Returns the current wall-clock time in ms, refreshed every `intervalMs`.
//
// Anchored on the real clock, not an accumulated tick count - see AppShell's
// uptime ticker bug (found 2026-07-05): setInterval is throttled/paused by
// the browser while the tab is backgrounded or the device sleeps, and missed
// ticks are never made up, so a plain "+1 every second" counter falls behind
// real elapsed time. Reading Date.now() on every tick instead means the
// value self-heals the moment the tab wakes up again, no matter how many
// ticks were actually delivered while it was asleep.
//
// Date.now() itself is only ever called inside the initial lazy useState
// initializer (which React runs once per mount, not on every render - the
// one place an impure call like this is exempt from the "components must be
// pure" rule) and inside the setInterval callback (an event-like callback,
// not render) - never in the render body itself. That's what lets every
// caller (AppShell's uptime, AdminSystemInfoPage's uptime and countdowns)
// derive time-based values from `now` during render without tripping
// react-hooks/purity or react-hooks/refs.
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}
