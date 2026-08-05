import { useEffect, useRef, useState, useCallback } from "react";
import { useNavigate } from "react-router";
import { getMe, getHealth, ApiError, type Session } from "./api";
import { useNotificationEvents } from "./useEvents";

// Safety-net poll only - the primary signal is the "session.changed" SSE
// event (backend/internal/auth/session.go's RevokeUserSessions/
// UpdateSessionsRole) subscribed to below, which fires immediately on
// lock/unlock/delete/approve instead of waiting for the next tick. Before
// this (H-3, PERFORMANCE_AUDIT.md), every page using this hook polled
// GET /v1/auth/me every 15 s for its entire lifetime - each call doubly
// validated the session (main.go's global rate-limit middleware plus this
// handler), so a handful of always-open tabs added up to tens of thousands
// of Valkey round trips a day for something that changes rarely and is now
// pushed instead. This interval only exists to cover the case where the SSE
// connection itself is down (dropped network, proxy hiccup) - 5 minutes is
// short enough that nobody ends up staring at a revoked session for long,
// long enough that it is no longer the primary mechanism.
const POLL_INTERVAL_MS = 5 * 60_000;

// On the initial page load, if the /v1/auth/me request fails with a transient
// error (network, 5xx), we retry up to this many times before giving up and
// leaving the user on a blank loading screen (which will auto-recover on the
// next POLL_INTERVAL_MS tick anyway).
const INITIAL_RETRY_DELAY_MS = 2_000;

// Shared guard for every page that requires a fully-approved session -
// currently Home ("/"), ProfilePage ("/profile"), and AdminUsersPage
// ("/admin/users"), all of which had this exact effect duplicated before
// this hook existed. Redirects to /login if there is no valid session, to
// /pending if the resolved session's role is still "pending" (see
// backend/internal/auth.CallbackHandler's two-gate access model - a
// pending session is real, just not allowed past that one screen), and
// otherwise hands back the resolved session for the page to render with.
//
// There used to be a client-side check here ("is there a token in
// sessionStorage at all") before ever calling the backend, back when the
// session lived in a locally-readable bearer token. Now that it lives in
// an httpOnly cookie this hook cannot see, GET /v1/auth/me is simply
// called unconditionally on mount and its 401 (missing/invalid/expired
// cookie) is what drives the /login redirect instead - one fewer thing to
// keep in sync, at the cost of always needing one round-trip to find out.
// This also resolved an open bug: iOS Safari's edge-swipe bfcache restore
// used to sometimes come back with sessionStorage empty (or lagging), which
// this poll investigated at length (see git history for the removed
// "[auth-diag]" logging) - an httpOnly cookie isn't held in page-scoped
// storage at all, so that whole failure class no longer applies.
//
// Re-checks the instant the backend pushes a "session.changed" SSE event
// (RevokeUserSessions/UpdateSessionsRole, backend/internal/auth/session.go -
// fired on lock/unlock/delete and on a live role update), not just on the
// POLL_INTERVAL_MS fallback timer or once on mount: an admin's lock/delete
// action revokes the session token server-side immediately, but without
// this push (or the poll, if the push is somehow missed) a tab that
// already finished loading would have no way to find that out - it had
// already gotten its Session and was never going to call getMe() again on
// its own. Before this (H-3, PERFORMANCE_AUDIT.md) the poll was the *only*
// mechanism, at 15 s - fine for one tab, but every page using this hook ran
// its own independent interval, so a handful of always-open tabs added up
// to tens of thousands of Valkey round trips a day just to notice a change
// that happens rarely and is now pushed instead.
export function useAuthenticatedSession(): { session: Session | null; loading: boolean } {
  const navigate = useNavigate();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  // Tracks whether the very first getMe() call has ever succeeded. Used to
  // decide whether a transient error on a subsequent check should trigger a
  // short retry (initial load) or just be silently skipped (already loaded).
  const initialLoadDone = useRef(false);
  // Refs, not effect-local closures: check() itself is now a useCallback
  // shared between the mount effect (initial call, fallback interval,
  // pageshow) and the SSE event handler below, so both need to see the same
  // "has this hook instance been torn down" flag and pending retry timer.
  const cancelledRef = useRef(false);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // check's own retry branch below calls back into check() itself - it
  // can't reference the `check` binding directly (self-reference inside a
  // useCallback body is a lint error: react-hooks/immutability, "accessed
  // before it is declared" - the linter has no way to know the retry only
  // ever fires after check has already been assigned). Routed through a ref
  // instead, same indirection useEvents.ts's onEventRef uses for the exact
  // same reason.
  const checkRef = useRef<(isRetry?: boolean) => void>(() => {});

  const check = useCallback(
    (isRetry = false) => {
      getMe()
        .then((s) => {
          if (cancelledRef.current) {
            return;
          }
          if (s.role === "pending") {
            // Covers both "an admin locked this account" and the (currently
            // unreachable, since approval never downgrades a role) case of
            // losing approval after the fact - either way /pending knows
            // how to render whichever it turns out to be.
            navigate("/pending", { replace: true });
            return;
          }
          // Only update state when something actually changed — avoids
          // producing a new object reference on every check, which would
          // cascade into re-running useEffect([session, ...]) consumers
          // (e.g. ModulePage) and cause visible re-mounts mid-interaction.
          setSession((prev) => {
            if (
              prev &&
              prev.user_id === s.user_id &&
              prev.role === s.role &&
              prev.email === s.email &&
              prev.name === s.name &&
              prev.locked === s.locked
            ) {
              return prev; // same reference → no re-render
            }
            return s;
          });
          initialLoadDone.current = true;
          setLoading(false);
        })
        .catch((err) => {
          if (cancelledRef.current) return;
          // Only treat explicit auth rejections (401/403) as "there is no
          // valid session" — those mean the backend actively refused (or
          // never received) a session cookie. Network errors, 502/503/504
          // from Traefik, and other transient failures are handled
          // differently depending on whether the initial load has already
          // succeeded:
          //   - Already loaded: silently ignore; the next check will retry.
          //   - Still on initial load: schedule one quick retry after 2 s so
          //     a brief backend restart on page load doesn't leave a blank screen.
          if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
            // Before sending the user to /login, check whether setup has
            // ever been completed. If not, /login is useless (OIDC isn't
            // configured yet) - send them to /setup instead so the wizard
            // can run.
            getHealth()
              .then((h) => navigate(h.setup_completed ? "/login" : "/setup", { replace: true }))
              .catch(() => navigate("/login", { replace: true }));
            return;
          }
          // Transient error — only retry once on initial load.
          if (!initialLoadDone.current && !isRetry) {
            retryTimerRef.current = setTimeout(() => {
              if (!cancelledRef.current) checkRef.current(true);
            }, INITIAL_RETRY_DELAY_MS);
          }
          // Already-loaded pages continue to work normally; the fallback
          // interval or the next SSE push will pick up again.
        });
    },
    [navigate],
  );

  // Keeps checkRef current on every render, same dependency-free-effect
  // pattern useEvents.ts's onEventRef uses and for the same reason:
  // assigning a ref during render itself (rather than in an effect) is
  // flagged by react-hooks/immutability.
  useEffect(() => {
    checkRef.current = check;
  });

  useEffect(() => {
    cancelledRef.current = false;
    check();
    const id = window.setInterval(() => check(), POLL_INTERVAL_MS);

    // iOS Safari's edge-swipe back/forward gesture restores the previous
    // page from the bfcache (back-forward cache) instead of re-mounting the
    // React tree - this effect does NOT re-run on that kind of restore, so
    // without this listener a frozen tab could sit on stale session state
    // until the next SSE push or fallback poll tick notices a
    // meanwhile-revoked/expired session (or, on the flip side, a
    // meanwhile-approved one). `pageshow`'s `persisted` flag is true exactly
    // for this bfcache-restore case (never on a fresh load, where the
    // `check()` call above already covers it), so re-checking here closes
    // that gap immediately.
    function handlePageShow(event: PageTransitionEvent) {
      if (event.persisted && !cancelledRef.current) {
        check();
      }
    }
    window.addEventListener("pageshow", handlePageShow);

    return () => {
      cancelledRef.current = true;
      window.clearInterval(id);
      if (retryTimerRef.current !== null) clearTimeout(retryTimerRef.current);
      window.removeEventListener("pageshow", handlePageShow);
    };
  }, [check]);

  // Primary signal (H-3, PERFORMANCE_AUDIT.md): re-check the instant the
  // backend publishes "session.changed" instead of waiting for the
  // POLL_INTERVAL_MS fallback above, which now only matters if this SSE
  // connection itself is down.
  useNotificationEvents(true, (event) => {
    if (event.type === "session.changed") {
      check();
    }
  });

  return { session, loading };
}
