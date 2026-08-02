import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { getMe, getHealth, ApiError, type Session } from "./api";

// Same interval Pending.tsx polls on - kept in sync so "how stale can a
// revoked session look in the UI" is one number, not two.
const POLL_INTERVAL_MS = 15_000;

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
// Re-checks on the same POLL_INTERVAL_MS as Pending.tsx, not just once on
// mount: an admin's lock/delete action now revokes the session token
// server-side immediately (auth.RevokeUserSessions), but without this poll
// a tab that already finished loading would have no way to find that out -
// it had already gotten its Session and was never going to call getMe()
// again on its own. The cost is the same one Pending.tsx already accepted
// for the same reason: one /v1/auth/me request per open tab every 15s.
export function useAuthenticatedSession(): { session: Session | null; loading: boolean } {
  const navigate = useNavigate();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  // Tracks whether the very first getMe() call has ever succeeded. Used to
  // decide whether a transient error on a subsequent poll should trigger a
  // short retry (initial load) or just be silently skipped (already loaded).
  // A ref, not state: it's only read inside the effect below, so turning it
  // into state would just make the effect (poll interval + listeners)
  // needlessly re-run every time the initial load completes.
  const initialLoadDone = useRef(false);

  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    function check(isRetry = false) {
      getMe()
        .then((s) => {
          if (cancelled) {
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
          // producing a new object reference every 15 s, which would
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
          if (cancelled) return;
          // Only treat explicit auth rejections (401/403) as "there is no
          // valid session" — those mean the backend actively refused (or
          // never received) a session cookie. Network errors, 502/503/504
          // from Traefik, and other transient failures are handled
          // differently depending on whether the initial load has already
          // succeeded:
          //   - Already loaded: silently ignore; the next poll will retry.
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
            retryTimer = setTimeout(() => {
              if (!cancelled) check(true);
            }, INITIAL_RETRY_DELAY_MS);
          }
          // Already-loaded pages continue to work normally; the interval
          // will pick up again on the next POLL_INTERVAL_MS tick.
        });
    }

    check();
    const id = window.setInterval(() => check(), POLL_INTERVAL_MS);

    // iOS Safari's edge-swipe back/forward gesture restores the previous
    // page from the bfcache (back-forward cache) instead of re-mounting the
    // React tree - this effect does NOT re-run on that kind of restore, so
    // without this listener a frozen tab could sit on stale session state
    // for up to POLL_INTERVAL_MS after the swipe before the next interval
    // tick notices a meanwhile-revoked/expired session (or, on the flip
    // side, a meanwhile-approved one). `pageshow`'s `persisted` flag is true
    // exactly for this bfcache-restore case (never on a fresh load, where
    // the `check()` call above already covers it), so re-checking here
    // closes that gap immediately instead of waiting on the poll.
    function handlePageShow(event: PageTransitionEvent) {
      if (event.persisted && !cancelled) {
        check();
      }
    }
    window.addEventListener("pageshow", handlePageShow);

    return () => {
      cancelled = true;
      window.clearInterval(id);
      if (retryTimer !== null) clearTimeout(retryTimer);
      window.removeEventListener("pageshow", handlePageShow);
    };
  }, [navigate]);

  return { session, loading };
}
