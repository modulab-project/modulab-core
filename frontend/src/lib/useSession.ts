import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { getMe, getHealth, ApiError, type Session } from "./api";
import { clearSessionToken, getSessionToken } from "./session";

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
// this hook existed. Redirects to /login if there is no token or it turns
// out to be invalid/expired, to /pending if the resolved session's role is
// still "pending" (see backend/internal/auth.CallbackHandler's two-gate
// access model - a pending session is real, just not allowed past that one
// screen), and otherwise hands back the resolved session for the page to
// render with.
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
  const [initialLoadDone, setInitialLoadDone] = useState(false);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) {
      // Before sending the user to /login, check whether setup has ever been
      // completed. If not, /login is useless (OIDC isn't configured yet) -
      // send them to /setup instead so the wizard can run.
      getHealth()
        .then((h) => navigate(h.setup_completed ? "/login" : "/setup", { replace: true }))
        .catch(() => navigate("/login", { replace: true }));
      return;
    }

    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    // Takes the token as a parameter rather than closing over the outer
    // `token` directly - same TypeScript narrowing limitation already
    // documented on Pending.tsx's `check`: the `string | null` -> `string`
    // guard above doesn't carry across into a separately declared nested
    // function, so it would otherwise widen back to `string | null` here.
    function check(currentToken: string, isRetry = false) {
      getMe(currentToken)
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
          setInitialLoadDone(true);
          setLoading(false);
        })
        .catch((err) => {
          if (cancelled) return;
          // Only treat explicit auth rejections (401/403) as "this token is
          // dead" — those mean the backend actively refused the credential.
          // Network errors, 502/503/504 from Traefik, and other transient
          // failures are handled differently depending on whether the initial
          // load has already succeeded:
          //   - Already loaded: silently ignore; the next poll will retry.
          //   - Still on initial load: schedule one quick retry after 2 s so
          //     a brief backend restart on page load doesn't leave a blank screen.
          if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
            clearSessionToken();
            navigate("/login", { replace: true });
            return;
          }
          // Transient error — only retry once on initial load.
          if (!initialLoadDone && !isRetry) {
            retryTimer = setTimeout(() => {
              if (!cancelled) check(currentToken, true);
            }, INITIAL_RETRY_DELAY_MS);
          }
          // Already-loaded pages continue to work normally; the interval
          // will pick up again on the next POLL_INTERVAL_MS tick.
        });
    }

    check(token);
    const id = window.setInterval(() => check(token), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
      if (retryTimer !== null) clearTimeout(retryTimer);
    };
  }, [navigate, initialLoadDone]);

  return { session, loading };
}
