import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getMe, type Session } from "./api";
import { clearSessionToken, getSessionToken } from "./session";

// Same interval Pending.tsx polls on - kept in sync so "how stale can a
// revoked session look in the UI" is one number, not two.
const POLL_INTERVAL_MS = 15_000;

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

  useEffect(() => {
    const token = getSessionToken();
    if (!token) {
      navigate("/login", { replace: true });
      return;
    }

    let cancelled = false;

    // Takes the token as a parameter rather than closing over the outer
    // `token` directly - same TypeScript narrowing limitation already
    // documented on Pending.tsx's `check`: the `string | null` -> `string`
    // guard above doesn't carry across into a separately declared nested
    // function, so it would otherwise widen back to `string | null` here.
    function check(currentToken: string) {
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
          setLoading(false);
        })
        .catch(() => {
          // Covers an expired token as well as one an admin revoked via
          // lock/delete - both look identical from here (the session key is
          // simply gone), and both fail closed the same way.
          if (!cancelled) {
            clearSessionToken();
            navigate("/login", { replace: true });
          }
        });
    }

    check(token);
    const id = window.setInterval(() => check(token), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [navigate]);

  return { session, loading };
}
