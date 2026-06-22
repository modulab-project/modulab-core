import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getMe, logoutRequest } from "../lib/api";
import { clearSessionToken, getSessionToken } from "../lib/session";
import { AuthShell } from "../components/AuthShell";

// 15s strikes a balance between "feels reasonably live" and not hammering
// /v1/auth/me from every still-pending tab a household might have open.
const POLL_INTERVAL_MS = 15_000;

// Spec section 6.4's "/pending" route ("Wartemaske 'Dein Konto wird
// geprüft'", Pending-User access). A user lands here straight out of
// AuthComplete when role === auth.RolePending (backend/internal/auth/
// role.go), which now covers two distinct situations CallbackHandler
// distinguishes via Session.Locked before either of them ever gets here:
// correctly grouped but never approved yet (locked === false - the far
// more common case), or previously approved and since locked by an admin
// (locked === true). The admin side of both (approve/lock/unlock/delete)
// lives at /admin/users now - see AdminUsersPage.tsx. Unlike an earlier
// version of this page, it does NOT claim to detect the moment an admin
// changes either flag: CallbackHandler bakes the role (and locked flag)
// into the session once at login and never revisits it, so an
// already-issued pending session stays "pending" for its full lifetime no
// matter what changes in the database afterwards. The periodic check below
// still exists, but only to catch this token being explicitly revoked
// (logout elsewhere, expiry) - not to detect approval/unlock. A fresh
// login is the only thing that picks up new approval/lock state.
export default function Pending() {
  const navigate = useNavigate();
  const [email, setEmail] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) {
      navigate("/login", { replace: true });
      return;
    }

    let cancelled = false;

    // Takes the token as a parameter rather than closing over the outer
    // `token` directly - TypeScript can't carry the `string | null` ->
    // `string` narrowing from the guard above across into a separately
    // declared function (even though `token` is a const and provably
    // still a string by the time this runs), so it would otherwise widen
    // back to `string | null` here and fail getMe()'s string parameter.
    async function check(currentToken: string) {
      try {
        const session = await getMe(currentToken);
        if (cancelled) {
          return;
        }
        setEmail(session.email);
        setLocked(session.locked === true);
        if (session.role !== "pending") {
          // Someone approved this account since the last check - no need
          // to make the user log in again, the existing token is still
          // good, it just authorizes more now.
          navigate("/", { replace: true });
        }
      } catch {
        // Expired or otherwise invalid token - fail closed, back to login.
        if (!cancelled) {
          clearSessionToken();
          navigate("/login", { replace: true });
        }
      }
    }

    check(token);
    const id = window.setInterval(() => check(token), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [navigate]);

  async function handleLogout() {
    const token = getSessionToken();
    clearSessionToken();
    if (token) {
      try {
        await logoutRequest(token);
      } catch {
        // Already invalid server-side - the local sign-out still succeeds.
      }
    }
    navigate("/login", { replace: true });
  }

  return (
    <AuthShell
      title={locked ? "Your account has been locked" : "Your account is pending approval"}
      centerText
    >
      <div className="text-center">
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {email ? `Signed in as ${email}. ` : ""}
          {locked
            ? "An administrator has locked your account. Contact your administrator if you believe this is a mistake."
            : "An Admin needs to approve your account before you can continue. Once approved, sign out below and sign in again to get access."}
        </p>
        <button
          type="button"
          onClick={handleLogout}
          className="mt-6 text-sm text-gray-500 underline hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
        >
          Sign out
        </button>
      </div>
    </AuthShell>
  );
}
