import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { getMe, logoutRequest } from "../lib/api";
import { queryClient } from "../lib/queryClient";
import { useNotificationEvents, type ServerEvent } from "../lib/useEvents";
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
// lives at /admin/users now - see AdminUsersPage.tsx. ApproveUserHandler
// (backend/internal/auth/admin.go) patches this token's session in place
// the moment an admin approves (UpdateSessionsRole, session.go) rather
// than waiting for a fresh login, so the check below does detect approval:
// once getMe() reports a role other than "pending", this page sends the
// user straight to "/" with the same session, no sign-out/back-in required.
// Lock is the one case that still requires a fresh login - LockUserHandler
// revokes the session outright (RevokeUserSessions) instead of patching it,
// so a locked session's next getMe() call fails closed below and lands on
// /login. The periodic poll exists for that case, and for catching this
// session being revoked for any other reason (logout elsewhere, expiry); the
// "user.approved" SSE handler further down just means approval itself does
// not have to wait for the next POLL_INTERVAL_MS tick.
export default function Pending() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [email, setEmail] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);

  // Pulled out of the polling effect below (as a useCallback, so it has a
  // stable identity across renders) so the SSE handler further down can
  // trigger the exact same re-check on demand instead of duplicating it.
  const check = useCallback(async () => {
    try {
      const session = await getMe();
      setEmail(session.email);
      setLocked(session.locked === true);
      if (session.role !== "pending") {
        // Someone approved this account since the last check - no need
        // to make the user log in again, the existing session cookie is
        // still good, it just authorizes more now.
        navigate("/", { replace: true });
      }
    } catch {
      // Expired, revoked, or otherwise invalid session - fail closed, back
      // to login.
      navigate("/login", { replace: true });
    }
  }, [navigate]);

  useEffect(() => {
    let cancelled = false;
    function poll() {
      if (!cancelled) {
        check();
      }
    }

    poll();
    const id = window.setInterval(poll, POLL_INTERVAL_MS);

    // Same bfcache-restore gap useSession.ts's useAuthenticatedSession
    // closes (see its comment) - iOS Safari's swipe back/forward gesture
    // can restore this page from bfcache without re-running this effect,
    // so re-check immediately on that kind of restore instead of waiting
    // up to POLL_INTERVAL_MS for the next tick.
    const onPageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        poll();
      }
    };
    window.addEventListener("pageshow", onPageShow);

    return () => {
      cancelled = true;
      window.clearInterval(id);
      window.removeEventListener("pageshow", onPageShow);
    };
  }, [check]);

  // Spec section 3.5's "user.approved" event: re-checks the instant it
  // arrives instead of waiting for the next POLL_INTERVAL_MS tick above -
  // see backend/internal/auth/events.go's doc comment for why a pending
  // session is allowed onto this SSE endpoint at all (the one deliberate
  // exception to "pending sessions only get /v1/auth/me and
  // /v1/auth/logout", specifically so this event can reach the person it
  // is about while they are still sitting on this very screen).
  useNotificationEvents(true, (event: ServerEvent) => {
    if (event.type !== "user.approved") {
      return;
    }
    check();
  });

  async function handleLogout() {
    try {
      await logoutRequest();
    } catch {
      // Already invalid server-side - the local sign-out still succeeds.
    }
    queryClient.clear();
    navigate("/login", { replace: true });
  }

  return (
    <AuthShell
      title={locked ? t("pending.title_locked") : t("pending.title_pending")}
      centerText
    >
      <div className="text-center">
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {email ? t("pending.signed_in_as", { email }) : ""}
          {locked ? t("pending.message_locked") : t("pending.message_pending")}
        </p>
        <button
          type="button"
          onClick={handleLogout}
          className="mt-6 text-sm text-gray-500 underline hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
        >
          {t("pending.sign_out")}
        </button>
      </div>
    </AuthShell>
  );
}
