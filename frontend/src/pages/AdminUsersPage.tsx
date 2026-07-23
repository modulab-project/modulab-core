import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  approveUser,
  deleteUser,
  listUsers,
  lockUser,
  unlockUser,
  type AdminUser,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { AppShell } from "../components/AppShell";
import { isAdminRole } from "../lib/roles";
import { isReauthRequiredError } from "../lib/authErrors";
import { ReauthBanner } from "../components/ReauthBanner";

// "/admin/users" - replaces the manual "UPDATE users SET approved = true"
// (and, before this page, no way at all to lock or delete someone) with a
// real admin UI on top of backend/internal/auth/admin.go's endpoints.
// org-admin/super-admin only, same role check the backend itself enforces
// (requireAdmin) - a non-admin hitting this URL directly gets bounced
// home rather than shown a dead-end error screen.
//
// One list, three derived states per row (Pending / Active / Locked), each
// with its own action set - intentionally not three separate pages: an
// admin managing users wants one place to look, not "is this person
// pending, or do I need the other tab".
type RowStatus = "pending" | "active" | "locked";

function statusOf(u: AdminUser): RowStatus {
  if (u.locked) {
    return "locked";
  }
  return u.approved ? "active" : "pending";
}

export default function AdminUsersPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // True when the last failed action was refused specifically because the
  // caller's own login is too old (backend/internal/auth.requireRecentLogin,
  // reauthWindow = 15 min) - lock/delete/self-delete require a recent login,
  // not just a still-valid session, since a session can slide its TTL for up
  // to 24h of intermittent use. Shown as a distinct banner with a re-login
  // link rather than folded into the generic `error` text.
  const [reauthRequired, setReauthRequired] = useState(false);
  const [busySubject, setBusySubject] = useState<string | null>(null);
  // Same cross-tab lock as Login.tsx - see lib/useLoginRedirect.ts. If
  // another tab is already re-authenticating (or already finished, and the
  // browser's session cookie is fresh again), this tab shouldn't also send
  // itself through a second OIDC round-trip; it just clears the banner once
  // the shared cookie is valid again, and the admin retries their action.
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setError(null);
  });

  const refresh = useCallback(() => {
    listUsers()
      .then((u) => {
        setUsers(u);
        setError(null);
      })
      .catch(() => setError(t("admin.users.load_error")));
  }, [t]);

  useEffect(() => {
    if (!session) {
      return;
    }
    // Not an org-admin/super-admin - this page isn't for them. Bounced
    // home rather than shown a dead-end error screen, same as how
    // useAuthenticatedSession itself handles "pending" by bouncing to
    // /pending instead of rendering anything here first.
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    refresh();
  }, [session, navigate, refresh]);

  if (loading || !session || !isAdminRole(session.role)) {
    return null;
  }

  async function runAction(subject: string, action: (subject: string) => Promise<void>) {
    setBusySubject(subject);
    setError(null);
    setReauthRequired(false);
    try {
      await action(subject);
      refresh();
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        // lockUser/deleteUser's self- and last-super-admin guards surface
        // here as a 400 with a human-readable message (see admin.go's
        // guardAgainstSelfOrLastSuperAdmin) - shown as-is rather than a
        // generic "something went wrong".
        const message = err instanceof Error ? err.message : t("admin.users.action_error");
        setError(message);
      }
    } finally {
      setBusySubject(null);
    }
  }

  function handleDelete(u: AdminUser) {
    const displayName = u.name.trim() || u.email;
    if (!window.confirm(t("admin.users.delete_confirm", { name: displayName }))) {
      return;
    }
    runAction(u.subject, deleteUser);
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("admin.users.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.users.subtitle")}
        </p>

        {error && !reauthRequired && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>
        )}
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}

        {users === null ? null : users.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-200">{t("admin.users.empty")}</p>
          </div>
        ) : (
          <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
            {users.map((u, i) => {
              const isSelf = u.subject === session.user_id;
              const status = statusOf(u);
              const busy = busySubject === u.subject;
              return (
                <div
                  key={u.subject}
                  className={`px-4 py-3.5 text-sm ${
                    i === users.length - 1 ? "" : "border-b border-gray-100 dark:border-gray-800"
                  }`}
                >
                  {/* Row 1: name + status badge */}
                  <div className="flex items-center justify-between gap-2">
                    <p className="min-w-0 break-words font-medium">
                      {u.name.trim() || u.email}
                      {isSelf && <span className="ml-1.5 text-xs text-gray-400">{t("admin.users.you")}</span>}
                    </p>
                    <StatusBadge status={status} />
                  </div>
                  {/* Row 2: details */}
                  <div className="mt-1 min-w-0 text-xs text-gray-500 dark:text-gray-400">
                    <p className="break-words">{u.email} · {u.role}</p>
                    <p className="break-words">{t("admin.users.joined")} {new Date(u.created_at).toLocaleDateString()} · {t("admin.users.last_login")} {new Date(u.last_login_at).toLocaleDateString()}</p>
                  </div>
                  {/* Row 3: action buttons — stacked vertically */}
                  {(status === "pending" || (status === "active" && !isSelf) || status === "locked") && (
                    <div className="mt-2.5 flex flex-col gap-1.5">
                      {status === "pending" && (
                        <ActionButton busy={busy} onClick={() => runAction(u.subject, approveUser)}>
                          {t("admin.users.action.approve")}
                        </ActionButton>
                      )}
                      {status === "active" && !isSelf && (
                        <>
                          <ActionButton
                            variant="secondary"
                            busy={busy}
                            onClick={() => runAction(u.subject, lockUser)}
                          >
                            {t("admin.users.action.lock")}
                          </ActionButton>
                          <ActionButton variant="danger" busy={busy} onClick={() => handleDelete(u)}>
                            {t("admin.users.action.delete")}
                          </ActionButton>
                        </>
                      )}
                      {status === "locked" && (
                        <>
                          <ActionButton busy={busy} onClick={() => runAction(u.subject, unlockUser)}>
                            {t("admin.users.action.unlock")}
                          </ActionButton>
                          <ActionButton variant="danger" busy={busy} onClick={() => handleDelete(u)}>
                            {t("admin.users.action.delete")}
                          </ActionButton>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppShell>
  );
}

function StatusBadge({ status }: { status: RowStatus }) {
  const { t } = useTranslation();
  const styles: Record<RowStatus, string> = {
    pending: "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400",
    active: "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400",
    locked: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-400",
  };
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles[status]}`}>
      {t(`admin.users.status.${status}`)}
    </span>
  );
}

function ActionButton({
  children,
  onClick,
  busy,
  variant = "primary",
}: {
  children: React.ReactNode;
  onClick: () => void;
  busy: boolean;
  variant?: "primary" | "secondary" | "danger";
}) {
  const styles = {
    primary: "bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400",
    secondary:
      "border border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800",
    danger: "border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950",
  };
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onClick}
      className={`w-full rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]}`}
    >
      {busy ? "…" : children}
    </button>
  );
}
