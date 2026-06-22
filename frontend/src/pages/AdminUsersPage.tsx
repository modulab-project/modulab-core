import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  approveUser,
  deleteUser,
  listUsers,
  lockUser,
  unlockUser,
  type AdminUser,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

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
  const { session, loading } = useAuthenticatedSession();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busySubject, setBusySubject] = useState<string | null>(null);

  const refresh = useCallback(() => {
    const token = getSessionToken();
    if (!token) {
      return;
    }
    listUsers(token)
      .then((u) => {
        setUsers(u);
        setError(null);
      })
      .catch(() => setError("Could not load users."));
  }, []);

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

  async function runAction(subject: string, action: (token: string, subject: string) => Promise<void>) {
    const token = getSessionToken();
    if (!token) {
      return;
    }
    setBusySubject(subject);
    setError(null);
    try {
      await action(token, subject);
      refresh();
    } catch (err) {
      // lockUser/deleteUser's self- and last-super-admin guards surface
      // here as a 400 with a human-readable message (see admin.go's
      // guardAgainstSelfOrLastSuperAdmin) - shown as-is rather than a
      // generic "something went wrong".
      const message = err instanceof Error ? err.message : "That action failed.";
      setError(message);
    } finally {
      setBusySubject(null);
    }
  }

  function handleDelete(u: AdminUser) {
    const displayName = u.name.trim() || u.email;
    if (!window.confirm(`Delete ${displayName}? This cannot be undone.`)) {
      return;
    }
    runAction(u.subject, deleteUser);
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <h1 className="mb-1 text-xl font-semibold">Users</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          Approve people waiting for access, or lock/delete anyone who already has it.
        </p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {users === null ? null : users.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-200">No users yet</p>
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
                  className={`flex items-center justify-between gap-3 px-4 py-3.5 text-sm ${
                    i === users.length - 1 ? "" : "border-b border-gray-100 dark:border-gray-800"
                  }`}
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">
                      {u.name.trim() || u.email}
                      {isSelf && <span className="ml-1.5 text-xs text-gray-400">(you)</span>}
                    </p>
                    <p className="truncate text-xs text-gray-500 dark:text-gray-400">
                      {u.email} · {u.role} · since {new Date(u.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex flex-none items-center gap-2">
                    <StatusBadge status={status} />
                    {status === "pending" && (
                      <ActionButton busy={busy} onClick={() => runAction(u.subject, approveUser)}>
                        Approve
                      </ActionButton>
                    )}
                    {status === "active" && !isSelf && (
                      <>
                        <ActionButton
                          variant="secondary"
                          busy={busy}
                          onClick={() => runAction(u.subject, lockUser)}
                        >
                          Lock
                        </ActionButton>
                        <ActionButton variant="danger" busy={busy} onClick={() => handleDelete(u)}>
                          Delete
                        </ActionButton>
                      </>
                    )}
                    {status === "locked" && (
                      <>
                        <ActionButton busy={busy} onClick={() => runAction(u.subject, unlockUser)}>
                          Unlock
                        </ActionButton>
                        <ActionButton variant="danger" busy={busy} onClick={() => handleDelete(u)}>
                          Delete
                        </ActionButton>
                      </>
                    )}
                  </div>
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
  const styles: Record<RowStatus, string> = {
    pending: "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400",
    active: "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400",
    locked: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-400",
  };
  const labels: Record<RowStatus, string> = {
    pending: "Pending",
    active: "Active",
    locked: "Locked",
  };
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

function ActionButton({
  children,
  onClick,
  busy,
  variant = "primary",
}: {
  children: string;
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
      className={`flex-none rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]}`}
    >
      {busy ? "…" : children}
    </button>
  );
}
