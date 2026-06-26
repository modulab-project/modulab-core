import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, Avatar } from "../components/AppShell";
import { AuthButton } from "../components/AuthShell";
import {
  deleteSelf,
  listAIProviders,
  setAIUserKey,
  deleteAIUserKey,
  type AIUserProvider,
} from "../lib/api";
import { clearSessionToken, getSessionToken } from "../lib/session";

// "/profile" route, linked from the profile panel AppShell renders on every
// page (header avatar -> "View profile"). Core has no UI of its own for
// editing any of these fields - the IdP (Pocket ID) owns the underlying
// account record, Core only ever reads it via OIDC claims at login time
// (backend/internal/auth.Claims) and mirrors them onto the session. So
// this page is read-only by design: it shows exactly what the IdP told
// Core about this user (name, email, whether the IdP considers that email
// verified) and, instead of pretending to offer edit controls that would
// have nowhere to actually save to, links straight out to the IdP's own
// account-settings page (session.account_settings_url, built by the
// backend's MeHandler from the configured issuer URL) for anyone who
// wants to change something. The one action this page does own outright
// is account deletion (DELETE /v1/auth/me, lib/api.ts's deleteSelf) - that
// is specifically about the ModuLab account row, not the IdP-owned profile
// fields above it, so it does not contradict the read-only framing.
//
// Uses AppShell - the same header/footer chrome as Home - rather than a
// standalone screen with its own "Back" button: this is meant to feel like
// a second tab of the same app, reachable straight from the avatar menu,
// not a one-off detour you have to explicitly back out of.
export default function ProfilePage() {
  const navigate = useNavigate();
  const { session, loading } = useAuthenticatedSession();
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  if (loading || !session) {
    return null;
  }

  const displayName = session.name.trim() || session.email;

  // No isSelf/last-super-admin UI branching needed here the way
  // AdminUsersPage.tsx has it for its own Delete button: this page only
  // ever acts on the signed-in user's own account, so there is nothing to
  // distinguish. The backend still enforces the last-remaining-super-admin
  // guard (guardAgainstLastSuperAdmin, admin.go) - that 400 surfaces below
  // as deleteError, same as AdminUsersPage's runAction does for its own
  // guard violations.
  async function handleDeleteAccount() {
    if (!window.confirm("Delete your account? This cannot be undone.")) {
      return;
    }
    const token = getSessionToken();
    if (!token) {
      return;
    }
    setDeleting(true);
    setDeleteError(null);
    try {
      await deleteSelf(token);
      clearSessionToken();
      navigate("/login", { replace: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not delete your account.";
      setDeleteError(message);
      setDeleting(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <div className="mb-6 flex items-center gap-4">
          <Avatar session={session} className="h-16 w-16 text-lg" />
          <div>
            <h1 className="text-xl font-semibold">Profile</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Managed by your identity provider - Core only displays what it received at login.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
          <ProfileRow label="Name" value={displayName} />
          <ProfileRow label="Username" value={<ClaimValue value={session.preferred_username} />} />
          <ProfileRow label="Email" value={session.email} />
          <ProfileRow
            label="Email verified"
            value={
              <span
                className={`flex items-center gap-1.5 text-xs font-medium ${
                  session.email_verified
                    ? "text-green-700 dark:text-green-400"
                    : "text-gray-500 dark:text-gray-400"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    session.email_verified ? "bg-green-600" : "bg-gray-400"
                  }`}
                />
                {session.email_verified ? "Verified" : "Not verified"}
              </span>
            }
          />
          <ProfileRow
            label="Subject (sub)"
            value={<span className="font-mono text-xs">{session.user_id}</span>}
            last
          />
        </div>

        {session.account_settings_url && (
          <AuthButton
            type="button"
            onClick={() => {
              window.open(session.account_settings_url, "_blank", "noopener,noreferrer");
            }}
            className="mt-6 w-full"
          >
            Manage account in OIDC
          </AuthButton>
        )}

        <AIKeysSection />

        <div className="mt-10 rounded-2xl border border-red-200 p-4 dark:border-red-900">
          <p className="text-sm font-medium text-red-700 dark:text-red-400">Delete account</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Permanently removes your ModuLab account and revokes access. Your identity provider
            account is not affected.
          </p>
          {deleteError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">{deleteError}</p>
          )}
          <button
            type="button"
            disabled={deleting}
            onClick={handleDeleteAccount}
            className="mt-3 rounded-md border border-red-300 px-3 py-1.5 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            {deleting ? "Deleting…" : "Delete my account"}
          </button>
        </div>
      </div>
    </AppShell>
  );
}

// Renders an optional OIDC claim (preferred_username today; the same
// pattern applies to any future one) that may legitimately be "" because
// the IdP never populated it - same treatment Name/Picture already get
// elsewhere on this page, just pulled out since this is now the second
// claim that needs it. Deliberately not an error state or a blank row:
// an admin reading this page should be able to tell "the IdP doesn't set
// this claim" apart from "something is broken", which a silently empty
// cell would not communicate.
function ClaimValue({ value }: { value: string }) {
  if (!value) {
    return <span className="text-gray-400 dark:text-gray-500">Not available</span>;
  }
  return <>{value}</>;
}

function ProfileRow({
  label,
  value,
  last = false,
}: {
  label: string;
  value: ReactNode;
  last?: boolean;
}) {
  return (
    <div
      className={`flex items-start justify-between gap-4 px-4 py-3.5 text-sm ${
        last ? "" : "border-b border-gray-100 dark:border-gray-800"
      }`}
    >
      <span className="flex-shrink-0 text-gray-500 dark:text-gray-400">{label}</span>
      <span className="min-w-0 break-all text-right font-medium">{value}</span>
    </div>
  );
}

// --- AI Keys Section --------------------------------------------------------
// Shown on the profile page. Lists all enabled providers and lets the user
// set their own API key (overriding the admin key) or remove it (falling
// back to the admin key). Providers the admin configured as user_can_override=false
// are shown as read-only (admin key only, no override possible).

function AIKeysSection() {
  const [providers, setProviders] = useState<AIUserProvider[] | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    const token = getSessionToken();
    if (!token) return;
    listAIProviders(token)
      .then(setProviders)
      .catch(() => {});
  };

  useEffect(() => {
    refresh();
  }, []);

  if (!providers || providers.length === 0) return null;

  async function handleSave(providerId: string) {
    if (!keyInput.trim()) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await setAIUserKey(token, providerId, keyInput.trim());
      setEditingId(null);
      setKeyInput("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save key.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(providerId: string) {
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await deleteAIUserKey(token, providerId);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to remove key.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-10">
      <h2 className="mb-1 text-base font-semibold">AI providers</h2>
      <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
        Your own API key overrides the admin key for that provider — useful if you have a better plan.
      </p>
      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        {providers.map((p, i) => {
          const isEditing = editingId === p.id;
          const isLast = i === providers.length - 1;
          return (
            <div
              key={p.id}
              className={`px-4 py-3.5 text-sm ${isLast ? "" : "border-b border-gray-100 dark:border-gray-800"}`}
            >
              <div className="flex items-center justify-between gap-2">
                <p className="font-medium">{p.name}</p>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    p.has_user_key
                      ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                      : p.has_admin_key
                      ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
                      : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                  }`}
                >
                  {p.has_user_key ? "Your key" : p.has_admin_key ? "Admin key" : "No key"}
                </span>
              </div>

              {isEditing ? (
                <div className="mt-2 flex items-center gap-2">
                  <input
                    type="password"
                    autoComplete="off"
                    autoFocus
                    value={keyInput}
                    onChange={(e) => setKeyInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSave(p.id);
                      if (e.key === "Escape") { setEditingId(null); setKeyInput(""); }
                    }}
                    placeholder="sk-..."
                    className="flex-1 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                  />
                  <button
                    type="button"
                    disabled={busy || !keyInput.trim()}
                    onClick={() => handleSave(p.id)}
                    className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                  >
                    {busy ? "…" : "Save"}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setEditingId(null); setKeyInput(""); }}
                    className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className="mt-1.5 flex items-center gap-1.5">
                  {p.can_override && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => { setEditingId(p.id); setKeyInput(""); }}
                      className="rounded-md border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
                    >
                      {p.has_user_key ? "Update key" : "Add own key"}
                    </button>
                  )}
                  {p.has_user_key && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleRemove(p.id)}
                      className="rounded-md border border-red-300 px-3 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                    >
                      Remove
                    </button>
                  )}
                  {!p.can_override && (
                    <span className="text-xs text-gray-400 dark:text-gray-600">Override not allowed</span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
