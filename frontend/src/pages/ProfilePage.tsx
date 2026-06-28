import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, Avatar } from "../components/AppShell";
import { AuthButton } from "../components/AuthShell";
import { deleteSelf, exportMyData } from "../lib/api";
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
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

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
  async function handleExportData() {
    const token = getSessionToken();
    if (!token) return;
    setExporting(true);
    setExportError(null);
    try {
      const blob = await exportMyData(token);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "modulab-export.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      setExportError(t("profile.export_error"));
    } finally {
      setExporting(false);
    }
  }

  async function handleDeleteAccount() {
    if (!window.confirm(t("profile.delete_confirm"))) {
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
      const message = err instanceof Error ? err.message : t("profile.delete_error_fallback");
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
            <h1 className="text-xl font-semibold">{t("profile.title")}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {t("profile.subtitle")}
            </p>
          </div>
        </div>

        <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
          <ProfileRow label={t("profile.name")} value={displayName} />
          <ProfileRow label={t("profile.username")} value={<ClaimValue value={session.preferred_username} />} />
          <ProfileRow label={t("profile.email")} value={session.email} />
          <ProfileRow
            label={t("profile.email_verified")}
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
                {session.email_verified ? t("profile.verified") : t("profile.not_verified")}
              </span>
            }
          />
          <ProfileRow
            label={t("profile.subject")}
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
            {t("profile.manage_account")}
          </AuthButton>
        )}

        <div className="mt-6 rounded-2xl border border-gray-200 p-4 dark:border-gray-800">
          <p className="text-sm font-medium">{t("profile.export_data")}</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t("profile.export_data_desc")}
          </p>
          {exportError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">{exportError}</p>
          )}
          <button
            type="button"
            disabled={exporting}
            onClick={handleExportData}
            className="mt-3 rounded-md border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            {exporting ? t("profile.exporting") : t("profile.export_data")}
          </button>
        </div>

        <div className="mt-6 rounded-2xl border border-red-200 p-4 dark:border-red-900">
          <p className="text-sm font-medium text-red-700 dark:text-red-400">{t("profile.delete_section_title")}</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t("profile.delete_section_body")}
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
            {deleting ? t("profile.deleting") : t("profile.delete_button")}
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
  const { t } = useTranslation();
  if (!value) {
    return <span className="text-gray-400 dark:text-gray-500">{t("profile.not_available")}</span>;
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

