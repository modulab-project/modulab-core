import { useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, Avatar } from "../components/AppShell";
import { AuthButton } from "../components/AuthShell";
import { deleteSelf, exportMyData, listMySessions, revokeMySession, type ActiveSession } from "../lib/api";
import { isReauthRequiredError } from "../lib/authErrors";
import { ReauthBanner } from "../components/ReauthBanner";
import { queryClient } from "../lib/queryClient";
import { useLoginRedirect } from "../lib/useLoginRedirect";

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
  // See AdminUsersPage.tsx's identical flag for lock/delete - self-delete
  // goes through the same requireRecentLogin gate (admin.go/handlers.go).
  const [reauthRequired, setReauthRequired] = useState(false);
  const [exporting, setExporting] = useState(false);
  // Same cross-tab lock as AdminUsersPage.tsx's identical flag - see
  // lib/useLoginRedirect.ts.
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setDeleteError(null);
  });
  const [exportError, setExportError] = useState<string | null>(null);

  // Self-service "my devices" (GET/DELETE /v1/auth/sessions) - the same
  // active-sessions data System Info shows admins, scoped by the backend
  // to the caller's own sessions only (ListActiveSessionsForUser), so any
  // approved user can see and end a lost/stolen device's session
  // themselves instead of needing to ask a super-admin.
  const [sessions, setSessions] = useState<ActiveSession[] | null>(null);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [revokingIds, setRevokingIds] = useState<Set<string>>(new Set());
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const hasFetchedSessions = useRef(false);

  useEffect(() => {
    if (!session || hasFetchedSessions.current) return;
    hasFetchedSessions.current = true;
    listMySessions()
      .then(setSessions)
      .catch(() => setSessionsError(t("profile.sessions_load_error")));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fetch-once-on-mount guarded by hasFetchedSessions, not meant to re-run on t changing.
  }, [session]);

  function handleRevokeSession(target: ActiveSession) {
    if (!window.confirm(t("profile.sessions_end_confirm", { device: target.user_agent ? parseUserAgent(target.user_agent, t) : target.ip || target.role }))) {
      return;
    }
    setRevokeError(null);
    setRevokingIds((prev) => new Set(prev).add(target.id));
    revokeMySession(target.id)
      .then(() => {
        setSessions((prev) => (prev ? prev.filter((s) => s.id !== target.id) : prev));
      })
      .catch(() => setRevokeError(t("profile.sessions_end_error")))
      .finally(() => {
        setRevokingIds((prev) => {
          const next = new Set(prev);
          next.delete(target.id);
          return next;
        });
      });
  }

  if (loading || !session) {
    return null;
  }

  const displayName = session.name.trim() || session.email;

  // No isSelf/last-super-admin UI branching needed here the way
  // AdminUsersPage.tsx has it for its own Delete button: this page only
  // ever acts on the signed-in user's own account, so there is nothing to
  // distinguish. The backend still enforces the last-remaining-super-admin
  // guard (guardAgainstLastAdmin, admin.go) - that 400 surfaces below
  // as deleteError, same as AdminUsersPage's runAction does for its own
  // guard violations.
  async function handleExportData() {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await exportMyData();
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
    setDeleting(true);
    setDeleteError(null);
    setReauthRequired(false);
    try {
      await deleteSelf();
      queryClient.clear();
      navigate("/login", { replace: true });
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        const message = err instanceof Error ? err.message : t("profile.delete_error_fallback");
        setDeleteError(message);
      }
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
                    ? "text-teal-700 dark:text-teal-400"
                    : "text-gray-500 dark:text-gray-400"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    session.email_verified ? "bg-teal-600" : "bg-gray-400"
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

        <div className="mt-6 rounded-2xl border border-gray-200 p-4 dark:border-gray-800">
          <p className="text-sm font-medium">{t("profile.sessions_title")}</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{t("profile.sessions_desc")}</p>
          {sessionsError && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{sessionsError}</p>}
          {revokeError && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{revokeError}</p>}
          {sessions === null && !sessionsError && (
            <p className="mt-3 text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
          )}
          {sessions && sessions.length === 0 && (
            <p className="mt-3 text-sm text-gray-400 dark:text-gray-500">{t("profile.sessions_empty")}</p>
          )}
          {sessions && sessions.length > 0 && (
            <ul className="mt-3 flex flex-col gap-2">
              {sessions.map((s) => (
                <SessionListItem
                  key={s.id}
                  session={s}
                  revoking={revokingIds.has(s.id)}
                  onRevoke={() => handleRevokeSession(s)}
                />
              ))}
            </ul>
          )}
        </div>

        <div className="mt-6 rounded-2xl border border-red-200 p-4 dark:border-red-900">
          <p className="text-sm font-medium text-red-700 dark:text-red-400">{t("profile.delete_section_title")}</p>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t("profile.delete_section_body")}
          </p>
          {deleteError && !reauthRequired && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">{deleteError}</p>
          )}
          {reauthRequired && (
            <ReauthBanner
              waiting={reauthWaiting}
              onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
              onDismiss={() => setReauthRequired(false)}
            />
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

// One row in the "my devices" list - deliberately a plainer single-line
// layout than AdminSecurityInfoPage.tsx's SessionRow table (no name/email/
// role columns, since every row here is unambiguously "you"; just device,
// IP, last-active, and an end button). parseUserAgent/formatDuration below
// are local copies of that page's identical helpers - same reasoning as
// its own formatDuration comment: duplicating ~15 lines beats a cross-file
// dependency for something this small.
function SessionListItem({
  session,
  revoking,
  onRevoke,
}: {
  session: ActiveSession;
  revoking: boolean;
  onRevoke: () => void;
}) {
  const { t } = useTranslation();
  const device = session.user_agent ? parseUserAgent(session.user_agent, t) : t("profile.sessions_unknown_device");
  return (
    <li
      className={`flex flex-col gap-2 rounded-lg border px-3 py-2.5 text-sm sm:flex-row sm:items-center sm:justify-between sm:gap-3 ${
        session.current
          ? "border-teal-200 bg-teal-50/60 dark:border-teal-900 dark:bg-teal-950/30"
          : "border-gray-200 dark:border-gray-800"
      }`}
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{device}</span>
          {session.current && (
            <span className="whitespace-nowrap rounded-full bg-teal-100 px-2 py-0.5 text-[10px] font-medium text-teal-700 dark:bg-teal-900 dark:text-teal-300">
              {t("profile.sessions_current")}
            </span>
          )}
        </div>
        {session.country && (
          <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{session.country}</p>
        )}
        {session.ip && (
          <p className="mt-0.5 break-all pl-3 text-xs text-gray-500 dark:text-gray-400">
            <span className="text-gray-400 dark:text-gray-500">{t("profile.sessions_ip")}: </span>
            {session.ip}
            {session.hostname && <> · {session.hostname}</>}
          </p>
        )}
        {session.last_active_seconds_ago !== undefined && (
          <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            {t("profile.sessions_last_active", { duration: formatDuration(session.last_active_seconds_ago) })}
          </p>
        )}
      </div>
      <button
        type="button"
        onClick={onRevoke}
        disabled={revoking || session.current}
        title={session.current ? t("profile.sessions_end_self_hint") : undefined}
        className="self-start text-xs font-medium text-red-600 hover:text-red-700 disabled:cursor-not-allowed disabled:opacity-40 dark:text-red-400 dark:hover:text-red-300 sm:flex-shrink-0"
      >
        {revoking ? t("common.loading") : t("profile.sessions_end")}
      </button>
    </li>
  );
}

function parseUserAgent(ua: string, t: TFunction): string {
  let browser = t("profile.sessions_unknown_device");
  if (ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("OPR/") || ua.includes("Opera")) browser = "Opera";
  else if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("CriOS") || ua.includes("Chrome/")) browser = "Chrome";
  else if (ua.includes("Safari/")) browser = "Safari";

  let os = "";
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac OS X") || ua.includes("Macintosh")) os = "macOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad") || ua.includes("iOS")) os = "iOS";
  else if (ua.includes("Linux")) os = "Linux";

  return os ? `${browser} · ${os}` : browser;
}

function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const minutes = Math.floor(s / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  if (hours < 24) return `${hours}h ${remMinutes}m`;
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return `${days}d ${remHours}h`;
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

