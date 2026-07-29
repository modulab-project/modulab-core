// Security Info — read-only "who/what is active right now" page
// (/admin/security/info), split out of System Info (2026-07-05) so that
// page can stay focused on "is Core healthy" (version, uptime, dependency
// reachability, background timers, modules) while this one answers a
// different question: which sessions are logged in, and is anyone (or any
// IP) currently rate-limited. Reuses the "admin.system_info.*" locale keys
// for the actual table column labels/messages that moved here unchanged —
// only the page-level title/subtitle/card_desc/load_error got a new
// "admin.security_info.*" namespace, to avoid a five-locale-file rename of
// every shared string for what is otherwise a pure page split.
import { useEffect, useRef, useState } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  getSystemInfo,
  revokeSession,
  resetRateLimit,
  type ActiveSession,
  type SystemInfo,
  type SystemInfoRateLimit,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { isSuperAdminRole } from "../lib/roles";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { queryClient } from "../lib/queryClient";
import { AppShell } from "../components/AppShell";
import { ReauthBanner } from "../components/ReauthBanner";

export default function AdminSecurityInfoPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (!isSuperAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;

    getSystemInfo()
      .then(setInfo)
      .catch(() => setError(t("admin.security_info.load_error")));
  }, [session, navigate, t]);

  // Tracks which session IDs currently have an in-flight or just-failed
  // revoke request, so the button can disable itself mid-request and the
  // row can show an inline error without disturbing the rest of the table.
  const [revokingIds, setRevokingIds] = useState<Set<string>>(new Set());
  const [revokeError, setRevokeError] = useState<string | null>(null);
  // Backend now gates DELETE /v1/admin/sessions/{id} behind requireRecentLogin
  // (RequireSuperAdminReauthMiddleware) - forcibly ending someone else's
  // session has the same immediate effect as locking their account, which
  // already got this step-up treatment. Same pattern as AdminUsersPage.tsx.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setRevokeError(null);
  });

  function handleRevoke(target: ActiveSession) {
    const confirmKey = target.current
      ? "admin.system_info.end_session_confirm_self"
      : "admin.system_info.end_session_confirm";
    if (!window.confirm(t(confirmKey, { name: target.name || target.email || target.role }))) {
      return;
    }
    setRevokeError(null);
    setReauthRequired(false);
    setRevokingIds((prev) => new Set(prev).add(target.id));
    revokeSession(target.id)
      .then(() => {
        // Ending your OWN session (found 2026-07-05): the session cookie
        // every tab of this browser shares was just revoked server-side,
        // but until now nothing told this tab that — it kept looking fully
        // logged in until the next API call happened to 401. Since this
        // action can only ever be the admin's own doing (confirmed via the
        // confirm-dialog above), clear the query cache and leave for
        // /login immediately instead of waiting for that to happen. Note
        // this now also signs out every other tab of the same browser -
        // see RevokeSessionByID's doc comment in session.go for why.
        if (target.current) {
          queryClient.clear();
          navigate("/login", { replace: true });
          return;
        }
        setInfo((prev) =>
          prev
            ? { ...prev, active_sessions: (prev.active_sessions ?? []).filter((s) => s.id !== target.id) }
            : prev,
        );
      })
      .catch((err) => {
        if (isReauthRequiredError(err)) {
          setReauthRequired(true);
        } else {
          setRevokeError(t("admin.system_info.end_session_error"));
        }
      })
      .finally(() => {
        setRevokingIds((prev) => {
          const next = new Set(prev);
          next.delete(target.id);
          return next;
        });
      });
  }

  // Same in-flight/error pattern as the sessions table above, keyed by the
  // raw Valkey key (unique per label+identifier) rather than an id field
  // since rate-limit entries have no separate id of their own.
  const [resettingKeys, setResettingKeys] = useState<Set<string>>(new Set());
  const [resetError, setResetError] = useState<string | null>(null);

  function handleResetRateLimit(target: SystemInfoRateLimit) {
    setResetError(null);
    setResettingKeys((prev) => new Set(prev).add(target.key));
    resetRateLimit(target.key)
      .then(() => {
        setInfo((prev) =>
          prev
            ? { ...prev, rate_limits: (prev.rate_limits ?? []).filter((r) => r.key !== target.key) }
            : prev,
        );
      })
      .catch(() => setResetError(t("admin.system_info.rate_limit_reset_error")))
      .finally(() => {
        setResettingKeys((prev) => {
          const next = new Set(prev);
          next.delete(target.key);
          return next;
        });
      });
  }

  if (loading || !session || !isSuperAdminRole(session.role)) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-3xl py-10">
        <Link
          to="/admin/system"
          className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200"
        >
          <i className="ti ti-arrow-left text-[14px]" />
          {t("admin.system.title")}
        </Link>

        <div className="mb-8">
          <h1 className="text-xl font-semibold mb-1">{t("admin.security_info.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.security_info.subtitle")}</p>
        </div>

        {error && <p className="mb-6 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {!info && !error && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}

        {info && (
          <div className="flex flex-col gap-6">
            {/* Active sessions */}
            <Section
              title={t("admin.system_info.section_sessions", { count: info.active_sessions?.length ?? 0 })}
            >
              {revokeError && !reauthRequired && (
                <p className="mb-2 text-sm text-red-600 dark:text-red-400">{revokeError}</p>
              )}
              {reauthRequired && (
                <ReauthBanner
                  waiting={reauthWaiting}
                  onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
                  onDismiss={() => setReauthRequired(false)}
                />
              )}
              {!info.active_sessions || info.active_sessions.length === 0 ? (
                <p className="text-sm text-gray-400 dark:text-gray-500">{t("admin.system_info.no_sessions")}</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {info.active_sessions.map((s) => (
                    <SessionListItem
                      key={s.id}
                      session={s}
                      revoking={revokingIds.has(s.id)}
                      onRevoke={() => handleRevoke(s)}
                    />
                  ))}
                </ul>
              )}
            </Section>

            {/* Rate limits — live Valkey counters, so an admin can see
                whether an IP (or user) is currently rate-limited without
                SSH-ing into Valkey, and clear it early if it's a false
                positive (shared office IP, misbehaving script now fixed,
                etc). Trips also land in the audit log (event_type
                "rate_limit.exceeded") so they're discoverable after the
                live counter has already expired. */}
            <Section
              title={t("admin.system_info.section_rate_limits", { count: info.rate_limits?.length ?? 0 })}
            >
              {resetError && <p className="mb-2 text-sm text-red-600 dark:text-red-400">{resetError}</p>}
              {!info.rate_limits || info.rate_limits.length === 0 ? (
                <p className="text-sm text-gray-400 dark:text-gray-500">{t("admin.system_info.no_rate_limits")}</p>
              ) : (
                <>
                  {/* Desktop/tablet: table. Hidden below the sm breakpoint -
                      see the stacked cards below instead. */}
                  <div className="hidden overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 sm:block">
                    <table className="min-w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-200 bg-gray-50 text-left dark:border-gray-800 dark:bg-gray-900">
                          <th className="whitespace-nowrap px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                            {t("admin.system_info.col_label")}
                          </th>
                          <th className="whitespace-nowrap px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                            {t("admin.system_info.col_identifier")}
                          </th>
                          <th className="whitespace-nowrap px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                            {t("admin.system_info.col_count")}
                          </th>
                          <th className="whitespace-nowrap px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                            {t("admin.system_info.col_resets_in")}
                          </th>
                          <th className="whitespace-nowrap px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                            <span className="sr-only">{t("admin.system_info.col_actions")}</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {info.rate_limits.map((r) => (
                          <RateLimitRow
                            key={r.key}
                            entry={r}
                            resetting={resettingKeys.has(r.key)}
                            onReset={() => handleResetRateLimit(r)}
                          />
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Phone: stacked cards, same data. */}
                  <div className="flex flex-col gap-2 sm:hidden">
                    {info.rate_limits.map((r) => (
                      <RateLimitCard
                        key={r.key}
                        entry={r}
                        resetting={resettingKeys.has(r.key)}
                        onReset={() => handleResetRateLimit(r)}
                      />
                    ))}
                  </div>
                </>
              )}
            </Section>
          </div>
        )}
      </div>
    </AppShell>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="mb-2.5 text-xs font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {title}
      </h2>
      {children}
    </div>
  );
}

// Single-list-item rendering for one active session - same shape as
// ProfilePage.tsx's SessionListItem (rounded bordered row, teal/green
// highlight when current, device+IP+last-active stacked on the left, End
// button on the right) rather than a separate desktop table + phone card
// pair. Unlike Profile's version this is admin-facing and shows every
// column the old table/card split had (name/email, role, login time,
// country, expires) via a small key/value grid under the device line.
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
  const device = session.user_agent ? parseUserAgent(session.user_agent, t) : null;
  return (
    <li
      className={`flex flex-col gap-2 rounded-lg border px-3 py-2.5 text-sm sm:flex-row sm:items-start sm:justify-between sm:gap-3 ${
        session.current
          ? "border-green-200 bg-green-50/60 dark:border-green-900 dark:bg-green-950/30"
          : "border-gray-200 dark:border-gray-800"
      }`}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-gray-700 dark:text-gray-300">
            {session.name || session.email || <span className="text-gray-300 dark:text-gray-600">—</span>}
          </span>
          {session.current && (
            <span className="whitespace-nowrap rounded-full bg-green-100 px-2 py-0.5 text-[10px] font-medium text-green-700 dark:bg-green-900 dark:text-green-300">
              {t("admin.system_info.session_current")}
            </span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400" title={session.user_agent}>
          {device ? `${device.browser} · ${device.os}` : "—"}
          {session.country && <> · {session.country}</>}
        </p>
        {session.ip && (
          <p className="mt-0.5 break-all text-xs text-gray-500 dark:text-gray-400">
            {session.ip}
            {session.hostname && <> · {session.hostname}</>}
          </p>
        )}
        <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-2 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
          <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_role")}</dt>
          <dd>{session.role}</dd>
          <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_login")}</dt>
          <dd>{session.created_at ? new Date(session.created_at).toLocaleString() : "—"}</dd>
          <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_last_active")}</dt>
          <dd>
            {session.last_active_seconds_ago !== undefined
              ? t("admin.system_info.last_active_ago", { duration: formatDuration(session.last_active_seconds_ago) })
              : "—"}
          </dd>
          <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_expires")}</dt>
          <dd>
            {session.expires_in_seconds !== undefined
              ? t("admin.system_info.expires_in", { duration: formatDuration(session.expires_in_seconds) })
              : "—"}
          </dd>
        </dl>
      </div>
      <button
        type="button"
        onClick={onRevoke}
        disabled={revoking}
        className="self-start text-xs font-medium text-red-600 hover:text-red-700 disabled:cursor-not-allowed disabled:opacity-50 dark:text-red-400 dark:hover:text-red-300 sm:flex-shrink-0"
      >
        {revoking ? t("common.loading") : t("admin.system_info.end_session")}
      </button>
    </li>
  );
}

function RateLimitRow({
  entry,
  resetting,
  onReset,
}: {
  entry: SystemInfoRateLimit;
  resetting: boolean;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const overLimit = entry.max !== undefined && entry.max > 0 && entry.count > entry.max;
  return (
    <tr className="border-b border-gray-100 last:border-0 dark:border-gray-800">
      <td className="whitespace-nowrap px-4 py-2.5 text-xs text-gray-600 dark:text-gray-400">{entry.label}</td>
      <td className="whitespace-nowrap px-4 py-2.5 text-xs text-gray-700 dark:text-gray-300">
        {entry.display_name ? (
          <div className="flex flex-col items-start gap-0.5">
            <span>{entry.display_name}</span>
            <span className="font-mono text-[10px] text-gray-400 dark:text-gray-600">{entry.identifier}</span>
          </div>
        ) : (
          <span className="font-mono">{entry.identifier || "—"}</span>
        )}
      </td>
      <td className="whitespace-nowrap px-4 py-2.5 text-xs">
        <span className={overLimit ? "font-medium text-red-600 dark:text-red-400" : "text-gray-600 dark:text-gray-400"}>
          {entry.max ? `${entry.count} / ${entry.max}` : entry.count}
        </span>
      </td>
      <td className="whitespace-nowrap px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">
        {t("admin.system_info.expires_in", { duration: formatDuration(entry.reset_in_seconds) })}
      </td>
      <td className="whitespace-nowrap px-4 py-2.5 text-right">
        <button
          type="button"
          onClick={onReset}
          disabled={resetting}
          className="text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50 dark:text-red-400 dark:hover:text-red-300"
        >
          {resetting ? t("common.loading") : t("admin.system_info.rate_limit_reset")}
        </button>
      </td>
    </tr>
  );
}

// Phone counterpart of RateLimitRow - same table/card split the sessions
// section used to have, kept as-is here since only "Aktive Sitzungen" was
// asked to match Profile's list style.
function RateLimitCard({
  entry,
  resetting,
  onReset,
}: {
  entry: SystemInfoRateLimit;
  resetting: boolean;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const overLimit = entry.max !== undefined && entry.max > 0 && entry.count > entry.max;
  return (
    <div className="rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-800">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <span className="font-medium text-gray-700 dark:text-gray-300">{entry.label}</span>
          {entry.display_name ? (
            <div className="mt-0.5 flex flex-col gap-0.5">
              <span className="break-all text-xs text-gray-600 dark:text-gray-400">{entry.display_name}</span>
              <span className="break-all font-mono text-[10px] text-gray-400 dark:text-gray-600">{entry.identifier}</span>
            </div>
          ) : (
            <div className="mt-0.5 break-all font-mono text-xs text-gray-600 dark:text-gray-400">
              {entry.identifier || "—"}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={onReset}
          disabled={resetting}
          className="flex-shrink-0 text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50 dark:text-red-400 dark:hover:text-red-300"
        >
          {resetting ? t("common.loading") : t("admin.system_info.rate_limit_reset")}
        </button>
      </div>
      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-2 gap-y-1 text-xs text-gray-500 dark:text-gray-400">
        <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_count")}</dt>
        <dd className={overLimit ? "font-medium text-red-600 dark:text-red-400" : ""}>
          {entry.max ? `${entry.count} / ${entry.max}` : entry.count}
        </dd>
        <dt className="text-gray-400 dark:text-gray-500">{t("admin.system_info.col_resets_in")}</dt>
        <dd>{t("admin.system_info.expires_in", { duration: formatDuration(entry.reset_in_seconds) })}</dd>
      </dl>
    </div>
  );
}

// parseUserAgent gives a compact, human-friendly reading of a raw
// User-Agent string ("Chrome · Windows" rather than the full ~120-character
// header value) - just enough for an admin to recognize which of their own
// devices a session belongs to. Deliberately a handful of substring checks
// rather than a full UA-parsing library: this only ever renders for this
// admin-only table, not anywhere accuracy is load-bearing, and covers every
// mainstream browser/OS combination in practice. Order matters - Edge and
// Opera both contain "Chrome" in their own UA strings, so those checks must
// come first.
function parseUserAgent(ua: string, t: TFunction): { browser: string; os: string } {
  let browser = t("admin.security_info.unknown");
  if (ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("OPR/") || ua.includes("Opera")) browser = "Opera";
  else if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("CriOS") || ua.includes("Chrome/")) browser = "Chrome";
  else if (ua.includes("Safari/")) browser = "Safari";

  let os = t("admin.security_info.unknown");
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac OS X") || ua.includes("Macintosh")) os = "macOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad") || ua.includes("iOS")) os = "iOS";
  else if (ua.includes("Linux")) os = "Linux";

  return { browser, os };
}

// formatDuration renders a second count as a compact human string ("45s",
// "12m", "3h 20m", "2d 4h"). Shared shape with AppShell's formatUptime and
// AdminSystemInfoPage's own copy, kept as its own local copy rather than
// exported/shared - duplicating ~15 lines beats introducing a cross-file
// dependency for something this small.
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
