// System Info — read-only diagnostics hub (/admin/system/info). Bundles what
// an admin previously had to piece together from three separate places
// (AppShell's status panel, the Installed Modules page, and the Store page):
// version/uptime, dependency reachability, and — the actual reason this page
// exists — countdowns until the next background module-update check and
// registry sync, so "I published a release, why hasn't ModuLab noticed yet"
// has a concrete answer instead of "wait and see".
import { useEffect, useRef, useState } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  getSystemInfo,
  revokeSession,
  type ActiveSession,
  type SystemInfo,
  type SystemInfoModule,
  type SystemInfoTimer,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";
import packageJson from "../../package.json";

const FRONTEND_VERSION = packageJson.version;

export default function AdminSystemInfoPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;

    const token = getSessionToken();
    if (!token) return;
    getSystemInfo(token)
      .then(setInfo)
      .catch(() => setError(t("admin.system_info.load_error")));
  }, [session, navigate, t]);

  // Anchored on Date.now() rather than counting ticks — see AppShell's
  // uptime ticker fix (2026-07-05): a plain "+1 every second" counter falls
  // behind after the tab is backgrounded or the device sleeps, since
  // setInterval is throttled/paused in both cases and missed ticks are never
  // made up. Anchoring on the real clock instead means the displayed value
  // self-heals the moment the tab wakes up, regardless of how many ticks
  // were actually delivered while it was asleep.
  const fetchedAtRef = useRef(Date.now());
  const [, forceTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => forceTick((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);
  const elapsedMs = Date.now() - fetchedAtRef.current;

  // Tracks which session IDs currently have an in-flight or just-failed
  // revoke request, so the button can disable itself mid-request and the
  // row can show an inline error without disturbing the rest of the table.
  const [revokingIds, setRevokingIds] = useState<Set<string>>(new Set());
  const [revokeError, setRevokeError] = useState<string | null>(null);

  function handleRevoke(target: ActiveSession) {
    const confirmKey = target.current
      ? "admin.system_info.end_session_confirm_self"
      : "admin.system_info.end_session_confirm";
    if (!window.confirm(t(confirmKey, { name: target.name || target.email || target.role }))) {
      return;
    }
    const token = getSessionToken();
    if (!token) return;
    setRevokeError(null);
    setRevokingIds((prev) => new Set(prev).add(target.id));
    revokeSession(token, target.id)
      .then(() => {
        setInfo((prev) =>
          prev
            ? { ...prev, active_sessions: (prev.active_sessions ?? []).filter((s) => s.id !== target.id) }
            : prev,
        );
      })
      .catch(() => setRevokeError(t("admin.system_info.end_session_error")))
      .finally(() => {
        setRevokingIds((prev) => {
          const next = new Set(prev);
          next.delete(target.id);
          return next;
        });
      });
  }

  if (loading || !session || session.role !== "super-admin") return null;

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
          <h1 className="text-xl font-semibold mb-1">{t("admin.system_info.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.system_info.subtitle")}</p>
        </div>

        {error && <p className="mb-6 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {!info && !error && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}

        {info && (
          <div className="flex flex-col gap-6">
            {/* Version & uptime */}
            <Section title={t("admin.system_info.section_version")}>
              {info.core_update_available && info.latest_core_version && (
                <div className="mb-3 flex items-center gap-2 rounded-xl border border-teal-200 bg-teal-50 px-4 py-2.5 text-sm text-teal-700 dark:border-teal-800 dark:bg-teal-950 dark:text-teal-300">
                  <i className="ti ti-arrow-big-up-lines text-[16px]" />
                  {t("admin.system_info.core_update_available", { version: info.latest_core_version })}
                </div>
              )}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <Stat label={t("shell.status.backend_version")} value={info.version} />
                <Stat label={t("shell.status.frontend_version")} value={FRONTEND_VERSION} />
                <Stat
                  label={t("shell.status.uptime")}
                  value={formatDuration((info.uptime_seconds * 1000 + elapsedMs) / 1000)}
                />
              </div>
            </Section>

            {/* Registry sync — also drives the next installed-module update
                check (the update check runs immediately after every sync,
                see the backend's RunUpdateCheckOnce), so this one countdown
                covers both instead of showing two timers that always
                converged on the same event anyway. */}
            <Section title={t("admin.system_info.section_timers")}>
              <TimerCard
                icon="ti-cloud-download"
                title={t("admin.system_info.registry_sync_title")}
                timer={info.registry_sync}
                t={t}
              />
            </Section>

            {/* Infrastructure */}
            <Section title={t("admin.system_info.section_infra")}>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <InfraRow icon="ti-database" label={t("shell.status.postgres")} ok={info.postgres_reachable} />
                <InfraRow icon="ti-bolt" label={t("shell.status.valkey")} ok={info.valkey_reachable} />
                {info.searxng_configured ? (
                  <InfraRow icon="ti-search" label={t("shell.status.searxng")} ok={!!info.searxng_reachable} />
                ) : (
                  <InfraRow
                    icon="ti-search"
                    label={t("shell.status.searxng")}
                    text={t("shell.status.not_configured")}
                  />
                )}
                {info.ntp_drift_ok !== undefined && (
                  <InfraRow icon="ti-clock" label={t("admin.system_info.ntp_drift")} ok={info.ntp_drift_ok} />
                )}
                {info.tls_cert_days_left !== undefined && (
                  <InfraRow
                    icon="ti-certificate"
                    label={t("admin.system_info.tls_cert")}
                    text={t("admin.system_info.tls_cert_days", { count: info.tls_cert_days_left })}
                    warn={info.tls_cert_days_left <= 14}
                  />
                )}
              </div>
            </Section>

            {/* Installed modules */}
            <Section title={t("admin.system_info.section_modules")}>
              {info.modules.length === 0 ? (
                <p className="text-sm text-gray-400 dark:text-gray-500">{t("modules.empty")}</p>
              ) : (
                <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-200 bg-gray-50 text-left dark:border-gray-800 dark:bg-gray-900">
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_module")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_version")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_status")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_source")}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {info.modules.map((m, i) => (
                        <ModuleRow key={m.name} mod={m} even={i % 2 === 0} />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>

            {/* Active sessions */}
            <Section
              title={t("admin.system_info.section_sessions", { count: info.active_sessions?.length ?? 0 })}
            >
              {revokeError && <p className="mb-2 text-sm text-red-600 dark:text-red-400">{revokeError}</p>}
              {!info.active_sessions || info.active_sessions.length === 0 ? (
                <p className="text-sm text-gray-400 dark:text-gray-500">{t("admin.system_info.no_sessions")}</p>
              ) : (
                <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-200 bg-gray-50 text-left dark:border-gray-800 dark:bg-gray-900">
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_name")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_role")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_login")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_ip")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_device")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_last_active")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          {t("admin.system_info.col_expires")}
                        </th>
                        <th className="px-4 py-2.5 font-medium text-gray-500 dark:text-gray-400">
                          <span className="sr-only">{t("admin.system_info.col_actions")}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {info.active_sessions.map((s) => (
                        <SessionRow
                          key={s.id}
                          session={s}
                          revoking={revokingIds.has(s.id)}
                          onRevoke={() => handleRevoke(s)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
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

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-gray-200 p-3 dark:border-gray-800">
      <div className="text-[11px] text-gray-400 dark:text-gray-500">{label}</div>
      <div className="mt-0.5 font-mono text-sm text-gray-800 dark:text-gray-200">{value}</div>
    </div>
  );
}

function InfraRow({
  icon,
  label,
  ok,
  text,
  warn,
}: {
  icon: string;
  label: string;
  ok?: boolean;
  text?: string;
  warn?: boolean;
}) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-gray-200 px-3 py-2.5 dark:border-gray-800">
      <div className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
        <i className={`ti ${icon} text-[15px] text-gray-400`} />
        {label}
      </div>
      {text ? (
        <span
          className={`text-xs ${warn ? "font-medium text-amber-600 dark:text-amber-400" : "text-gray-400 dark:text-gray-500"}`}
        >
          {text}
        </span>
      ) : (
        <span className={`h-2 w-2 rounded-full ${ok ? "bg-green-500" : "bg-red-500"}`} />
      )}
    </div>
  );
}

// TimerCard renders a countdown that recomputes from real timestamps on
// every parent re-render (the parent's 1 s ticker), never from an
// accumulated tick count — the same drift-avoidance the uptime fix above
// applies, since "next run in X" is exactly the kind of value that would
// otherwise quietly go stale after the tab is backgrounded.
function TimerCard({
  icon,
  title,
  timer,
  t,
}: {
  icon: string;
  title: string;
  timer: SystemInfoTimer;
  t: (key: string, opts?: Record<string, unknown>) => string;
}) {
  const nextInMs = timer.next_run_at ? new Date(timer.next_run_at).getTime() - Date.now() : null;

  return (
    <div className="rounded-xl border border-gray-200 p-4 dark:border-gray-800">
      <div className="mb-2 flex items-center gap-2">
        <i className={`ti ${icon} text-[16px] text-gray-400`} />
        <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">{title}</span>
      </div>
      {timer.last_run_at ? (
        <>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {t("admin.system_info.last_run", { time: new Date(timer.last_run_at).toLocaleTimeString() })}
          </p>
          <p className="mt-1 text-sm font-medium text-teal-700 dark:text-teal-400">
            {nextInMs !== null && nextInMs > 0
              ? t("admin.system_info.next_run_in", { duration: formatDuration(nextInMs / 1000) })
              : t("admin.system_info.next_run_soon")}
          </p>
        </>
      ) : (
        <p className="text-xs text-gray-400 dark:text-gray-500">{t("admin.system_info.not_run_yet")}</p>
      )}
      <p className="mt-2 text-[11px] text-gray-400 dark:text-gray-600">
        {t("admin.system_info.interval", { duration: formatDuration(timer.interval_seconds) })}
      </p>
    </div>
  );
}

function ModuleRow({ mod, even }: { mod: SystemInfoModule; even: boolean }) {
  const { t } = useTranslation();
  return (
    <tr className={`border-b border-gray-100 last:border-0 dark:border-gray-800 ${even ? "" : "bg-gray-50/50 dark:bg-gray-900/30"}`}>
      <td className="px-4 py-2.5 text-gray-700 dark:text-gray-300">
        <div className="flex items-center gap-1.5">
          {mod.name}
          {mod.pinned && <i className="ti ti-pin text-[12px] text-gray-400" title={t("modules.pinned")} />}
        </div>
      </td>
      <td className="px-4 py-2.5">
        <span className="text-gray-700 dark:text-gray-300">v{mod.version}</span>
        {mod.available_version && (
          <span className="ml-1.5 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900 dark:text-amber-300">
            v{mod.available_version}
          </span>
        )}
      </td>
      <td className="px-4 py-2.5">
        <span className="text-xs text-gray-600 dark:text-gray-400">{t(`modules.status.${mod.status}`)}</span>
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">{mod.source}</td>
    </tr>
  );
}

function SessionRow({
  session,
  revoking,
  onRevoke,
}: {
  session: ActiveSession;
  revoking: boolean;
  onRevoke: () => void;
}) {
  const { t } = useTranslation();
  const device = session.user_agent ? parseUserAgent(session.user_agent) : null;
  return (
    <tr className={`border-b border-gray-100 last:border-0 dark:border-gray-800 ${session.current ? "bg-teal-50/60 dark:bg-teal-950/30" : ""}`}>
      <td className="px-4 py-2.5 text-gray-700 dark:text-gray-300">
        {session.name || session.email || <span className="text-gray-300 dark:text-gray-600">—</span>}
        {session.current && (
          <span className="ml-1.5 rounded-full bg-teal-100 px-2 py-0.5 text-[10px] font-medium text-teal-700 dark:bg-teal-900 dark:text-teal-300">
            {t("admin.system_info.session_current")}
          </span>
        )}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-600 dark:text-gray-400">{session.role}</td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">
        {session.created_at ? new Date(session.created_at).toLocaleString() : "—"}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">{session.ip || "—"}</td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500" title={session.user_agent}>
        {device ? `${device.browser} · ${device.os}` : "—"}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">
        {session.last_active_seconds_ago !== undefined
          ? t("admin.system_info.last_active_ago", { duration: formatDuration(session.last_active_seconds_ago) })
          : "—"}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400 dark:text-gray-500">
        {session.expires_in_seconds !== undefined
          ? t("admin.system_info.expires_in", { duration: formatDuration(session.expires_in_seconds) })
          : "—"}
      </td>
      <td className="px-4 py-2.5 text-right">
        <button
          type="button"
          onClick={onRevoke}
          disabled={revoking}
          className="text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50 dark:text-red-400 dark:hover:text-red-300"
        >
          {revoking ? t("common.loading") : t("admin.system_info.end_session")}
        </button>
      </td>
    </tr>
  );
}

// parseUserAgent gives a compact, human-friendly reading of a raw
// User-Agent string ("Chrome · Windows" rather than the full ~120-character
// header value) - just enough for an admin to recognize which of their own
// devices a session belongs to. Deliberately a handful of substring checks
// rather than a full UA-parsing library: this only ever renders for the
// System Info page's admin-only table, not anywhere accuracy is load-
// bearing, and covers every mainstream browser/OS combination in practice.
// Order matters - Edge and Opera both contain "Chrome" in their own UA
// strings, so those checks must come first.
function parseUserAgent(ua: string): { browser: string; os: string } {
  let browser = "Unknown";
  if (ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("OPR/") || ua.includes("Opera")) browser = "Opera";
  else if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("CriOS") || ua.includes("Chrome/")) browser = "Chrome";
  else if (ua.includes("Safari/")) browser = "Safari";

  let os = "Unknown";
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac OS X") || ua.includes("Macintosh")) os = "macOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad") || ua.includes("iOS")) os = "iOS";
  else if (ua.includes("Linux")) os = "Linux";

  return { browser, os };
}

// formatDuration renders a second count as a compact human string ("45s",
// "12m", "3h 20m", "2d 4h"). Shared shape with AppShell's formatUptime, kept
// as its own local copy rather than exported/shared - this file is the only
// other place that needs it, and duplicating ~15 lines beats introducing a
// cross-file dependency for something this small.
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
