import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { getAuditLog, verifyAuditLog, type AuditEntry, type AuditVerifyResult } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// Known event types for the filter dropdown — matches the constants in
// backend/internal/audit/audit.go.
const EVENT_TYPES = [
  // Auth
  "auth.login",
  // User lifecycle (admin-driven)
  "user.approved",
  "user.locked",
  "user.unlocked",
  "user.deleted",
  // User self-service
  "user.self_deleted",
  // System config
  "config.smtp",
  "config.smtp.deleted",
  "config.oidc",
  "config.oidc.deleted",
  "config.searxng",
  "config.searxng.deleted",
  "config.ai_provider",
  "config.ai_provider.deleted",
  "config.ai_provider.key_cleared",
  "config.ai_settings",
  // Setup
  "setup.completed",
  // Module lifecycle
  "module.installed",
  "module.uninstalled",
  "module.updated",
  "module.restarted",
  "module.pinned",
  "module.unpinned",
  // Feed management
  "feed.created",
  "feed.updated",
  "feed.deleted",
  // Quick links
  "quicklink.created",
  "quicklink.updated",
  "quicklink.deleted",
  // Store registry sync
  "store.sync_triggered",
  // Rate limiting
  "rate_limit.exceeded",
];

const PAGE_SIZE = 50;

// Translates a raw event_type ("user.approved", "config.ai_provider.key_cleared",
// ...) into a human-readable label ("Benutzer freigegeben", ...) via
// admin.audit.event_types.<type_with_underscores> - i18next keys can't
// contain literal dots (they're the nesting separator), hence the
// underscore rewrite. Falls back to the raw type itself via `defaultValue`
// if a translation is ever missing - e.g. a backend event type shipped
// before its locale entry was added, or a module-defined type in the
// future - so an untranslated entry still shows something useful (the raw
// string) rather than a blank/broken-looking cell.
function eventTypeLabel(t: (key: string, opts?: { defaultValue: string }) => string, type: string): string {
  return t(`admin.audit.event_types.${type.replace(/\./g, "_")}`, { defaultValue: type });
}

export default function AdminAuditPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(false);
  const [hasMore, setHasMore] = useState(false);

  // Hash-chain integrity check — on-demand only, see verifyAuditLog's doc
  // comment. verifyResult is null until the admin actually clicks the button.
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [verifyError, setVerifyError] = useState(false);

  function handleVerify() {
    const token = getSessionToken();
    if (!token || verifying) return;
    setVerifying(true);
    setVerifyError(false);
    setVerifyResult(null);
    verifyAuditLog(token)
      .then(setVerifyResult)
      .catch(() => setVerifyError(true))
      .finally(() => setVerifying(false));
  }

  // Filter state
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const appliedFilter = useRef("");

  // Cursor for "load more" pagination (id of last loaded entry).
  const cursorRef = useRef<number | undefined>(undefined);

  const hasFetched = useRef(false);

  // Load the first page whenever filter changes or on initial mount.
  function loadFirstPage(eventType: string) {
    const token = getSessionToken();
    if (!token) return;
    cursorRef.current = undefined;
    appliedFilter.current = eventType;
    setFetching(true);
    setError(null);
    getAuditLog(token, { event_type: eventType || undefined, limit: PAGE_SIZE })
      .then((data) => {
        setEntries(data);
        setHasMore(data.length === PAGE_SIZE);
        if (data.length > 0) {
          cursorRef.current = data[data.length - 1].id;
        }
      })
      .catch(() => setError(t("admin.audit.load_error")))
      .finally(() => setFetching(false));
  }

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;
    loadFirstPage("");
  }, [session, navigate]);

  if (loading || !session || session.role !== "super-admin") return null;

  function handleFilterChange(value: string) {
    setEventTypeFilter(value);
    hasFetched.current = true; // prevent the useEffect re-trigger
    loadFirstPage(value);
  }

  function loadMore() {
    const token = getSessionToken();
    if (!token || !cursorRef.current) return;
    setFetching(true);
    getAuditLog(token, {
      event_type: appliedFilter.current || undefined,
      before: cursorRef.current,
      limit: PAGE_SIZE,
    })
      .then((data) => {
        setEntries((prev) => [...prev, ...data]);
        setHasMore(data.length === PAGE_SIZE);
        if (data.length > 0) {
          cursorRef.current = data[data.length - 1].id;
        }
      })
      .catch(() => setError(t("admin.audit.load_error")))
      .finally(() => setFetching(false));
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-4xl py-10">
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-xl font-semibold">{t("admin.audit.title")}</h1>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              {t("admin.audit.subtitle")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <label className="sr-only">{t("admin.audit.filter_label")}</label>
            <select
              value={eventTypeFilter}
              onChange={(e) => handleFilterChange(e.target.value)}
              className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
            >
              <option value="">{t("admin.audit.filter_all")}</option>
              {EVENT_TYPES.map((et) => (
                <option key={et} value={et}>
                  {eventTypeLabel(t, et)}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={handleVerify}
              disabled={verifying}
              className="whitespace-nowrap rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
            >
              {verifying ? t("admin.audit.verifying") : t("admin.audit.verify")}
            </button>
          </div>
        </div>

        {verifyResult && (
          <p
            className={`mb-4 flex items-center gap-1.5 text-sm ${
              verifyResult.ok
                ? "text-teal-600 dark:text-teal-400"
                : "text-red-600 dark:text-red-400"
            }`}
          >
            <i className={`ti ${verifyResult.ok ? "ti-shield-check" : "ti-alert-triangle"} text-[14px]`} />
            {verifyResult.ok
              ? t("admin.audit.verify_ok", { count: verifyResult.entries_checked })
              : t("admin.audit.verify_broken", { id: verifyResult.broken_at_id })}
          </p>
        )}
        {verifyError && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">{t("admin.audit.verify_error")}</p>
        )}

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {entries.length === 0 && fetching && (
          <div className="flex flex-col gap-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-10 animate-pulse rounded-lg bg-gray-100 dark:bg-gray-800" />
            ))}
          </div>
        )}

        {entries.length === 0 && !fetching && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("admin.audit.empty")}</p>
        )}

        {entries.length > 0 && (
          <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 text-left dark:border-gray-800 dark:bg-gray-900">
                  <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">{t("admin.audit.col_time")}</th>
                  <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">{t("admin.audit.col_event")}</th>
                  <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">{t("admin.audit.col_actor")}</th>
                  <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">{t("admin.audit.col_target")}</th>
                  <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">{t("admin.audit.col_details")}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e, i) => (
                  <tr
                    key={e.id}
                    className={`border-b border-gray-100 last:border-0 dark:border-gray-800 ${
                      i % 2 === 0 ? "" : "bg-gray-50/50 dark:bg-gray-900/30"
                    }`}
                  >
                    <td className="whitespace-nowrap px-4 py-3 tabular-nums text-gray-500 dark:text-gray-400">
                      {new Date(e.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <EventBadge type={e.event_type} />
                    </td>
                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
                      {e.actor_name || e.actor_email || e.actor_id}
                    </td>
                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
                      {e.target_name || e.target_email || e.target_id || "—"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-400 dark:text-gray-500">
                      {e.details ? <DetailsCell raw={e.details} /> : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {(hasMore || fetching) && (
          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={loadMore}
              disabled={fetching}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
            >
              {fetching ? t("admin.audit.loading") : t("admin.audit.load_more")}
            </button>
          </div>
        )}
      </div>
    </AppShell>
  );
}

// Colour-coded badge for event types.
// Shows the translated, human-readable label (eventTypeLabel) as the
// primary text - the point of this whole component (2026-07-08: admins
// couldn't tell at a glance what "config.ai_provider.key_cleared" meant).
// The raw type string is kept as a `title` tooltip, not dropped: someone
// cross-referencing against backend/internal/audit/audit.go or writing a
// filter still needs the exact wire value, just not as the first thing
// they read.
function EventBadge({ type }: { type: string }) {
  const { t } = useTranslation();
  let color = "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400";
  if (type.startsWith("user.")) {
    color = "bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200";
  } else if (type.startsWith("config.")) {
    color = "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300";
  } else if (type === "setup.completed") {
    color = "bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300";
  }
  return (
    <span
      title={type}
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${color}`}
    >
      {eventTypeLabel(t, type)}
    </span>
  );
}

// Pretty-print the details JSON blob if valid, otherwise show raw string.
function DetailsCell({ raw }: { raw: string }) {
  let entries: [string, string][] | null = null;
  try {
    const parsed = JSON.parse(raw);
    entries = Object.entries(parsed as Record<string, string>);
  } catch {
    // entries stays null - raw is shown as-is below.
  }

  if (entries === null) return <span>{raw}</span>;
  if (entries.length === 0) return <span className="text-gray-300 dark:text-gray-600">—</span>;
  return (
    <span title={raw}>
      {entries.map(([k, v]) => `${k}: ${v}`).join(" · ")}
    </span>
  );
}
