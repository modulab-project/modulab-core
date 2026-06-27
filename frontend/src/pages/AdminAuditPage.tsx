import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { getAuditLog, type AuditEntry } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// Known event types for the filter dropdown — matches the constants in
// backend/internal/audit/audit.go.
const EVENT_TYPES = [
  "user.approved",
  "user.locked",
  "user.unlocked",
  "user.deleted",
  "config.smtp",
  "config.smtp.deleted",
  "config.oidc",
  "config.dns_challenge",
  "setup.completed",
];

const PAGE_SIZE = 50;

export default function AdminAuditPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(false);
  const [hasMore, setHasMore] = useState(false);

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
              className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
            >
              <option value="">{t("admin.audit.filter_all")}</option>
              {EVENT_TYPES.map((et) => (
                <option key={et} value={et}>
                  {et}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

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
                      {e.actor_email || e.actor_id}
                    </td>
                    <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
                      {e.target_email || e.target_id || "—"}
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
function EventBadge({ type }: { type: string }) {
  let color = "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400";
  if (type.startsWith("user.")) {
    color = "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300";
  } else if (type.startsWith("config.")) {
    color = "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300";
  } else if (type === "setup.completed") {
    color = "bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300";
  }
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${color}`}>
      {type}
    </span>
  );
}

// Pretty-print the details JSON blob if valid, otherwise show raw string.
function DetailsCell({ raw }: { raw: string }) {
  try {
    const parsed = JSON.parse(raw);
    return (
      <span title={raw}>
        {Object.entries(parsed as Record<string, string>)
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ")}
      </span>
    );
  } catch {
    return <span>{raw}</span>;
  }
}
