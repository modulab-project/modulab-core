import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  getAuditLog,
  getAuditActors,
  verifyAuditLog,
  type AuditActor,
  type AuditEntry,
  type AuditVerifyResult,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// Known event types for the filter dropdown, grouped by category — matches
// the constants in backend/internal/audit/audit.go. Grouped (rendered as
// <optgroup>) rather than one flat 40+-option list, which was unreadable -
// an admin looking for "module updated" had to scan the whole alphabet of
// event types with no structure to anchor on.
const EVENT_TYPE_CATEGORIES: { category: string; types: string[] }[] = [
  {
    category: "auth",
    types: [
      "auth.login",
      "auth.logout",
      "auth.session_revoked_by_admin",
      "auth.session_revoked_by_idp",
    ],
  },
  {
    category: "user",
    types: ["user.approved", "user.locked", "user.unlocked", "user.deleted", "user.self_deleted"],
  },
  {
    category: "config",
    types: [
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
      "config.news_settings",
      "config.search_provider",
      "config.search_provider.key_cleared",
      "config.search_settings",
      "config.system_limits",
    ],
  },
  { category: "ai", types: ["ai.user_key_set", "ai.user_key_deleted"] },
  { category: "search", types: ["search.user_key_set", "search.user_key_deleted"] },
  {
    category: "setup",
    types: ["setup.completed", "setup.oidc_configured", "setup.group_prefix_configured"],
  },
  {
    category: "module",
    types: [
      "module.installed",
      "module.uninstalled",
      "module.updated",
      "module.restarted",
      "module.pinned",
      "module.unpinned",
    ],
  },
  { category: "feed", types: ["feed.created", "feed.updated", "feed.deleted"] },
  {
    category: "quicklink",
    types: ["quicklink.created", "quicklink.updated", "quicklink.deleted"],
  },
  {
    category: "store",
    types: ["store.sync_triggered", "store.custom_source_added", "store.custom_source_removed"],
  },
  { category: "rate_limit", types: ["rate_limit.exceeded"] },
];

const PAGE_SIZE = 50;

// store.sync_triggered fires on every visit to the Store/Modules pages (see
// frontend/src/lib/api.ts's syncStore, called from StorePage/
// AdminModulesPage on mount) - a page view, not a deliberate admin action -
// so in bursts it drowns out the entries an admin actually cares about.
// Hidden by default (see hideSyncNoise below); still fully visible if the
// admin explicitly filters the dropdown down to this exact type.
const STORE_SYNC_TYPE = "store.sync_triggered";

// Consecutive entries (list is newest-first) with the same event_type and
// actor, fired within this many ms of each other, are collapsed into one
// summary row - e.g. three "session ended by admin" rows 5s apart from a
// single bulk revoke, or three module updates fired back-to-back from one
// "update all" click. Threshold is generous on purpose: these are rendered
// as one *interaction*, not one exact timestamp.
const GROUP_WINDOW_MS = 10_000;

// Two extra caps on top of GROUP_WINDOW_MS, both needed because that window
// is measured between *consecutive* entries, not from the group's start - a
// steady trickle of same-type/same-actor entries each <10s apart would
// otherwise chain into one arbitrarily large, arbitrarily long-lived group
// (seen in practice: an 11-entry bulk session revoke is a real, useful
// group; a group spanning unrelated activity across many minutes is not).
// MAX_GROUP_SPAN_MS bounds total group duration from the first entry;
// MAX_GROUP_SIZE bounds entry count outright.
const MAX_GROUP_SPAN_MS = 60_000;
const MAX_GROUP_SIZE = 25;

// How long to wait after the admin stops typing in the search box before
// actually querying the server - avoids firing a request per keystroke.
const SEARCH_DEBOUNCE_MS = 400;

type EntryGroup = { key: string; entries: AuditEntry[] };

function groupEntries(list: AuditEntry[]): EntryGroup[] {
  const groups: EntryGroup[] = [];
  for (const e of list) {
    const last = groups[groups.length - 1];
    const lastEntry = last?.entries[last.entries.length - 1];
    const firstEntry = last?.entries[0];
    const eTime = new Date(e.created_at).getTime();
    const withinWindow = lastEntry && Math.abs(new Date(lastEntry.created_at).getTime() - eTime) <= GROUP_WINDOW_MS;
    const withinSpan = firstEntry && Math.abs(new Date(firstEntry.created_at).getTime() - eTime) <= MAX_GROUP_SPAN_MS;
    const underSize = last && last.entries.length < MAX_GROUP_SIZE;
    if (
      last &&
      lastEntry.event_type === e.event_type &&
      lastEntry.actor_id === e.actor_id &&
      withinWindow &&
      withinSpan &&
      underSize
    ) {
      last.entries.push(e);
    } else {
      groups.push({ key: String(e.id), entries: [e] });
    }
  }
  return groups;
}

// Unique, human-readable target labels across a group's entries, used in
// the summary row/card so grouping a burst of "module updated" events
// doesn't just drop which modules were touched. Falls back to a bare count
// once there are too many distinct targets to list usefully.
function summarizeTargets(entries: AuditEntry[], t: (key: string, opts?: { count: number }) => string): string {
  const labels = Array.from(
    new Set(entries.map((e) => e.target_name || e.target_email || e.target_id).filter((v): v is string => Boolean(v))),
  );
  if (labels.length === 0) return "—";
  if (labels.length <= 3) return labels.join(", ");
  return t("admin.audit.group_target_count", { count: labels.length });
}

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

type Filters = {
  eventType: string;
  actorId: string;
  since: string; // YYYY-MM-DD, "" = no lower bound
  until: string; // YYYY-MM-DD, "" = no upper bound
  search: string; // applied (debounced) search text
};

const EMPTY_FILTERS: Filters = { eventType: "", actorId: "", since: "", until: "", search: "" };

function hasActiveFilters(f: Filters): boolean {
  return Boolean(f.eventType || f.actorId || f.since || f.until || f.search);
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

  // Noise reduction: hide store.sync_triggered by default (see STORE_SYNC_TYPE
  // above), and remember which duplicate-burst groups the admin expanded.
  const [hideSyncNoise, setHideSyncNoise] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  function toggleGroup(key: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function handleVerify() {
    if (verifying) return;
    setVerifying(true);
    setVerifyError(false);
    setVerifyResult(null);
    verifyAuditLog()
      .then(setVerifyResult)
      .catch(() => setVerifyError(true))
      .finally(() => setVerifying(false));
  }

  // Filter state. eventType/actorId/since/until apply immediately on
  // change; search is debounced (see searchInput below) so the applied
  // `search` field only updates SEARCH_DEBOUNCE_MS after the admin stops
  // typing.
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [sinceFilter, setSinceFilter] = useState("");
  const [untilFilter, setUntilFilter] = useState("");
  const [searchInput, setSearchInput] = useState(""); // raw textbox value
  const [searchFilter, setSearchFilter] = useState(""); // debounced, applied value

  const [actors, setActors] = useState<AuditActor[]>([]);

  // Actor dropdown options, loaded once - the audit log itself is what
  // tells us which actors exist, so this can't be pre-known like
  // EVENT_TYPE_CATEGORIES.
  useEffect(() => {
    getAuditActors()
      .then(setActors)
      .catch(() => {
        /* Non-critical: the actor filter just stays empty. */
      });
  }, []);

  // Client-side noise filter + duplicate-burst grouping, applied on top of
  // whatever page(s) the server already returned. Recomputed only when the
  // fetched entries, the toggle, or the dropdown filter change.
  const visibleEntries = useMemo(() => {
    if (!hideSyncNoise || eventTypeFilter === STORE_SYNC_TYPE) return entries;
    return entries.filter((e) => e.event_type !== STORE_SYNC_TYPE);
  }, [entries, hideSyncNoise, eventTypeFilter]);

  const hiddenSyncCount = entries.length - visibleEntries.length;

  const groups = useMemo(() => groupEntries(visibleEntries), [visibleEntries]);

  // Cursor for "load more" pagination (id of last loaded entry), and the
  // filter set that produced the currently-loaded page (loadMore must keep
  // using it, even if the admin has since changed a control but not yet
  // triggered a new search).
  const cursorRef = useRef<number | undefined>(undefined);
  const appliedFilters = useRef<Filters>(EMPTY_FILTERS);

  const hasFetched = useRef(false);

  // Runs a fresh (first-page) query for the given filter set.
  const runQuery = useCallback(
    (f: Filters) => {
      appliedFilters.current = f;
      cursorRef.current = undefined;
      setFetching(true);
      setError(null);
      getAuditLog({
        event_type: f.eventType || undefined,
        actor_id: f.actorId || undefined,
        since: f.since || undefined,
        until: f.until || undefined,
        search: f.search || undefined,
        limit: PAGE_SIZE,
      })
        .then((data) => {
          setEntries(data);
          setHasMore(data.length === PAGE_SIZE);
          if (data.length > 0) {
            cursorRef.current = data[data.length - 1].id;
          }
        })
        .catch(() => setError(t("admin.audit.load_error")))
        .finally(() => setFetching(false));
    },
    [t],
  );

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetched.current) return;
    hasFetched.current = true;
    runQuery(EMPTY_FILTERS);
  }, [session, navigate, runQuery]);

  // Debounce the search box: only apply it (and re-query) once the admin
  // has paused typing. Reads the *other* filters fresh at the moment the
  // timer fires so a search doesn't clobber a filter changed in between.
  useEffect(() => {
    const handle = setTimeout(() => {
      setSearchFilter(searchInput);
      hasFetched.current = true;
      runQuery({
        eventType: eventTypeFilter,
        actorId: actorFilter,
        since: sinceFilter,
        until: untilFilter,
        search: searchInput,
      });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(handle);
    // Only the search box itself should restart the debounce timer - the
    // other filters apply immediately via their own handlers below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput]);

  if (loading || !session || session.role !== "super-admin") return null;

  function handleEventTypeChange(value: string) {
    setEventTypeFilter(value);
    hasFetched.current = true;
    runQuery({ eventType: value, actorId: actorFilter, since: sinceFilter, until: untilFilter, search: searchFilter });
  }

  function handleActorChange(value: string) {
    setActorFilter(value);
    hasFetched.current = true;
    runQuery({ eventType: eventTypeFilter, actorId: value, since: sinceFilter, until: untilFilter, search: searchFilter });
  }

  function handleSinceChange(value: string) {
    setSinceFilter(value);
    hasFetched.current = true;
    runQuery({ eventType: eventTypeFilter, actorId: actorFilter, since: value, until: untilFilter, search: searchFilter });
  }

  function handleUntilChange(value: string) {
    setUntilFilter(value);
    hasFetched.current = true;
    runQuery({ eventType: eventTypeFilter, actorId: actorFilter, since: sinceFilter, until: value, search: searchFilter });
  }

  function handleResetFilters() {
    setEventTypeFilter("");
    setActorFilter("");
    setSinceFilter("");
    setUntilFilter("");
    setSearchInput("");
    setSearchFilter("");
    hasFetched.current = true;
    runQuery(EMPTY_FILTERS);
  }

  function loadMore() {
    if (!cursorRef.current) return;
    const f = appliedFilters.current;
    setFetching(true);
    getAuditLog({
      event_type: f.eventType || undefined,
      actor_id: f.actorId || undefined,
      since: f.since || undefined,
      until: f.until || undefined,
      search: f.search || undefined,
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

  const activeFilters = hasActiveFilters({
    eventType: eventTypeFilter,
    actorId: actorFilter,
    since: sinceFilter,
    until: untilFilter,
    search: searchFilter,
  });

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-4xl py-10">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-xl font-semibold">{t("admin.audit.title")}</h1>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              {t("admin.audit.subtitle")}
            </p>
          </div>
          <button
            type="button"
            onClick={handleVerify}
            disabled={verifying}
            className="whitespace-nowrap self-start rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900 sm:self-auto"
          >
            {verifying ? t("admin.audit.verifying") : t("admin.audit.verify")}
          </button>
        </div>

        {/* Filter bar, split into two rows so neither gets cramped: event
            type + actor (the two dropdowns) on top, date range + search
            (the three free-form inputs, which need more breathing room)
            below. Each row stacks to a single column on phones and widens
            on tablet/desktop. All inputs use text-base (16px) to avoid iOS
            Safari's auto-zoom-on-focus. */}
        <div className="mb-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div>
            <label className="sr-only" htmlFor="audit-filter-event-type">
              {t("admin.audit.filter_label")}
            </label>
            <select
              id="audit-filter-event-type"
              value={eventTypeFilter}
              onChange={(e) => handleEventTypeChange(e.target.value)}
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
            >
              <option value="">{t("admin.audit.filter_all")}</option>
              {EVENT_TYPE_CATEGORIES.map(({ category, types }) => (
                <optgroup key={category} label={t(`admin.audit.categories.${category}`)}>
                  {types.map((et) => (
                    <option key={et} value={et}>
                      {eventTypeLabel(t, et)}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </div>

          <div>
            <label className="sr-only" htmlFor="audit-filter-actor">
              {t("admin.audit.filter_actor_label")}
            </label>
            <select
              id="audit-filter-actor"
              value={actorFilter}
              onChange={(e) => handleActorChange(e.target.value)}
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
            >
              <option value="">{t("admin.audit.filter_actor_all")}</option>
              {actors.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name || a.id}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="sr-only" htmlFor="audit-filter-since">
                {t("admin.audit.filter_since_label")}
              </label>
              <input
                id="audit-filter-since"
                type="date"
                value={sinceFilter}
                max={untilFilter || undefined}
                onChange={(e) => handleSinceChange(e.target.value)}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
              />
            </div>
            <div className="flex-1">
              <label className="sr-only" htmlFor="audit-filter-until">
                {t("admin.audit.filter_until_label")}
              </label>
              <input
                id="audit-filter-until"
                type="date"
                value={untilFilter}
                min={sinceFilter || undefined}
                onChange={(e) => handleUntilChange(e.target.value)}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
              />
            </div>
          </div>

          <div className="relative sm:col-span-2">
            <label className="sr-only" htmlFor="audit-filter-search">
              {t("admin.audit.filter_search_placeholder")}
            </label>
            <i className="ti ti-search pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[14px] text-gray-400" />
            <input
              id="audit-filter-search"
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder={t("admin.audit.filter_search_placeholder")}
              className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-9 pr-3 text-base text-gray-900 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
            />
          </div>
        </div>

        <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <label className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
            <input
              type="checkbox"
              checked={hideSyncNoise}
              onChange={(e) => setHideSyncNoise(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-teal-600 focus:ring-teal-500 dark:border-gray-700"
            />
            {t("admin.audit.hide_sync_noise")}
            {hideSyncNoise && hiddenSyncCount > 0 && (
              <span className="text-gray-400 dark:text-gray-500">
                ({t("admin.audit.hidden_sync_count", { count: hiddenSyncCount })})
              </span>
            )}
          </label>
          {activeFilters && (
            <button
              type="button"
              onClick={handleResetFilters}
              className="text-sm text-teal-600 hover:underline dark:text-teal-400"
            >
              {t("admin.audit.reset_filters")}
            </button>
          )}
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

        {visibleEntries.length === 0 && !fetching && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("admin.audit.empty")}</p>
        )}

        {visibleEntries.length > 0 && (
          <>
            {/* Desktop/tablet: table. Hidden below the sm breakpoint - five
                columns of tabular data does not fit a phone screen, and
                horizontal scrolling a data table on a touchscreen is a poor
                substitute for the stacked cards below. */}
            <div className="hidden overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 sm:block">
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
                  {groups.map((g, gi) => {
                    const first = g.entries[0];
                    const zebra = gi % 2 !== 0;
                    if (g.entries.length === 1) {
                      return <EntryRow key={first.id} e={first} zebra={zebra} />;
                    }
                    const expanded = expandedGroups.has(g.key);
                    return (
                      <Fragment key={g.key}>
                        <tr
                          onClick={() => toggleGroup(g.key)}
                          className={`cursor-pointer border-b border-gray-100 last:border-0 hover:bg-gray-100 dark:border-gray-800 dark:hover:bg-gray-800 ${
                            zebra ? "bg-gray-50/50 dark:bg-gray-900/30" : ""
                          }`}
                        >
                          <td className="whitespace-nowrap px-4 py-3 tabular-nums text-gray-500 dark:text-gray-400">
                            {new Date(first.created_at).toLocaleString()}
                          </td>
                          <td className="px-4 py-3">
                            <EventBadge type={first.event_type} />
                          </td>
                          <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
                            {first.actor_name || first.actor_email || first.actor_id}
                          </td>
                          <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
                            {summarizeTargets(g.entries, t)}
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center gap-1.5 text-teal-600 dark:text-teal-400">
                              <span className="rounded-full bg-teal-100 px-1.5 py-0.5 text-xs font-medium text-teal-700 dark:bg-teal-900/40 dark:text-teal-300">
                                ×{g.entries.length}
                              </span>
                              <span className="underline decoration-dotted underline-offset-2">
                                {expanded ? t("admin.audit.group_collapse") : t("admin.audit.group_expand")}
                              </span>
                            </span>
                          </td>
                        </tr>
                        {expanded && g.entries.map((e) => <EntryRow key={e.id} e={e} zebra={zebra} muted />)}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Phone: stacked cards, same grouped data. */}
            <div className="flex flex-col gap-2 sm:hidden">
              {groups.map((g) => {
                const first = g.entries[0];
                if (g.entries.length === 1) {
                  return <EntryCard key={first.id} e={first} />;
                }
                const expanded = expandedGroups.has(g.key);
                return (
                  <div key={g.key}>
                    <button
                      type="button"
                      onClick={() => toggleGroup(g.key)}
                      className="w-full rounded-lg border border-teal-200 bg-teal-50 p-3 text-left dark:border-teal-900/50 dark:bg-teal-900/20"
                    >
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <EventBadge type={first.event_type} />
                        <span className="whitespace-nowrap text-xs tabular-nums text-gray-500 dark:text-gray-400">
                          {new Date(first.created_at).toLocaleString()}
                        </span>
                      </div>
                      <div className="mb-1 break-words text-xs text-gray-500 dark:text-gray-400">
                        {t("admin.audit.col_target")}: {summarizeTargets(g.entries, t)}
                      </div>
                      <div className="flex items-center gap-1.5 text-sm text-teal-700 dark:text-teal-300">
                        <span className="rounded-full bg-teal-100 px-1.5 py-0.5 text-xs font-medium text-teal-700 dark:bg-teal-900/40 dark:text-teal-300">
                          ×{g.entries.length}
                        </span>
                        <span className="underline decoration-dotted underline-offset-2">
                          {expanded ? t("admin.audit.group_collapse") : t("admin.audit.group_expand")}
                        </span>
                      </div>
                    </button>
                    {expanded && (
                      <div className="ml-3 mt-2 flex flex-col gap-2 border-l-2 border-teal-100 pl-3 dark:border-teal-900/40">
                        {g.entries.map((e) => (
                          <EntryCard key={e.id} e={e} muted />
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}

        {(hasMore || fetching) && visibleEntries.length > 0 && (
          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={loadMore}
              disabled={fetching}
              className="min-h-[44px] rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
            >
              {fetching ? t("admin.audit.loading") : t("admin.audit.load_more")}
            </button>
          </div>
        )}
      </div>
    </AppShell>
  );
}

// Colour-coded badge for event types, one colour per top-level category
// (the same grouping as EVENT_TYPE_CATEGORIES above) so the shape of the
// log is scannable at a glance even before reading any text. Originally
// only user./config./setup.completed had colours and everything else
// (auth, module, feed, quicklink, ai, search, store, rate_limit - the
// majority of real-world entries, see the module-update-heavy log sample
// from 2026-07-16) fell back to the same flat grey.
const CATEGORY_BADGE_COLORS: [prefix: string, classes: string][] = [
  ["auth.", "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300"],
  ["user.", "bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200"],
  ["config.", "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"],
  ["ai.", "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300"],
  ["search.", "bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300"],
  ["setup.", "bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300"],
  ["module.", "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300"],
  ["feed.", "bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300"],
  ["quicklink.", "bg-pink-100 text-pink-700 dark:bg-pink-900/40 dark:text-pink-300"],
  ["store.", "bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300"],
  ["rate_limit.", "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300"],
];

function badgeColor(type: string): string {
  for (const [prefix, classes] of CATEGORY_BADGE_COLORS) {
    if (type.startsWith(prefix)) return classes;
  }
  return "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400";
}

// Shows the translated, human-readable label (eventTypeLabel) as the
// primary text - the point of this whole component (2026-07-08: admins
// couldn't tell at a glance what "config.ai_provider.key_cleared" meant).
// The raw type string is kept as a `title` tooltip, not dropped: someone
// cross-referencing against backend/internal/audit/audit.go or writing a
// filter still needs the exact wire value, just not as the first thing
// they read.
function EventBadge({ type }: { type: string }) {
  const { t } = useTranslation();
  return (
    <span
      title={type}
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${badgeColor(type)}`}
    >
      {eventTypeLabel(t, type)}
    </span>
  );
}

// Renders the full value, always - wraps onto new lines instead of hiding
// any of it behind an ellipsis or a click-to-expand toggle. Details/reason/
// hash values (e.g. config.system_limits' dozen+ key:value pairs) can make
// a row tall, but that's preferable to text a phone user can't ever see in
// full (a hover `title` tooltip doesn't exist on touch devices at all).
function ExpandableText({ text, className = "" }: { text: string; className?: string }) {
  return (
    <span className={`block whitespace-pre-wrap break-words text-left ${className}`}>
      {text}
    </span>
  );
}

// Pretty-print the details JSON blob if valid, otherwise show raw string.
// Click-to-expand (see ExpandableText) rather than left to wrap or overflow
// the row - entries like config.system_limits carry a dozen+ key:value
// pairs, and auth.session_revoked_by_idp's `reason` is a full raw OAuth2
// error string; both used to blow the row out to several lines.
function DetailsCell({ raw }: { raw: string }) {
  let entries: [string, string][] | null = null;
  try {
    const parsed = JSON.parse(raw);
    entries = Object.entries(parsed as Record<string, string>);
  } catch {
    // entries stays null - raw is shown as-is below.
  }

  if (entries === null) return <ExpandableText text={raw} />;
  if (entries.length === 0) return <span className="text-gray-300 dark:text-gray-600">—</span>;
  return <ExpandableText text={entries.map(([k, v]) => `${k}: ${v}`).join(" · ")} />;
}

// Renders actor/target identity cells. Prefers the resolved display name,
// falling back to email, then the raw subject/session ID. Raw IDs longer
// than 16 chars (session hashes, OIDC subs) are click-to-expand (see
// ExpandableText) - previously a bare 64-char hex hash (e.g. the target of
// "session ended by admin") was printed out in full, pushing the Details
// column off-screen on anything narrower than a wide desktop, or relied on
// a hover title that touch devices can't trigger at all.
function IdentityCell({ name, email, id }: { name?: string; email?: string; id?: string }) {
  const label = name || email;
  if (label) return <span>{label}</span>;
  if (!id) return <span className="text-gray-300 dark:text-gray-600">—</span>;
  if (id.length > 16) return <ExpandableText text={id} className="font-mono text-xs" />;
  return <span>{id}</span>;
}

// One table row - shared by the flat (ungrouped) case and by each entry
// inside an expanded duplicate-burst group (see groupEntries above). `muted`
// gives expanded sub-rows a slightly dimmer, indented look so they read as
// "part of the group above" rather than independent top-level rows.
function EntryRow({ e, zebra, muted }: { e: AuditEntry; zebra: boolean; muted?: boolean }) {
  return (
    <tr
      className={`border-b border-gray-100 last:border-0 dark:border-gray-800 ${
        zebra ? "bg-gray-50/50 dark:bg-gray-900/30" : ""
      } ${muted ? "text-gray-400 dark:text-gray-500" : ""}`}
    >
      <td
        className={`whitespace-nowrap px-4 py-3 tabular-nums text-gray-500 dark:text-gray-400 ${
          muted ? "pl-8" : ""
        }`}
      >
        {new Date(e.created_at).toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <EventBadge type={e.event_type} />
      </td>
      <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
        <IdentityCell name={e.actor_name} email={e.actor_email} id={e.actor_id} />
      </td>
      <td className="px-4 py-3 text-gray-700 dark:text-gray-300">
        <IdentityCell name={e.target_name} email={e.target_email} id={e.target_id} />
      </td>
      <td className="px-4 py-3 font-mono text-xs text-gray-400 dark:text-gray-500">
        {e.details ? <DetailsCell raw={e.details} /> : "—"}
      </td>
    </tr>
  );
}

// Phone-width equivalent of EntryRow: a stacked card instead of a table row,
// used below the sm breakpoint. See the "flex sm:hidden" container in the
// main component - the table itself is hidden on phones, this is what
// replaces it.
function EntryCard({ e, muted }: { e: AuditEntry; muted?: boolean }) {
  const { t } = useTranslation();
  const hasTarget = e.target_name || e.target_email || e.target_id;
  return (
    <div
      className={`rounded-lg border border-gray-200 p-3 dark:border-gray-800 ${
        muted ? "opacity-70" : ""
      }`}
    >
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <EventBadge type={e.event_type} />
        <span className="whitespace-nowrap text-xs tabular-nums text-gray-500 dark:text-gray-400">
          {new Date(e.created_at).toLocaleString()}
        </span>
      </div>
      <div className="mb-1 text-sm text-gray-700 dark:text-gray-300">
        <span className="text-gray-400 dark:text-gray-500">{t("admin.audit.col_actor")}: </span>
        <IdentityCell name={e.actor_name} email={e.actor_email} id={e.actor_id} />
      </div>
      {hasTarget && (
        <div className="mb-1 text-sm text-gray-700 dark:text-gray-300">
          <span className="text-gray-400 dark:text-gray-500">{t("admin.audit.col_target")}: </span>
          <IdentityCell name={e.target_name} email={e.target_email} id={e.target_id} />
        </div>
      )}
      {e.details && (
        <div className="mt-1 font-mono text-xs text-gray-400 dark:text-gray-500">
          <DetailsCell raw={e.details} />
        </div>
      )}
    </div>
  );
}
