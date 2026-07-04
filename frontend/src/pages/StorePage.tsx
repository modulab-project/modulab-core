// Module Store browse page (/admin/modules/store).
// Admin-only. Shows all known modules from the registry cache (official + community).
// Only org-admin/super-admin can access, install, or sync.
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  listStore,
  listInstalledModules,
  installModule,
  syncStore,
  type StoreEntry,
  type InstalledModule,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";
import { safeHref } from "../lib/url";

type SourceFilter = "all" | "official" | "community";

export default function StorePage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [entries, setEntries] = useState<StoreEntry[]>([]);
  const [installed, setInstalled] = useState<Map<string, InstalledModule>>(new Map());
  const [fetching, setFetching] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);
  const [lastSynced, setLastSynced] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    load();
  }, [session, navigate]);

  function load() {
    const token = getSessionToken();
    if (!token) return;
    setFetching(true);
    Promise.all([
      listStore(token),
      listInstalledModules(token),
    ])
      .then(([storeResp, installedList]) => {
        setEntries(storeResp.entries ?? []);
        setLastSynced(storeResp.last_synced_at ?? null);
        const map = new Map<string, InstalledModule>();
        for (const m of installedList ?? []) map.set(m.name, m);
        setInstalled(map);
        setError(null);
      })
      .catch(() => setError(t("store.load_error")))
      .finally(() => setFetching(false));
  }

  async function handleSync() {
    const token = getSessionToken();
    if (!token) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await syncStore(token);
      setSyncMsg(res.ok ? t("store.sync_ok") : t("store.sync_partial"));
      load();
    } catch {
      setSyncMsg(t("store.sync_error"));
    } finally {
      setSyncing(false);
    }
  }

  async function handleInstall(name: string) {
    const token = getSessionToken();
    if (!token) return;
    setBusyName(name);
    try {
      const mod = await installModule(token, name);
      setInstalled((prev) => new Map(prev).set(name, mod));
    } catch (e) {
      alert(`${t("store.install_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  if (loading || !session || !isAdminRole(session.role)) return null;

  const isAdmin = isAdminRole(session.role);
  const visible = sourceFilter === "all"
    ? entries
    : entries.filter((e) => e.source === sourceFilter);

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-4xl py-6 px-2">
        <Link
          to="/admin/modules"
          className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200"
        >
          <i className="ti ti-arrow-left text-[14px]" />
          {t("admin.modules.title")}
        </Link>
        {/* Header */}
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold">{t("store.title")}</h1>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              {t("store.subtitle")}
            </p>
            {lastSynced && (
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("store.last_synced", {
                  time: new Date(lastSynced).toLocaleString(),
                })}
              </p>
            )}
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={handleSync}
              disabled={syncing}
              className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-900"
            >
              <i className={`ti ti-refresh text-[14px] ${syncing ? "animate-spin" : ""}`} />
              {syncing ? t("store.syncing") : t("store.sync")}
            </button>
          )}
        </div>

        {syncMsg && (
          <div className="mb-4 rounded-lg border border-teal-200 bg-teal-50 px-4 py-2 text-sm text-teal-700 dark:border-teal-800 dark:bg-teal-950 dark:text-teal-300">
            {syncMsg}
          </div>
        )}

        {/* Source filter tabs */}
        <div className="mb-5 flex gap-1 rounded-xl bg-gray-100 p-1 dark:bg-gray-900">
          {(["all", "official", "community"] as SourceFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setSourceFilter(f)}
              className={`flex-1 rounded-lg py-1.5 text-sm font-medium transition-colors ${
                sourceFilter === f
                  ? "bg-white text-gray-900 shadow-sm dark:bg-gray-800 dark:text-gray-100"
                  : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              }`}
            >
              {t(`store.filter.${f}`)}
            </button>
          ))}
        </div>

        {/* Content */}
        {error && (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        )}
        {fetching && !error && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}
        {!fetching && !error && visible.length === 0 && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("store.empty")}</p>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          {visible.map((entry) => {
            const inst = installed.get(entry.name);
            const isInstalled = !!inst;
            const isBusy = busyName === entry.name;
            const description =
              (entry.manifest as { description?: string } | undefined)?.description ?? "";

            return (
              <div
                key={entry.name}
                className="flex flex-col gap-3 rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900"
              >
                {/* Top row */}
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold leading-snug">{entry.name}</h2>
                    {entry.latest_version && (
                      <span className="text-xs text-gray-400 dark:text-gray-500">
                        v{entry.latest_version}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-none items-center gap-1.5">
                    <SourceBadge source={entry.source} />
                    {entry.category && <CategoryBadge category={entry.category} />}
                  </div>
                </div>

                {/* Description */}
                {description && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
                    {description}
                  </p>
                )}

                {/* Bottom row */}
                <div className="mt-auto flex items-center justify-between gap-2">
                  <a
                    href={safeHref(entry.source_repo)}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                  >
                    <i className="ti ti-brand-github text-[13px]" />
                    {t("store.source")}
                  </a>

                  {isInstalled ? (
                    <span className="flex items-center gap-1 rounded-full bg-teal-50 px-2.5 py-1 text-xs font-medium text-teal-700 dark:bg-teal-950 dark:text-teal-300">
                      <i className="ti ti-check text-[12px]" />
                      {t("store.installed")}
                      {inst?.available_version && (
                        <span className="ml-1 rounded-full bg-amber-100 px-1.5 text-amber-700 dark:bg-amber-900 dark:text-amber-300">
                          {t("store.update_available")}
                        </span>
                      )}
                    </span>
                  ) : isAdmin ? (
                    <button
                      type="button"
                      onClick={() => handleInstall(entry.name)}
                      disabled={isBusy}
                      className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                    >
                      {isBusy ? (
                        <>
                          <i className="ti ti-loader-2 animate-spin text-[13px]" />
                          {t("store.installing")}
                        </>
                      ) : (
                        <>
                          <i className="ti ti-download text-[13px]" />
                          {t("store.install")}
                        </>
                      )}
                    </button>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AppShell>
  );
}

function SourceBadge({ source }: { source: string }) {
  const isOfficial = source === "official";
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
        isOfficial
          ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-300"
          : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300"
      }`}
    >
      {source}
    </span>
  );
}

function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="rounded-full bg-gray-100 px-2 py-0.5 text-[10px] text-gray-500 dark:bg-gray-800 dark:text-gray-400">
      {category}
    </span>
  );
}
