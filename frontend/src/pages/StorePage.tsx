// Module Store browse page (/admin/modules/store).
// Admin-only. Shows all known modules from the registry cache (official + community).
// Only org-admin/super-admin can access, install, or sync.
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
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
import { AppShell } from "../components/AppShell";
import { Logo } from "../components/AuthShell";
import { isAdminRole } from "../lib/roles";
import { safeHref } from "../lib/url";

type SourceFilter = "all" | "official" | "community";

const STORE_QUERY_KEY = ["module-store"] as const;

interface StoreData {
  entries: StoreEntry[];
  lastSynced: string | null;
  installed: Map<string, InstalledModule>;
}

export default function StorePage() {
  const { t, i18n: i18nInstance } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);

  const isAdmin = !!session && isAdminRole(session.role);

  // Redirect stays an effect (imperative router call, not a setState the
  // render-time-adjustment pattern applies to) - kept separate from the
  // data fetch below.
  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
    }
  }, [session, navigate]);

  const {
    data,
    isLoading: fetching,
    isError: hasLoadError,
  } = useQuery({
    queryKey: STORE_QUERY_KEY,
    queryFn: async (): Promise<StoreData> => {
      const token = getSessionToken();
      if (!token) throw new Error("no session token");
      const [storeResp, installedList] = await Promise.all([
        listStore(token),
        listInstalledModules(token),
      ]);
      const installed = new Map<string, InstalledModule>();
      for (const m of installedList ?? []) installed.set(m.name, m);
      return {
        entries: storeResp.entries ?? [],
        lastSynced: storeResp.last_synced_at ?? null,
        installed,
      };
    },
    enabled: !loading && isAdmin,
  });
  const entries = data?.entries ?? [];
  const installed = data?.installed ?? new Map<string, InstalledModule>();
  const lastSynced = data?.lastSynced ?? null;
  const error = hasLoadError ? t("store.load_error") : null;

  async function handleSync() {
    const token = getSessionToken();
    if (!token) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await syncStore(token);
      setSyncMsg(res.ok ? t("store.sync_ok") : t("store.sync_partial"));
      queryClient.invalidateQueries({ queryKey: STORE_QUERY_KEY });
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
      queryClient.setQueryData<StoreData>(STORE_QUERY_KEY, (prev) =>
        prev ? { ...prev, installed: new Map(prev.installed).set(name, mod) } : prev,
      );
    } catch (e) {
      alert(`${t("store.install_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  if (loading || !session || !isAdmin) return null;

  const lng = i18nInstance.language?.slice(0, 2) ?? "en";

  // Categories present in the current data, alphabetical - so the filter
  // never offers a category with zero matching entries.
  const categories = Array.from(new Set(entries.map((e) => e.category).filter(Boolean))).sort();

  const searchNeedle = search.trim().toLowerCase();
  const visible = entries.filter((e) => {
    if (sourceFilter !== "all" && e.source !== sourceFilter) return false;
    if (categoryFilter !== "all" && e.category !== categoryFilter) return false;
    if (searchNeedle) {
      const description = e.description?.[lng] ?? e.description?.["en"] ?? "";
      const haystack = `${e.name} ${description}`.toLowerCase();
      if (!haystack.includes(searchNeedle)) return false;
    }
    return true;
  });

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

        {/* Search */}
        <div className="relative mb-3">
          <i className="ti ti-search absolute left-3 top-1/2 -translate-y-1/2 text-[15px] text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("store.search_placeholder")}
            className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-9 pr-3 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-900"
            style={{ fontSize: 16 }}
          />
        </div>

        {/* Source filter tabs */}
        <div className="mb-3 flex gap-1 rounded-xl bg-gray-100 p-1 dark:bg-gray-900">
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

        {/* Category filter chips - only shown once there's more than one
            category in the data, otherwise it'd just be a single "All" chip */}
        {categories.length > 1 && (
          <div className="mb-5 flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => setCategoryFilter("all")}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                categoryFilter === "all"
                  ? "bg-teal-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
              }`}
            >
              {t("store.category_all")}
            </button>
            {categories.map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setCategoryFilter(c)}
                className={`rounded-full px-3 py-1 text-xs font-medium capitalize transition-colors ${
                  categoryFilter === c
                    ? "bg-teal-600 text-white"
                    : "bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
                }`}
              >
                {c}
              </button>
            ))}
          </div>
        )}

        {/* Content */}
        {error && (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        )}
        {fetching && !error && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}
        {!fetching && !error && entries.length > 0 && visible.length === 0 && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("store.no_results")}</p>
        )}
        {!fetching && !error && entries.length === 0 && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("store.empty")}</p>
        )}

        <div className="flex flex-col gap-3">
          {visible.map((entry) => {
            const inst = installed.get(entry.name);
            const isInstalled = !!inst;
            const isBusy = busyName === entry.name;
            const description = entry.description?.[lng] ?? entry.description?.["en"] ?? "";

            return (
              <div
                key={entry.name}
                className="flex flex-col gap-3 rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900 sm:flex-row sm:items-start"
              >
                <ModuleLogo url={entry.logo_url} name={entry.name} />

                <div className="min-w-0 flex-1">
                  {/* Top row */}
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-semibold leading-snug">{entry.name}</h2>
                    {entry.latest_version && (
                      <span className="text-xs text-gray-400 dark:text-gray-500">
                        v{entry.latest_version}
                      </span>
                    )}
                    <SourceBadge source={entry.source} />
                    {entry.category && <CategoryBadge category={entry.category} />}
                  </div>

                  {/* Description - full text, no truncation */}
                  {description && (
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                      {description}
                    </p>
                  )}

                  {/* Bottom row */}
                  <div className="mt-3 flex items-center justify-between gap-2">
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
              </div>
            );
          })}
        </div>
      </div>
    </AppShell>
  );
}

// Shows the module's own logo image when it has one; falls back to the
// ModuLab mark on missing logo_url OR a failed image load (404, unreachable
// host, etc.) via onError - so a broken/removed logo never breaks the layout
// or leaves a blank box.
function ModuleLogo({ url, name }: { url?: string; name: string }) {
  const [failed, setFailed] = useState(false);
  if (!url || failed) {
    return (
      <div className="flex h-10 w-10 flex-none items-center justify-center rounded-xl bg-gray-100 dark:bg-gray-800">
        <Logo className="h-6 w-6" />
      </div>
    );
  }
  return (
    <img
      src={url}
      alt={name}
      onError={() => setFailed(true)}
      className="h-10 w-10 flex-none rounded-xl border border-gray-200 object-cover dark:border-gray-800"
    />
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
