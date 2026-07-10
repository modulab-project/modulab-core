// /admin/modules — hub page for module management.
// On mount: automatically runs registry sync + update check + installed count
// in the background so the user arrives at /admin/modules/installed with
// fresh data and update badges already set — no manual clicks needed.
// Gate: org-admin and super-admin.
import { useEffect } from "react";
import { Link, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import {
  checkModuleUpdates,
  listInstalledModules,
  listStore,
  syncStore,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";
import { isAdminRole } from "../lib/roles";

const MODULES_HUB_QUERY_KEY = ["admin-modules-hub"] as const;

interface ModulesHubData {
  storeCount: number | null;
  installedCount: number | null;
  updateCount: number | null;
  syncError: boolean;
}

export default function AdminModulesPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
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

  // Step 1: sync registry first so the DB has the latest versions.
  // Step 2: only after sync completes, run update-check + read counts
  // in parallel — otherwise checkModuleUpdates reads stale data.
  //
  // A failed sync is still non-fatal (the counts below fall back to
  // whatever was already cached), but it used to be swallowed entirely
  // with no feedback at all — an admin had no way to tell "these numbers
  // might be stale" from "everything's fine". syncError surfaces that via
  // the banner rendered below, without blocking the rest of the page.
  const { data, isFetching: syncing } = useQuery({
    queryKey: MODULES_HUB_QUERY_KEY,
    queryFn: async (): Promise<ModulesHubData> => {
      const token = getSessionToken();
      if (!token) throw new Error("no session token");

      let syncError = false;
      try {
        await syncStore(token);
      } catch {
        syncError = true;
      }

      const [storeRes, updateRes, installedRes] = await Promise.allSettled([
        listStore(token),
        checkModuleUpdates(token),
        listInstalledModules(token),
      ]);

      const storeCount = storeRes.status === "fulfilled" ? storeRes.value.total_count : null;

      let updateCount: number | null = null;
      if (updateRes.status === "fulfilled") {
        updateCount = updateRes.value.count;
      } else {
        // Was silently defaulting to 0 here, which renders as "all up to
        // date" (admin.modules.all_up_to_date) - actively misleading,
        // since a failed check is not the same as a check that found
        // nothing. Surface it via the same banner as a sync failure
        // instead of a false all-clear.
        syncError = true;
      }

      const installedCount = installedRes.status === "fulfilled" ? (installedRes.value?.length ?? 0) : null;

      return { storeCount, updateCount, installedCount, syncError };
    },
    enabled: !loading && isAdmin,
  });

  if (loading || !session || !isAdmin) return null;

  const storeCount = data?.storeCount ?? null;
  const installedCount = data?.installedCount ?? null;
  const updateCount = data?.updateCount ?? null;
  const syncError = data?.syncError ?? false;
  const hasUpdates = updateCount !== null && updateCount > 0;

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-semibold">{t("admin.modules.title")}</h1>
            {syncing && (
              <i className="ti ti-loader-2 animate-spin text-[16px] text-gray-400 dark:text-gray-500" />
            )}
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {syncing
              ? t("admin.modules.syncing")
              : t("admin.modules.subtitle")}
          </p>
          {syncError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">
              {t("admin.modules.sync_failed")}
            </p>
          )}
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {/* Store */}
          <Link
            to="/admin/modules/store"
            className="group flex flex-col rounded-xl border border-gray-200 p-4 transition-colors hover:border-teal-400 hover:bg-teal-50/40 dark:border-gray-800 dark:hover:border-teal-700 dark:hover:bg-teal-950/30"
          >
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-center gap-2.5">
                <i className="ti ti-building-store text-[18px] text-gray-400 group-hover:text-teal-600 dark:group-hover:text-teal-400" />
                <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  {t("admin.modules.store_title")}
                </span>
              </div>
              <i className="ti ti-chevron-right flex-none text-gray-300 group-hover:text-teal-500 dark:text-gray-600 dark:group-hover:text-teal-400" />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
              {t("admin.modules.store_desc")}
            </p>
            <div className="mt-auto flex items-center gap-1.5 min-h-[16px]">
              {syncing ? (
                <span className="text-[11px] text-gray-400 dark:text-gray-500 animate-pulse">
                  {t("admin.modules.syncing")}
                </span>
              ) : storeCount !== null ? (
                <>
                  <span className="h-1.5 w-1.5 rounded-full bg-teal-400" />
                  <span className="text-[11px] text-gray-400 dark:text-gray-500">
                    {t("admin.modules.store_count", { count: storeCount })}
                  </span>
                </>
              ) : null}
            </div>
          </Link>

          {/* Installed modules — highlighted when updates are available */}
          <Link
            to="/admin/modules/installed"
            className={`group flex flex-col rounded-xl border p-4 transition-colors ${
              hasUpdates
                ? "border-amber-300 bg-amber-50/40 hover:border-amber-400 hover:bg-amber-50/60 dark:border-amber-700 dark:bg-amber-950/20 dark:hover:border-amber-600"
                : "border-gray-200 hover:border-teal-400 hover:bg-teal-50/40 dark:border-gray-800 dark:hover:border-teal-700 dark:hover:bg-teal-950/30"
            }`}
          >
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-center gap-2.5">
                <i className={`ti ti-puzzle text-[18px] ${hasUpdates ? "text-amber-500 dark:text-amber-400" : "text-gray-400 group-hover:text-teal-600 dark:group-hover:text-teal-400"}`} />
                <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  {t("admin.modules.installed_title")}
                </span>
                {hasUpdates && (
                  <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:bg-amber-900 dark:text-amber-300">
                    {updateCount}
                  </span>
                )}
              </div>
              <i className={`ti ti-chevron-right flex-none ${hasUpdates ? "text-amber-400 dark:text-amber-600" : "text-gray-300 group-hover:text-teal-500 dark:text-gray-600 dark:group-hover:text-teal-400"}`} />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
              {t("admin.modules.installed_desc")}
            </p>
            <div className="mt-auto flex items-center gap-1.5 min-h-[16px]">
              {syncing ? (
                <span className="text-[11px] text-gray-400 dark:text-gray-500 animate-pulse">
                  {t("admin.modules.syncing")}
                </span>
              ) : updateCount !== null ? (
                hasUpdates ? (
                  <>
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                    <span className="text-[11px] text-amber-600 dark:text-amber-400 font-medium">
                      {t("admin.modules.updates_available", { count: updateCount })}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="h-1.5 w-1.5 rounded-full bg-teal-500" />
                    <span className="text-[11px] text-gray-400 dark:text-gray-500">
                      {installedCount !== null
                        ? t("admin.modules.installed_count", { count: installedCount })
                        : t("admin.modules.all_up_to_date")}
                    </span>
                  </>
                )
              ) : installedCount !== null ? (
                <>
                  <span className={`h-1.5 w-1.5 rounded-full ${installedCount > 0 ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
                  <span className="text-[11px] text-gray-400 dark:text-gray-500">
                    {t("admin.modules.installed_count", { count: installedCount })}
                  </span>
                </>
              ) : null}
            </div>
          </Link>
        </div>
      </div>
    </AppShell>
  );
}
