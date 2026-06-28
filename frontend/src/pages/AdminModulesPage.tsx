// /admin/modules — hub page for module management.
// Links to the Module Store browser (/admin/modules/store) and the
// installed-modules manager (/admin/modules/installed).
// Gate: org-admin and super-admin (same as AdminUsersPage).
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { listInstalledModules, listStore } from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

export default function AdminModulesPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [storeCount, setStoreCount] = useState<number | null>(null);
  const [installedCount, setInstalledCount] = useState<number | null>(null);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }

    const token = getSessionToken();
    if (!token) return;

    listStore(token)
      .then((r) => setStoreCount(r.total_count))
      .catch(() => setStoreCount(null));

    listInstalledModules(token)
      .then((list) => setInstalledCount(list?.length ?? 0))
      .catch(() => setInstalledCount(null));
  }, [session, navigate]);

  if (loading || !session || !isAdminRole(session.role)) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <div className="mb-8">
          <h1 className="text-xl font-semibold mb-1">{t("admin.modules.title")}</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {t("admin.modules.subtitle")}
          </p>
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
            {storeCount !== null && (
              <div className="mt-auto flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                <span className="text-[11px] text-gray-400 dark:text-gray-500">
                  {t("admin.modules.store_count", { count: storeCount })}
                </span>
              </div>
            )}
          </Link>

          {/* Installed modules */}
          <Link
            to="/admin/modules/installed"
            className="group flex flex-col rounded-xl border border-gray-200 p-4 transition-colors hover:border-teal-400 hover:bg-teal-50/40 dark:border-gray-800 dark:hover:border-teal-700 dark:hover:bg-teal-950/30"
          >
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-center gap-2.5">
                <i className="ti ti-puzzle text-[18px] text-gray-400 group-hover:text-teal-600 dark:group-hover:text-teal-400" />
                <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                  {t("admin.modules.installed_title")}
                </span>
              </div>
              <i className="ti ti-chevron-right flex-none text-gray-300 group-hover:text-teal-500 dark:text-gray-600 dark:group-hover:text-teal-400" />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
              {t("admin.modules.installed_desc")}
            </p>
            {installedCount !== null && (
              <div className="mt-auto flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${installedCount > 0 ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`} />
                <span className="text-[11px] text-gray-400 dark:text-gray-500">
                  {t("admin.modules.installed_count", { count: installedCount })}
                </span>
              </div>
            )}
          </Link>
        </div>
      </div>
    </AppShell>
  );
}
