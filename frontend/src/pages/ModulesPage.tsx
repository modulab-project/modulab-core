// Installed modules management page (/modules).
// Lists all installed modules with status, version, and admin actions.
// Browsing is open to all active users; install/uninstall/update/pin is admin-only.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  listInstalledModules,
  checkModuleUpdates,
  updateModule,
  uninstallModule,
  pinModule,
  unpinModule,
  type InstalledModule,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

export default function ModulesPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [modules, setModules] = useState<InstalledModule[]>([]);
  const [fetching, setFetching] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyName, setBusyName] = useState<string | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updatesMsg, setUpdatesMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    load();
  }, [session]);

  function load() {
    const token = getSessionToken();
    if (!token) return;
    setFetching(true);
    listInstalledModules(token)
      .then((list) => {
        setModules(list ?? []);
        setError(null);
      })
      .catch(() => setError(t("modules.load_error")))
      .finally(() => setFetching(false));
  }

  async function handleCheckUpdates() {
    const token = getSessionToken();
    if (!token) return;
    setCheckingUpdates(true);
    setUpdatesMsg(null);
    try {
      const res = await checkModuleUpdates(token);
      if (res.count === 0) {
        setUpdatesMsg(t("modules.no_updates"));
      } else {
        setUpdatesMsg(t("modules.updates_found", { count: res.count }));
      }
      load(); // refresh to show available_version badges
    } catch {
      setUpdatesMsg(t("modules.check_updates_error"));
    } finally {
      setCheckingUpdates(false);
    }
  }

  async function handleUpdate(name: string) {
    const token = getSessionToken();
    if (!token) return;
    setBusyName(name);
    try {
      const updated = await updateModule(token, name);
      setModules((prev) => prev.map((m) => (m.name === name ? updated : m)));
    } catch (e) {
      alert(`${t("modules.update_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  async function handleUninstall(name: string, pinned: boolean) {
    if (pinned) {
      alert(t("modules.pinned_uninstall_blocked"));
      return;
    }
    if (!confirm(t("modules.uninstall_confirm", { name }))) return;
    const token = getSessionToken();
    if (!token) return;
    setBusyName(name);
    try {
      await uninstallModule(token, name);
      setModules((prev) => prev.filter((m) => m.name !== name));
    } catch (e) {
      alert(`${t("modules.uninstall_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  async function handleTogglePin(name: string, currentlyPinned: boolean) {
    const token = getSessionToken();
    if (!token) return;
    setBusyName(name);
    try {
      const res = currentlyPinned
        ? await unpinModule(token, name)
        : await pinModule(token, name);
      setModules((prev) =>
        prev.map((m) => (m.name === name ? { ...m, pinned: res.pinned } : m)),
      );
    } catch {
      alert(t("modules.pin_error"));
    } finally {
      setBusyName(null);
    }
  }

  if (loading || !session) return null;

  const isAdmin = isAdminRole(session.role);

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-4xl py-6 px-2">
        {/* Header */}
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold">{t("modules.title")}</h1>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              {t("modules.subtitle")}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => navigate("/store")}
              className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900"
            >
              <i className="ti ti-building-store text-[14px]" />
              {t("modules.browse_store")}
            </button>
            {isAdmin && (
              <button
                type="button"
                onClick={handleCheckUpdates}
                disabled={checkingUpdates}
                className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-900"
              >
                <i className={`ti ti-refresh text-[14px] ${checkingUpdates ? "animate-spin" : ""}`} />
                {checkingUpdates ? t("modules.checking") : t("modules.check_updates")}
              </button>
            )}
          </div>
        </div>

        {updatesMsg && (
          <div className="mb-4 rounded-lg border border-teal-200 bg-teal-50 px-4 py-2 text-sm text-teal-700 dark:border-teal-800 dark:bg-teal-950 dark:text-teal-300">
            {updatesMsg}
          </div>
        )}

        {error && (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        )}
        {fetching && !error && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}
        {!fetching && !error && modules.length === 0 && (
          <div className="rounded-2xl border border-dashed border-gray-200 px-6 py-12 text-center dark:border-gray-800">
            <i className="ti ti-package-off text-[36px] text-gray-300 dark:text-gray-700" />
            <p className="mt-3 text-sm text-gray-400 dark:text-gray-500">
              {t("modules.empty")}
            </p>
            <button
              type="button"
              onClick={() => navigate("/store")}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700"
            >
              <i className="ti ti-building-store text-[14px]" />
              {t("modules.go_to_store")}
            </button>
          </div>
        )}

        <div className="flex flex-col gap-3">
          {modules.map((mod) => {
            const isBusy = busyName === mod.name;
            const hasUpdate = !!mod.available_version;

            return (
              <div
                key={mod.name}
                className="flex flex-col gap-3 rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900 sm:flex-row sm:items-center"
              >
                {/* Left: name + meta */}
                <div className="flex min-w-0 flex-1 flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm">{mod.name}</span>
                    {mod.pinned && (
                      <i
                        className="ti ti-pin text-[13px] text-gray-400 dark:text-gray-500"
                        title={t("modules.pinned")}
                      />
                    )}
                    {hasUpdate && (
                      <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900 dark:text-amber-300">
                        {mod.available_version}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      v{mod.version}
                    </span>
                    <TierBadge tier={mod.tier} />
                    <StatusBadge status={mod.status} />
                    <span className="rounded-full bg-gray-100 px-2 py-0.5 text-[10px] text-gray-500 dark:bg-gray-800 dark:text-gray-400">
                      {mod.source}
                    </span>
                  </div>
                </div>

                {/* Right: actions (admin only) */}
                {isAdmin && (
                  <div className="flex flex-none items-center gap-2">
                    {hasUpdate && (
                      <button
                        type="button"
                        onClick={() => handleUpdate(mod.name)}
                        disabled={isBusy}
                        className="flex items-center gap-1 rounded-lg bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                      >
                        {isBusy ? (
                          <i className="ti ti-loader-2 animate-spin text-[13px]" />
                        ) : (
                          <i className="ti ti-arrow-up text-[13px]" />
                        )}
                        {t("modules.update")}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => handleTogglePin(mod.name, mod.pinned)}
                      disabled={isBusy}
                      title={mod.pinned ? t("modules.unpin") : t("modules.pin")}
                      className="flex h-8 w-8 items-center justify-center rounded-lg border border-gray-200 text-gray-400 hover:bg-gray-50 hover:text-gray-700 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-800 dark:hover:text-gray-200"
                    >
                      <i className={`ti ${mod.pinned ? "ti-pin-filled" : "ti-pin"} text-[14px]`} />
                    </button>
                    <button
                      type="button"
                      onClick={() => handleUninstall(mod.name, mod.pinned)}
                      disabled={isBusy || mod.status === "installing"}
                      title={t("modules.uninstall")}
                      className="flex h-8 w-8 items-center justify-center rounded-lg border border-gray-200 text-gray-400 hover:border-red-200 hover:bg-red-50 hover:text-red-600 disabled:opacity-50 dark:border-gray-700 dark:hover:border-red-800 dark:hover:bg-red-950 dark:hover:text-red-400"
                    >
                      <i className="ti ti-trash text-[14px]" />
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </AppShell>
  );
}

function TierBadge({ tier }: { tier: number }) {
  const colors: Record<number, string> = {
    1: "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400",
    2: "bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
    3: "bg-purple-50 text-purple-700 dark:bg-purple-950 dark:text-purple-300",
  };
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${colors[tier] ?? colors[1]}`}
    >
      Tier {tier}
    </span>
  );
}

function StatusBadge({ status }: { status: InstalledModule["status"] }) {
  const { t } = useTranslation();
  const map: Record<InstalledModule["status"], { cls: string; icon: string }> = {
    active: {
      cls: "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400",
      icon: "ti-circle-check",
    },
    installing: {
      cls: "bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
      icon: "ti-loader-2",
    },
    degraded: {
      cls: "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
      icon: "ti-alert-triangle",
    },
    failed: {
      cls: "bg-red-50 text-red-600 dark:bg-red-950 dark:text-red-400",
      icon: "ti-circle-x",
    },
    isolated: {
      cls: "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400",
      icon: "ti-lock",
    },
  };
  const { cls, icon } = map[status] ?? map.failed;
  return (
    <span className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}>
      <i className={`ti ${icon} text-[11px] ${status === "installing" ? "animate-spin" : ""}`} />
      {t(`modules.status.${status}`)}
    </span>
  );
}
