// Installed modules management page (/admin/modules/installed).
// Admin-only. Lists all installed modules with status, version, and admin actions.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listInstalledModules,
  checkModuleUpdates,
  updateModule,
  restartModule,
  migratePiiKey,
  uninstallModule,
  pinModule,
  unpinModule,
  type InstalledModule,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { ReauthBanner } from "../components/ReauthBanner";
import { AppShell } from "../components/AppShell";
import { isAdminRole } from "../lib/roles";

const MODULES_QUERY_KEY = ["installed-modules"] as const;

export default function ModulesPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [busyName, setBusyName] = useState<string | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updatesMsg, setUpdatesMsg] = useState<string | null>(null);
  // Same reauth pattern as AdminUsersPage.tsx's lock/delete actions -
  // migrate-pii-key is the one module action gated by adminReauthOnly
  // (backend/internal/modules/handlers.go's MigratePIIKeyHandler), since
  // withholding the legacy key afterwards is hard to undo for any row the
  // module failed to re-encrypt.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
  });

  const isAdmin = !!session && isAdminRole(session.role);

  // Redirect (not a data concern, so not folded into the useQuery below) -
  // stays an effect since navigate() is an imperative call to an external
  // system (the router), not a setState call the render-time-adjustment
  // pattern applies to.
  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
    }
  }, [session, navigate]);

  const {
    data: modules = [],
    isLoading: fetching,
    isError: hasLoadError,
  } = useQuery({
    queryKey: MODULES_QUERY_KEY,
    queryFn: async () => {
      return (await listInstalledModules()) ?? [];
    },
    enabled: !loading && isAdmin,
  });
  const error = hasLoadError ? t("modules.load_error") : null;

  function setModules(updater: (prev: InstalledModule[]) => InstalledModule[]) {
    queryClient.setQueryData<InstalledModule[]>(MODULES_QUERY_KEY, (prev) => updater(prev ?? []));
  }

  async function handleCheckUpdates() {
    setCheckingUpdates(true);
    setUpdatesMsg(null);
    try {
      const res = await checkModuleUpdates();
      if (res.count === 0) {
        setUpdatesMsg(t("modules.no_updates"));
      } else {
        setUpdatesMsg(t("modules.updates_found", { count: res.count }));
      }
      // refresh to show available_version badges
      queryClient.invalidateQueries({ queryKey: MODULES_QUERY_KEY });
    } catch {
      setUpdatesMsg(t("modules.check_updates_error"));
    } finally {
      setCheckingUpdates(false);
    }
  }

  async function handleUpdate(name: string) {
    setBusyName(name);
    try {
      const updated = await updateModule(name);
      setModules((prev) => prev.map((m) => (m.name === name ? updated : m)));
    } catch (e) {
      alert(`${t("modules.update_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  async function handleRestart(name: string) {
    setBusyName(name);
    try {
      const updated = await restartModule(name);
      setModules((prev) => prev.map((m) => (m.name === name ? updated : m)));
    } catch (e) {
      alert(`${t("modules.restart_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  async function handleMigratePiiKey(name: string) {
    if (!confirm(t("modules.migrate_pii_key_confirm", { name }))) return;
    setBusyName(name);
    setReauthRequired(false);
    try {
      const updated = await migratePiiKey(name);
      setModules((prev) => prev.map((m) => (m.name === name ? updated : m)));
    } catch (e) {
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        alert(t("modules.migrate_pii_key_error_for", { name, reason: describeMigratePiiKeyError(e, t) }));
      }
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
    setBusyName(name);
    try {
      await uninstallModule(name);
      setModules((prev) => prev.filter((m) => m.name !== name));
    } catch (e) {
      alert(`${t("modules.uninstall_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  async function handleTogglePin(name: string, currentlyPinned: boolean) {
    setBusyName(name);
    try {
      const res = currentlyPinned
        ? await unpinModule(name)
        : await pinModule(name);
      setModules((prev) =>
        prev.map((m) => (m.name === name ? { ...m, pinned: res.pinned } : m)),
      );
    } catch {
      alert(t("modules.pin_error"));
    } finally {
      setBusyName(null);
    }
  }

  if (loading || !session || !isAdmin) return null;

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

        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
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
                  <div className="flex flex-wrap items-center gap-2">
                    {mod.tier >= 2 && (mod.status === "degraded" || mod.status === "failed") && (
                      <button
                        type="button"
                        onClick={() => handleRestart(mod.name)}
                        disabled={isBusy}
                        className="flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700 disabled:opacity-50"
                      >
                        {isBusy ? (
                          <i className="ti ti-loader-2 animate-spin text-[13px]" />
                        ) : (
                          <i className="ti ti-refresh text-[13px]" />
                        )}
                        {t("modules.restart")}
                      </button>
                    )}
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
                    {mod.tier >= 2 && !mod.pii_migrated_at && (
                      <button
                        type="button"
                        onClick={() => handleMigratePiiKey(mod.name)}
                        disabled={isBusy || mod.status !== "active"}
                        title={t("modules.migrate_pii_key_hint")}
                        className="flex items-center gap-1 rounded-lg border border-amber-300 px-3 py-1.5 text-xs font-medium text-amber-700 hover:bg-amber-50 disabled:opacity-50 dark:border-amber-800 dark:text-amber-400 dark:hover:bg-amber-950"
                      >
                        {isBusy ? (
                          <i className="ti ti-loader-2 animate-spin text-[13px]" />
                        ) : (
                          <i className="ti ti-key text-[13px]" />
                        )}
                        {t("modules.migrate_pii_key")}
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

// Known error_code/error values a migrate-pii-key attempt can come back
// with, mapped to a translation key each. Two different shapes can reach
// here: Core's own MigratePIIKeyHandler (handlers.go) sends a plain-text
// http.Error body (e.g. "module worker not running") - shown as-is, it's
// already human-readable. A module's own /admin/migrate-pii-key handler
// forwards its error as JSON instead, either { error_code: "..." } (pantry)
// or { error: "..." } (recipes/my-place/unifi-network) - see each module's
// errorResponse()/badRequest() helpers. "not_found"/"route_not_found" is by
// far the most common case in practice: it's the module's generic
// catch-all for an unmatched route, meaning this module's installed code
// predates the migrate-pii-key handler entirely and needs its update
// installed first - worth calling out explicitly rather than leaving an
// admin to guess why a route "wasn't found" on a module they just clicked
// a button for.
const MIGRATE_PII_KEY_ERROR_REASON_KEYS: Record<string, string> = {
  not_found: "modules.migrate_pii_key_reason.needs_update",
  route_not_found: "modules.migrate_pii_key_reason.needs_update",
  pii_key_missing: "modules.migrate_pii_key_reason.no_pii_key",
  pii_key_not_configured: "modules.migrate_pii_key_reason.no_pii_key",
  server_encryption_not_configured: "modules.migrate_pii_key_reason.no_pii_key",
  forbidden: "modules.migrate_pii_key_reason.forbidden",
};

function describeMigratePiiKeyError(err: unknown, t: TFunction): string {
  const raw = err instanceof Error ? err.message : String(err);
  try {
    const parsed = JSON.parse(raw);
    const code = typeof parsed?.error_code === "string" ? parsed.error_code : parsed?.error;
    if (typeof code === "string") {
      const key = MIGRATE_PII_KEY_ERROR_REASON_KEYS[code];
      return key ? t(key) : t("modules.migrate_pii_key_reason.unknown_code", { code });
    }
  } catch {
    // Not JSON - Core's own http.Error responses (module not installed,
    // module worker not running, ...) are plain text and already read fine
    // shown as-is.
  }
  return raw;
}

function TierBadge({ tier }: { tier: number }) {
  // Tier 2/3 intentionally avoid amber/red here even though they're in the
  // confirmed-safe Tailwind palette: those two are reserved for status
  // severity in StatusBadge below (degraded/failed), which can appear right
  // next to this badge in the same row - reusing them for tier would make
  // "Tier 3" visually read as a warning. teal/gray-shades keep tier and
  // status badges unambiguous at a glance.
  const { t } = useTranslation();
  const colors: Record<number, string> = {
    1: "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400",
    2: "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-300",
    3: "bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300",
  };
  // Out-of-range tier (e.g. stale data, manual DB edit) used to silently
  // fall back to colors[1] while still printing the real (wrong) number in
  // the label - a badge could read "Tier 5" in the same gray as a normal
  // Tier 1, masking exactly the kind of bad data an admin would want to
  // notice (found 2026-07-16). This is the one deliberate exception to the
  // "no amber/red on tier badges" rule above: an invalid tier is a genuine
  // data error, not a normal tier value, so it should read as one.
  const cls =
    colors[tier] ?? "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300";
  return (
    <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}>
      {t("common.tier", { tier })}
    </span>
  );
}

function StatusBadge({ status }: { status: InstalledModule["status"] }) {
  const { t } = useTranslation();
  const map: Record<InstalledModule["status"], { cls: string; icon: string }> = {
    active: {
      cls: "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400",
      icon: "ti-circle-check",
    },
    installing: {
      cls: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300",
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
