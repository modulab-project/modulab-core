// Module Store browse page (/admin/modules/store).
// Admin-only. Shows all known modules from the registry cache (official + community).
// Only org-admin/super-admin can access, install, or sync.
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listStore,
  listInstalledModules,
  installModule,
  installManualModule,
  syncStore,
  listCustomSources,
  addCustomSource,
  updateCustomSource,
  deleteCustomSource,
  type StoreEntry,
  type InstalledModule,
  type CustomSource,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { AppShell } from "../components/AppShell";
import { ReauthBanner } from "../components/ReauthBanner";
import { Logo } from "../components/AuthShell";
import { isAdminRole, isSuperAdminRole } from "../lib/roles";
import { safeHref } from "../lib/url";

type SourceFilter = "all" | "official" | "community" | "custom";

const STORE_QUERY_KEY = ["module-store"] as const;
const CUSTOM_SOURCES_QUERY_KEY = ["module-store", "custom-sources"] as const;

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
  const [showCustomDialog, setShowCustomDialog] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const isAdmin = !!session && isAdminRole(session.role);
  // Custom module sources were elevated to super-admin-only on the backend
  // (2026-07-22, alongside adding step-up reauth for edit/delete) - a
  // GitHub token plus the ability to point Core at arbitrary third-party
  // code is a higher-value target than typical org-admin-level config.
  // isAdmin above still gates the rest of this page (browsing/installing
  // from the Store), which org-admins keep unrestricted access to.
  const isSuperAdmin = !!session && isSuperAdminRole(session.role);

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
      const [storeResp, installedList] = await Promise.all([
        listStore(),
        listInstalledModules(),
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

  const { data: customSources } = useQuery({
    queryKey: CUSTOM_SOURCES_QUERY_KEY,
    queryFn: listCustomSources,
    enabled: !loading && isSuperAdmin,
  });

  async function handleSync() {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await syncStore();
      setSyncMsg(res.ok ? t("store.sync_ok") : t("store.sync_partial"));
      queryClient.invalidateQueries({ queryKey: STORE_QUERY_KEY });
    } catch {
      setSyncMsg(t("store.sync_error"));
    } finally {
      setSyncing(false);
    }
  }

  async function handleInstall(name: string) {
    setBusyName(name);
    try {
      const mod = await installModule(name);
      queryClient.setQueryData<StoreData>(STORE_QUERY_KEY, (prev) =>
        prev ? { ...prev, installed: new Map(prev.installed).set(name, mod) } : prev,
      );
    } catch (e) {
      alert(`${t("store.install_error")}: ${(e as Error).message}`);
    } finally {
      setBusyName(null);
    }
  }

  // Handles a manually uploaded module ZIP (no registry entry) — the
  // installed module doesn't show up in `entries` below (that list is
  // registry-driven), so the only feedback here is uploadMsg + a link to
  // the installed-modules page, where it will appear like any other module.
  async function handleManualUpload(file: File) {
    setUploading(true);
    setUploadMsg(null);
    try {
      const mod = await installManualModule(file);
      setUploadMsg({ ok: true, text: t("store.manual.upload_ok", { name: mod.name, version: mod.version }) });
      // Different query key than STORE_QUERY_KEY (this page's registry+installed
      // merge) - the installed-modules list lives on ModulesPage.tsx under its
      // own "installed-modules" key, invalidated here too so it doesn't show
      // stale data if the admin navigates there right after.
      queryClient.invalidateQueries({ queryKey: ["installed-modules"] });
      queryClient.invalidateQueries({ queryKey: STORE_QUERY_KEY });
    } catch (e) {
      setUploadMsg({ ok: false, text: `${t("store.manual.upload_error")}: ${(e as Error).message}` });
    } finally {
      setUploading(false);
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
      const title = e.display_name?.[lng] ?? e.display_name?.["en"] ?? e.name;
      const description = e.description?.[lng] ?? e.description?.["en"] ?? "";
      const haystack = `${e.name} ${title} ${description}`.toLowerCase();
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
            <div className="flex flex-wrap items-center gap-2">
              {isSuperAdmin && (
                <button
                  type="button"
                  onClick={() => setShowCustomDialog(true)}
                  className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900"
                >
                  <i className="ti ti-plus text-[14px]" />
                  {t("store.custom.manage")}
                </button>
              )}
              <button
                type="button"
                onClick={handleSync}
                disabled={syncing}
                className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:hover:bg-gray-900"
              >
                <i className={`ti ti-refresh text-[14px] ${syncing ? "animate-spin" : ""}`} />
                {syncing ? t("store.syncing") : t("store.sync")}
              </button>
              <label
                className={`flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900 ${
                  uploading ? "cursor-not-allowed opacity-50" : "cursor-pointer"
                }`}
              >
                <i className={`ti ${uploading ? "ti-loader-2 animate-spin" : "ti-upload"} text-[14px]`} />
                {uploading ? t("store.manual.uploading") : t("store.manual.upload")}
                <input
                  type="file"
                  accept=".zip"
                  disabled={uploading}
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = ""; // allow re-selecting the same file next time
                    if (file) void handleManualUpload(file);
                  }}
                />
              </label>
            </div>
          )}
        </div>

        {uploadMsg && (
          <div
            className={`mb-4 rounded-lg border px-4 py-2 text-sm ${
              uploadMsg.ok
                ? "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-800 dark:bg-teal-950 dark:text-teal-300"
                : "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300"
            }`}
          >
            {uploadMsg.text}
            {uploadMsg.ok && (
              <>
                {" "}
                <Link to="/admin/modules/installed" className="underline">
                  {t("store.manual.view_installed")}
                </Link>
              </>
            )}
          </div>
        )}

        {showCustomDialog && (
          <CustomSourcesDialog
            sources={customSources ?? []}
            onClose={() => setShowCustomDialog(false)}
            onChanged={() => {
              queryClient.invalidateQueries({ queryKey: CUSTOM_SOURCES_QUERY_KEY });
              queryClient.invalidateQueries({ queryKey: STORE_QUERY_KEY });
            }}
          />
        )}

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
          {(["all", "official", "community", "custom"] as SourceFilter[]).map((f) => (
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
                {t(`store.category.${c}`, { defaultValue: c })}
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
            const title = entry.display_name?.[lng] ?? entry.display_name?.["en"] ?? entry.name;
            const description = entry.description?.[lng] ?? entry.description?.["en"] ?? "";
            const githubURL = entry.browse_url || entry.source_repo;

            return (
              <div
                key={entry.name}
                className="flex flex-col gap-3 rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-800 dark:bg-gray-900 sm:flex-row sm:items-start"
              >
                <ModuleLogo url={entry.logo_url} name={title} />

                <div className="min-w-0 flex-1">
                  {/* Top row */}
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-semibold leading-snug">{title}</h2>
                    {entry.latest_version && (
                      <span className="text-xs text-gray-400 dark:text-gray-500">
                        v{entry.latest_version}
                      </span>
                    )}
                    <SourceBadge source={entry.source} />
                    {entry.source === "custom" && <UnverifiedBadge hasPubKey={!!entry.cosign_pubkey} />}
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
                      href={safeHref(githubURL)}
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
  const isCustom = source === "custom";
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
        isOfficial
          ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-300"
          : isCustom
            ? "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300"
            : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300"
      }`}
    >
      {source}
    </span>
  );
}

// Shown on every "custom" entry — this source was never reviewed by ModuLab,
// unlike official/community. hasPubKey just means the admin entered a
// signing key when adding the source (so installer.go CAN verify it); the
// actual pass/fail is only known after install, see
// installed_modules.cosign_verified.
function UnverifiedBadge({ hasPubKey }: { hasPubKey: boolean }) {
  const { t } = useTranslation();
  // hasPubKey=true ("signable") and false ("unverified") used to share the
  // same red styling, which read as "something's wrong" either way even
  // though hasPubKey=true is the good state (a signing key is on file,
  // installer.go CAN verify releases from this source). Split the colors:
  // teal for "signable", matching the same teal Core already uses elsewhere
  // for positive/active states (see StorePage.tsx's official-source badge,
  // ModulePage.tsx's tier badge) - red stays reserved for "unverified".
  const colorClasses = hasPubKey
    ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-300"
    : "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300";
  return (
    <span
      title={t(hasPubKey ? "store.custom.signed_hint" : "store.custom.unverified_hint")}
      className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium ${colorClasses}`}
    >
      <i className={`ti ${hasPubKey ? "ti-shield-check" : "ti-shield-exclamation"} text-[11px]`} />
      {t(hasPubKey ? "store.custom.signed" : "store.custom.unverified")}
    </span>
  );
}

// Admin dialog: manage custom module sources (list existing, add new, delete).
// Kept as a plain centered overlay (no portal/library) - matches the rest of
// the admin UI's lightweight inline-dialog pattern.
function CustomSourcesDialog({
  sources,
  onClose,
  onChanged,
}: {
  sources: CustomSource[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [repoUrl, setRepoUrl] = useState("");
  const [name, setName] = useState("");
  const [pubkey, setPubkey] = useState("");
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Edit (added 2026-07-22 alongside elevating this whole feature to
  // super-admin-only + step-up reauth): until now, reacting to a
  // maintainer rotating their Cosign key meant deleting the source and
  // re-adding it from scratch. editingId identifies which row (if any) is
  // currently showing its inline edit form instead of its normal display.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editPubkey, setEditPubkey] = useState("");
  const [editToken, setEditToken] = useState("");
  const [editSaving, setEditSaving] = useState(false);

  // PATCH (edit) and DELETE are both step-up reauth-gated on the backend
  // now (main.go's superAdminReauthOnly) - POST (add, above) deliberately
  // is not, see main.go's route registration comment. One shared banner
  // for the whole dialog rather than per-row: only one action can be
  // in flight at a time here anyway (editSaving/deletingId are mutually
  // exclusive in practice), and a single banner is simpler than tracking
  // which specific row triggered it.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setActionError(null);
  });

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setSaving(true);
    try {
      await addCustomSource(repoUrl.trim(), name.trim(), pubkey.trim(), token.trim());
      setRepoUrl("");
      setName("");
      setPubkey("");
      setToken("");
      onChanged();
    } catch (err) {
      setFormError((err as Error).message || t("store.custom.add_error"));
    } finally {
      setSaving(false);
    }
  }

  function startEdit(s: CustomSource) {
    setEditingId(s.id);
    setEditName(s.name);
    setEditPubkey(s.pubkey ?? "");
    setEditToken("");
    setActionError(null);
    setReauthRequired(false);
  }

  async function handleSaveEdit(e: FormEvent) {
    e.preventDefault();
    if (!editingId) return;
    setEditSaving(true);
    setActionError(null);
    setReauthRequired(false);
    try {
      await updateCustomSource(
        editingId,
        editName.trim(),
        editPubkey.trim(),
        editToken.trim() ? editToken.trim() : undefined,
      );
      setEditingId(null);
      onChanged();
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setActionError((err as Error).message || t("store.custom.edit_error"));
      }
    } finally {
      setEditSaving(false);
    }
  }

  async function handleDelete(id: string) {
    setDeletingId(id);
    setActionError(null);
    setReauthRequired(false);
    try {
      await deleteCustomSource(id);
      onChanged();
    } catch (err) {
      if (isReauthRequiredError(err)) {
        setReauthRequired(true);
      } else {
        setActionError((err as Error).message || t("store.custom.remove_error"));
      }
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl bg-white p-5 dark:bg-gray-900">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold">{t("store.custom.title")}</h2>
            <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
              {t("store.custom.subtitle")}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700 dark:hover:bg-gray-800 dark:hover:text-gray-200"
          >
            <i className="ti ti-x text-[16px]" />
          </button>
        </div>

        {/* Existing sources */}
        {sources.length > 0 && (
          <div className="mb-4 flex flex-col gap-2">
            {sources.map((s) =>
              editingId === s.id ? (
                <form
                  key={s.id}
                  onSubmit={handleSaveEdit}
                  className="flex flex-col gap-2 rounded-xl border border-teal-300 p-3 dark:border-teal-700"
                >
                  <p className="break-all text-xs text-gray-500 dark:text-gray-400">{s.repo_url}</p>
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    placeholder={t("store.custom.name")}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
                    style={{ fontSize: 16 }}
                  />
                  <textarea
                    value={editPubkey}
                    onChange={(e) => setEditPubkey(e.target.value)}
                    placeholder={t("store.custom.pubkey")}
                    rows={2}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
                    style={{ fontSize: 16 }}
                  />
                  <input
                    type="password"
                    autoComplete="off"
                    value={editToken}
                    onChange={(e) => setEditToken(e.target.value)}
                    placeholder={s.has_token ? "•••••••••••• " : t("store.custom.token")}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
                    style={{ fontSize: 16 }}
                  />
                  <p className="text-[11px] text-gray-400 dark:text-gray-500">
                    {t("store.custom.token_keep_hint")}
                  </p>
                  <div className="flex gap-2">
                    <button
                      type="submit"
                      disabled={editSaving}
                      className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                    >
                      {editSaving && <i className="ti ti-loader-2 animate-spin text-[12px]" />}
                      {t("common.save")}
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditingId(null)}
                      disabled={editSaving}
                      className="rounded-lg border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
                    >
                      {t("common.cancel")}
                    </button>
                  </div>
                </form>
              ) : (
                <div
                  key={s.id}
                  className="flex items-center justify-between gap-2 rounded-xl border border-gray-200 px-3 py-2 dark:border-gray-800"
                >
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-1.5 break-words text-sm font-medium">
                      {s.name}
                      {s.has_token && (
                        <i
                          className="ti ti-lock text-[12px] text-gray-400"
                          title={t("store.custom.private")}
                        />
                      )}
                    </p>
                    <p className="break-all text-xs text-gray-500 dark:text-gray-400">{s.repo_url}</p>
                  </div>
                  <div className="flex flex-none items-center gap-1">
                    <button
                      type="button"
                      onClick={() => startEdit(s)}
                      className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700 dark:hover:bg-gray-800 dark:hover:text-gray-200"
                      title={t("store.custom.edit")}
                    >
                      <i className="ti ti-pencil text-[15px]" />
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(s.id)}
                      disabled={deletingId === s.id}
                      className="rounded-lg p-1.5 text-red-500 hover:bg-red-50 disabled:opacity-50 dark:hover:bg-red-950"
                      title={t("store.custom.remove")}
                    >
                      <i className={`ti ${deletingId === s.id ? "ti-loader-2 animate-spin" : "ti-trash"} text-[15px]`} />
                    </button>
                  </div>
                </div>
              ),
            )}
          </div>
        )}
        {sources.length === 0 && (
          <p className="mb-4 text-xs text-gray-400 dark:text-gray-500">{t("store.custom.empty")}</p>
        )}

        {actionError && !reauthRequired && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">{actionError}</p>
        )}
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}

        {/* Warning */}
        <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
          <i className="ti ti-alert-triangle mr-1 text-[13px]" />
          {t("store.custom.warning")}
        </div>

        {/* Add form */}
        <form onSubmit={handleAdd} className="flex flex-col gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-300">
              {t("store.custom.repo_url")}
            </label>
            <input
              type="text"
              required
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
              style={{ fontSize: 16 }}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-300">
              {t("store.custom.name")}
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="owner/repo"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
              style={{ fontSize: 16 }}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-300">
              {t("store.custom.pubkey")}
            </label>
            <textarea
              value={pubkey}
              onChange={(e) => setPubkey(e.target.value)}
              placeholder="-----BEGIN PUBLIC KEY-----…"
              rows={3}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
              style={{ fontSize: 16 }}
            />
            <p className="mt-1 text-[11px] text-gray-400 dark:text-gray-500">
              {t("store.custom.pubkey_hint")}
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-300">
              {t("store.custom.token")}
            </label>
            <input
              type="password"
              autoComplete="off"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_… / github_pat_…"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-950"
              style={{ fontSize: 16 }}
            />
            <p className="mt-1 text-[11px] text-gray-400 dark:text-gray-500">
              {t("store.custom.token_hint")}
            </p>
          </div>

          {formError && <p className="text-xs text-red-600 dark:text-red-400">{formError}</p>}

          <button
            type="submit"
            disabled={saving}
            className="flex items-center justify-center gap-1.5 rounded-lg bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {saving ? (
              <>
                <i className="ti ti-loader-2 animate-spin text-[14px]" />
                {t("store.custom.adding")}
              </>
            ) : (
              t("store.custom.add")
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

function CategoryBadge({ category }: { category: string }) {
  const { t } = useTranslation();
  return (
    <span className="rounded-full bg-gray-100 px-2 py-0.5 text-[10px] text-gray-500 dark:bg-gray-800 dark:text-gray-400">
      {t(`store.category.${category}`, { defaultValue: category })}
    </span>
  );
}
