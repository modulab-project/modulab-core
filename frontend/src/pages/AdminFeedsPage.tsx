// Admin news-feed management page (/admin/feeds).
// Org-admin and super-admin can add, edit, and delete RSS/Atom feed URLs
// from the global feed pool that all users pick from. They can also configure
// global news display settings (max articles fetched, articles shown on the
// home page, whether to show images).
// Gate is enforced server-side (requireAdminDeps in internal/news/news.go);
// client-side we additionally redirect non-admins to / via isAdminRole.
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  adminListFeeds,
  adminCreateFeed,
  adminUpdateFeed,
  adminDeleteFeed,
  adminCheckFeed,
  adminParseOPML,
  adminImportFeeds,
  adminFetchCatalogLanguages,
  adminFetchCatalogByLang,
  adminGetNewsSettings,
  adminUpdateNewsSettings,
  type Feed,
  type AdminNewsSettings,
  type FeedCheckResult,
  type FeedImportResult,
  type OPMLEntry,
  type ApiError,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

export default function AdminFeedsPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [fetching, setFetching] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // News settings state
  const [settings, setSettings] = useState<AdminNewsSettings | null>(null);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  // Modal state
  const [editTarget, setEditTarget] = useState<Feed | null>(null); // null = create
  const [modalOpen, setModalOpen] = useState(false);

  // OPML import state
  const [parsing, setParsing] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [opmlEntries, setOpmlEntries] = useState<OPMLEntry[] | null>(null); // non-null = modal open
  const [importResults, setImportResults] = useState<FeedImportResult[] | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // Catalog state
  // "lang_pick" = Sprachauswahl offen, "checking" = Erreichbarkeits-Check läuft, "select" = Auswahl-Modal
  const [catalogStep, setCatalogStep] = useState<"lang_pick" | "checking" | "select" | null>(null);
  const [catalogLangs, setCatalogLangs] = useState<string[]>([]);
  const [catalogCheckingLang, setCatalogCheckingLang] = useState<string>("");
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [catalogEntries, setCatalogEntries] = useState<OPMLEntry[] | null>(null);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    load();
    loadSettings();
  }, [session]);

  function load() {
    const token = getSessionToken();
    if (!token) return;
    setFetching(true);
    adminListFeeds(token)
      .then((f) => {
        setFeeds(f ?? []);
        setError(null);
      })
      .catch((e: ApiError) => setError(e.message))
      .finally(() => setFetching(false));
  }

  function loadSettings() {
    const token = getSessionToken();
    if (!token) return;
    adminGetNewsSettings(token)
      .then(setSettings)
      .catch(() => {});
  }

  async function handleSettingChange(patch: Partial<AdminNewsSettings>) {
    const token = getSessionToken();
    if (!token || settingsSaving) return;
    setSettingsSaving(true);
    setSettingsError(null);
    try {
      const updated = await adminUpdateNewsSettings(token, patch);
      setSettings(updated);
    } catch {
      setSettingsError(t("admin.feeds.settings_save_error"));
    } finally {
      setSettingsSaving(false);
    }
  }

  function openCreate() {
    setEditTarget(null);
    setModalOpen(true);
  }

  function openEdit(feed: Feed) {
    setEditTarget(feed);
    setModalOpen(true);
  }

  async function handleDelete(feed: Feed) {
    if (!confirm(t("admin.feeds.delete_confirm", { label: feed.label }))) return;
    const token = getSessionToken();
    if (!token) return;
    try {
      await adminDeleteFeed(token, feed.id);
      setFeeds((prev) => prev.filter((f) => f.id !== feed.id));
    } catch (e: unknown) {
      setError((e as ApiError).message ?? t("admin.feeds.delete_error"));
    }
  }

  // Step 1: parse OPML file and open the selection modal.
  async function handleOPMLFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const token = getSessionToken();
    if (!token) return;
    setParsing(true);
    setParseError(null);
    setImportResults(null);
    setImportError(null);
    try {
      const entries = await adminParseOPML(token, file);
      setOpmlEntries(entries);
    } catch (err: unknown) {
      setParseError((err as ApiError).message ?? t("admin.feeds.import_error"));
    } finally {
      setParsing(false);
      // Reset the file input so the same file can be re-selected.
      e.target.value = "";
    }
  }

  // Step 2: import the user-selected feeds from the modal.
  async function handleImportSelected(selected: OPMLEntry[]) {
    const token = getSessionToken();
    if (!token) return;
    setOpmlEntries(null);
    setImportResults(null);
    setImportError(null);
    try {
      const results = await adminImportFeeds(token, selected);
      setImportResults(results);
      // Reload feed list to show newly imported feeds.
      load();
    } catch (err: unknown) {
      setImportError((err as ApiError).message ?? t("admin.feeds.import_error"));
    }
  }

  // Step 1: open language picker (fetch available languages from backend).
  async function handleCatalogOpen() {
    const token = getSessionToken();
    if (!token) return;
    setCatalogError(null);
    setCatalogEntries(null);
    setImportResults(null);
    setImportError(null);
    try {
      const { languages } = await adminFetchCatalogLanguages(token);
      setCatalogLangs(languages);
      setCatalogStep("lang_pick");
    } catch (err: unknown) {
      setCatalogError((err as ApiError).message ?? t("admin.feeds.catalog_error"));
    }
  }

  // Step 2: user picks a language → backend fetches + checks feeds.
  async function handleCatalogLangSelect(lang: string) {
    const token = getSessionToken();
    if (!token) return;
    setCatalogStep("checking");
    setCatalogCheckingLang(lang);
    setCatalogError(null);
    try {
      const entries = await adminFetchCatalogByLang(token, lang);
      setCatalogEntries(entries);
      setCatalogStep("select");
    } catch (err: unknown) {
      setCatalogError((err as ApiError).message ?? t("admin.feeds.catalog_error"));
      setCatalogStep(null);
    }
  }

  // Step 3: import selected feeds.
  async function handleCatalogImportSelected(selected: OPMLEntry[]) {
    const token = getSessionToken();
    if (!token) return;
    setCatalogStep(null);
    setCatalogEntries(null);
    setImportResults(null);
    setImportError(null);
    try {
      const results = await adminImportFeeds(token, selected);
      setImportResults(results);
      load();
    } catch (err: unknown) {
      setImportError((err as ApiError).message ?? t("admin.feeds.import_error"));
    }
  }

  if (loading || !session) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-3xl py-8 px-2">

        {/* ── News display settings ────────────────────────────────── */}
        <div className="mb-8">
          <h1 className="text-xl font-semibold">{t("admin.feeds.settings_title")}</h1>
          <p className="mt-0.5 mb-4 text-sm text-gray-500 dark:text-gray-400">
            {t("admin.feeds.settings_subtitle")}
          </p>

          {settings && (
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 divide-y divide-gray-100 dark:divide-gray-800">
              {/* Articles on home page */}
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t("admin.feeds.home_count_label")}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {t("admin.feeds.home_count_desc")}
                  </p>
                </div>
                <div className="flex gap-1 ml-4 shrink-0">
                  {[3, 5, 10, 20].map((n) => (
                    <button
                      key={n}
                      type="button"
                      disabled={settingsSaving}
                      onClick={() => handleSettingChange({ home_count: n })}
                      className={`h-7 w-9 rounded-lg text-[12px] font-medium transition-colors disabled:opacity-50 ${
                        settings.home_count === n
                          ? "bg-teal-600 text-white"
                          : "border border-gray-200 text-gray-600 hover:border-teal-400 dark:border-gray-700 dark:text-gray-300"
                      }`}
                    >
                      {n}
                    </button>
                  ))}
                </div>
              </div>

              {/* Max articles total */}
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t("admin.feeds.max_articles_label")}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {t("admin.feeds.max_articles_desc")}
                  </p>
                </div>
                <div className="flex gap-1 ml-4 shrink-0">
                  {[50, 100, 200, 500].map((n) => (
                    <button
                      key={n}
                      type="button"
                      disabled={settingsSaving}
                      onClick={() => handleSettingChange({ max_articles: n })}
                      className={`h-7 min-w-[2.5rem] px-2 rounded-lg text-[12px] font-medium transition-colors disabled:opacity-50 ${
                        settings.max_articles === n
                          ? "bg-teal-600 text-white"
                          : "border border-gray-200 text-gray-600 hover:border-teal-400 dark:border-gray-700 dark:text-gray-300"
                      }`}
                    >
                      {n}
                    </button>
                  ))}
                </div>
              </div>

              {/* Show images */}
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{t("admin.feeds.show_images_label")}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {t("admin.feeds.show_images_desc")}
                  </p>
                </div>
                <button
                  type="button"
                  disabled={settingsSaving}
                  aria-label={settings.show_images ? t("admin.feeds.disable_images") : t("admin.feeds.enable_images")}
                  onClick={() => handleSettingChange({ show_images: !settings.show_images })}
                  className={`relative h-[22px] w-10 flex-none rounded-full border transition-colors disabled:opacity-50 ml-4 ${
                    settings.show_images
                      ? "border-teal-600 bg-teal-600"
                      : "border-gray-300 bg-gray-100 dark:border-gray-600 dark:bg-gray-800"
                  }`}
                >
                  <span
                    className={`absolute top-[2px] h-4 w-4 rounded-full bg-white transition-all ${
                      settings.show_images ? "left-[21px]" : "left-[2px]"
                    }`}
                  />
                </button>
              </div>
            </div>
          )}

          {settingsError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">{settingsError}</p>
          )}
        </div>

        {/* ── Feed pool ───────────────────────────────────────────── */}
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">{t("admin.feeds.title")}</h2>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              {t("admin.feeds.subtitle")}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Catalog import */}
            <button
              type="button"
              disabled={catalogStep === "checking"}
              onClick={handleCatalogOpen}
              className="flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800 disabled:opacity-50 disabled:pointer-events-none"
            >
              <i className="ti ti-book text-[14px]" />
              {catalogStep === "checking"
                ? t("admin.feeds.catalog_checking", { lang: catalogCheckingLang })
                : t("admin.feeds.catalog_open")}
            </button>
            {/* OPML import — hidden file input triggered by label */}
            <label className={`flex cursor-pointer items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800 ${parsing ? "opacity-50 pointer-events-none" : ""}`}>
              <i className="ti ti-upload text-[14px]" />
              {parsing ? t("admin.feeds.parsing_opml") : t("admin.feeds.import_opml")}
              <input
                type="file"
                accept=".opml,.xml"
                className="sr-only"
                onChange={handleOPMLFileSelected}
                disabled={parsing}
              />
            </label>
            <button
              type="button"
              onClick={openCreate}
              className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-700"
            >
              <i className="ti ti-plus text-[14px]" /> {t("admin.feeds.action.add")}
            </button>
          </div>
        </div>

        {/* Parse error */}
        {parseError && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {parseError}
          </div>
        )}

        {/* Catalog error */}
        {catalogError && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {catalogError}
          </div>
        )}

        {/* Import result summary */}
        {importError && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {importError}
          </div>
        )}
        {importResults && (
          <div className="mb-4 rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-800/50">
            <p className="mb-1 text-sm font-medium text-gray-700 dark:text-gray-200">
              {t("admin.feeds.import_result", {
                added: importResults.filter(r => !r.skipped && !r.error).length,
                skipped: importResults.filter(r => r.skipped).length,
                failed: importResults.filter(r => !!r.error).length,
              })}
            </p>
            {importResults.filter(r => !!r.error).map((r, i) => (
              <p key={i} className="text-xs text-red-600 dark:text-red-400 truncate">✗ {r.label}: {r.error}</p>
            ))}
            <button
              type="button"
              onClick={() => setImportResults(null)}
              className="mt-1 text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
            >
              {t("common.dismiss")}
            </button>
          </div>
        )}

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {error}
          </div>
        )}

        {fetching ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">{t("admin.feeds.loading")}</p>
        ) : feeds.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-200">{t("admin.feeds.empty_title")}</p>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {t("admin.feeds.empty_body")}
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-gray-200 dark:border-gray-800">
            {feeds.map((feed, idx) => (
              <div
                key={feed.id}
                className={`flex items-center gap-3 px-4 py-3 ${
                  idx !== feeds.length - 1
                    ? "border-b border-gray-100 dark:border-gray-800"
                    : ""
                }`}
              >
                <i className="ti ti-rss shrink-0 text-[16px] text-teal-600 dark:text-teal-400" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{feed.label}</p>
                  <p className="truncate text-xs text-gray-500 dark:text-gray-400">{feed.url}</p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <button
                    type="button"
                    onClick={() => openEdit(feed)}
                    aria-label={t("admin.feeds.action.edit_aria", { name: feed.label })}
                    className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    <i className="ti ti-pencil text-[14px] text-gray-500" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDelete(feed)}
                    aria-label={t("admin.feeds.action.delete_aria", { name: feed.label })}
                    className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-red-50 dark:hover:bg-red-950"
                  >
                    <i className="ti ti-trash text-[14px] text-red-500" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {modalOpen && (
        <FeedModal
          feed={editTarget}
          onClose={() => setModalOpen(false)}
          onSaved={(saved) => {
            if (editTarget) {
              setFeeds((prev) => prev.map((f) => (f.id === saved.id ? saved : f)));
            } else {
              setFeeds((prev) => [...prev, saved]);
            }
            setModalOpen(false);
          }}
        />
      )}

      {opmlEntries && (
        <OPMLSelectionModal
          entries={opmlEntries}
          onClose={() => setOpmlEntries(null)}
          onImport={handleImportSelected}
        />
      )}

      {catalogStep === "lang_pick" && (
        <CatalogLangModal
          languages={catalogLangs}
          onClose={() => setCatalogStep(null)}
          onSelect={handleCatalogLangSelect}
        />
      )}

      {catalogStep === "checking" && (
        <CatalogCheckingOverlay lang={catalogCheckingLang} />
      )}

      {catalogStep === "select" && catalogEntries && (
        <OPMLSelectionModal
          entries={catalogEntries}
          titleKey="admin.feeds.catalog_modal.title"
          subtitleKey="admin.feeds.catalog_modal.subtitle"
          onClose={() => { setCatalogStep(null); setCatalogEntries(null); }}
          onImport={handleCatalogImportSelected}
        />
      )}
    </AppShell>
  );
}

// ---- Catalog language picker ------------------------------------------------

const LANG_LABELS: Record<string, string> = {
  DE: "Deutsch",
  EN: "English",
  ES: "Español",
  FR: "Français",
  NL: "Nederlands",
};

function CatalogLangModal({
  languages,
  onClose,
  onSelect,
}: {
  languages: string[];
  onClose: () => void;
  onSelect: (lang: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/40" onClick={onClose} />
      <div className="fixed inset-x-4 top-[25%] z-50 mx-auto max-w-sm rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl dark:border-gray-800 dark:bg-gray-950">
        <h2 className="mb-1 text-base font-semibold">{t("admin.feeds.catalog_modal.pick_title")}</h2>
        <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.feeds.catalog_modal.pick_subtitle")}
        </p>
        <div className="flex flex-col gap-2">
          {languages.map((lang) => (
            <button
              key={lang}
              type="button"
              onClick={() => onSelect(lang)}
              className="flex items-center gap-3 rounded-xl border border-gray-200 px-4 py-3 text-left text-sm font-medium hover:border-teal-400 hover:bg-teal-50 dark:border-gray-700 dark:hover:border-teal-500 dark:hover:bg-teal-950 transition-colors"
            >
              <span className="text-lg">{langFlag(lang)}</span>
              <span>{LANG_LABELS[lang] ?? lang}</span>
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="mt-4 w-full rounded-lg px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800"
        >
          {t("admin.feeds.opml_modal.cancel")}
        </button>
      </div>
    </>
  );
}

function langFlag(lang: string): string {
  const flags: Record<string, string> = {
    DE: "🇩🇪",
    EN: "🇬🇧",
    ES: "🇪🇸",
    FR: "🇫🇷",
    NL: "🇳🇱",
  };
  return flags[lang] ?? "🌐";
}

// ---- Catalog checking overlay -----------------------------------------------

function CatalogCheckingOverlay({ lang }: { lang: string }) {
  const { t } = useTranslation();
  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/40" />
      <div className="fixed inset-x-4 top-[30%] z-50 mx-auto max-w-sm rounded-2xl border border-gray-200 bg-white p-8 shadow-2xl dark:border-gray-800 dark:bg-gray-950 text-center">
        <div className="mb-3 flex justify-center">
          <svg className="h-8 w-8 animate-spin text-teal-600" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
          </svg>
        </div>
        <p className="text-sm font-medium">{t("admin.feeds.catalog_modal.checking", { lang: LANG_LABELS[lang] ?? lang })}</p>
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t("admin.feeds.catalog_modal.checking_hint")}</p>
      </div>
    </>
  );
}

// ---- OPML selection modal ---------------------------------------------------

function OPMLSelectionModal({
  entries,
  onClose,
  onImport,
  titleKey = "admin.feeds.opml_modal.title",
  subtitleKey = "admin.feeds.opml_modal.subtitle",
}: {
  entries: OPMLEntry[];
  onClose: () => void;
  onImport: (selected: OPMLEntry[]) => void;
  titleKey?: string;
  subtitleKey?: string;
}) {
  const { t } = useTranslation();
  // Pre-select entries that are new AND reachable.
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(entries.filter((e) => !e.already_exists && e.reachable).map((e) => e.url)),
  );
  const [importing, setImporting] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Selectable = not already in DB and reachable.
  const selectable = entries.filter((e) => !e.already_exists && e.reachable);
  const allSelectableSelected = selectable.length > 0 && selectable.every((e) => selected.has(e.url));

  function toggle(url: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      return next;
    });
    setValidationError(null);
  }

  function toggleAll() {
    const selectableUrls = selectable.map((e) => e.url);
    if (allSelectableSelected) {
      setSelected((prev) => {
        const next = new Set(prev);
        selectableUrls.forEach((u) => next.delete(u));
        return next;
      });
    } else {
      setSelected((prev) => new Set([...prev, ...selectableUrls]));
    }
  }

  async function handleImport() {
    const chosen = entries.filter((e) => selected.has(e.url));
    if (chosen.length === 0) {
      setValidationError(t("admin.feeds.opml_modal.none_selected"));
      return;
    }
    setImporting(true);
    onImport(chosen);
  }

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/40" onClick={onClose} />
      {/* Dialog */}
      <div className="fixed inset-x-4 top-[8%] z-50 mx-auto flex max-w-lg flex-col rounded-2xl border border-gray-200 bg-white shadow-2xl dark:border-gray-800 dark:bg-gray-950"
        style={{ maxHeight: "80vh" }}>
        {/* Header */}
        <div className="px-6 pt-5 pb-3 shrink-0">
          <h2 className="text-base font-semibold">{t(titleKey)}</h2>
          <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
            {t(subtitleKey)}
          </p>
          <div className="mt-3 flex items-center justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {entries.length} {entries.length === 1 ? "Feed" : "Feeds"}
            </span>
            {selectable.length > 0 && (
              <button
                type="button"
                onClick={toggleAll}
                className="text-xs font-medium text-teal-600 hover:text-teal-700 dark:text-teal-400"
              >
                {allSelectableSelected
                  ? t("admin.feeds.opml_modal.deselect_all")
                  : t("admin.feeds.opml_modal.select_all")}
              </button>
            )}
          </div>
        </div>

        {/* Scrollable feed list */}
        <div className="overflow-y-auto flex-1 divide-y divide-gray-100 dark:divide-gray-800 px-2">
          {entries.map((entry) => {
            const isDisabled = entry.already_exists || !entry.reachable;
            const isChecked = selected.has(entry.url);
            return (
              <label
                key={entry.url}
                className={`flex items-start gap-3 px-4 py-3 rounded-lg transition-colors ${
                  isDisabled
                    ? "opacity-50 cursor-default"
                    : "cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-900"
                }`}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  disabled={isDisabled}
                  onChange={() => !isDisabled && toggle(entry.url)}
                  className="mt-0.5 h-4 w-4 shrink-0 accent-teal-600"
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium leading-tight">{entry.label}</p>
                  <p className="truncate text-xs text-gray-500 dark:text-gray-400">{entry.url}</p>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {entry.already_exists && (
                      <span className="inline-block rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-500 dark:bg-gray-800 dark:text-gray-400">
                        {t("admin.feeds.opml_modal.already_exists")}
                      </span>
                    )}
                    {!entry.reachable && (
                      <span className="inline-block rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-medium text-red-600 dark:bg-red-950 dark:text-red-400">
                        {t("admin.feeds.opml_modal.unreachable")}
                      </span>
                    )}
                  </div>
                </div>
              </label>
            );
          })}
        </div>

        {/* Footer */}
        <div className="shrink-0 border-t border-gray-100 dark:border-gray-800 px-6 py-4">
          {validationError && (
            <p className="mb-2 text-xs text-red-600 dark:text-red-400">{validationError}</p>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={importing}
              className="rounded-lg px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-800 disabled:opacity-50"
            >
              {t("admin.feeds.opml_modal.cancel")}
            </button>
            <button
              type="button"
              onClick={handleImport}
              disabled={importing || selected.size === 0}
              className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
            >
              {importing
                ? t("admin.feeds.opml_modal.importing")
                : t("admin.feeds.opml_modal.import", { count: selected.size })}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ---- Feed create/edit modal -------------------------------------------------

function FeedModal({
  feed,
  onClose,
  onSaved,
}: {
  feed: Feed | null;
  onClose: () => void;
  onSaved: (saved: Feed) => void;
}) {
  const { t } = useTranslation();
  const [url, setUrl] = useState(feed?.url ?? "");
  const [label, setLabel] = useState(feed?.label ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<FeedCheckResult | null>(null);

  async function handleCheck() {
    if (!url.trim()) return;
    const token = getSessionToken();
    if (!token) return;
    setChecking(true);
    setCheckResult(null);
    try {
      const result = await adminCheckFeed(token, url.trim());
      setCheckResult(result);
    } catch {
      setCheckResult({ reachable: false, article_count: 0, has_images: false, error: t("admin.feeds.modal.check_error") });
    } finally {
      setChecking(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    setSaving(true);
    setError(null);
    try {
      if (feed) {
        await adminUpdateFeed(token, feed.id, { url: url.trim(), label: label.trim() });
        onSaved({ ...feed, url: url.trim(), label: label.trim() });
      } else {
        const created = await adminCreateFeed(token, { url: url.trim(), label: label.trim() });
        onSaved(created);
      }
    } catch (e: unknown) {
      setError((e as ApiError).message ?? t("admin.feeds.modal.save_error"));
      setSaving(false);
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/40"
        onClick={onClose}
      />
      {/* Dialog */}
      <div className="fixed inset-x-4 top-[20%] z-50 mx-auto max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl dark:border-gray-800 dark:bg-gray-950">
        <h2 className="mb-4 text-base font-semibold">
          {feed ? t("admin.feeds.modal.title_edit") : t("admin.feeds.modal.title_add")}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium">{t("admin.feeds.modal.label")}</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Hacker News"
              required
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-900"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">{t("admin.feeds.modal.url")}</label>
            <div className="flex gap-2">
              <input
                type="url"
                value={url}
                onChange={(e) => { setUrl(e.target.value); setCheckResult(null); }}
                placeholder="https://example.com/feed.xml"
                required
                className="min-w-0 flex-1 rounded-lg border border-gray-300 px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-900"
              />
              <button
                type="button"
                disabled={checking || !url.trim()}
                onClick={handleCheck}
                className="flex-none rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                {checking ? t("admin.feeds.modal.checking") : t("admin.feeds.modal.check_button")}
              </button>
            </div>
            {checkResult && (
              <div className={`mt-2 rounded-md px-3 py-2 text-xs ${
                checkResult.reachable
                  ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
                  : "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-400"
              }`}>
                {checkResult.reachable ? (
                  <>
                    <span className="font-medium">✓ {t("admin.feeds.modal.check_ok")}</span>
                    {" · "}{t("admin.feeds.modal.check_articles", { count: checkResult.article_count })}
                    {" · "}{checkResult.has_images ? t("admin.feeds.modal.check_has_images") : t("admin.feeds.modal.check_no_images")}
                  </>
                ) : (
                  <span>✗ {checkResult.error ?? t("admin.feeds.modal.check_unreachable")}</span>
                )}
              </div>
            )}
          </div>
          {error && (
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              {t("admin.feeds.modal.cancel")}
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
            >
              {saving ? t("admin.feeds.modal.saving") : t("admin.feeds.modal.save")}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
