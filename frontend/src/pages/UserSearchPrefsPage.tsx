import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AppShell } from "../components/AppShell";
import { useAuthenticatedSession } from "../lib/useSession";
import {
  getSearchPrefs,
  updateSearchPrefs,
  listSearchProvidersForUser,
  setUserSearchKey,
  deleteUserSearchKey,
  type SearchPrefs,
  type UserSearchProvider,
} from "../lib/api";

// Individual language names are intentionally left as native endonyms
// (Deutsch, English, Français, ...) rather than translated - standard
// convention for language pickers, so a user's own language always reads
// correctly regardless of the current UI locale. Only the "all languages"
// entry is real UI copy and goes through t() at render time below.
const SEARCH_LANGUAGES = [
  { value: "all", label: "" },
  { value: "de", label: "Deutsch" },
  { value: "en", label: "English" },
  { value: "fr", label: "Français" },
  { value: "es", label: "Español" },
  { value: "it", label: "Italiano" },
  { value: "nl", label: "Nederlands" },
  { value: "pl", label: "Polski" },
  { value: "pt", label: "Português" },
  { value: "ru", label: "Русский" },
  { value: "zh", label: "中文" },
];

// /user/search-prefs — per-user search filter settings (safesearch + language).
// Changes are saved immediately on interaction (same optimistic pattern as
// news prefs). Reachable from the profile panel on every page.
export default function UserSearchPrefsPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  // Placeholder only, overwritten the moment getSearchPrefs resolves below -
  // matches the backend's own no-row defaults (db.GetSearchPrefs: strict
  // safesearch, language falls back to the user's ModuLab UI language) so
  // there's no visible flash of different values while the real fetch is
  // still in flight.
  const [prefs, setPrefs] = useState<SearchPrefs>({ safesearch: 2, language: "all" });
  const [fetching, setFetching] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [saveError, setSaveError] = useState(false);

  // Providers with a per-user key concept at all (currently: Serper.dev).
  // SearXNG never appears here - it has no key, only an admin-wide base URL,
  // same distinction the admin provider page draws via "usesURL"/"usesKey".
  const [keyProviders, setKeyProviders] = useState<UserSearchProvider[]>([]);

  useEffect(() => {
    getSearchPrefs()
      .then(setPrefs)
      .catch(() => setLoadError(true))
      .finally(() => setFetching(false));
    listSearchProvidersForUser()
      .then((provs) => setKeyProviders(provs.filter((p) => p.type !== "searxng")))
      .catch(() => {
        // Non-fatal: the own-key section simply stays hidden.
      });
  }, []);

  async function handleChange(patch: Partial<SearchPrefs>) {
    if (saving) return;
    const next = { ...prefs, ...patch };
    setPrefs(next);
    setSaving(true);
    setSaved(false);
    setSaveError(false);
    try {
      const updated = await updateSearchPrefs(next);
      setPrefs(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      // Roll back on error, and say so - a control that visibly reverts
      // is confusing without an explanation.
      setPrefs(prefs);
      setSaveError(true);
    } finally {
      setSaving(false);
    }
  }

  if (loading || !session) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-3xl px-4 py-10">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="mb-1 text-xl font-semibold">{t("user.search.title")}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {t("user.search.subtitle")}
            </p>
          </div>
          {saved && (
            <span className="flex items-center gap-1.5 text-[13px] text-teal-600 dark:text-teal-400">
              <i className="ti ti-check text-[14px]" /> {t("user.search.saved")}
            </span>
          )}
        </div>

        {(loadError || saveError) && (
          <p className="mb-4 text-sm text-red-600 dark:text-red-400">
            {loadError ? t("user.search.load_error") : t("user.search.save_error")}
          </p>
        )}

        {fetching ? (
          <div className="flex flex-col gap-4">
            {[1, 2].map((i) => (
              <div key={i} className="animate-pulse h-20 rounded-xl bg-gray-100 dark:bg-gray-800" />
            ))}
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {/* SafeSearch */}
            <div className="rounded-2xl border border-gray-100 px-5 py-4 dark:border-gray-800">
              <p className="mb-1 text-sm font-medium">{t("home.search.safesearch")}</p>
              <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
                {t("user.search.safesearch_desc")}
              </p>
              <div className="flex gap-2">
                {([0, 1, 2] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    disabled={saving}
                    onClick={() => handleChange({ safesearch: v })}
                    className={`flex-1 rounded-xl py-2 text-sm font-medium transition-colors disabled:opacity-50 ${
                      prefs.safesearch === v
                        ? "bg-teal-600 text-white"
                        : "border border-gray-200 text-gray-600 hover:border-teal-400 dark:border-gray-700 dark:text-gray-300"
                    }`}
                  >
                    {v === 0 ? t("home.search.safe_off") : v === 1 ? t("home.search.safe_moderate") : t("home.search.safe_strict")}
                  </button>
                ))}
              </div>
            </div>

            {/* Language */}
            <div className="rounded-2xl border border-gray-100 px-5 py-4 dark:border-gray-800">
              <p className="mb-1 text-sm font-medium">{t("home.search.language")}</p>
              <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
                {t("user.search.language_desc")}
              </p>
              <select
                value={prefs.language}
                disabled={saving}
                onChange={(e) => handleChange({ language: e.target.value })}
                className="w-full rounded-xl border border-gray-200 bg-white px-3 py-2.5 text-base text-gray-700 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
              >
                {SEARCH_LANGUAGES.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.value === "all" ? t("home.search.language_all") : l.label}
                  </option>
                ))}
              </select>
            </div>

            {keyProviders.length > 0 && (
              <OwnKeySection
                providers={keyProviders}
                onChanged={(id, hasKey) =>
                  setKeyProviders((prev) => prev.map((p) => (p.id === id ? { ...p, has_user_key: hasKey } : p)))
                }
              />
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}

// Optional per-user API key for providers that have a key concept at all
// (currently: Serper.dev). Mirrors UserAIKeysPage.tsx's status-badge +
// inline-edit pattern exactly (same "your key" / "ModuLab API key" / "no
// key" pill, same edit-row/save/cancel/remove flow) so it reads as the same
// pattern the user already knows from /user/ai-keys, rather than a
// different-looking one-off just because it's a different feature -
// backend/internal/search's ResolveSearchKey resolves own-key-over-admin-key
// the same way internal/ai's ResolveAIKey does.
function OwnKeySection({
  providers,
  onChanged,
}: {
  providers: UserSearchProvider[];
  onChanged: (id: string, hasKey: boolean) => void;
}) {
  const { t } = useTranslation();
  const [editingKeyId, setEditingKeyId] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSaveKey(providerId: string) {
    if (!keyInput.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await setUserSearchKey(providerId, keyInput.trim());
      setEditingKeyId(null);
      setKeyInput("");
      onChanged(providerId, true);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("user.search.save_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(providerId: string) {
    setBusy(true);
    setError(null);
    try {
      await deleteUserSearchKey(providerId);
      onChanged(providerId, false);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("user.search.save_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="mb-1 px-1 text-sm font-medium">{t("user.search.own_key_title")}</p>
      <p className="mb-3 px-1 text-xs text-gray-500 dark:text-gray-400">{t("user.search.own_key_desc")}</p>
      {error && <p className="mb-3 px-1 text-xs text-red-600 dark:text-red-400">{error}</p>}

      <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        {providers.map((p, i) => {
          const isEditingKey = editingKeyId === p.id;
          const isLast = i === providers.length - 1;
          return (
            <div key={p.id} className={`px-4 py-3.5 text-sm ${isLast ? "" : "border-b border-gray-100 dark:border-gray-800"}`}>
              {/* Header row: name + badges */}
              <div className="flex items-center justify-between gap-2">
                <p className={`font-medium ${!p.enabled ? "text-gray-400 dark:text-gray-500" : ""}`}>{p.name}</p>
                <div className="flex items-center gap-1.5">
                  {!p.enabled && (
                    <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 dark:bg-gray-800 dark:text-gray-400">
                      {t("user.search.status.not_enabled")}
                    </span>
                  )}
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                      p.has_user_key || p.has_admin_key
                        ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                        : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                    }`}
                  >
                    {p.has_user_key ? t("user.search.status.your_key") : p.has_admin_key ? t("user.search.status.modulab_key") : t("user.search.status.no_key")}
                  </span>
                </div>
              </div>

              {/* Key edit row */}
              {isEditingKey ? (
                <div className="mt-2 flex items-center gap-2">
                  <input
                    type="password"
                    autoComplete="off"
                    // eslint-disable-next-line jsx-a11y/no-autofocus -- input appears only after explicit user click on "edit", not on page load
                    autoFocus
                    value={keyInput}
                    onChange={(e) => setKeyInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSaveKey(p.id);
                      if (e.key === "Escape") { setEditingKeyId(null); setKeyInput(""); }
                    }}
                    className="flex-1 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                  />
                  <button
                    type="button"
                    disabled={busy || !keyInput.trim()}
                    onClick={() => handleSaveKey(p.id)}
                    className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                  >
                    {busy ? "…" : t("user.search.action.save")}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setEditingKeyId(null); setKeyInput(""); }}
                    className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300"
                  >
                    {t("user.search.action.cancel")}
                  </button>
                </div>
              ) : (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  {p.can_override && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => { setEditingKeyId(p.id); setKeyInput(""); }}
                      className="rounded-md border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
                    >
                      {p.has_user_key ? t("user.search.action.update_key") : t("user.search.action.add_key")}
                    </button>
                  )}
                  {p.has_user_key && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleRemove(p.id)}
                      className="rounded-md border border-red-300 px-3 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                    >
                      {t("user.search.action.remove_key")}
                    </button>
                  )}
                  {!p.can_override && (
                    <span className="text-xs text-gray-400 dark:text-gray-600">{t("user.search.override_not_allowed")}</span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
