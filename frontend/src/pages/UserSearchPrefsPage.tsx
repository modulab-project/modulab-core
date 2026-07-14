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
import { getSessionToken } from "../lib/session";

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

  // Providers that allow a per-user key override (currently: Serper.dev, if
  // an admin has enabled it and switched on user_can_override). SearXNG
  // never appears here - it has no per-user key concept, only an admin-wide
  // base URL.
  const [overridableProviders, setOverridableProviders] = useState<UserSearchProvider[]>([]);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) return;
    getSearchPrefs(token)
      .then(setPrefs)
      .catch(() => setLoadError(true))
      .finally(() => setFetching(false));
    listSearchProvidersForUser(token)
      .then((provs) => setOverridableProviders(provs.filter((p) => p.can_override)))
      .catch(() => {
        // Non-fatal: the own-key section simply stays hidden.
      });
  }, []);

  async function handleChange(patch: Partial<SearchPrefs>) {
    const token = getSessionToken();
    if (!token || saving) return;
    const next = { ...prefs, ...patch };
    setPrefs(next);
    setSaving(true);
    setSaved(false);
    setSaveError(false);
    try {
      const updated = await updateSearchPrefs(token, next);
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
      <div className="mx-auto max-w-xl px-4 py-10">
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

            {overridableProviders.map((prov) => (
              <OwnKeyCard key={prov.id} provider={prov}
                onChanged={(hasKey) =>
                  setOverridableProviders((prev) =>
                    prev.map((p) => (p.id === prov.id ? { ...p, has_user_key: hasKey } : p)),
                  )
                } />
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}

// Optional per-user API key for a provider that allows overriding the
// admin-wide key (see backend/internal/search's ResolveSearchKey: own key
// wins over the admin key when both exist). Kept as its own small
// component/card so it only renders when at least one such provider exists,
// same pattern as the AI provider key cards on the AI settings page.
function OwnKeyCard({ provider, onChanged }: { provider: UserSearchProvider; onChanged: (hasKey: boolean) => void }) {
  const { t } = useTranslation();
  const [keyInput, setKeyInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(false);

  async function handleSave() {
    const token = getSessionToken();
    if (!token || !keyInput.trim() || saving) return;
    setSaving(true);
    setError(false);
    try {
      await setUserSearchKey(token, provider.id, keyInput.trim());
      setKeyInput("");
      onChanged(true);
    } catch {
      setError(true);
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token || saving) return;
    setSaving(true);
    setError(false);
    try {
      await deleteUserSearchKey(token, provider.id);
      onChanged(false);
    } catch {
      setError(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="rounded-2xl border border-gray-100 px-5 py-4 dark:border-gray-800">
      <p className="mb-1 text-sm font-medium">{t("user.search.own_key_title")}</p>
      <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">{t("user.search.own_key_desc")}</p>
      <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
        {provider.has_user_key ? t("user.search.own_key_set") : t("user.search.own_key_not_set")}
      </p>
      {error && <p className="mb-3 text-xs text-red-600 dark:text-red-400">{t("user.search.save_error")}</p>}
      <div className="flex gap-2">
        <input
          type="password"
          value={keyInput}
          disabled={saving}
          onChange={(e) => setKeyInput(e.target.value)}
          placeholder={t("user.search.own_key_placeholder")}
          className="flex-1 rounded-xl border border-gray-200 bg-white px-3 py-2.5 text-base text-gray-700 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
        />
        <button type="button" disabled={saving || !keyInput.trim()} onClick={handleSave}
          className="rounded-xl bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400">
          {t("user.search.own_key_save")}
        </button>
        {provider.has_user_key && (
          <button type="button" disabled={saving} onClick={handleRemove}
            className="rounded-xl border border-red-300 px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
            {t("user.search.own_key_remove")}
          </button>
        )}
      </div>
    </div>
  );
}
