import { useEffect, useState } from "react";
import { AppShell } from "../components/AppShell";
import { useAuthenticatedSession } from "../lib/useSession";
import { getSearchPrefs, updateSearchPrefs, type SearchPrefs } from "../lib/api";
import { getSessionToken } from "../lib/session";

const SEARCH_LANGUAGES = [
  { value: "all", label: "All languages" },
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
  const { session, loading } = useAuthenticatedSession();
  const [prefs, setPrefs] = useState<SearchPrefs>({ safesearch: 0, language: "all" });
  const [fetching, setFetching] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const token = getSessionToken();
    if (!token) return;
    getSearchPrefs(token)
      .then(setPrefs)
      .catch(() => {})
      .finally(() => setFetching(false));
  }, []);

  async function handleChange(patch: Partial<SearchPrefs>) {
    const token = getSessionToken();
    if (!token || saving) return;
    const next = { ...prefs, ...patch };
    setPrefs(next);
    setSaving(true);
    setSaved(false);
    try {
      const updated = await updateSearchPrefs(token, next);
      setPrefs(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      // Roll back on error.
      setPrefs(prefs);
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
            <h1 className="mb-1 text-xl font-semibold">Search settings</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              These preferences apply to all your web searches.
            </p>
          </div>
          {saved && (
            <span className="flex items-center gap-1.5 text-[13px] text-teal-600 dark:text-teal-400">
              <i className="ti ti-check text-[14px]" /> Saved
            </span>
          )}
        </div>

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
              <p className="mb-1 text-sm font-medium">SafeSearch</p>
              <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
                Filter explicit content from your web and image search results.
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
                    {v === 0 ? "Off" : v === 1 ? "Moderate" : "Strict"}
                  </button>
                ))}
              </div>
            </div>

            {/* Language */}
            <div className="rounded-2xl border border-gray-100 px-5 py-4 dark:border-gray-800">
              <p className="mb-1 text-sm font-medium">Language</p>
              <p className="mb-3 text-xs text-gray-500 dark:text-gray-400">
                Prefer results in a specific language.
              </p>
              <select
                value={prefs.language}
                disabled={saving}
                onChange={(e) => handleChange({ language: e.target.value })}
                className="w-full rounded-xl border border-gray-200 bg-white px-3 py-2.5 text-sm text-gray-700 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200"
              >
                {SEARCH_LANGUAGES.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
