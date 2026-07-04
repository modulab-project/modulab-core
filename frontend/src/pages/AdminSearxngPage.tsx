import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  searxngStatus,
  configureSearxng,
  deleteSearxngConfig,
  type SearXNGStatus,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// "/admin/searxng" — super-admin only. Lets the operator configure the
// SearXNG instance URL, the maximum number of results shown to users,
// and how many SearXNG pages are fetched in parallel per query.
export default function AdminSearxngPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [status, setStatus] = useState<SearXNGStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);

  const [url, setUrl] = useState("");
  const [maxResults, setMaxResults] = useState(25);
  const [fetchPages, setFetchPages] = useState(2);

  const hasFetchedStatus = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") {
      navigate("/", { replace: true });
      return;
    }
    if (hasFetchedStatus.current) return;
    hasFetchedStatus.current = true;
    const token = getSessionToken();
    if (!token) return;

    searxngStatus(token)
      .then((s) => {
        setStatus(s);
        if (s.configured && s.url) setUrl(s.url);
        setMaxResults(s.max_results);
        setFetchPages(s.fetch_pages);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [session, navigate]);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token || saving) return;
    setError(null);
    setSaving(true);
    try {
      const s = await configureSearxng(token, {
        url: url.trim(),
        max_results: maxResults,
        fetch_pages: fetchPages,
      });
      setStatus(s);
      setSavedAt(Date.now());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token || removing) return;
    setError(null);
    setRemoving(true);
    try {
      await deleteSearxngConfig(token);
      setStatus({ configured: false, max_results: 25, fetch_pages: 2 });
      setUrl("");
      setMaxResults(25);
      setFetchPages(2);
      setSavedAt(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRemoving(false);
    }
  }

  if (loading || !session) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-xl py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("admin.searxng.title")}</h1>
        <p className="mb-8 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.searxng.subtitle")}
        </p>

        {status && (
          <div className="mb-6 flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                status.configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"
              }`}
            />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {status.configured ? t("admin.searxng.status_configured") : t("admin.searxng.status_not_configured")}
            </span>
          </div>
        )}

        <form onSubmit={handleSave} className="flex flex-col gap-5">
          {/* URL */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="searxng-url" className="text-sm font-medium">
              {t("admin.searxng.url_label")}
            </label>
            <input
              id="searxng-url"
              type="url"
              required
              placeholder="https://search.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="rounded-lg border border-gray-300 px-3 py-2 text-base outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900"
            />
            <p className="text-[12px] text-gray-500 dark:text-gray-400">
              {t("admin.searxng.url_hint")}
            </p>
          </div>

          {/* Max results + fetch pages side by side */}
          <div className="grid grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="max-results" className="text-sm font-medium">
                {t("admin.searxng.max_results_label")}
              </label>
              <input
                id="max-results"
                type="number"
                min={1}
                max={100}
                value={maxResults}
                onChange={(e) => setMaxResults(Math.max(1, Math.min(100, Number(e.target.value))))}
                className="rounded-lg border border-gray-300 px-3 py-2 text-base outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900"
              />
              <p className="text-[12px] text-gray-500 dark:text-gray-400">
                {t("admin.searxng.max_results_hint")}
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <label htmlFor="fetch-pages" className="text-sm font-medium">
                {t("admin.searxng.fetch_pages_label")}
              </label>
              <input
                id="fetch-pages"
                type="number"
                min={1}
                max={5}
                value={fetchPages}
                onChange={(e) => setFetchPages(Math.max(1, Math.min(5, Number(e.target.value))))}
                className="rounded-lg border border-gray-300 px-3 py-2 text-base outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900"
              />
              <p className="text-[12px] text-gray-500 dark:text-gray-400">
                {t("admin.searxng.fetch_pages_hint")}
              </p>
            </div>
          </div>

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}

          {savedAt && (
            <p className="text-sm text-green-700 dark:text-green-400">{t("admin.searxng.saved")}</p>
          )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
            >
              {saving ? t("admin.searxng.saving") : t("admin.searxng.save")}
            </button>

            {status?.configured && (
              <button
                type="button"
                disabled={removing}
                onClick={handleRemove}
                className="rounded-lg border border-red-300 px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
              >
                {removing ? t("admin.searxng.action.removing") : t("admin.searxng.action.remove")}
              </button>
            )}
          </div>
        </form>

      </div>
    </AppShell>
  );
}
