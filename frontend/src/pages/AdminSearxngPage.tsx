import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
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
// SearXNG instance URL that ModuLab's home-page search box proxies to.
// The URL is stored GCM-encrypted in core_settings (same treatment as SMTP
// credentials) and never returned to non-super-admin callers.
//
// When SearXNG is not configured (status.configured === false), the
// GET /v1/search/web endpoint returns 503 and the frontend silently hides
// the web-results section - so this setting is purely opt-in.
export default function AdminSearxngPage() {
  const navigate = useNavigate();
  const { session, loading } = useAuthenticatedSession();
  const [status, setStatus] = useState<SearXNGStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);

  const [url, setUrl] = useState("");

  // Same guard as AdminSmtpPage: prevent the 15s session poll from
  // re-fetching status and overwriting unsaved field edits.
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
        if (s.configured && s.url) {
          setUrl(s.url);
        }
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
      const s = await configureSearxng(token, url.trim());
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
      setStatus({ configured: false });
      setUrl("");
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
        <h1 className="mb-1 text-xl font-semibold">SearXNG</h1>
        <p className="mb-8 text-sm text-gray-500 dark:text-gray-400">
          Configure the SearXNG instance that powers ModuLab's home-page web search. When set, the
          search box on the home page shows inline results instead of opening an external search
          engine.
        </p>

        {/* Current status badge */}
        {status && (
          <div className="mb-6 flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                status.configured ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"
              }`}
            />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {status.configured ? "Configured" : "Not configured — web search is disabled"}
            </span>
          </div>
        )}

        <form onSubmit={handleSave} className="flex flex-col gap-4">
          {/* URL */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="searxng-url" className="text-sm font-medium">
              SearXNG URL
            </label>
            <input
              id="searxng-url"
              type="url"
              required
              placeholder="https://search.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900"
            />
            <p className="text-[12px] text-gray-500 dark:text-gray-400">
              Base URL of your SearXNG instance without a trailing slash. ModuLab will call{" "}
              <code className="rounded bg-gray-100 px-1 dark:bg-gray-800">/search?format=json</code>{" "}
              on this URL server-side.
            </p>
          </div>

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}

          {savedAt && (
            <p className="text-sm text-green-700 dark:text-green-400">
              Saved successfully.
            </p>
          )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save"}
            </button>

            {status?.configured && (
              <button
                type="button"
                disabled={removing}
                onClick={handleRemove}
                className="rounded-lg border border-red-300 px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
              >
                {removing ? "Removing…" : "Remove configuration"}
              </button>
            )}
          </div>
        </form>

        {/* Docker Compose hint for operators who don't have SearXNG yet */}
        {!status?.configured && (
          <div className="mt-10 rounded-xl border border-gray-200 p-5 dark:border-gray-800">
            <p className="mb-2 text-sm font-medium">Don't have SearXNG yet?</p>
            <p className="mb-3 text-[13px] text-gray-500 dark:text-gray-400">
              Start it alongside ModuLab by running Docker Compose with the{" "}
              <code className="rounded bg-gray-100 px-1 dark:bg-gray-800">search</code> profile:
            </p>
            <pre className="overflow-x-auto rounded-lg bg-gray-900 px-4 py-3 text-[12px] text-gray-100">
              {"docker compose --profile search up -d"}
            </pre>
            <p className="mt-2 text-[12px] text-gray-500 dark:text-gray-400">
              Then enter{" "}
              <code className="rounded bg-gray-100 px-1 dark:bg-gray-800">
                https://your-domain/searxng
              </code>{" "}
              as the URL above (or the internal Docker hostname for same-compose setups).
            </p>
          </div>
        )}
      </div>
    </AppShell>
  );
}
