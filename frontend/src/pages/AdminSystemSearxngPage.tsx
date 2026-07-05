import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  searxngStatus as fetchSearxngStatus,
  configureSearxng,
  deleteSearxngConfig,
  type SearXNGStatus,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

export default function AdminSystemSearxngPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [status, setStatus] = useState<SearXNGStatus | null>(null);
  const [url, setUrl] = useState("");
  const [maxResults, setMaxResults] = useState(25);
  const [fetchPages, setFetchPages] = useState(2);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    const token = getSessionToken();
    if (!token) return;
    fetchSearxngStatus(token)
      .then((s) => {
        setStatus(s);
        if (s.configured && s.url) setUrl(s.url);
        setMaxResults(s.max_results);
        setFetchPages(s.fetch_pages);
      })
      .catch((err) => setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) }));
  }, [session, navigate]);

  if (loading || !session || session.role !== "super-admin") return null;

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token || saving) return;
    setSaving(true);
    setMsg(null);
    try {
      const result = await configureSearxng(token, { url: url.trim(), max_results: maxResults, fetch_pages: fetchPages });
      setStatus(result);
      setMsg({ ok: true, text: t("admin.searxng.saved") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setSaving(false);
    }
  }

  async function handleRemove() {
    const token = getSessionToken();
    if (!token || removing) return;
    setRemoving(true);
    setMsg(null);
    try {
      await deleteSearxngConfig(token);
      setStatus({ configured: false, max_results: 25, fetch_pages: 2 });
      setUrl(""); setMaxResults(25); setFetchPages(2);
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    } finally {
      setRemoving(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <BackLink />
        <div className="mb-1 flex items-center gap-2">
          <h1 className="text-xl font-semibold">{t("admin.searxng.title")}</h1>
          {status && (
            <span className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
              <span className={`h-2 w-2 rounded-full ${status.configured ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
              {status.configured ? t("admin.searxng.status_configured") : t("admin.searxng.status_not_configured")}
            </span>
          )}
        </div>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.searxng.subtitle")}</p>
        {msg && <Msg msg={msg} />}
        <form onSubmit={handleSave} className="space-y-4">
          <Field label={t("admin.searxng.url_label")}>
            <input type="url" required value={url} onChange={(e) => setUrl(e.target.value)}
              placeholder="https://search.example.com" className={inputClass} />
            <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.url_hint")}</p>
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label={t("admin.searxng.max_results_label")}>
              <input type="number" min={1} max={100} value={maxResults}
                onChange={(e) => setMaxResults(Math.max(1, Math.min(100, Number(e.target.value))))}
                className={inputClass} />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.max_results_hint")}</p>
            </Field>
            <Field label={t("admin.searxng.fetch_pages_label")}>
              <input type="number" min={1} max={5} value={fetchPages}
                onChange={(e) => setFetchPages(Math.max(1, Math.min(5, Number(e.target.value))))}
                className={inputClass} />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.searxng.fetch_pages_hint")}</p>
            </Field>
          </div>
          <div className="flex gap-3">
            <button type="submit" disabled={saving}
              className="flex-1 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400">
              {saving ? t("admin.searxng.saving") : t("admin.searxng.save")}
            </button>
            {status?.configured && (
              <button type="button" disabled={removing} onClick={handleRemove}
                className="flex-1 rounded-lg border border-red-300 px-4 py-2.5 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
                {removing ? t("admin.searxng.action.removing") : t("admin.searxng.action.remove")}
              </button>
            )}
          </div>
        </form>
      </div>
    </AppShell>
  );
}

function BackLink() {
  const { t } = useTranslation();
  return (
    <Link to="/admin/system"
      className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
      <i className="ti ti-arrow-left text-[14px]" />
      {t("admin.system.back")}
    </Link>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } }) {
  return (
    <p className={`mb-4 text-sm ${msg.ok ? "text-teal-700 dark:text-teal-400" : "text-red-600 dark:text-red-400"}`}>
      {msg.text}
    </p>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</span>
      {children}
    </label>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-base text-gray-900 placeholder:text-gray-400 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:placeholder:text-gray-500";
