import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  adminListSearchProviders,
  adminPatchSearchProvider,
  adminClearSearchProviderKey,
  adminGetSearchSettings,
  adminPatchSearchSettings,
  type SearchProvider,
  type SearchSettings,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system/search — general web-search provider admin page: lists
// every configured provider (SearXNG, Serper.dev, and whatever gets added
// later on the backend) and lets an admin edit each one's credentials, pick
// a primary + optional fallback provider, and tune the two shared timeouts.
// See backend/internal/search's package doc comment for the
// provider-dispatch/fallback model this configures.
export default function AdminSystemSearchPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [providers, setProviders] = useState<SearchProvider[]>([]);
  const [settings, setSettings] = useState<SearchSettings | null>(null);
  const [fetching, setFetching] = useState(true);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const hasFetched = useRef(false);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    const token = getSessionToken();
    if (!token) return;
    Promise.all([adminListSearchProviders(token), adminGetSearchSettings(token)])
      .then(([provs, sett]) => { setProviders(provs); setSettings(sett); })
      .catch((err) => setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) }))
      .finally(() => setFetching(false));
  }, [session, navigate]);

  if (loading || !session || session.role !== "super-admin") return null;

  function updateProviderLocal(id: string, patch: Partial<SearchProvider>) {
    setProviders((prev) => prev.map((p) => (p.id === id ? { ...p, ...patch } : p)));
  }

  async function handleSaveProvider(id: string, adminKeyInput: string) {
    const token = getSessionToken();
    if (!token) return;
    const prov = providers.find((p) => p.id === id);
    if (!prov) return;
    setMsg(null);
    try {
      const patch: Record<string, unknown> = {
        base_url: prov.base_url ?? "",
        max_results: prov.max_results,
        fetch_pages: prov.fetch_pages,
        user_can_override: prov.user_can_override,
        enabled: prov.enabled,
        sort_order: prov.sort_order,
      };
      if (adminKeyInput.trim()) patch.admin_key = adminKeyInput.trim();
      const updated = await adminPatchSearchProvider(token, id, patch);
      setProviders((prev) => prev.map((p) => (p.id === id ? updated : p)));
      setMsg({ ok: true, text: t("admin.search.saved") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function handleClearKey(id: string) {
    const token = getSessionToken();
    if (!token) return;
    try {
      await adminClearSearchProviderKey(token, id);
      updateProviderLocal(id, { has_admin_key: false });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function handleSaveSettings(e: FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token || !settings) return;
    setMsg(null);
    try {
      const updated = await adminPatchSearchSettings(token, settings);
      setSettings(updated);
      setMsg({ ok: true, text: t("admin.search.saved") });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <BackLink />
        <h1 className="mb-1 text-xl font-semibold">{t("admin.search.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.search.subtitle")}</p>
        {msg && <Msg msg={msg} />}

        {fetching ? (
          <div className="flex flex-col gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="animate-pulse h-32 rounded-xl bg-gray-100 dark:bg-gray-800" />
            ))}
          </div>
        ) : (
          <div className="flex flex-col gap-6">
            {providers.map((prov) => (
              <ProviderCard
                key={prov.id}
                provider={prov}
                onChangeLocal={(patch) => updateProviderLocal(prov.id, patch)}
                onSave={(adminKey) => handleSaveProvider(prov.id, adminKey)}
                onClearKey={() => handleClearKey(prov.id)}
              />
            ))}

            {settings && (
              <form onSubmit={handleSaveSettings} className="rounded-2xl border border-gray-100 p-5 dark:border-gray-800">
                <h2 className="mb-1 text-sm font-semibold">{t("admin.search.mode_title")}</h2>
                <p className="mb-4 text-xs text-gray-500 dark:text-gray-400">{t("admin.search.mode_hint")}</p>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label={t("admin.search.primary_label")}>
                    <select value={settings.primary_provider_id}
                      onChange={(e) => setSettings({ ...settings, primary_provider_id: e.target.value })}
                      className={inputClass}>
                      {providers.map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label={t("admin.search.fallback_label")}>
                    <select value={settings.fallback_provider_id}
                      onChange={(e) => setSettings({ ...settings, fallback_provider_id: e.target.value })}
                      className={inputClass}>
                      <option value="">{t("admin.search.fallback_none")}</option>
                      {providers.filter((p) => p.id !== settings.primary_provider_id).map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label={t("admin.search.timeout_label")}>
                    <input type="number" min={1} value={settings.timeout_seconds}
                      onChange={(e) => setSettings({ ...settings, timeout_seconds: Math.max(1, Number(e.target.value)) })}
                      className={inputClass} />
                  </Field>
                  <Field label={t("admin.search.fallback_timeout_label")}>
                    <input type="number" min={1} value={settings.fallback_timeout_seconds}
                      onChange={(e) => setSettings({ ...settings, fallback_timeout_seconds: Math.max(1, Number(e.target.value)) })}
                      className={inputClass} />
                    <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.search.fallback_timeout_hint")}</p>
                  </Field>
                </div>
                <button type="submit"
                  className="mt-4 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400">
                  {t("admin.search.save")}
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </AppShell>
  );
}

function ProviderCard({
  provider, onChangeLocal, onSave, onClearKey,
}: {
  provider: SearchProvider;
  onChangeLocal: (patch: Partial<SearchProvider>) => void;
  onSave: (adminKeyInput: string) => void;
  onClearKey: () => void;
}) {
  const { t } = useTranslation();
  const [adminKeyInput, setAdminKeyInput] = useState("");
  const usesURL = provider.type === "searxng";
  const usesKey = !usesURL;

  return (
    <div className="rounded-2xl border border-gray-100 p-5 dark:border-gray-800">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold">{provider.name}</h2>
          <span className={`h-2 w-2 rounded-full ${provider.enabled ? "bg-teal-500" : "bg-gray-300 dark:bg-gray-600"}`} />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
          {t("admin.search.enabled_label")}
          <input type="checkbox" checked={provider.enabled}
            onChange={(e) => onChangeLocal({ enabled: e.target.checked })} />
        </label>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {usesURL && (
          <Field label={t("admin.search.url_label")}>
            <input type="url" value={provider.base_url ?? ""}
              onChange={(e) => onChangeLocal({ base_url: e.target.value })}
              placeholder="https://search.example.com" className={inputClass} />
          </Field>
        )}
        {usesKey && (
          <Field label={t("admin.search.key_label")}>
            <input type="password" value={adminKeyInput} onChange={(e) => setAdminKeyInput(e.target.value)}
              placeholder={provider.has_admin_key ? t("admin.search.key_set_placeholder") : ""}
              className={inputClass} />
            {provider.has_admin_key && (
              <button type="button" onClick={onClearKey}
                className="mt-1 text-xs text-red-600 hover:underline dark:text-red-400">
                {t("admin.search.clear_key")}
              </button>
            )}
          </Field>
        )}
        <Field label={t("admin.search.max_results_label")}>
          <input type="number" min={1} max={100} value={provider.max_results}
            onChange={(e) => onChangeLocal({ max_results: Math.max(1, Math.min(100, Number(e.target.value))) })}
            className={inputClass} />
        </Field>
        {usesURL && (
          <Field label={t("admin.search.fetch_pages_label")}>
            <input type="number" min={1} max={5} value={provider.fetch_pages}
              onChange={(e) => onChangeLocal({ fetch_pages: Math.max(1, Math.min(5, Number(e.target.value))) })}
              className={inputClass} />
          </Field>
        )}
        {usesKey && (
          <label className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300 sm:col-span-2">
            <input type="checkbox" checked={provider.user_can_override}
              onChange={(e) => onChangeLocal({ user_can_override: e.target.checked })} />
            {t("admin.search.user_can_override_label")}
          </label>
        )}
      </div>

      <button type="button" onClick={() => onSave(adminKeyInput)}
        className="mt-4 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400">
        {t("admin.search.save")}
      </button>
    </div>
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
