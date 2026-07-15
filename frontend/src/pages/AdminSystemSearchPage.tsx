import React, { useCallback, useEffect, useRef, useState } from "react";
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
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";

// /admin/system/search — general web-search provider admin page: lists
// every configured provider (SearXNG, Serper.dev, and whatever gets added
// later on the backend), plus primary/fallback selection and the two
// shared timeouts. See backend/internal/search's package doc comment for
// the provider-dispatch/fallback model this configures.
//
// The provider list/row/modal/API-key-input pattern here is deliberately
// copied from AdminAIPage.tsx (row + badge + "Edit"/"Enable"/"Clear key"
// actions + an Overlay modal for the actual field editing) rather than
// invented fresh — same underlying shape (admin key with an
// admin/user-override split, has_admin_key badge, clear-key action), so it
// should look and behave the same to anyone who's already used the AI
// provider page.
type ModalState = { kind: "closed" } | { kind: "edit"; provider: SearchProvider };

export default function AdminSystemSearchPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();

  const [providers, setProviders] = useState<SearchProvider[]>([]);
  const [settings, setSettings] = useState<SearchSettings | null>(null);
  const [fetching, setFetching] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modal, setModal] = useState<ModalState>({ kind: "closed" });
  const hasFetched = useRef(false);

  // Only enabled providers make sense as primary/fallback — a disabled one
  // (e.g. SearXNG after it was pulled from docker-compose) has nothing to
  // actually search with.
  const enabledProviders = providers.filter((p) => p.enabled);

  const refresh = useCallback(() => {
    adminListSearchProviders()
      .then((p) => { setProviders(p); setError(null); })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  useEffect(() => {
    if (!session) return;
    if (session.role !== "super-admin") { navigate("/", { replace: true }); return; }
    if (hasFetched.current) return;
    hasFetched.current = true;
    Promise.all([adminListSearchProviders(), adminGetSearchSettings()])
      .then(([provs, sett]) => { setProviders(provs); setSettings(sett); })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setFetching(false));
  }, [session, navigate]);

  if (loading || !session || session.role !== "super-admin") return null;

  // A provider "has a key" in the AI-page sense: for SearXNG that means a
  // base URL is set (its only credential), for everything else (Serper)
  // it's the actual admin_key.
  function hasCredential(p: SearchProvider): boolean {
    return p.type === "searxng" ? !!p.base_url : p.has_admin_key;
  }

  async function handleToggleEnabled(p: SearchProvider) {
    setBusy(true);
    setError(null);
    try {
      await adminPatchSearchProvider(p.id, { enabled: !p.enabled });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.search.save_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleClearKey(id: string) {
    setBusy(true);
    setError(null);
    try {
      await adminClearSearchProviderKey(id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.search.save_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    if (!settings) return;
    setError(null);
    try {
      const updated = await adminPatchSearchSettings(settings);
      setSettings(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.search.save_error"));
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <BackLink />
        <h1 className="mb-1 text-xl font-semibold">{t("admin.search.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">{t("admin.search.subtitle")}</p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {fetching ? (
          <div className="flex flex-col gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="animate-pulse h-16 rounded-xl bg-gray-100 dark:bg-gray-800" />
            ))}
          </div>
        ) : (
          <>
            <div className="mb-6 rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
              {providers.map((p, i) => {
                const hasKey = hasCredential(p);
                return (
                  <div
                    key={p.id}
                    className={`px-4 py-3.5 text-sm ${i < providers.length - 1 ? "border-b border-gray-100 dark:border-gray-800" : ""}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-medium">{p.name}</p>
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          hasKey && p.enabled
                            ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                            : hasKey
                            ? "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                            : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                        }`}
                      >
                        {hasKey && p.enabled ? t("admin.search.status.active") : hasKey ? t("admin.search.status.disabled") : t("admin.search.status.no_key")}
                      </span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between gap-2">
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {t("admin.search.max_results_label")}: <span className="font-medium text-gray-700 dark:text-gray-300">{p.max_results}</span>
                      </p>
                      <div className="flex flex-none items-center gap-1.5">
                        <ActionButton variant="secondary" busy={busy} onClick={() => setModal({ kind: "edit", provider: p })}>
                          {t("admin.search.action.edit")}
                        </ActionButton>
                        <ActionButton variant="secondary" busy={busy} onClick={() => handleToggleEnabled(p)}>
                          {p.enabled ? t("admin.search.action.disable") : t("admin.search.action.enable")}
                        </ActionButton>
                        {p.type !== "searxng" && p.has_admin_key && (
                          <ActionButton variant="danger" busy={busy} onClick={() => handleClearKey(p.id)}>
                            {t("admin.search.action.clear_key")}
                          </ActionButton>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {settings && (
              <form onSubmit={handleSaveSettings} className="rounded-2xl border border-gray-100 p-5 dark:border-gray-800">
                <h2 className="mb-1 text-sm font-semibold">{t("admin.search.mode_title")}</h2>
                <p className="mb-4 text-xs text-gray-500 dark:text-gray-400">{t("admin.search.mode_hint")}</p>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label={t("admin.search.primary_label")}>
                    <select value={settings.primary_provider_id}
                      onChange={(e) => setSettings({ ...settings, primary_provider_id: e.target.value })}
                      className={inputCls}>
                      {/* Only enabled providers are selectable — a disabled
                          provider (e.g. SearXNG removed from docker-compose)
                          has nothing to actually search with. If the
                          currently saved primary is itself disabled, it's
                          still listed once so the <select> has a matching
                          option instead of silently showing the wrong
                          value — saving the form without changing it would
                          otherwise re-submit a disabled provider. */}
                      {enabledProviders.map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                      {!enabledProviders.some((p) => p.id === settings.primary_provider_id) && (
                        (() => {
                          const current = providers.find((p) => p.id === settings.primary_provider_id);
                          return current ? (
                            <option key={current.id} value={current.id}>
                              {current.name} ({t("admin.search.status.disabled")})
                            </option>
                          ) : null;
                        })()
                      )}
                    </select>
                  </Field>
                  <Field label={t("admin.search.fallback_label")}>
                    <select value={settings.fallback_provider_id}
                      onChange={(e) => setSettings({ ...settings, fallback_provider_id: e.target.value })}
                      className={inputCls}>
                      <option value="">{t("admin.search.fallback_none")}</option>
                      {enabledProviders.filter((p) => p.id !== settings.primary_provider_id).map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                      {settings.fallback_provider_id &&
                        !enabledProviders.some((p) => p.id === settings.fallback_provider_id) && (
                          (() => {
                            const current = providers.find((p) => p.id === settings.fallback_provider_id);
                            return current ? (
                              <option key={current.id} value={current.id}>
                                {current.name} ({t("admin.search.status.disabled")})
                              </option>
                            ) : null;
                          })()
                        )}
                    </select>
                  </Field>
                  <Field label={t("admin.search.timeout_label")}>
                    <input type="number" min={1} value={settings.timeout_seconds}
                      onChange={(e) => setSettings({ ...settings, timeout_seconds: Math.max(1, Number(e.target.value)) })}
                      className={inputCls} />
                  </Field>
                  <Field label={t("admin.search.fallback_timeout_label")}>
                    <input type="number" min={1} value={settings.fallback_timeout_seconds}
                      onChange={(e) => setSettings({ ...settings, fallback_timeout_seconds: Math.max(1, Number(e.target.value)) })}
                      className={inputCls} />
                    <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{t("admin.search.fallback_timeout_hint")}</p>
                  </Field>
                </div>
                <button type="submit"
                  className="mt-4 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400">
                  {t("admin.search.save")}
                </button>
              </form>
            )}
          </>
        )}

        {modal.kind === "edit" && (
          <EditProviderModal
            provider={modal.provider}
            onClose={() => setModal({ kind: "closed" })}
            onSaved={refresh}
            setError={setError}
          />
        )}
      </div>
    </AppShell>
  );
}

// ---- EditProviderModal ------------------------------------------------------
// Mirrors AdminAIPage.tsx's EditBuiltinModal: one combined form, submitted
// together on "Save" - the admin_key field is only included in the PATCH
// when the admin actually typed something new (an empty field means "leave
// the stored key untouched"), same convention as UpdateSearchProvider's
// COALESCE-on-conflict behavior on the backend.
function EditProviderModal({
  provider,
  onClose,
  onSaved,
  setError,
}: {
  provider: SearchProvider;
  onClose: () => void;
  onSaved: () => void;
  setError: (e: string | null) => void;
}) {
  const { t } = useTranslation();
  const isSearXNG = provider.type === "searxng";
  const [baseURL, setBaseURL] = useState(provider.base_url ?? "");
  const [key, setKey] = useState("");
  const [maxResults, setMaxResults] = useState(provider.max_results);
  const [fetchPages, setFetchPages] = useState(provider.fetch_pages);
  const [userCanOverride, setUserCanOverride] = useState(provider.user_can_override);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const patch: Parameters<typeof adminPatchSearchProvider>[1] = {
        max_results: Math.max(1, Math.min(100, maxResults)),
      };
      if (isSearXNG) {
        patch.base_url = baseURL.trim();
        patch.fetch_pages = Math.max(1, Math.min(5, fetchPages));
      } else {
        patch.user_can_override = userCanOverride;
        if (key.trim()) patch.admin_key = key.trim();
      }
      await adminPatchSearchProvider(provider.id, patch);
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.search.save_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-base font-semibold">{t("admin.search.modal.edit_title", { name: provider.name })}</h2>
        <div className="space-y-3">
          {isSearXNG ? (
            <>
              <Field label={t("admin.search.url_label")}>
                <input type="url" value={baseURL} onChange={(e) => setBaseURL(e.target.value)}
                  placeholder="https://search.example.com" className={inputCls} />
              </Field>
              <Field label={t("admin.search.fetch_pages_label")}>
                <input type="number" min={1} max={5} value={fetchPages}
                  onChange={(e) => setFetchPages(Math.max(1, Math.min(5, Number(e.target.value))))}
                  className={inputCls} />
              </Field>
            </>
          ) : (
            <Field label={provider.has_admin_key ? t("admin.search.modal.api_key_keep") : t("admin.search.modal.api_key")}>
              <input
                type="password"
                autoComplete="off"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={provider.has_admin_key ? "••••••••" : "..."}
                className={inputCls}
              />
            </Field>
          )}
          <Field label={t("admin.search.max_results_label")}>
            <input type="number" min={1} max={100} value={maxResults}
              onChange={(e) => setMaxResults(Math.max(1, Math.min(100, Number(e.target.value))))}
              className={inputCls} />
          </Field>
          {!isSearXNG && (
            <label className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-300">
              <input type="checkbox" checked={userCanOverride} onChange={(e) => setUserCanOverride(e.target.checked)} />
              {t("admin.search.user_can_override_label")}
            </label>
          )}
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose}
            className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800">
            {t("common.cancel")}
          </button>
          <button type="submit" disabled={busy}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50">
            {busy ? t("common.saving") : t("common.save")}
          </button>
        </div>
      </form>
    </Overlay>
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

// ---- Shared components (copied from AdminAIPage.tsx for visual parity) -----

const inputCls =
  "w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">{label}</label>
      {children}
    </div>
  );
}

function Overlay({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {
  return (
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/40" onClick={onClose}>
      {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions */}
      <div
        className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-gray-800 dark:bg-gray-950"
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}

function ActionButton({
  children,
  onClick,
  busy,
  variant = "primary",
}: {
  children: React.ReactNode;
  onClick: () => void;
  busy: boolean;
  variant?: "primary" | "secondary" | "danger";
}) {
  const styles = {
    primary: "bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400",
    secondary:
      "border border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800",
    danger:
      "border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950",
  };
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onClick}
      className={`flex-none rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]}`}
    >
      {children}
    </button>
  );
}
