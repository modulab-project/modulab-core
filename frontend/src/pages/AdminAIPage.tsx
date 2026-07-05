import React, { useCallback, useEffect, useState } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import {
  adminListAIProviders,
  adminCreateAIProvider,
  adminPatchAIProvider,
  adminDeleteAIProvider,
  adminClearAIProviderKey,
  adminFetchAIProviderModels,
  adminFetchAIProviderBalance,
  adminGetAISettings,
  adminPatchAISettings,
  type AIProvider,
  type AISettings,
  type AIBalanceResult,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

// Built-in provider definitions — these are the four first-class providers
// that have known base URLs and dedicated types. Admins only need to supply
// an API key. Custom providers (type = "openai_compat") are freely created.
const BUILTIN_PROVIDERS = [
  { id: "anthropic", type: "anthropic", name: "Anthropic (Claude)", defaultModel: "claude-sonnet-4-5" },
  { id: "openai", type: "openai", name: "OpenAI", defaultModel: "gpt-4o" },
  { id: "gemini", type: "gemini", name: "Google Gemini", defaultModel: "gemini-2.0-flash" },
  { id: "deepseek", type: "deepseek", name: "DeepSeek", defaultModel: "deepseek-chat" },
] as const;

type ModalState =
  | { kind: "closed" }
  | { kind: "edit-builtin"; provider: AIProvider }
  | { kind: "create-custom" }
  | { kind: "edit-custom"; provider: AIProvider };

export default function AdminAIPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [providers, setProviders] = useState<AIProvider[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState<ModalState>({ kind: "closed" });
  const [balances, setBalances] = useState<Record<string, AIBalanceResult & { loading?: boolean }>>({});

  // AI settings (rate limit + body limit)
  const [aiSettings, setAiSettings] = useState<AISettings | null>(null);
  const [rpmInput, setRpmInput] = useState("");
  const [bodyInput, setBodyInput] = useState("");
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [settingsSaved, setSettingsSaved] = useState(false);

  const refresh = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    adminListAIProviders(token)
      .then((p) => { setProviders(p); setError(null); })
      .catch(() => setError(t("admin.ai.load_error")));
  }, []);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    refresh();
    const token = getSessionToken();
    if (token) {
      adminGetAISettings(token)
        .then((s) => {
          setAiSettings(s);
          setRpmInput(String(s.chat_rpm_limit));
          setBodyInput(String(s.max_body_bytes));
        })
        .catch(() => setError(t("admin.ai.settings.load_error")));
    }
  }, [session, navigate, refresh]);

  if (loading || !session || !isAdminRole(session.role)) return null;

  // Map built-in IDs to existing provider rows for easy lookup.
  const providerMap = new Map((providers ?? []).map((p) => [p.id, p]));
  const customProviders = (providers ?? []).filter((p) => p.type === "openai_compat");

  async function handleClearKey(id: string) {
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await adminClearAIProviderKey(token, id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.clear_key_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(p: AIProvider) {
    if (!window.confirm(t("admin.ai.delete_confirm", { name: p.name }))) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await adminDeleteAIProvider(token, p.id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.delete_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    const rpm = parseInt(rpmInput, 10);
    const body = parseInt(bodyInput, 10);
    if (isNaN(rpm) || rpm < 0 || isNaN(body) || body < 0) return;
    const token = getSessionToken();
    if (!token) return;
    setSettingsBusy(true);
    try {
      const s = await adminPatchAISettings(token, { chat_rpm_limit: rpm, max_body_bytes: body });
      setAiSettings(s);
      setRpmInput(String(s.chat_rpm_limit));
      setBodyInput(String(s.max_body_bytes));
      setSettingsSaved(true);
      setTimeout(() => setSettingsSaved(false), 2000);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.settings.save_error"));
    } finally {
      setSettingsBusy(false);
    }
  }

  async function handleFetchBalance(id: string) {
    const token = getSessionToken();
    if (!token) return;
    setBalances((prev) => ({ ...prev, [id]: { supported: true, loading: true } }));
    try {
      const result = await adminFetchAIProviderBalance(token, id);
      setBalances((prev) => ({ ...prev, [id]: result }));
    } catch (e) {
      setBalances((prev) => ({
        ...prev,
        [id]: { supported: true, error: e instanceof Error ? e.message : t("admin.ai.balance.fetch_error") },
      }));
    }
  }

  async function handleToggleEnabled(p: AIProvider) {
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    try {
      await adminPatchAIProvider(token, p.id, { enabled: !p.enabled });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.update_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <Link to="/admin/system"
          className="mb-6 flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
          <i className="ti ti-arrow-left text-[14px]" />
          {t("admin.system.back")}
        </Link>
        <h1 className="mb-1 text-xl font-semibold">{t("admin.ai.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.ai.subtitle")}
        </p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {/* Built-in providers */}
        <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">
          {t("admin.ai.builtin_title")}
        </h2>
        <div className="mb-6 rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
          {BUILTIN_PROVIDERS.map((def, i) => {
            const p = providerMap.get(def.id);
            const hasKey = p?.has_admin_key ?? false;
            const enabled = p?.enabled ?? false;
            return (
              <div
                key={def.id}
                className={`px-4 py-3.5 text-sm ${
                  i < BUILTIN_PROVIDERS.length - 1
                    ? "border-b border-gray-100 dark:border-gray-800"
                    : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="font-medium">{def.name}</p>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                      hasKey && enabled
                        ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                        : hasKey
                        ? "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                        : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                    }`}
                  >
                    {hasKey && enabled ? t("admin.ai.status.active") : hasKey ? t("admin.ai.status.disabled") : t("admin.ai.status.no_key")}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {t("admin.ai.model_label")}: <span className="font-medium text-gray-700 dark:text-gray-300">{p?.default_model ?? def.defaultModel}</span>
                    </p>
                    {/* Balance display — only for providers with a public balance API (DeepSeek only) */}
                    {hasKey && def.type === "deepseek" && (() => {
                      const bal = balances[def.id];
                      if (!bal) return (
                        <button
                          type="button"
                          onClick={() => handleFetchBalance(def.id)}
                          className="mt-0.5 text-[11px] text-teal-600 hover:underline dark:text-teal-400"
                        >
                          {t("admin.ai.balance.check")}
                        </button>
                      );
                      if (bal.loading) return <p className="mt-0.5 text-[11px] text-gray-400">{t("admin.ai.balance.loading")}</p>;
                      if (bal.error) return <p className="mt-0.5 text-[11px] text-red-500">{bal.error}</p>;
                      if (!bal.supported) return null;
                      return (
                        <p className="mt-0.5 text-[11px] text-gray-500 dark:text-gray-400">
                          {t("admin.ai.balance.label")}: <span className="font-medium text-gray-700 dark:text-gray-300">{bal.amount?.toFixed(2)} {bal.currency}</span>
                          <button type="button" onClick={() => handleFetchBalance(def.id)} className="ml-1.5 text-teal-600 hover:underline dark:text-teal-400">↺</button>
                        </p>
                      );
                    })()}
                  </div>
                  <div className="flex flex-none items-center gap-1.5">
                    <ActionButton
                      variant="secondary"
                      busy={busy}
                      onClick={() =>
                        setModal({
                          kind: "edit-builtin",
                          provider: p ?? {
                            id: def.id,
                            type: def.type,
                            name: def.name,
                            has_admin_key: false,
                            default_model: def.defaultModel,
                            user_can_override: true,
                            enabled: true,
                            sort_order: 0,
                          },
                        })
                      }
                    >
                      {t("admin.ai.action.edit")}
                    </ActionButton>
                    {p && (
                      <ActionButton
                        variant="secondary"
                        busy={busy}
                        onClick={() => handleToggleEnabled(p)}
                      >
                        {enabled ? t("admin.ai.action.disable") : t("admin.ai.action.enable")}
                      </ActionButton>
                    )}
                    {hasKey && (
                      <ActionButton
                        variant="danger"
                        busy={busy}
                        onClick={() => handleClearKey(def.id)}
                      >
                        {t("admin.ai.action.clear_key")}
                      </ActionButton>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Custom providers */}
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
            {t("admin.ai.custom_title")}
          </h2>
          <ActionButton
            variant="primary"
            busy={false}
            onClick={() => setModal({ kind: "create-custom" })}
          >
            {t("admin.ai.action.add_provider")}
          </ActionButton>
        </div>

        {customProviders.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-8 text-center dark:border-gray-700">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {t("admin.ai.custom_empty")}
            </p>
          </div>
        ) : (
          <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
            {customProviders.map((p, i) => (
              <div
                key={p.id}
                className={`px-4 py-3.5 text-sm ${
                  i < customProviders.length - 1
                    ? "border-b border-gray-100 dark:border-gray-800"
                    : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="font-medium">{p.name}</p>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                      p.enabled
                        ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                        : "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                    }`}
                  >
                    {p.enabled ? t("admin.ai.status.active") : t("admin.ai.status.disabled")}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center justify-between gap-2">
                  <p className="min-w-0 truncate text-xs text-gray-500 dark:text-gray-400">
                    {p.base_url} · {p.default_model}
                    {p.has_admin_key ? "" : t("admin.ai.no_key_suffix")}
                  </p>
                  <div className="flex flex-none items-center gap-1.5">
                    <ActionButton
                      variant="secondary"
                      busy={busy}
                      onClick={() => setModal({ kind: "edit-custom", provider: p })}
                    >
                      {t("admin.ai.action.edit")}
                    </ActionButton>
                    <ActionButton
                      variant="secondary"
                      busy={busy}
                      onClick={() => handleToggleEnabled(p)}
                    >
                      {p.enabled ? t("admin.ai.action.disable") : t("admin.ai.action.enable")}
                    </ActionButton>
                    <ActionButton
                      variant="danger"
                      busy={busy}
                      onClick={() => handleDelete(p)}
                    >
                      {t("admin.ai.action.delete")}
                    </ActionButton>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* AI settings */}
        <h2 className="mb-2 mt-8 text-sm font-semibold text-gray-700 dark:text-gray-300">
          {t("admin.ai.settings.title")}
        </h2>
        <div className="rounded-2xl border border-gray-200 bg-white px-4 py-4 dark:border-gray-800 dark:bg-gray-900">
          <form onSubmit={handleSaveSettings} className="space-y-4">
            <div>
              <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
                {t("admin.ai.settings.rpm_label")}
              </label>
              <input
                type="number"
                min={0}
                value={rpmInput}
                onChange={(e) => setRpmInput(e.target.value)}
                className={inputCls}
              />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.ai.settings.rpm_hint")}
              </p>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
                {t("admin.ai.settings.body_label")}
              </label>
              <input
                type="number"
                min={0}
                value={bodyInput}
                onChange={(e) => setBodyInput(e.target.value)}
                className={inputCls}
              />
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.ai.settings.body_hint")}
              </p>
            </div>
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={
                  settingsBusy ||
                  (rpmInput === String(aiSettings?.chat_rpm_limit) &&
                    bodyInput === String(aiSettings?.max_body_bytes))
                }
                className="rounded-md bg-teal-600 px-3 py-2 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
              >
                {settingsSaved ? t("admin.ai.settings.saved") : settingsBusy ? t("common.saving") : t("common.save")}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Modals */}
      {modal.kind === "edit-builtin" && (
        <EditBuiltinModal
          provider={modal.provider}
          onClose={() => setModal({ kind: "closed" })}
          onSaved={refresh}
          setError={setError}
        />
      )}
      {modal.kind === "create-custom" && (
        <CustomProviderModal
          onClose={() => setModal({ kind: "closed" })}
          onSaved={refresh}
          setError={setError}
        />
      )}
      {modal.kind === "edit-custom" && (
        <CustomProviderModal
          existing={modal.provider}
          onClose={() => setModal({ kind: "closed" })}
          onSaved={refresh}
          setError={setError}
        />
      )}
    </AppShell>
  );
}

// ---- EditBuiltinModal ------------------------------------------------------
// Lets the admin change the default model and/or API key for a built-in
// provider (Anthropic, OpenAI, Gemini, DeepSeek). The key field is optional
// when a key is already stored — leave it empty to keep the existing one.

function EditBuiltinModal({
  provider,
  onClose,
  onSaved,
  setError,
}: {
  provider: AIProvider;
  onClose: () => void;
  onSaved: () => void;
  setError: (e: string | null) => void;
}) {
  const { t } = useTranslation();
  const [model, setModel] = useState(provider.default_model);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [models, setModels] = useState<string[] | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelsError, setModelsError] = useState<string | null>(null);

  // The "load models" button is visible when either the provider already has a
  // stored key OR the user has typed a new key in this session (key.trim() != "").
  const canLoadModels = provider.has_admin_key || key.trim() !== "";

  async function handleLoadModels() {
    const token = getSessionToken();
    if (!token) return;
    setLoadingModels(true);
    setModelsError(null);
    // If the user typed a new key, save it first so the backend can use it to
    // fetch the model list, then reload so has_admin_key becomes true.
    if (key.trim() && !provider.has_admin_key) {
      try {
        await adminPatchAIProvider(token, provider.id, {
          default_model: model.trim(),
          admin_key: key.trim(),
        }).catch(async () => {
          await adminCreateAIProvider(token, {
            id: provider.id,
            type: provider.type,
            name: provider.name,
            default_model: model.trim(),
            admin_key: key.trim(),
            user_can_override: true,
            enabled: true,
            sort_order: provider.sort_order,
          });
        });
        onSaved(); // refresh parent list so has_admin_key is updated
      } catch {
        // proceed anyway — the backend will use the in-flight key if supported
      }
    }
    try {
      const list = await adminFetchAIProviderModels(token, provider.id);
      setModels(list);
      // If the current model is not in the list, snap to the first entry so
      // the select and the state stay in sync.
      if (list.length > 0 && !list.includes(model)) {
        setModel(list[0]);
      }
    } catch (e) {
      setModelsError(e instanceof Error ? e.message : t("admin.ai.modal.fetch_models_error"));
    } finally {
      setLoadingModels(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!model.trim()) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    try {
      const patch: Parameters<typeof adminPatchAIProvider>[2] = {
        default_model: model.trim(),
      };
      if (key.trim()) patch.admin_key = key.trim();

      // Rows are seeded on startup, so PATCH should always work.
      // Fall back to CREATE if the row somehow doesn't exist yet.
      try {
        await adminPatchAIProvider(token, provider.id, patch);
      } catch {
        await adminCreateAIProvider(token, {
          id: provider.id,
          type: provider.type,
          name: provider.name,
          default_model: model.trim(),
          admin_key: key.trim() || undefined,
          user_can_override: true,
          enabled: true,
          sort_order: provider.sort_order,
        });
      }
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.save_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-base font-semibold">{t("admin.ai.modal.edit_builtin_title", { name: provider.name })}</h2>
        <div className="space-y-3">
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-xs text-gray-500 dark:text-gray-400">
                {t("admin.ai.modal.default_model")} <span className="ml-0.5 text-red-500">*</span>
              </label>
              {canLoadModels && (
                <button
                  type="button"
                  disabled={loadingModels}
                  onClick={handleLoadModels}
                  className="text-xs text-teal-600 hover:underline disabled:opacity-50 dark:text-teal-400"
                >
                  {loadingModels ? t("common.loading") : t("admin.ai.modal.load_models")}
                </button>
              )}
            </div>
            {models && models.length > 0 ? (
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className={inputCls}
              >
                {models.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            ) : (
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="gpt-4o"
                className={inputCls}
              />
            )}
            {modelsError && (
              <p className="mt-1 text-xs text-red-500">{modelsError}</p>
            )}
            {!provider.has_admin_key && (
              <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
                {t("admin.ai.modal.save_key_first")}
              </p>
            )}
          </div>
          <Field label={provider.has_admin_key ? t("admin.ai.modal.api_key_keep") : t("admin.ai.modal.api_key")}>
            <input
              type="password"
              autoComplete="off"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={provider.has_admin_key ? "••••••••" : "sk-..."}
              className={inputCls}
            />
          </Field>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            disabled={busy || !model.trim()}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {busy ? t("common.saving") : t("common.save")}
          </button>
        </div>
      </form>
    </Overlay>
  );
}

// ---- CustomProviderModal ---------------------------------------------------

function CustomProviderModal({
  existing,
  onClose,
  onSaved,
  setError,
}: {
  existing?: AIProvider;
  onClose: () => void;
  onSaved: () => void;
  setError: (e: string | null) => void;
}) {
  const { t } = useTranslation();
  const [id, setId] = useState(existing?.id ?? "");
  const [name, setName] = useState(existing?.name ?? "");
  const [baseURL, setBaseURL] = useState(existing?.base_url ?? "");
  const [model, setModel] = useState(existing?.default_model ?? "");
  const [models, setModels] = useState<string[] | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [userCanOverride, setUserCanOverride] = useState(existing?.user_can_override ?? true);
  const [busy, setBusy] = useState(false);

  // For existing providers: load models via the stored admin key.
  // The provider must already be saved (existing != null) to use this.
  async function handleLoadModels() {
    if (!existing) return;
    const token = getSessionToken();
    if (!token) return;
    setLoadingModels(true);
    setModelsError(null);
    try {
      const list = await adminFetchAIProviderModels(token, existing.id);
      setModels(list);
    } catch (e) {
      setModelsError(e instanceof Error ? e.message : t("admin.ai.modal.fetch_models_error"));
    } finally {
      setLoadingModels(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !baseURL.trim() || !model.trim()) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    try {
      if (existing) {
        const patch: Parameters<typeof adminPatchAIProvider>[2] = {
          name: name.trim(),
          base_url: baseURL.trim(),
          default_model: model.trim(),
          user_can_override: userCanOverride,
        };
        if (apiKey.trim()) patch.admin_key = apiKey.trim();
        await adminPatchAIProvider(token, existing.id, patch);
      } else {
        const providerId = id.trim() || name.trim().toLowerCase().replace(/\s+/g, "-");
        await adminCreateAIProvider(token, {
          id: providerId,
          type: "openai_compat",
          name: name.trim(),
          base_url: baseURL.trim(),
          admin_key: apiKey.trim() || undefined,
          default_model: model.trim(),
          user_can_override: userCanOverride,
          enabled: true,
          sort_order: 100,
        });
      }
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("admin.ai.modal.save_provider_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-base font-semibold">
          {existing ? t("admin.ai.modal.custom_title_edit") : t("admin.ai.modal.custom_title_add")}
        </h2>
        <div className="space-y-3">
          <Field label={t("admin.ai.modal.name")} required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("admin.ai.modal.name_placeholder")}
              className={inputCls}
            />
          </Field>
          {!existing && (
            <Field label={t("admin.ai.modal.id")}>
              <input
                value={id}
                onChange={(e) => setId(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
                placeholder="ollama-homelab"
                className={inputCls}
              />
            </Field>
          )}
          <Field label={t("admin.ai.modal.base_url")} required>
            <input
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
              placeholder="http://homelab:11434/v1"
              className={inputCls}
            />
          </Field>
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-xs text-gray-500 dark:text-gray-400">
                {t("admin.ai.modal.default_model")} <span className="ml-0.5 text-red-500">*</span>
              </label>
              {existing?.has_admin_key && (
                <button
                  type="button"
                  disabled={loadingModels}
                  onClick={handleLoadModels}
                  className="text-xs text-teal-600 hover:underline disabled:opacity-50 dark:text-teal-400"
                >
                  {loadingModels ? t("common.loading") : t("admin.ai.modal.load_models")}
                </button>
              )}
            </div>
            {models && models.length > 0 ? (
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className={inputCls}
              >
                {models.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            ) : (
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="llama3.2"
                className={inputCls}
              />
            )}
            {modelsError && (
              <p className="mt-1 text-xs text-red-500">{modelsError}</p>
            )}
          </div>
          <Field label={existing ? t("admin.ai.modal.api_key_keep") : t("admin.ai.modal.api_key_optional")}>
            <input
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={t("admin.ai.modal.api_key_placeholder")}
              className={inputCls}
            />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={userCanOverride}
              onChange={(e) => setUserCanOverride(e.target.checked)}
              className="h-4 w-4 rounded accent-teal-600"
            />
            <span>{t("admin.ai.modal.user_override")}</span>
          </label>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800">
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            disabled={busy || !name.trim() || !baseURL.trim() || !model.trim()}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {busy ? t("common.saving") : existing ? t("admin.ai.modal.save_changes") : t("admin.ai.modal.add_provider")}
          </button>
        </div>
      </form>
    </Overlay>
  );
}

// ---- Shared components -----------------------------------------------------

const inputCls =
  "w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800";

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs text-gray-500 dark:text-gray-400">
        {label}{required && <span className="ml-0.5 text-red-500">*</span>}
      </label>
      {children}
    </div>
  );
}

function Overlay({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {
  return (
    // Click-outside-to-close backdrop; the inner div only stops
    // propagation so clicking the dialog itself doesn't also close it.
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
