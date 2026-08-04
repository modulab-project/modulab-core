import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import {
  adminListAIProviders,
  adminCreateAIProvider,
  adminPatchAIProvider,
  adminDeleteAIProvider,
  adminClearAIProviderKey,
  adminFetchAIProviderModels,
  adminFetchAIProviderBalance,
  type AIProvider,
  type AIBalanceResult,
} from "../lib/api";
import { useAuthenticatedSession } from "../lib/useSession";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { isReauthRequiredError } from "../lib/authErrors";
import { AppShell } from "../components/AppShell";
import { Modal } from "../components/Modal";
import { ReauthBanner } from "../components/ReauthBanner";
import { isAdminRole } from "../lib/roles";

// Built-in provider definitions — these are the seven first-class providers
// that have known base URLs and dedicated types. Admins only need to supply
// an API key. Custom providers (type = "openai_compat") are freely created.
//
// defaultModel is only pre-filled for providers with a vendor-guaranteed
// "always latest" alias (mistral, openrouter). The rest ship with an empty
// model - hardcoded model IDs go stale as vendors release new versions (see
// the deepseek-chat retirement), so the admin picks one explicitly on first
// setup via the "load models" button, which queries the provider's live
// model list instead of relying on a string we'd have to keep updating here.
const BUILTIN_PROVIDERS = [
  { id: "anthropic", type: "anthropic", name: "Anthropic (Claude)", defaultModel: "" },
  { id: "openai", type: "openai", name: "OpenAI", defaultModel: "" },
  { id: "gemini", type: "gemini", name: "Google Gemini", defaultModel: "" },
  { id: "deepseek", type: "deepseek", name: "DeepSeek", defaultModel: "" },
  { id: "kimi", type: "kimi", name: "Kimi (Moonshot AI)", defaultModel: "" },
  { id: "mistral", type: "mistral", name: "Mistral AI", defaultModel: "mistral-large-latest" },
  { id: "openrouter", type: "openrouter", name: "OpenRouter", defaultModel: "openrouter/auto" },
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
  // Backend now gates PATCH/DELETE /v1/admin/ai/providers/{id} and
  // DELETE .../key behind requireRecentLogin (RequireAdminReauthMiddleware,
  // 2026-07-22) - create (POST) stays reauth-free, see main.go's route
  // registration comment. Page-level actions (toggle enabled, clear key,
  // delete) use this; the two edit modals below each have their own
  // separate instance so their banner renders inside the modal overlay,
  // not hidden behind it in the page body.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
    setError(null);
  });

  const refresh = useCallback(() => {
    adminListAIProviders()
      .then((p) => { setProviders(p); setError(null); })
      .catch(() => setError(t("admin.ai.load_error")));
  }, [t]);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    refresh();
  }, [session, navigate, refresh, t]);

  if (loading || !session || !isAdminRole(session.role)) return null;

  // Map built-in IDs to existing provider rows for easy lookup.
  const providerMap = new Map((providers ?? []).map((p) => [p.id, p]));
  const customProviders = (providers ?? []).filter((p) => p.type === "openai_compat");

  async function handleClearKey(id: string) {
    setBusy(true);
    setError(null);
    setReauthRequired(false);
    try {
      await adminClearAIProviderKey(id);
      refresh();
    } catch (e) {
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        setError(e instanceof Error ? e.message : t("admin.ai.clear_key_error"));
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(p: AIProvider) {
    if (!window.confirm(t("admin.ai.delete_confirm", { name: p.name }))) return;
    setBusy(true);
    setError(null);
    setReauthRequired(false);
    try {
      await adminDeleteAIProvider(p.id);
      refresh();
    } catch (e) {
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        setError(e instanceof Error ? e.message : t("admin.ai.delete_error"));
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleFetchBalance(id: string) {
    setBalances((prev) => ({ ...prev, [id]: { supported: true, loading: true } }));
    try {
      const result = await adminFetchAIProviderBalance(id);
      setBalances((prev) => ({ ...prev, [id]: result }));
    } catch (e) {
      setBalances((prev) => ({
        ...prev,
        [id]: { supported: true, error: e instanceof Error ? e.message : t("admin.ai.balance.fetch_error") },
      }));
    }
  }

  async function handleToggleEnabled(p: AIProvider) {
    setBusy(true);
    setReauthRequired(false);
    try {
      await adminPatchAIProvider(p.id, { enabled: !p.enabled });
      refresh();
    } catch (e) {
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        setError(e instanceof Error ? e.message : t("admin.ai.update_error"));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-3xl py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("admin.ai.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("admin.ai.subtitle")}
        </p>

        {error && !reauthRequired && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}

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
                          <button type="button" onClick={() => handleFetchBalance(def.id)} aria-label={t("admin.ai.balance.refresh")} className="ml-1.5 text-teal-600 hover:underline dark:text-teal-400">↺</button>
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
                  <p className="min-w-0 break-all text-xs text-gray-500 dark:text-gray-400">
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
  // Own instance (not the page-level one in AdminAIPage) so the banner
  // renders inside this Overlay, where it's actually visible - the page
  // body's own reauthRequired state sits behind the modal's black/40
  // backdrop while this dialog is open.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
  });

  // The "load models" button is visible when either the provider already has a
  // stored key OR the user has typed a new key in this session (key.trim() != "").
  const canLoadModels = provider.has_admin_key || key.trim() !== "";

  async function handleLoadModels() {
    setLoadingModels(true);
    setModelsError(null);
    setReauthRequired(false);
    // If the user typed a new key, save it first so the backend can use it to
    // fetch the model list, then reload so has_admin_key becomes true.
    if (key.trim() && !provider.has_admin_key) {
      try {
        await adminPatchAIProvider(provider.id, {
          default_model: model.trim(),
          admin_key: key.trim(),
        });
        onSaved(); // refresh parent list so has_admin_key is updated
      } catch (err) {
        if (isReauthRequiredError(err)) {
          // Stale session - don't attempt the create fallback below (it
          // isn't reauth-gated, so it could otherwise silently "succeed"
          // via a completely different code path than the admin intended,
          // or fail confusingly on a duplicate ID since the row already
          // exists). Show the banner and stop; the admin can reauth and
          // retry.
          setReauthRequired(true);
          setLoadingModels(false);
          return;
        }
        try {
          await adminCreateAIProvider({
            id: provider.id,
            type: provider.type,
            name: provider.name,
            default_model: model.trim(),
            admin_key: key.trim(),
            user_can_override: true,
            enabled: true,
            sort_order: provider.sort_order,
          });
          onSaved();
        } catch {
          // proceed anyway — the backend will use the in-flight key if supported
        }
      }
    }
    try {
      const list = await adminFetchAIProviderModels(provider.id);
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
    setBusy(true);
    setReauthRequired(false);
    try {
      const patch: Parameters<typeof adminPatchAIProvider>[1] = {
        default_model: model.trim(),
      };
      if (key.trim()) patch.admin_key = key.trim();

      // Rows are seeded on startup, so PATCH should always work.
      // Fall back to CREATE if the row somehow doesn't exist yet - but
      // NOT when PATCH failed with reauth_required: retrying via CREATE
      // isn't reauth-gated, so it would either "succeed" through a
      // completely different code path than intended, or fail confusingly
      // on a duplicate ID since the row already exists. Rethrow instead so
      // the outer catch shows the reauth banner.
      try {
        await adminPatchAIProvider(provider.id, patch);
      } catch (patchErr) {
        if (isReauthRequiredError(patchErr)) throw patchErr;
        await adminCreateAIProvider({
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
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        setError(e instanceof Error ? e.message : t("admin.ai.save_error"));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose} titleId="ai-edit-builtin-title">
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 id="ai-edit-builtin-title" className="text-base font-semibold">{t("admin.ai.modal.edit_builtin_title", { name: provider.name })}</h2>
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}
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
  // Only relevant for the `existing` (PATCH) branch below - create isn't
  // reauth-gated. Own instance so the banner renders inside this Overlay,
  // same reasoning as EditBuiltinModal above.
  const [reauthRequired, setReauthRequired] = useState(false);
  const { waiting: reauthWaiting, startLogin } = useLoginRedirect(() => {
    setReauthRequired(false);
  });

  // For existing providers: load models via the stored admin key.
  // The provider must already be saved (existing != null) to use this.
  async function handleLoadModels() {
    if (!existing) return;
    setLoadingModels(true);
    setModelsError(null);
    try {
      const list = await adminFetchAIProviderModels(existing.id);
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
    setBusy(true);
    setReauthRequired(false);
    try {
      if (existing) {
        const patch: Parameters<typeof adminPatchAIProvider>[1] = {
          name: name.trim(),
          base_url: baseURL.trim(),
          default_model: model.trim(),
          user_can_override: userCanOverride,
        };
        if (apiKey.trim()) patch.admin_key = apiKey.trim();
        await adminPatchAIProvider(existing.id, patch);
      } else {
        const providerId = id.trim() || name.trim().toLowerCase().replace(/\s+/g, "-");
        await adminCreateAIProvider({
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
      if (isReauthRequiredError(e)) {
        setReauthRequired(true);
      } else {
        setError(e instanceof Error ? e.message : t("admin.ai.modal.save_provider_error"));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose} titleId="ai-custom-provider-title">
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 id="ai-custom-provider-title" className="text-base font-semibold">
          {existing ? t("admin.ai.modal.custom_title_edit") : t("admin.ai.modal.custom_title_add")}
        </h2>
        {reauthRequired && (
          <ReauthBanner
            waiting={reauthWaiting}
            onReauth={() => startLogin({ reauth: true, returnPath: window.location.pathname })}
            onDismiss={() => setReauthRequired(false)}
          />
        )}
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

function Overlay({
  onClose,
  titleId,
  children,
}: {
  onClose: () => void;
  titleId: string;
  children: React.ReactNode;
}) {
  return (
    <Modal
      open
      onClose={onClose}
      titleId={titleId}
      className="max-h-[85vh] w-full max-w-md overflow-y-auto rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-gray-800 dark:bg-gray-950"
    >
      {children}
    </Modal>
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
