import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  adminListAIProviders,
  adminCreateAIProvider,
  adminPatchAIProvider,
  adminDeleteAIProvider,
  adminClearAIProviderKey,
  adminFetchAIProviderModels,
  type AIProvider,
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
  const { session, loading } = useAuthenticatedSession();
  const [providers, setProviders] = useState<AIProvider[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState<ModalState>({ kind: "closed" });

  const refresh = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    adminListAIProviders(token)
      .then((p) => { setProviders(p); setError(null); })
      .catch(() => setError("Could not load AI providers."));
  }, []);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    refresh();
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
      setError(e instanceof Error ? e.message : "Failed to clear key.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(p: AIProvider) {
    if (!window.confirm(`Delete "${p.name}"? This removes the provider and all user keys for it.`)) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await adminDeleteAIProvider(token, p.id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete provider.");
    } finally {
      setBusy(false);
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
      setError(e instanceof Error ? e.message : "Failed to update provider.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-2xl py-10">
        <h1 className="mb-1 text-xl font-semibold">AI providers</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          Manage API keys for built-in providers and add custom OpenAI-compatible endpoints.
          Users with their own key always override the admin key for that provider.
        </p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {/* Built-in providers */}
        <h2 className="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-300">
          Built-in providers
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
                        ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
                        : hasKey
                        ? "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                        : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                    }`}
                  >
                    {hasKey && enabled ? "Active" : hasKey ? "Disabled" : "No key"}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center justify-between gap-2">
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Model: <span className="font-medium text-gray-700 dark:text-gray-300">{p?.default_model ?? def.defaultModel}</span>
                  </p>
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
                      Edit
                    </ActionButton>
                    {p && (
                      <ActionButton
                        variant="secondary"
                        busy={busy}
                        onClick={() => handleToggleEnabled(p)}
                      >
                        {enabled ? "Disable" : "Enable"}
                      </ActionButton>
                    )}
                    {hasKey && (
                      <ActionButton
                        variant="danger"
                        busy={busy}
                        onClick={() => handleClearKey(def.id)}
                      >
                        Clear key
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
            Custom providers (OpenAI-compatible)
          </h2>
          <ActionButton
            variant="primary"
            busy={false}
            onClick={() => setModal({ kind: "create-custom" })}
          >
            Add provider
          </ActionButton>
        </div>

        {customProviders.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-8 text-center dark:border-gray-700">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              No custom providers yet. Add Ollama, Groq, Mistral, or any OpenAI-compatible endpoint.
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
                        ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
                        : "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                    }`}
                  >
                    {p.enabled ? "Active" : "Disabled"}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center justify-between gap-2">
                  <p className="min-w-0 truncate text-xs text-gray-500 dark:text-gray-400">
                    {p.base_url} · {p.default_model}
                    {p.has_admin_key ? "" : " · no key"}
                  </p>
                  <div className="flex flex-none items-center gap-1.5">
                    <ActionButton
                      variant="secondary"
                      busy={busy}
                      onClick={() => setModal({ kind: "edit-custom", provider: p })}
                    >
                      Edit
                    </ActionButton>
                    <ActionButton
                      variant="secondary"
                      busy={busy}
                      onClick={() => handleToggleEnabled(p)}
                    >
                      {p.enabled ? "Disable" : "Enable"}
                    </ActionButton>
                    <ActionButton
                      variant="danger"
                      busy={busy}
                      onClick={() => handleDelete(p)}
                    >
                      Delete
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
  const [model, setModel] = useState(provider.default_model);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [models, setModels] = useState<string[] | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [modelsError, setModelsError] = useState<string | null>(null);

  async function handleLoadModels() {
    const token = getSessionToken();
    if (!token) return;
    setLoadingModels(true);
    setModelsError(null);
    try {
      const list = await adminFetchAIProviderModels(token, provider.id);
      setModels(list);
    } catch (e) {
      setModelsError(e instanceof Error ? e.message : "Could not fetch models.");
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
      setError(e instanceof Error ? e.message : "Failed to save.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-base font-semibold">Edit — {provider.name}</h2>
        <div className="space-y-3">
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-xs text-gray-500 dark:text-gray-400">
                Default model <span className="ml-0.5 text-red-500">*</span>
              </label>
              {provider.has_admin_key && (
                <button
                  type="button"
                  disabled={loadingModels}
                  onClick={handleLoadModels}
                  className="text-xs text-teal-600 hover:underline disabled:opacity-50 dark:text-teal-400"
                >
                  {loadingModels ? "Loading…" : "Load available models"}
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
                Save an API key first to load available models.
              </p>
            )}
          </div>
          <Field label={provider.has_admin_key ? "API key (leave empty to keep existing)" : "API key"}>
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
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !model.trim()}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save"}
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
      setModelsError(e instanceof Error ? e.message : "Could not fetch models.");
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
      setError(e instanceof Error ? e.message : "Failed to save provider.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Overlay onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-base font-semibold">
          {existing ? "Edit" : "Add"} custom provider
        </h2>
        <div className="space-y-3">
          <Field label="Name" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Ollama (homelab)"
              className={inputCls}
            />
          </Field>
          {!existing && (
            <Field label="ID (auto-generated from name if empty)">
              <input
                value={id}
                onChange={(e) => setId(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
                placeholder="ollama-homelab"
                className={inputCls}
              />
            </Field>
          )}
          <Field label="Base URL" required>
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
                Default model <span className="ml-0.5 text-red-500">*</span>
              </label>
              {existing?.has_admin_key && (
                <button
                  type="button"
                  disabled={loadingModels}
                  onClick={handleLoadModels}
                  className="text-xs text-teal-600 hover:underline disabled:opacity-50 dark:text-teal-400"
                >
                  {loadingModels ? "Loading…" : "Load available models"}
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
          <Field label={existing ? "API key (leave empty to keep existing)" : "API key (optional)"}>
            <input
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Leave empty if not required"
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
            <span>Allow users to override with their own key</span>
          </label>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800">
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !name.trim() || !baseURL.trim() || !model.trim()}
            className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {busy ? "Saving…" : existing ? "Save changes" : "Add provider"}
          </button>
        </div>
      </form>
    </Overlay>
  );
}

// ---- Shared components -----------------------------------------------------

const inputCls =
  "w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800";

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
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/40" onClick={onClose}>
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
  children: string;
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
