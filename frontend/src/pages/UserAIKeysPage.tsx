import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AppShell } from "../components/AppShell";
import { useAuthenticatedSession } from "../lib/useSession";
import {
  listAIProviders,
  setAIUserKey,
  deleteAIUserKey,
  setAIUserPreferredModel,
  fetchUserAIProviderModels,
  type AIUserProvider,
} from "../lib/api";

// /user/ai-keys — lets users manage their own AI provider API keys and, when
// using their own key, choose which model to use. Users using the admin key
// cannot change the model (the admin's default_model is used, fixed).
export default function UserAIKeysPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const [providers, setProviders] = useState<AIUserProvider[] | null>(null);
  const [editingKeyId, setEditingKeyId] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    listAIProviders()
      .then(({ providers }) => { setProviders(providers); setError(null); })
      .catch(() => setError(t("user.ai.load_error")));
  }, [t]);

  useEffect(() => {
    if (!session) return;
    refresh();
  }, [session, refresh]);

  if (loading || !session) return null;

  async function handleSaveKey(providerId: string) {
    if (!keyInput.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await setAIUserKey(providerId, keyInput.trim());
      setEditingKeyId(null);
      setKeyInput("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("user.ai.save_key_error"));
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(providerId: string) {
    setBusy(true);
    setError(null);
    try {
      await deleteAIUserKey(providerId);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("user.ai.remove_key_error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-3xl py-10">
        <h1 className="mb-1 text-xl font-semibold">{t("user.ai.title")}</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          {t("user.ai.subtitle")}
        </p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {providers === null ? null : providers.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {t("user.ai.empty")}
          </p>
        ) : (
          <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
            {providers.map((p, i) => {
              const isEditingKey = editingKeyId === p.id;
              const isLast = i === providers.length - 1;
              return (
                <div
                  key={p.id}
                  className={`px-4 py-3.5 text-sm ${isLast ? "" : "border-b border-gray-100 dark:border-gray-800"}`}
                >
                  {/* Header row: name + badges */}
                  <div className="flex items-center justify-between gap-2">
                    <p className={`font-medium ${!p.enabled ? "text-gray-400 dark:text-gray-500" : ""}`}>
                      {p.name}
                    </p>
                    <div className="flex items-center gap-1.5">
                      {!p.enabled && (
                        <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-500 dark:bg-gray-800 dark:text-gray-400">
                          {t("user.ai.status.not_enabled")}
                        </span>
                      )}
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          p.has_user_key
                            ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                            : p.has_admin_key
                            ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                            : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                        }`}
                      >
                        {p.has_user_key ? t("user.ai.status.your_key") : p.has_admin_key ? t("user.ai.status.modulab_key") : t("user.ai.status.no_key")}
                      </span>
                    </div>
                  </div>

                  {/* Model line */}
                  <p className="mt-0.5 text-xs text-gray-400 dark:text-gray-500">
                    {p.has_user_key
                      ? t("user.ai.model_own", { model: p.preferred_model || p.default_model })
                      : t("user.ai.model_managed", { model: p.default_model })}
                  </p>

                  {/* Key edit row */}
                  {isEditingKey ? (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        type="password"
                        autoComplete="off"
                        // eslint-disable-next-line jsx-a11y/no-autofocus -- input appears only after explicit user click on "edit", not on page load
                        autoFocus
                        value={keyInput}
                        onChange={(e) => setKeyInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleSaveKey(p.id);
                          if (e.key === "Escape") { setEditingKeyId(null); setKeyInput(""); }
                        }}
                        placeholder="sk-..."
                        className="flex-1 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-base outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                      />
                      <button
                        type="button"
                        disabled={busy || !keyInput.trim()}
                        onClick={() => handleSaveKey(p.id)}
                        className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                      >
                        {busy ? "…" : t("user.ai.action.save")}
                      </button>
                      <button
                        type="button"
                        onClick={() => { setEditingKeyId(null); setKeyInput(""); }}
                        className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300"
                      >
                        {t("user.ai.action.cancel")}
                      </button>
                    </div>
                  ) : (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      {p.can_override && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => { setEditingKeyId(p.id); setKeyInput(""); }}
                          className="rounded-md border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
                        >
                          {p.has_user_key ? t("user.ai.action.update_key") : t("user.ai.action.add_key")}
                        </button>
                      )}
                      {p.has_user_key && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => handleRemove(p.id)}
                          className="rounded-md border border-red-300 px-3 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                        >
                          {t("user.ai.action.remove_key")}
                        </button>
                      )}
                      {!p.can_override && (
                        <span className="text-xs text-gray-400 dark:text-gray-600">{t("user.ai.override_not_allowed")}</span>
                      )}
                    </div>
                  )}

                  {/* Model selector — only shown when user has their own key */}
                  {p.has_user_key && !isEditingKey && (
                    <ModelSelector
                      provider={p}
                      onChanged={refresh}
                      onError={setError}
                    />
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppShell>
  );
}

// ModelSelector lets the user pick which model to use with their own key.
// It lazily fetches the available models from the provider on demand.
function ModelSelector({
  provider,
  onChanged,
  onError,
}: {
  provider: AIUserProvider;
  onChanged: () => void;
  onError: (e: string | null) => void;
}) {
  const { t } = useTranslation();
  const [models, setModels] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const current = provider.preferred_model || provider.default_model;

  async function handleLoad() {
    setLoading(true);
    onError(null);
    try {
      const list = await fetchUserAIProviderModels(provider.id);
      setModels(list);
    } catch (e) {
      onError(e instanceof Error ? e.message : t("user.ai.fetch_models_error"));
    } finally {
      setLoading(false);
    }
  }

  async function handleSelect(model: string) {
    setSaving(true);
    onError(null);
    try {
      await setAIUserPreferredModel(provider.id, model);
      onChanged();
    } catch (e) {
      onError(e instanceof Error ? e.message : t("user.ai.save_model_error"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mt-2 border-t border-gray-100 pt-2 dark:border-gray-800">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-gray-500 dark:text-gray-400">{t("user.ai.your_model")}</span>
        {models === null ? (
          <button
            type="button"
            disabled={loading}
            onClick={handleLoad}
            className="text-xs text-teal-600 hover:underline disabled:opacity-50 dark:text-teal-400"
          >
            {loading ? t("common.loading") : t("user.ai.load_models")}
          </button>
        ) : (
          <select
            value={current}
            disabled={saving}
            onChange={(e) => handleSelect(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1 text-base outline-none focus:border-teal-500 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800"
          >
            {models.map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        )}
      </div>
    </div>
  );
}
