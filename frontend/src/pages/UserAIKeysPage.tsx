import { useEffect, useState } from "react";
import { AppShell } from "../components/AppShell";
import { useAuthenticatedSession } from "../lib/useSession";
import { listAIProviders, setAIUserKey, deleteAIUserKey, type AIUserProvider } from "../lib/api";
import { getSessionToken } from "../lib/session";

// /user/ai-keys — lets users manage their own AI provider API keys.
// Each key overrides the admin-configured key for that provider, useful when
// the user has a higher-tier plan. Reachable from the profile panel.
export default function UserAIKeysPage() {
  const { session, loading } = useAuthenticatedSession();
  const [providers, setProviders] = useState<AIUserProvider[] | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    const token = getSessionToken();
    if (!token) return;
    listAIProviders(token)
      .then(setProviders)
      .catch(() => {});
  };

  useEffect(() => {
    if (!session) return;
    refresh();
  }, [session]);

  if (loading || !session) return null;

  async function handleSave(providerId: string) {
    if (!keyInput.trim()) return;
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await setAIUserKey(token, providerId, keyInput.trim());
      setEditingId(null);
      setKeyInput("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save key.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(providerId: string) {
    const token = getSessionToken();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await deleteAIUserKey(token, providerId);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to remove key.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell session={session}>
      <div className="mx-auto w-full max-w-md py-10">
        <h1 className="mb-1 text-xl font-semibold">AI providers</h1>
        <p className="mb-6 text-sm text-gray-500 dark:text-gray-400">
          Your own API key overrides the admin key for that provider — useful if you have a better plan.
        </p>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {providers === null ? null : providers.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">No AI providers have been configured by the admin yet.</p>
        ) : (
          <div className="rounded-2xl border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
            {providers.map((p, i) => {
              const isEditing = editingId === p.id;
              const isLast = i === providers.length - 1;
              return (
                <div
                  key={p.id}
                  className={`px-4 py-3.5 text-sm ${isLast ? "" : "border-b border-gray-100 dark:border-gray-800"}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-medium">{p.name}</p>
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                        p.has_user_key
                          ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
                          : p.has_admin_key
                          ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
                          : "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-400"
                      }`}
                    >
                      {p.has_user_key ? "Your key" : p.has_admin_key ? "Admin key" : "No key"}
                    </span>
                  </div>

                  {isEditing ? (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        type="password"
                        autoComplete="off"
                        autoFocus
                        value={keyInput}
                        onChange={(e) => setKeyInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleSave(p.id);
                          if (e.key === "Escape") { setEditingId(null); setKeyInput(""); }
                        }}
                        placeholder="sk-..."
                        className="flex-1 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-800"
                      />
                      <button
                        type="button"
                        disabled={busy || !keyInput.trim()}
                        onClick={() => handleSave(p.id)}
                        className="rounded-md bg-teal-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-700 disabled:opacity-50"
                      >
                        {busy ? "…" : "Save"}
                      </button>
                      <button
                        type="button"
                        onClick={() => { setEditingId(null); setKeyInput(""); }}
                        className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <div className="mt-1.5 flex items-center gap-1.5">
                      {p.can_override && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => { setEditingId(p.id); setKeyInput(""); }}
                          className="rounded-md border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
                        >
                          {p.has_user_key ? "Update key" : "Add own key"}
                        </button>
                      )}
                      {p.has_user_key && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => handleRemove(p.id)}
                          className="rounded-md border border-red-300 px-3 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                        >
                          Remove
                        </button>
                      )}
                      {!p.can_override && (
                        <span className="text-xs text-gray-400 dark:text-gray-600">Override not allowed</span>
                      )}
                    </div>
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
