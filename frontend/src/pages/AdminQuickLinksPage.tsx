import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthenticatedSession } from "../lib/useSession";
import { getSessionToken } from "../lib/session";
import { AppShell, isAdminRole } from "../components/AppShell";
import {
  type AdminTile,
  createAdminQuickLink,
  deleteAdminQuickLink,
  listAdminQuickLinks,
  updateAdminQuickLink,
} from "../lib/quicklinks";

// ---- Edit / Create form -----------------------------------------------------

function QuickLinkForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: AdminTile;
  onSave: (data: {
    title: string;
    url: string;
    icon: string;
    description: string;
    sort_order: number;
  }) => Promise<void>;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState(initial?.title ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [icon, setIcon] = useState(initial?.icon ?? "ti-link");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [sortOrder, setSortOrder] = useState(initial?.sort_order ?? 0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim() || !url.trim()) return;
    setSaving(true);
    setError("");
    try {
      await onSave({ title, url, icon, description, sort_order: sortOrder });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fehler");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
            Titel *
          </label>
          <input
            type="text"
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
            URL *
          </label>
          <input
            type="url"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
          />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
            Icon <span className="text-gray-400">(Tabler, z. B. ti-server)</span>
          </label>
          <div className="flex items-center gap-2">
            <i className={`ti ${icon || "ti-link"} text-xl text-teal-600 dark:text-teal-400`} />
            <input
              type="text"
              value={icon}
              onChange={(e) => setIcon(e.target.value)}
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
            Reihenfolge
          </label>
          <input
            type="number"
            value={sortOrder}
            onChange={(e) => setSortOrder(Number(e.target.value))}
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
          />
        </div>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
          Beschreibung
        </label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
        />
      </div>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800"
        >
          Abbrechen
        </button>
        <button
          type="submit"
          disabled={saving}
          className="rounded-lg bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500"
        >
          {saving ? "Speichern…" : initial ? "Speichern" : "Erstellen"}
        </button>
      </div>
    </form>
  );
}

// ---- Page -------------------------------------------------------------------

export default function AdminQuickLinksPage() {
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
  const [links, setLinks] = useState<AdminTile[]>([]);
  const [fetching, setFetching] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  const token = getSessionToken() ?? "";

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    listAdminQuickLinks(token)
      .then(setLinks)
      .catch(() => {})
      .finally(() => setFetching(false));
  }, [session, token, navigate]);

  if (loading || !session) return null;

  async function handleCreate(data: {
    title: string;
    url: string;
    icon: string;
    description: string;
    sort_order: number;
  }) {
    const created = await createAdminQuickLink(token, data);
    setLinks((prev) => [...prev, created]);
    setShowCreate(false);
  }

  async function handleUpdate(
    id: string,
    data: { title: string; url: string; icon: string; description: string; sort_order: number }
  ) {
    await updateAdminQuickLink(token, id, data);
    setLinks((prev) =>
      prev.map((l) => (l.id === id ? { ...l, ...data } : l))
    );
    setEditId(null);
  }

  async function handleDelete(id: string) {
    await deleteAdminQuickLink(token, id);
    setLinks((prev) => prev.filter((l) => l.id !== id));
  }

  return (
    <AppShell session={session}>
    <div className="mx-auto max-w-3xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
            Schnellzugriff-Kacheln
          </h1>
          <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
            Globale Kacheln, die für alle Nutzer sichtbar sind
          </p>
        </div>
        {!showCreate && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400"
          >
            <i className="ti ti-plus" />
            Neu
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="mb-6 rounded-2xl border border-teal-200 bg-teal-50/50 p-5 dark:border-teal-800 dark:bg-teal-950/20">
          <h2 className="mb-4 text-sm font-semibold text-gray-800 dark:text-gray-200">
            Neue Kachel
          </h2>
          <QuickLinkForm
            onSave={handleCreate}
            onCancel={() => setShowCreate(false)}
          />
        </div>
      )}

      {/* List */}
      {links.length === 0 && !showCreate ? (
        <p className="text-sm text-gray-400 dark:text-gray-500">
          Noch keine globalen Kacheln angelegt.
        </p>
      ) : (
        <div className="space-y-2">
          {links.map((link) => (
            <div
              key={link.id}
              className="rounded-xl border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800"
            >
              {editId === link.id ? (
                <div className="p-4">
                  <QuickLinkForm
                    initial={link}
                    onSave={(data) => handleUpdate(link.id, data)}
                    onCancel={() => setEditId(null)}
                  />
                </div>
              ) : (
                <div className="flex items-center gap-3 p-4">
                  <span className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-400">
                    <i className={`ti ${link.icon || "ti-link"} text-lg`} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-gray-900 dark:text-gray-100">
                      {link.title}
                    </p>
                    <p className="truncate text-xs text-gray-400 dark:text-gray-500">
                      {link.url}
                    </p>
                  </div>
                  <span className="hidden text-xs text-gray-400 sm:block">
                    #{link.sort_order}
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setEditId(link.id)}
                      title="Bearbeiten"
                      className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700 dark:hover:bg-gray-700 dark:hover:text-gray-200"
                    >
                      <i className="ti ti-pencil text-sm" />
                    </button>
                    <button
                      onClick={() => handleDelete(link.id)}
                      title="Löschen"
                      className="rounded-lg p-1.5 text-gray-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/30 dark:hover:text-red-400"
                    >
                      <i className="ti ti-trash text-sm" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
    </AppShell>
  );
}
