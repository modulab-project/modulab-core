// Admin news-feed management page (/admin/feeds).
// Org-admin and super-admin can add, edit, and delete RSS/Atom feed URLs
// from the global feed pool that all users pick from.
// Gate is enforced server-side (requireAdminDeps in internal/news/news.go);
// client-side we additionally redirect non-admins to / via isAdminRole.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  adminListFeeds,
  adminCreateFeed,
  adminUpdateFeed,
  adminDeleteFeed,
  type Feed,
  type ApiError,
} from "../lib/api";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell, isAdminRole } from "../components/AppShell";

export default function AdminFeedsPage() {
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [fetching, setFetching] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal state
  const [editTarget, setEditTarget] = useState<Feed | null>(null); // null = create
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    load();
  }, [session]);

  function load() {
    const token = getSessionToken();
    if (!token) return;
    setFetching(true);
    adminListFeeds(token)
      .then((f) => {
        setFeeds(f ?? []);
        setError(null);
      })
      .catch((e: ApiError) => setError(e.message))
      .finally(() => setFetching(false));
  }

  function openCreate() {
    setEditTarget(null);
    setModalOpen(true);
  }

  function openEdit(feed: Feed) {
    setEditTarget(feed);
    setModalOpen(true);
  }

  async function handleDelete(feed: Feed) {
    if (!confirm(`Delete "${feed.label}"? This removes it for all users.`)) return;
    const token = getSessionToken();
    if (!token) return;
    try {
      await adminDeleteFeed(token, feed.id);
      setFeeds((prev) => prev.filter((f) => f.id !== feed.id));
    } catch (e: unknown) {
      setError((e as ApiError).message ?? "Delete failed");
    }
  }

  if (loading || !session) return null;

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-3xl py-8 px-2">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold">News Feeds</h1>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
              Manage the global RSS/Atom feed pool users can subscribe to.
            </p>
          </div>
          <button
            type="button"
            onClick={openCreate}
            className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-700"
          >
            <i className="ti ti-plus text-[14px]" /> Add feed
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {error}
          </div>
        )}

        {fetching ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">Loading…</p>
        ) : feeds.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-300 px-6 py-10 text-center dark:border-gray-700">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-200">No feeds yet</p>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Add an RSS or Atom feed URL to get started.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-gray-200 dark:border-gray-800">
            {feeds.map((feed, idx) => (
              <div
                key={feed.id}
                className={`flex items-center gap-3 px-4 py-3 ${
                  idx !== feeds.length - 1
                    ? "border-b border-gray-100 dark:border-gray-800"
                    : ""
                }`}
              >
                <i className="ti ti-rss shrink-0 text-[16px] text-teal-600 dark:text-teal-400" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{feed.label}</p>
                  <p className="truncate text-xs text-gray-500 dark:text-gray-400">{feed.url}</p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <button
                    type="button"
                    onClick={() => openEdit(feed)}
                    aria-label={`Edit ${feed.label}`}
                    className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    <i className="ti ti-pencil text-[14px] text-gray-500" />
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDelete(feed)}
                    aria-label={`Delete ${feed.label}`}
                    className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-red-50 dark:hover:bg-red-950"
                  >
                    <i className="ti ti-trash text-[14px] text-red-500" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {modalOpen && (
        <FeedModal
          feed={editTarget}
          onClose={() => setModalOpen(false)}
          onSaved={(saved) => {
            if (editTarget) {
              setFeeds((prev) => prev.map((f) => (f.id === saved.id ? saved : f)));
            } else {
              setFeeds((prev) => [...prev, saved]);
            }
            setModalOpen(false);
          }}
        />
      )}
    </AppShell>
  );
}

// ---- Feed create/edit modal -------------------------------------------------

function FeedModal({
  feed,
  onClose,
  onSaved,
}: {
  feed: Feed | null;
  onClose: () => void;
  onSaved: (saved: Feed) => void;
}) {
  const [url, setUrl] = useState(feed?.url ?? "");
  const [label, setLabel] = useState(feed?.label ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const token = getSessionToken();
    if (!token) return;
    setSaving(true);
    setError(null);
    try {
      if (feed) {
        await adminUpdateFeed(token, feed.id, { url: url.trim(), label: label.trim() });
        onSaved({ ...feed, url: url.trim(), label: label.trim() });
      } else {
        const created = await adminCreateFeed(token, { url: url.trim(), label: label.trim() });
        onSaved(created);
      }
    } catch (e: unknown) {
      setError((e as ApiError).message ?? "Save failed");
      setSaving(false);
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/40"
        onClick={onClose}
      />
      {/* Dialog */}
      <div className="fixed inset-x-4 top-[20%] z-50 mx-auto max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl dark:border-gray-800 dark:bg-gray-950">
        <h2 className="mb-4 text-base font-semibold">
          {feed ? "Edit feed" : "Add feed"}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium">Label</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Hacker News"
              required
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-900"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">RSS / Atom URL</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/feed.xml"
              required
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-teal-500 dark:border-gray-700 dark:bg-gray-900"
            />
          </div>
          {error && (
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
