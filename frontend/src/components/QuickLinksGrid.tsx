import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Tile } from "../lib/quicklinks";
import { createUserQuickLink, deleteUserQuickLink, saveOrder } from "../lib/quicklinks";

// ---- Drag-and-drop ----------------------------------------------------------
//
// Uses HTML5 native DnD (no extra dependency). dragSrcIdx tracks which tile
// the drag started from; on drop we reorder the local state and fire PATCH
// /v1/quick-links/order in the background. If the save fails the tile list is
// left in the new visual order (optimistic) - a full reload would restore the
// server order.

function tileKey(t: Tile) {
  return `${t.type}:${t.id}`;
}

// ---- Add-tile modal ---------------------------------------------------------

function AddTileModal({
  token,
  onClose,
  onAdded,
}: {
  token: string;
  onClose: () => void;
  onAdded: (tile: Tile) => void;
}) {
  const { t } = useTranslation();
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [icon, setIcon] = useState("ti-link");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim() || !url.trim()) return;
    setSaving(true);
    setError("");
    try {
      const newTile = await createUserQuickLink(token, { title, url, icon, description });
      onAdded(newTile);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("home.quick_links_error"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">
          {t("home.quick_links_add_modal_title")}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              {t("home.quick_links_tile_title")} *
            </label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              placeholder="z. B. Nextcloud"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              {t("home.quick_links_tile_url")} *
            </label>
            <input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              placeholder="https://cloud.example.com"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              {t("home.quick_links_tile_icon")}{" "}
              <span className="text-gray-400">(Tabler-Icon-Name, z. B. ti-cloud)</span>
            </label>
            <input
              type="text"
              value={icon}
              onChange={(e) => setIcon(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              {t("home.quick_links_tile_desc")}
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800"
            >
              {t("home.quick_links_cancel")}
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-md bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400"
            >
              {saving ? t("home.quick_links_saving") : t("home.quick_links_add_submit")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---- Single tile card -------------------------------------------------------

function TileCard({
  tile,
  dragging,
  dragOver,
  onDragStart,
  onDragEnter,
  onDragEnd,
  onDrop,
  onDelete,
}: {
  tile: Tile;
  dragging: boolean;
  dragOver: boolean;
  onDragStart: () => void;
  onDragEnter: () => void;
  onDragEnd: () => void;
  onDrop: () => void;
  onDelete?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div
      draggable
      onDragStart={onDragStart}
      onDragEnter={onDragEnter}
      onDragEnd={onDragEnd}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        onDrop();
      }}
      className={[
        "group relative flex cursor-grab flex-col items-center gap-2 rounded-2xl border p-4 text-center",
        "transition-all duration-150 select-none",
        "hover:shadow-md",
        dragging
          ? "opacity-40 scale-95"
          : dragOver
            ? "border-teal-400 bg-teal-50 dark:border-teal-500 dark:bg-teal-950/30"
            : "border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800",
      ].join(" ")}
    >
      {/* Delete button — only on user tiles, visible on hover */}
      {onDelete && (
        <button
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onDelete();
          }}
          title={t("home.quick_links_remove")}
          className="absolute right-2 top-2 hidden rounded-full p-0.5 text-gray-400 hover:bg-red-100 hover:text-red-600 group-hover:flex dark:hover:bg-red-900/40 dark:hover:text-red-400"
        >
          <i className="ti ti-x text-sm" />
        </button>
      )}

      {/* Icon */}
      <a
        href={tile.url}
        target="_blank"
        rel="noopener noreferrer"
        draggable={false}
        onClick={(e) => e.stopPropagation()}
        className="flex flex-col items-center gap-2 text-inherit no-underline"
      >
        <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-teal-500 to-teal-700 text-white shadow-sm">
          <i className={`ti ${tile.icon || "ti-link"} text-2xl`} />
        </span>

        {/* Title */}
        <span className="line-clamp-2 text-sm font-medium text-gray-800 dark:text-gray-100">
          {tile.title}
        </span>

        {/* Description */}
        {tile.description && (
          <span className="line-clamp-1 text-xs text-gray-400 dark:text-gray-500">
            {tile.description}
          </span>
        )}
      </a>
    </div>
  );
}

// ---- Main grid component ----------------------------------------------------

export function QuickLinksGrid({
  initialTiles,
  token,
}: {
  initialTiles: Tile[];
  token: string;
}) {
  const { t } = useTranslation();
  const [tiles, setTiles] = useState<Tile[]>(initialTiles);
  const [showAdd, setShowAdd] = useState(false);
  const dragSrcIdx = useRef<number | null>(null);
  const [draggingIdx, setDraggingIdx] = useState<number | null>(null);
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null);

  // Persist order to backend (fire-and-forget; optimistic UI).
  const persistOrder = useCallback(
    (ordered: Tile[]) => {
      const refs = ordered.map((t) => ({ type: t.type, id: t.id }));
      saveOrder(token, refs).catch(() => {
        // Silent failure: the grid already reflects the new visual order.
        // The saved order is authoritative only on next page load.
      });
    },
    [token]
  );

  function handleDragStart(idx: number) {
    dragSrcIdx.current = idx;
    setDraggingIdx(idx);
  }

  function handleDragEnter(idx: number) {
    setDragOverIdx(idx);
  }

  function handleDragEnd() {
    dragSrcIdx.current = null;
    setDraggingIdx(null);
    setDragOverIdx(null);
  }

  function handleDrop(targetIdx: number) {
    const srcIdx = dragSrcIdx.current;
    if (srcIdx === null || srcIdx === targetIdx) return;
    const next = [...tiles];
    const [moved] = next.splice(srcIdx, 1);
    next.splice(targetIdx, 0, moved);
    setTiles(next);
    persistOrder(next);
    dragSrcIdx.current = null;
    setDraggingIdx(null);
    setDragOverIdx(null);
  }

  async function handleDelete(tile: Tile) {
    try {
      await deleteUserQuickLink(token, tile.id);
      setTiles((prev) => prev.filter((t) => t.id !== tile.id));
    } catch {
      // ignore — tile remains visible
    }
  }

  function handleTileAdded(newTile: Tile) {
    setTiles((prev) => [...prev, newTile]);
    persistOrder([...tiles, newTile]);
  }

  return (
    <div>
      {/* Grid */}
      <div className="grid grid-cols-3 gap-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-6">
        {tiles.map((tile, idx) => (
          <TileCard
            key={tileKey(tile)}
            tile={tile}
            dragging={draggingIdx === idx}
            dragOver={dragOverIdx === idx && draggingIdx !== idx}
            onDragStart={() => handleDragStart(idx)}
            onDragEnter={() => handleDragEnter(idx)}
            onDragEnd={handleDragEnd}
            onDrop={() => handleDrop(idx)}
            onDelete={tile.type === "user" ? () => handleDelete(tile) : undefined}
          />
        ))}

        {/* Add-tile button */}
        <button
          onClick={() => setShowAdd(true)}
          className="flex flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-gray-300 p-4 text-gray-400 transition-colors hover:border-teal-400 hover:text-teal-600 dark:border-gray-600 dark:hover:border-teal-500 dark:hover:text-teal-400"
        >
          <i className="ti ti-plus text-2xl" />
          <span className="text-xs font-medium">{t("home.quick_links_add")}</span>
        </button>
      </div>

      {/* Empty state */}
      {tiles.length === 0 && (
        <p className="mt-2 text-sm text-gray-400 dark:text-gray-500">
          {t("home.quick_links_empty")}
        </p>
      )}

      {showAdd && (
        <AddTileModal
          token={token}
          onClose={() => setShowAdd(false)}
          onAdded={handleTileAdded}
        />
      )}
    </div>
  );
}
