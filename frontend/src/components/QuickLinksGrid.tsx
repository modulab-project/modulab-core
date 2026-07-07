import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Tile } from "../lib/quicklinks";
import { createUserQuickLink, deleteUserQuickLink, saveOrder } from "../lib/quicklinks";
import { listInstalledModules, type InstalledModule } from "../lib/api";
import { safeHref } from "../lib/url";

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

// ---- Helpers ----------------------------------------------------------------

function moduleDisplayName(mod: InstalledModule, lang: string): string {
  const mf = mod.manifest as { display_name?: Record<string, string>; name?: string } | null;
  return mf?.display_name?.[lang] ?? mf?.display_name?.["en"] ?? mf?.name ?? mod.name;
}

function moduleIcon(mod: InstalledModule): string {
  const mf = mod.manifest as { icon?: string } | null;
  return mf?.icon ?? "ti-puzzle";
}

// ---- Add-tile modal ---------------------------------------------------------

type AddMode = "url" | "module";

function AddTileModal({
  token,
  onClose,
  onAdded,
}: {
  token: string;
  onClose: () => void;
  onAdded: (tile: Tile) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language?.slice(0, 2) ?? "en";

  const [mode, setMode] = useState<AddMode>("url");

  // URL-mode fields
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [icon, setIcon] = useState("ti-link");
  const [description, setDescription] = useState("");

  // Module-mode
  const [modules, setModules] = useState<InstalledModule[]>([]);
  const [modulesLoading, setModulesLoading] = useState(false);
  const [selectedModule, setSelectedModule] = useState<InstalledModule | null>(null);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  // Load modules when switching to module mode.
  useEffect(() => {
    if (mode !== "module" || modules.length > 0) return;
    setModulesLoading(true);
    listInstalledModules(token)
      .then((mods) => setModules(mods.filter((m) => m.status === "active")))
      .catch(() => {})
      .finally(() => setModulesLoading(false));
  }, [mode, token, modules.length]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");

    let body: { title: string; url: string; icon: string; description: string };

    if (mode === "module") {
      if (!selectedModule) {
        setError(t("home.quick_links_module_required"));
        setSaving(false);
        return;
      }
      body = {
        title: moduleDisplayName(selectedModule, lang),
        url: `/modules/${encodeURIComponent(selectedModule.name)}`,
        icon: moduleIcon(selectedModule),
        description: "",
      };
    } else {
      if (!title.trim() || !url.trim()) {
        setSaving(false);
        return;
      }
      body = { title, url, icon, description };
    }

    try {
      const newTile = await createUserQuickLink(token, body);
      onAdded(newTile);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("home.quick_links_error"));
    } finally {
      setSaving(false);
    }
  }

  const tabCls = (active: boolean) =>
    `flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${
      active
        ? "bg-white shadow-sm text-gray-900 dark:bg-gray-800 dark:text-gray-100"
        : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
    }`;

  return (
    // Click-outside-to-close backdrop; the inner div below only stops
    // propagation so clicking the dialog itself doesn't also close it -
    // neither has real keyboard-actionable semantics of its own.
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={onClose}
    >
      {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions */}
      <div
        className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-gray-700 dark:bg-gray-900"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-gray-100">
          {t("home.quick_links_add_modal_title")}
        </h2>

        {/* Mode toggle */}
        <div className="mb-4 flex rounded-xl bg-gray-100 p-1 dark:bg-gray-800">
          <button type="button" className={tabCls(mode === "url")} onClick={() => setMode("url")}>
            <i className="ti ti-link mr-1.5 text-[13px]" />
            {t("home.quick_links_mode_url")}
          </button>
          <button type="button" className={tabCls(mode === "module")} onClick={() => setMode("module")}>
            <i className="ti ti-puzzle mr-1.5 text-[13px]" />
            {t("home.quick_links_mode_module")}
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === "url" ? (
            <>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {t("home.quick_links_tile_title")} *
                </label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
                  placeholder={t("home.quick_links_tile_title_placeholder")}
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
                  className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
                  placeholder="https://cloud.example.com"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {t("home.quick_links_tile_icon")}{" "}
                  <span className="text-gray-400">(Tabler, z. B. ti-cloud)</span>
                </label>
                <input
                  type="text"
                  value={icon}
                  onChange={(e) => setIcon(e.target.value)}
                  className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
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
                  className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
                />
              </div>
            </>
          ) : (
            <div>
              {modulesLoading ? (
                <p className="py-4 text-center text-sm text-gray-400">{t("home.quick_links_modules_loading")}</p>
              ) : modules.length === 0 ? (
                <p className="py-4 text-center text-sm text-gray-400">{t("home.quick_links_modules_empty")}</p>
              ) : (
                <div className="flex flex-col gap-1.5 max-h-64 overflow-y-auto">
                  {modules.map((mod) => {
                    const isSelected = selectedModule?.name === mod.name;
                    return (
                      <button
                        key={mod.name}
                        type="button"
                        onClick={() => setSelectedModule(isSelected ? null : mod)}
                        className={`flex items-center gap-3 rounded-xl border px-3 py-2.5 text-left text-sm transition-colors ${
                          isSelected
                            ? "border-teal-500 bg-teal-50 dark:border-teal-400 dark:bg-teal-950/40"
                            : "border-gray-200 hover:border-gray-300 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-800"
                        }`}
                      >
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-teal-500 to-teal-700 text-white">
                          <i className={`ti ${moduleIcon(mod)} text-base`} />
                        </span>
                        <span className="font-medium text-gray-800 dark:text-gray-100">
                          {moduleDisplayName(mod, lang)}
                        </span>
                        {isSelected && (
                          <i className="ti ti-check ml-auto text-teal-600 dark:text-teal-400" />
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}

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
              disabled={saving || (mode === "module" && !selectedModule)}
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

function TileIcon({ tile }: { tile: Tile }) {
  const [failed, setFailed] = useState(false);

  let faviconUrl: string | null = null;
  try {
    faviconUrl = new URL(tile.url).origin + "/favicon.ico";
  } catch {
    // invalid URL — fall through to Tabler icon
  }

  if (faviconUrl && !failed) {
    return (
      <span className="flex h-12 w-12 items-center justify-center rounded-xl border border-gray-200 bg-white p-1.5 shadow-sm dark:border-gray-700 dark:bg-gray-900">
        <img
          src={faviconUrl}
          alt=""
          onError={() => setFailed(true)}
          className="h-full w-full object-contain"
        />
      </span>
    );
  }

  return (
    <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-teal-500 to-teal-700 text-white shadow-sm">
      <i className={`ti ${tile.icon || "ti-link"} text-2xl`} />
    </span>
  );
}

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
      {/* Delete button — only on user tiles. Always rendered (not
          hover-gated): a pure `hidden group-hover:flex` pair depends on a
          :hover state that touch devices (iPhone, tablet - reported
          2026-07-08) never reliably enter, which made this button
          effectively unreachable there - no mouse ever "hovers" a finger
          tap. Kept visually subtle at rest (faint, no background) so it
          doesn't clutter the tile on desktop either, then goes fully
          opaque/red on hover for the same discoverability desktop had
          before. */}
      {onDelete && (
        <button
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onDelete();
          }}
          title={t("home.quick_links_remove")}
          aria-label={t("home.quick_links_remove")}
          className="absolute right-2 top-2 flex rounded-full p-0.5 text-gray-400/70 hover:bg-red-100 hover:text-red-600 dark:text-gray-500/70 dark:hover:bg-red-900/40 dark:hover:text-red-400"
        >
          <i className="ti ti-x text-sm" />
        </button>
      )}

      {/* Icon — internal module paths open in same tab, external URLs in new tab */}
      <a
        href={safeHref(tile.url)}
        target={tile.url.startsWith("/") ? "_self" : "_blank"}
        rel={tile.url.startsWith("/") ? undefined : "noopener noreferrer"}
        draggable={false}
        onClick={(e) => e.stopPropagation()}
        className="flex flex-col items-center gap-2 text-inherit no-underline"
      >
        <TileIcon tile={tile} />

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
  const [reorderError, setReorderError] = useState(false);
  const [deleteError, setDeleteError] = useState(false);

  // Sync when the parent delivers fetched tiles after first render.
  useEffect(() => {
    setTiles(initialTiles);
  }, [initialTiles]);
  const dragSrcIdx = useRef<number | null>(null);
  const [draggingIdx, setDraggingIdx] = useState<number | null>(null);
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null);

  // Persist order to backend (fire-and-forget; optimistic UI).
  const persistOrder = useCallback(
    (ordered: Tile[]) => {
      const refs = ordered.map((t) => ({ type: t.type, id: t.id }));
      setReorderError(false);
      saveOrder(token, refs).catch(() => {
        // The grid already reflects the new visual order optimistically -
        // but if the server never got it, the next page load silently
        // reverts to the old order with no explanation. Surfaced instead
        // of swallowed so the user knows to retry rather than assuming the
        // reorder just worked.
        setReorderError(true);
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
    setDeleteError(false);
    try {
      await deleteUserQuickLink(token, tile.id);
      setTiles((prev) => prev.filter((t) => t.id !== tile.id));
    } catch {
      // Tile remains visible - surfaced so the user knows the click
      // didn't silently do nothing.
      setDeleteError(true);
    }
  }

  function handleTileAdded(newTile: Tile) {
    setTiles((prev) => [...prev, newTile]);
    persistOrder([...tiles, newTile]);
  }

  return (
    <div>
      {(reorderError || deleteError) && (
        <p className="mb-2 text-sm text-red-600 dark:text-red-400">
          {reorderError
            ? t("home.quick_links_reorder_failed")
            : t("home.quick_links_delete_failed")}
        </p>
      )}
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
