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
  registerNode,
  isDragSource,
  isDragTarget,
  dragOffset,
  onPointerDownTile,
  onPointerMoveTile,
  onPointerEndTile,
  onDelete,
}: {
  tile: Tile;
  registerNode: (node: HTMLDivElement | null) => void;
  isDragSource: boolean;
  isDragTarget: boolean;
  dragOffset: { x: number; y: number } | null;
  onPointerDownTile: (e: React.PointerEvent<HTMLDivElement>) => void;
  onPointerMoveTile: (e: React.PointerEvent<HTMLDivElement>) => void;
  onPointerEndTile: (e: React.PointerEvent<HTMLDivElement>) => void;
  onDelete?: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div
      ref={registerNode}
      onPointerDown={onPointerDownTile}
      onPointerMove={onPointerMoveTile}
      onPointerUp={onPointerEndTile}
      onPointerCancel={onPointerEndTile}
      // touch-none: the trade-off this makes is that a scroll gesture
      // starting exactly on top of a tile no longer scrolls the page (see
      // QuickLinksGrid's drag-state doc comment for the full reasoning) -
      // accepted since the grid has gaps between tiles and the rest of the
      // page to scroll from instead.
      className={[
        "group relative flex touch-none cursor-grab flex-col items-center gap-2 rounded-2xl border p-4 text-center",
        "transition-shadow duration-150 select-none",
        "hover:shadow-md",
        isDragSource
          ? "z-50 shadow-xl"
          : isDragTarget
            ? "border-teal-400 bg-teal-50 dark:border-teal-500 dark:bg-teal-950/30"
            : "border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800",
      ].join(" ")}
      style={
        isDragSource && dragOffset
          ? {
              transform: `translate(${dragOffset.x}px, ${dragOffset.y}px) scale(1.06)`,
              opacity: 0.92,
            }
          : undefined
      }
    >
      {/* Delete button — only on user tiles. Always rendered (not
          hover-gated): a pure `hidden group-hover:flex` pair depends on a
          :hover state that touch devices (iPhone, tablet - reported
          2026-07-08) never reliably enter, which made this button
          effectively unreachable there - no mouse ever "hovers" a finger
          tap. Kept visually subtle at rest (faint, no background) so it
          doesn't clutter the tile on desktop either, then goes fully
          opaque/red on hover for the same discoverability desktop had
          before. Dragging the tile onto the trash drop zone (below) is the
          second, touch-friendly way to delete - see QuickLinksGrid. */}
      {onDelete && (
        <button
          onPointerDown={(e) => e.stopPropagation()}
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
//
// Drag-and-drop (reorder + drag-to-delete) runs entirely on Pointer Events
// instead of HTML5 native `draggable`. Native DnD has no touch equivalent at
// all on iOS/Android - the earlier `draggable`/onDragStart/onDrop
// implementation reordered fine with a mouse but was completely inert to a
// finger, which is also why the delete "x" (originally hover-only, itself
// unreachable via touch) had no working fallback either. Pointer Events
// unify mouse/touch/pen into one model, so one implementation now drives
// both, plus the drag-to-trash gesture requested 2026-07-08 as the primary
// mobile delete path.
//
// Mouse vs touch/pen start differently:
//   - mouse: a drag begins as soon as the pointer moves past
//     DRAG_MOVE_THRESHOLD px - matches how the old native DnD felt.
//   - touch/pen: a drag only begins after holding still for TOUCH_HOLD_MS -
//     without this, every ordinary tap-to-open or page-scroll gesture that
//     happens to start on a tile would be hijacked into a reorder attempt.
//     Moving more than TOUCH_HOLD_TOLERANCE px before the hold timer fires
//     cancels the drag attempt outright (it was a scroll/tap, not a hold).
//
// Hit-testing (which tile the pointer is currently over, and whether it's
// over the trash zone) is done by comparing pointer coordinates against
// each tile's live getBoundingClientRect() - not the more common
// document.elementFromPoint(), since that would return the dragged tile
// itself (it's the topmost element under the pointer) rather than whatever
// is underneath it.

const DRAG_MOVE_THRESHOLD = 6; // px - mouse: how far before a click becomes a drag
const TOUCH_HOLD_MS = 300; // touch/pen: how long to hold before a drag starts
const TOUCH_HOLD_TOLERANCE = 10; // px of wiggle room allowed during the hold

interface DragState {
  idx: number;
  pointerId: number;
  startX: number;
  startY: number;
  x: number;
  y: number;
  // false until the mouse threshold is crossed or the touch hold timer
  // fires - a gesture that never reaches `active` never reorders or
  // deletes anything, and never called preventDefault, so it falls
  // through to the browser's own tap/scroll handling untouched.
  active: boolean;
}

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

  const [drag, setDrag] = useState<DragState | null>(null);
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null);
  const [overTrash, setOverTrash] = useState(false);
  const tileNodes = useRef<Map<number, HTMLDivElement>>(new Map());
  const trashNode = useRef<HTMLDivElement | null>(null);
  const holdTimer = useRef<number | null>(null);

  function clearHoldTimer() {
    if (holdTimer.current !== null) {
      window.clearTimeout(holdTimer.current);
      holdTimer.current = null;
    }
  }

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

  // Recomputes dragOverIdx (which tile, if any, the pointer currently sits
  // over) and overTrash (whether it sits over the trash drop zone - only
  // meaningful for a deletable "user" tile, since the trash zone doesn't
  // even render for the other kinds - see its JSX below).
  function updateHitTargets(d: DragState) {
    let overIdx: number | null = null;
    tileNodes.current.forEach((node, i) => {
      if (i === d.idx) return;
      const r = node.getBoundingClientRect();
      if (d.x >= r.left && d.x <= r.right && d.y >= r.top && d.y <= r.bottom) {
        overIdx = i;
      }
    });
    setDragOverIdx(overIdx);

    const draggedTile = tiles[d.idx];
    if (draggedTile?.type === "user" && trashNode.current) {
      const r = trashNode.current.getBoundingClientRect();
      setOverTrash(d.x >= r.left && d.x <= r.right && d.y >= r.top && d.y <= r.bottom);
    } else {
      setOverTrash(false);
    }
  }

  function handleTileDragStart(idx: number, e: React.PointerEvent<HTMLDivElement>) {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    setDrag({
      idx,
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      x: e.clientX,
      y: e.clientY,
      active: false,
    });
    if (e.pointerType !== "mouse") {
      const pointerId = e.pointerId;
      holdTimer.current = window.setTimeout(() => {
        setDrag((d) => (d && d.pointerId === pointerId ? { ...d, active: true } : d));
      }, TOUCH_HOLD_MS);
    }
  }

  function handleTileDragMove(e: React.PointerEvent<HTMLDivElement>) {
    if (!drag || drag.pointerId !== e.pointerId) return;
    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;

    if (!drag.active) {
      if (e.pointerType === "mouse") {
        if (Math.hypot(dx, dy) < DRAG_MOVE_THRESHOLD) {
          setDrag({ ...drag, x: e.clientX, y: e.clientY });
          return;
        }
        setDrag({ ...drag, x: e.clientX, y: e.clientY, active: true });
        return;
      }
      // touch/pen: still waiting on the hold timer. Moving too far before
      // it fires means this was a scroll/tap, not a hold - bail out
      // entirely instead of dragging.
      if (Math.hypot(dx, dy) > TOUCH_HOLD_TOLERANCE) {
        clearHoldTimer();
        setDrag(null);
        return;
      }
      setDrag({ ...drag, x: e.clientX, y: e.clientY });
      return;
    }

    e.preventDefault();
    const next = { ...drag, x: e.clientX, y: e.clientY };
    setDrag(next);
    updateHitTargets(next);
  }

  function handleTileDragEnd(e: React.PointerEvent<HTMLDivElement>) {
    clearHoldTimer();
    if (drag && drag.pointerId === e.pointerId) {
      if (drag.active) {
        const draggedTile = tiles[drag.idx];
        if (overTrash && draggedTile?.type === "user") {
          handleDelete(draggedTile);
        } else if (dragOverIdx !== null && dragOverIdx !== drag.idx) {
          const next = [...tiles];
          const [moved] = next.splice(drag.idx, 1);
          next.splice(dragOverIdx, 0, moved);
          setTiles(next);
          persistOrder(next);
        }
      }
      try {
        e.currentTarget.releasePointerCapture(e.pointerId);
      } catch {
        // Already released (e.g. pointercancel beat us here) - fine to ignore.
      }
    }
    setDrag(null);
    setDragOverIdx(null);
    setOverTrash(false);
  }

  const showTrash = !!drag?.active && tiles[drag.idx]?.type === "user";

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
            registerNode={(node) => {
              if (node) tileNodes.current.set(idx, node);
              else tileNodes.current.delete(idx);
            }}
            isDragSource={drag?.active === true && drag.idx === idx}
            isDragTarget={dragOverIdx === idx && drag?.idx !== idx}
            dragOffset={
              drag?.active && drag.idx === idx
                ? { x: drag.x - drag.startX, y: drag.y - drag.startY }
                : null
            }
            onPointerDownTile={(e) => handleTileDragStart(idx, e)}
            onPointerMoveTile={handleTileDragMove}
            onPointerEndTile={handleTileDragEnd}
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

      {/* Trash drop zone - fixed above the app footer, only while actively
          dragging a deletable ("user") tile. Positioned above
          AppShell.tsx's 44px footer bar (bottom-[44px] elsewhere in this
          codebase) plus a gap, so it never sits under it. */}
      {showTrash && (
        <div
          ref={trashNode}
          role="img"
          aria-label={t("home.quick_links_remove")}
          className={`fixed bottom-[64px] left-1/2 z-50 flex h-16 w-16 -translate-x-1/2 items-center justify-center rounded-full border-2 shadow-lg transition-transform ${
            overTrash
              ? "scale-110 border-red-500 bg-red-500 text-white"
              : "border-red-300 bg-white text-red-500 dark:border-red-800 dark:bg-gray-900"
          }`}
        >
          <i className="ti ti-trash text-2xl" aria-hidden="true" />
        </div>
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
