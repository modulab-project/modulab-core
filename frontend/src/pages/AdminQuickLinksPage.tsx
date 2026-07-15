import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { useAuthenticatedSession } from "../lib/useSession";
import { AppShell } from "../components/AppShell";
import { isAdminRole } from "../lib/roles";
import {
  type AdminTile,
  createAdminQuickLink,
  deleteAdminQuickLink,
  listAdminQuickLinks,
  updateAdminQuickLink,
} from "../lib/quicklinks";
import { listInstalledModules, type InstalledModule } from "../lib/api";
import { ACTIVE_MODULES_QUERY_KEY } from "../lib/queryKeys";

function moduleDisplayName(mod: InstalledModule, lang: string): string {
  const mf = mod.manifest as { display_name?: Record<string, string>; name?: string } | null;
  return mf?.display_name?.[lang] ?? mf?.display_name?.["en"] ?? mf?.name ?? mod.name;
}
function moduleIcon(mod: InstalledModule): string {
  const mf = mod.manifest as { icon?: string } | null;
  return mf?.icon ?? "ti-puzzle";
}

// ---- Edit / Create form -----------------------------------------------------

type FormMode = "url" | "module";

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
  const { t, i18n } = useTranslation();
  const lang = i18n.language?.slice(0, 2) ?? "en";

  // When editing an existing tile that points to a module path, start in module mode.
  const initialMode: FormMode =
    !initial || initial.url.startsWith("/modules/") ? "url" : "url";
  const [mode, setMode] = useState<FormMode>(initialMode);

  const [title, setTitle] = useState(initial?.title ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [icon, setIcon] = useState(initial?.icon ?? "ti-link");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [sortOrder, setSortOrder] = useState(initial?.sort_order ?? 0);

  const [selectedModule, setSelectedModule] = useState<InstalledModule | null>(null);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const { data: modules = [], isLoading: modulesLoading } = useQuery({
    queryKey: ACTIVE_MODULES_QUERY_KEY,
    queryFn: async () => {
      const mods = await listInstalledModules();
      return mods.filter((m) => m.status === "active");
    },
    enabled: mode === "module",
  });

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");

    let data: { title: string; url: string; icon: string; description: string; sort_order: number };

    if (mode === "module") {
      if (!selectedModule) {
        setError(t("home.quick_links_module_required"));
        setSaving(false);
        return;
      }
      data = {
        title: moduleDisplayName(selectedModule, lang),
        url: `/modules/${encodeURIComponent(selectedModule.name)}`,
        icon: moduleIcon(selectedModule),
        description: "",
        sort_order: sortOrder,
      };
    } else {
      if (!title.trim() || !url.trim()) { setSaving(false); return; }
      data = { title, url, icon, description, sort_order: sortOrder };
    }

    try {
      await onSave(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("admin.quick_links.form.error"));
    } finally {
      setSaving(false);
    }
  }

  const tabCls = (active: boolean) =>
    `flex-1 py-1.5 text-xs font-medium rounded-lg transition-colors ${
      active
        ? "bg-white shadow-sm text-gray-900 dark:bg-gray-800 dark:text-gray-100"
        : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
    }`;

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      {/* Mode toggle — only shown when creating */}
      {!initial && (
        <div className="flex rounded-xl bg-gray-100 p-1 dark:bg-gray-700/50">
          <button type="button" className={tabCls(mode === "url")} onClick={() => setMode("url")}>
            <i className="ti ti-link mr-1 text-[12px]" />{t("home.quick_links_mode_url")}
          </button>
          <button type="button" className={tabCls(mode === "module")} onClick={() => setMode("module")}>
            <i className="ti ti-puzzle mr-1 text-[12px]" />{t("home.quick_links_mode_module")}
          </button>
        </div>
      )}

      {mode === "module" && !initial ? (
        /* Module picker */
        <div>
          {modulesLoading ? (
            <p className="py-3 text-center text-xs text-gray-400">{t("home.quick_links_modules_loading")}</p>
          ) : modules.length === 0 ? (
            <p className="py-3 text-center text-xs text-gray-400">{t("home.quick_links_modules_empty")}</p>
          ) : (
            <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto">
              {modules.map((mod) => {
                const isSel = selectedModule?.name === mod.name;
                return (
                  <button
                    key={mod.name}
                    type="button"
                    onClick={() => setSelectedModule(isSel ? null : mod)}
                    className={`flex items-center gap-3 rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                      isSel
                        ? "border-teal-500 bg-teal-50 dark:border-teal-400 dark:bg-teal-950/40"
                        : "border-gray-200 hover:border-gray-300 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700"
                    }`}
                  >
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-teal-500 to-teal-700 text-white">
                      <i className={`ti ${moduleIcon(mod)} text-sm`} />
                    </span>
                    <span className="font-medium text-gray-800 dark:text-gray-100 text-sm">
                      {moduleDisplayName(mod, lang)}
                    </span>
                    {isSel && <i className="ti ti-check ml-auto text-teal-600 dark:text-teal-400" />}
                  </button>
                );
              })}
            </div>
          )}
          <div>
            <label className="mb-1 mt-2 block text-xs font-medium text-gray-600 dark:text-gray-400">
              {t("admin.quick_links.form.order_label")}
            </label>
            <input
              type="number"
              value={sortOrder}
              onChange={(e) => setSortOrder(Number(e.target.value))}
              className="w-24 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
        </div>
      ) : (
        /* URL form (existing or new URL tile) */
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
                {t("admin.quick_links.form.title_label")} *
              </label>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
                {t("admin.quick_links.form.url_label")} *
              </label>
              <input
                type="text"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder={t("admin.quick_links.form.url_placeholder")}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
                {t("admin.quick_links.form.icon_label")}{" "}
                <span className="text-gray-400">{t("admin.quick_links.form.icon_hint")}</span>
              </label>
              <div className="flex items-center gap-2">
                <i className={`ti ${icon || "ti-link"} text-xl text-teal-600 dark:text-teal-400`} />
                <input
                  type="text"
                  value={icon}
                  onChange={(e) => setIcon(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
                />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
                {t("admin.quick_links.form.order_label")}
              </label>
              <input
                type="number"
                value={sortOrder}
                onChange={(e) => setSortOrder(Number(e.target.value))}
                className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">
              {t("admin.quick_links.form.desc_label")}
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-base focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
            />
          </div>
        </>
      )}

      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-200 dark:hover:bg-gray-800"
        >
          {t("admin.quick_links.form.cancel")}
        </button>
        <button
          type="submit"
          disabled={saving || (mode === "module" && !initial && !selectedModule)}
          className="rounded-lg bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50 dark:bg-teal-500"
        >
          {saving
            ? t("admin.quick_links.form.saving")
            : initial
              ? t("admin.quick_links.form.save")
              : t("admin.quick_links.form.create")}
        </button>
      </div>
    </form>
  );
}

// ---- Page -------------------------------------------------------------------

export default function AdminQuickLinksPage() {
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
  const [links, setLinks] = useState<AdminTile[]>([]);
  const [fetching, setFetching] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    if (!isAdminRole(session.role)) {
      navigate("/", { replace: true });
      return;
    }
    listAdminQuickLinks()
      .then(setLinks)
      .catch(() => {})
      .finally(() => setFetching(false));
  }, [session, navigate]);

  if (loading || !session || fetching) return null;

  async function handleCreate(data: {
    title: string;
    url: string;
    icon: string;
    description: string;
    sort_order: number;
  }) {
    const created = await createAdminQuickLink(data);
    setLinks((prev) => [...prev, created]);
    setShowCreate(false);
  }

  async function handleUpdate(
    id: string,
    data: { title: string; url: string; icon: string; description: string; sort_order: number }
  ) {
    await updateAdminQuickLink(id, data);
    setLinks((prev) =>
      prev.map((l) => (l.id === id ? { ...l, ...data } : l))
    );
    setEditId(null);
  }

  async function handleDelete(id: string) {
    await deleteAdminQuickLink(id);
    setLinks((prev) => prev.filter((l) => l.id !== id));
  }

  return (
    <AppShell session={session}>
    <div className="mx-auto max-w-3xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
            {t("admin.quick_links.title")}
          </h1>
          <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
            {t("admin.quick_links.subtitle")}
          </p>
        </div>
        {!showCreate && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-teal-600 px-3 py-2 text-sm font-medium text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-400"
          >
            <i className="ti ti-plus" />
            {t("admin.quick_links.new_button")}
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="mb-6 rounded-2xl border border-teal-200 bg-teal-50/50 p-5 dark:border-teal-800 dark:bg-teal-950/20">
          <h2 className="mb-4 text-sm font-semibold text-gray-800 dark:text-gray-200">
            {t("admin.quick_links.new_tile")}
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
          {t("admin.quick_links.empty")}
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
                      title={t("admin.quick_links.edit_title")}
                      className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700 dark:hover:bg-gray-700 dark:hover:text-gray-200"
                    >
                      <i className="ti ti-pencil text-sm" />
                    </button>
                    <button
                      onClick={() => handleDelete(link.id)}
                      title={t("admin.quick_links.delete_title")}
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
