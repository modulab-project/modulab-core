// Built-in fallback UI for Tier 1 (config-driven CRUD) modules - see
// docs/tier1-crud-plan.md and backend/internal/modules/crud.go, which this
// is the frontend counterpart of. A Tier 1 module ships no ui/bundle.js at
// all (see ModulePage.tsx's bundle-load effect, which skips fetching one
// for tier === 1 modules); this component is rendered directly by Core
// instead, built purely from the installed module's manifest.crud metadata
// (table, fields, owner_scoped) - the module author writes no UI code.
//
// Talks to the generic CRUD API (backend/internal/modules/crud.go) via the
// same moduleApiFetch/module-scoped-token mechanism a real Tier 2/3 bundle
// would use - from the API's point of view this is just another module
// client, nothing special.
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { moduleApiFetch, type InstalledModule } from "../lib/api";

// Mirrors backend/internal/modules/installer.go's ManifestCrudField/
// ManifestCrud (the subset relevant to rendering - "encrypted" isn't
// needed client-side, the API already returns decrypted values).
interface CrudField {
  name: string;
  type: "string" | "text" | "integer" | "float" | "boolean" | "date" | "datetime" | "uuid";
  required?: boolean;
}

interface CrudManifest {
  table: string;
  fields: CrudField[];
  owner_scoped?: boolean;
}

type CrudRow = Record<string, unknown> & { id: string };

const inputClass =
  // text-[16px]: inputs must stay >=16px to avoid iOS Safari's auto-zoom on focus.
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-[16px] dark:border-gray-700 dark:bg-gray-800";

export function CrudModuleView({ mod, token }: { mod: InstalledModule; token: string }) {
  const { t } = useTranslation();
  const manifest = mod.manifest as { crud?: CrudManifest } | null;
  const crud = manifest?.crud;

  const [rows, setRows] = useState<CrudRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<CrudRow | "create" | null>(null);
  const [formValues, setFormValues] = useState<Record<string, string | boolean>>({});
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!crud) return;
    setLoading(true);
    setError(null);
    try {
      const data = await moduleApiFetch<CrudRow[]>(token, mod.name, `/${crud.table}`);
      setRows(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, mod.name, crud?.table]);

  useEffect(() => {
    // load() sets loading/error state synchronously before its first await
    // (the fetch itself) - same class of "fetch on mount/dependency change"
    // effect as ModulePage.tsx's metadata/bundle-load effects, which
    // suppress this identically rather than restructure a standard,
    // harmless fetch-on-mount pattern.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [load]);

  if (!crud) {
    // Should not happen for an actual Tier 1 module (validateManifestTier
    // requires crud) - defensive only, e.g. a manifest fetched before it
    // fully synced.
    return (
      <p className="text-sm text-red-600 dark:text-red-400">{t("module_page.crud.no_manifest")}</p>
    );
  }

  function openCreate() {
    const initial: Record<string, string | boolean> = {};
    for (const f of crud!.fields) initial[f.name] = f.type === "boolean" ? false : "";
    setFormValues(initial);
    setEditing("create");
  }

  function openEdit(row: CrudRow) {
    const initial: Record<string, string | boolean> = {};
    for (const f of crud!.fields) {
      const v = row[f.name];
      if (f.type === "boolean") {
        initial[f.name] = Boolean(v);
      } else if (f.type === "datetime" && typeof v === "string") {
        // Backend returns RFC3339 (e.g. "2026-07-18T14:30:00Z"); <input
        // type="datetime-local"> needs "YYYY-MM-DDTHH:mm" with no zone.
        initial[f.name] = v.slice(0, 16);
      } else {
        initial[f.name] = v == null ? "" : String(v);
      }
    }
    setFormValues(initial);
    setEditing(row);
  }

  function closeForm() {
    setEditing(null);
  }

  async function handleSave() {
    if (!crud) return;
    setSaving(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {};
      for (const f of crud.fields) {
        const raw = formValues[f.name];
        if (f.type === "boolean") {
          body[f.name] = Boolean(raw);
          continue;
        }
        if (raw === "" || raw === undefined) {
          if (f.required) {
            throw new Error(t("module_page.crud.field_required", { field: f.name }));
          }
          continue; // omit: server keeps existing value on PATCH, skips on POST
        }
        if (f.type === "integer") body[f.name] = parseInt(String(raw), 10);
        else if (f.type === "float") body[f.name] = parseFloat(String(raw));
        else if (f.type === "datetime") body[f.name] = new Date(String(raw)).toISOString();
        else body[f.name] = raw;
      }

      if (editing === "create") {
        await moduleApiFetch(token, mod.name, `/${crud.table}`, {
          method: "POST",
          body: JSON.stringify(body),
        });
      } else if (editing) {
        await moduleApiFetch(token, mod.name, `/${crud.table}/${editing.id}`, {
          method: "PATCH",
          body: JSON.stringify(body),
        });
      }
      closeForm();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(row: CrudRow) {
    if (!crud) return;
    if (!window.confirm(t("module_page.crud.confirm_delete"))) return;
    setError(null);
    try {
      await moduleApiFetch(token, mod.name, `/${crud.table}/${row.id}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold capitalize">{mod.name}</h1>
        <button
          onClick={openCreate}
          className="rounded-full bg-teal-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-teal-700"
        >
          {t("module_page.crud.add")}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
          {error}
        </div>
      )}

      {loading && <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>}

      {!loading && rows.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400">{t("module_page.crud.empty")}</p>
      )}

      {!loading && rows.length > 0 && (
        <div className="overflow-x-auto rounded-2xl border border-gray-200 dark:border-gray-800">
          <table className="min-w-full divide-y divide-gray-200 text-sm dark:divide-gray-800">
            <thead>
              <tr className="text-left text-gray-500 dark:text-gray-400">
                {crud.fields.map((f) => (
                  <th key={f.name} className="whitespace-nowrap px-4 py-2 font-medium capitalize">
                    {f.name}
                  </th>
                ))}
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {rows.map((row) => (
                <tr key={String(row.id)}>
                  {crud.fields.map((f) => (
                    <td key={f.name} className="px-4 py-2">
                      {f.type === "boolean" ? (row[f.name] ? "✓" : "") : String(row[f.name] ?? "")}
                    </td>
                  ))}
                  <td className="whitespace-nowrap px-4 py-2 text-right">
                    <button
                      onClick={() => openEdit(row)}
                      className="mr-3 text-teal-600 hover:underline dark:text-teal-400"
                    >
                      {t("module_page.crud.edit")}
                    </button>
                    <button
                      onClick={() => handleDelete(row)}
                      className="text-red-600 hover:underline dark:text-red-400"
                    >
                      {t("module_page.crud.delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-md rounded-2xl bg-white p-6 dark:bg-gray-900">
            <h2 className="mb-4 text-lg font-semibold">
              {editing === "create" ? t("module_page.crud.add") : t("module_page.crud.edit")}
            </h2>
            <div className="space-y-3">
              {crud.fields.map((f) => (
                <label key={f.name} className="block text-sm">
                  <span className="mb-1 block font-medium capitalize text-gray-700 dark:text-gray-300">
                    {f.name}
                    {f.required && <span className="text-red-500"> *</span>}
                  </span>
                  <CrudFieldInput
                    field={f}
                    value={formValues[f.name]}
                    onChange={(v) => setFormValues((prev) => ({ ...prev, [f.name]: v }))}
                  />
                </label>
              ))}
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button
                onClick={closeForm}
                className="rounded-full px-4 py-1.5 text-sm text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                {t("module_page.crud.cancel")}
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="rounded-full bg-teal-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
              >
                {t("module_page.crud.save")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CrudFieldInput({
  field,
  value,
  onChange,
}: {
  field: CrudField;
  value: string | boolean | undefined;
  onChange: (v: string | boolean) => void;
}) {
  const strValue = typeof value === "string" ? value : "";

  switch (field.type) {
    case "text":
      return (
        <textarea
          value={strValue}
          onChange={(e) => onChange(e.target.value)}
          rows={3}
          className={inputClass}
        />
      );
    case "boolean":
      return (
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
          className="h-4 w-4 rounded border-gray-300"
        />
      );
    case "integer":
      return (
        <input
          type="number"
          step="1"
          value={strValue}
          onChange={(e) => onChange(e.target.value)}
          className={inputClass}
        />
      );
    case "float":
      return (
        <input
          type="number"
          step="any"
          value={strValue}
          onChange={(e) => onChange(e.target.value)}
          className={inputClass}
        />
      );
    case "date":
      return (
        <input
          type="date"
          value={strValue}
          onChange={(e) => onChange(e.target.value)}
          className={inputClass}
        />
      );
    case "datetime":
      return (
        <input
          type="datetime-local"
          value={strValue}
          onChange={(e) => onChange(e.target.value)}
          className={inputClass}
        />
      );
    case "uuid":
    case "string":
    default:
      return (
        <input type="text" value={strValue} onChange={(e) => onChange(e.target.value)} className={inputClass} />
      );
  }
}
