// ModulePage renders the UI for any installed Tier 2/3 module.
// The module's React component (built as ui/bundle.js) is loaded dynamically
// and mounted inside an AppShell so it gets the same header/navigation as
// the rest of ModuLab.
//
// Communication between the host and the module component:
//   - The session token is passed as a prop (ModuleComponentProps) so the
//     module can call its own /v1/modules/{name}/api/* endpoints.
//   - The module component is responsible for its own data fetching.
//
// For v1 (no external bundle yet), a fallback is shown when no bundle is found.
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import i18n from "../lib/i18n";
import { getSessionToken } from "../lib/session";
import { useAuthenticatedSession } from "../lib/useSession";
import { moduleApiUrl, type InstalledModule } from "../lib/api";
import { AppShell } from "../components/AppShell";

// Props the host passes to every module component.
export interface ModuleComponentProps {
  moduleName: string;
  apiBase: string;       // full URL prefix for /v1/modules/{name}/api
  token: string;
}

export default function ModulePage() {
  const { moduleName } = useParams<{ moduleName: string }>();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();

  const [mod, setMod] = useState<InstalledModule | null>(null);
  const [ModuleComponent, setModuleComponent] = useState<React.ComponentType<ModuleComponentProps> | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(true);

  // Fetch module metadata
  useEffect(() => {
    if (!session || !moduleName) return;
    const token = getSessionToken();
    if (!token) return;

    fetch(`/v1/modules/${encodeURIComponent(moduleName)}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<InstalledModule>;
      })
      .then((m) => {
        setMod(m);
        if (m.status !== "active") {
          setLoadError(t("module_page.not_active", { status: m.status }));
        }
      })
      .catch((e) => setLoadError(String(e)))
      .finally(() => setFetching(false));
  }, [session, moduleName, t]);

  // Load the module's own locale files and register them in i18next under the
  // "mod_{name}" namespace. This runs before the bundle is imported so that
  // the module component can call useTranslation("mod_{name}") immediately.
  useEffect(() => {
    if (!mod || mod.status !== "active") return;
    const token = getSessionToken();
    if (!token) return;

    const ns = `mod_${mod.name}`;
    const lng = i18n.language?.slice(0, 2) ?? "en"; // "en-US" → "en"
    const fallback = "en";

    async function loadLocale(language: string): Promise<Record<string, unknown> | null> {
      try {
        const r = await fetch(`/v1/modules/${encodeURIComponent(mod!.name)}/locales/${language}.json`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!r.ok) return null;
        return r.json();
      } catch {
        return null;
      }
    }

    (async () => {
      // Always load the fallback (en) first, then overlay the active language.
      const [fbData, lngData] = await Promise.all([
        loadLocale(fallback),
        lng !== fallback ? loadLocale(lng) : Promise.resolve(null),
      ]);
      if (fbData) i18n.addResourceBundle(fallback, ns, fbData, true, true);
      if (lngData) i18n.addResourceBundle(lng, ns, lngData, true, true);
    })();
  }, [mod]);

  // Dynamically import the module's UI bundle (ui/bundle.js served from Core's
  // static file path). If the bundle is absent (Tier 1 or not yet built),
  // we fall back to a placeholder.
  useEffect(() => {
    if (!mod || mod.status !== "active") return;

    // The bundle is served by Core at /modules/{name}/ui/bundle.js.
    // (Core's static file handler serves files from DataDir/{name}/ui/.)
    const bundleUrl = `/modules/${encodeURIComponent(mod.name)}/ui/bundle.js`;

    import(/* @vite-ignore */ bundleUrl)
      .then((m: { default?: React.ComponentType<ModuleComponentProps> }) => {
        if (m.default) {
          setModuleComponent(() => m.default!);
        } else {
          setLoadError(t("module_page.no_default_export"));
        }
      })
      .catch(() => {
        // No bundle — use built-in fallback (acceptable for Tier 1 or dev).
        setModuleComponent(null);
        setLoadError(null); // not an error, just no custom UI
      });
  }, [mod, t]);

  if (loading || !session) return null;
  if (!moduleName) {
    navigate("/", { replace: true });
    return null;
  }

  const token = getSessionToken() ?? "";
  const apiBase = moduleApiUrl(moduleName);

  return (
    <AppShell session={session}>
      <div className="mx-auto max-w-5xl py-6 px-2">
        {fetching && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}

        {loadError && (
          <div className="rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
            {loadError}
          </div>
        )}

        {!fetching && !loadError && ModuleComponent && (
          <ModuleComponent moduleName={moduleName} apiBase={apiBase} token={token} />
        )}

        {!fetching && !loadError && !ModuleComponent && mod && (
          <ModuleFallback mod={mod} apiBase={apiBase} token={token} />
        )}
      </div>
    </AppShell>
  );
}

// ── Built-in fallback UI ──────────────────────────────────────────────────────
// Shown when a module has no ui/bundle.js. Displays the module's name,
// description, and a JSON view of the /api/ root response.

function ModuleFallback({
  mod,
  apiBase,
}: {
  mod: InstalledModule;
  apiBase: string;
  token?: string;
}) {
  const { t } = useTranslation();
  const manifest = mod.manifest as {
    description?: string;
    version?: string;
    author?: string;
  } | null;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-semibold capitalize">{mod.name}</h1>
        {manifest?.description && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{manifest.description}</p>
        )}
        <div className="mt-2 flex flex-wrap gap-2">
          {manifest?.version && (
            <span className="rounded-full bg-gray-100 px-2.5 py-0.5 text-xs text-gray-500 dark:bg-gray-800 dark:text-gray-400">
              v{manifest.version}
            </span>
          )}
          <span className="rounded-full bg-blue-50 px-2.5 py-0.5 text-xs text-blue-700 dark:bg-blue-950 dark:text-blue-300">
            Tier {mod.tier}
          </span>
          <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs text-green-700 dark:bg-green-950 dark:text-green-300">
            {mod.status}
          </span>
        </div>
      </div>
      <div className="rounded-2xl border border-dashed border-gray-200 px-6 py-10 text-center dark:border-gray-800">
        <i className="ti ti-puzzle text-[36px] text-gray-300 dark:text-gray-700" />
        <p className="mt-3 text-sm text-gray-500 dark:text-gray-400">
          {t("module_page.no_ui_bundle")}
        </p>
        <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">
          {t("module_page.api_base")}: <code className="font-mono">{apiBase}</code>
        </p>
      </div>
    </div>
  );
}
