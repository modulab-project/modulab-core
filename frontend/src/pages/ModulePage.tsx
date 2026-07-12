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
//
// Deliberately NOT migrated to TanStack Query (unlike the other admin/store
// pages) even though its bundle-load effect below trips
// react-hooks/set-state-in-effect: the bundle fetch is a dynamic import()
// of executable code via a Blob URL, with manual 404-retry and cancellation
// - not cacheable server state, and re-running it on every query
// stale/refetch would risk exactly the "unmounts the module component
// mid-interaction, loses unsaved input" bug the `t`-dependency comments
// further down already warn about. Suppressed with a targeted
// eslint-disable instead.
import { useEffect, useState } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router";
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
  // initialQuery carries the URL's query string as-is (e.g. "view=pending"),
  // parsed from /modules/{name}?<query>. Added so a module notification's
  // actionPath (Core: WorkerResponse.Notifications, deno.go) can deep-link
  // into a specific in-module view — e.g. unifi-network's pending-devices
  // tab — without Core needing to know anything about the module's internal
  // view state. A module that doesn't care about query params can just
  // ignore this prop; it is optional, generic, and not unifi-network-
  // specific, so any module can use the same mechanism.
  initialQuery?: URLSearchParams;
}

export default function ModulePage() {
  const { moduleName } = useParams<{ moduleName: string }>();
  const { t } = useTranslation();
  const { session, loading } = useAuthenticatedSession();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [mod, setMod] = useState<InstalledModule | null>(null);
  const [ModuleComponent, setModuleComponent] = useState<React.ComponentType<ModuleComponentProps> | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(true);
  // True while the bundle fetch below is still retrying a 404 — kept separate
  // from `fetching` (module metadata) so the "no frontend" fallback only
  // renders once we're sure it's a genuine Tier 1 module, not mid-retry.
  const [bundleLoading, setBundleLoading] = useState(true);

  // Fetch module metadata.
  // NOTE: `t` is intentionally NOT in the dependency array — same reason as
  // the bundle-load effect below: locale loading fires a re-render with a new
  // `t` reference, which would re-fetch metadata, set a new `mod` object, and
  // cascade into a full bundle re-import mid-interaction.
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
          setLoadError(`module_page.not_active:${m.status}`);
        }
      })
      .catch((e) => setLoadError(`module_page.fetch_error:${e instanceof Error ? e.message : String(e)}`))
      .finally(() => setFetching(false));
  }, [session, moduleName]);

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
        const r = await fetch(`/v1/modules/${encodeURIComponent(mod!.name)}/locales/${language}`, {
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

  // Dynamically import the module's UI bundle with auth.
  //
  // dynamic import() cannot send Authorization headers, so we:
  //   1. fetch() the bundle JS with the Bearer token (authenticated)
  //   2. wrap it in a Blob URL so the browser can import() it
  //   3. revoke the Blob URL after import to free memory
  //
  // NOTE: `t` is intentionally NOT in the dependency array. Adding it would
  // cause a re-import every time the locale finishes loading (i18n fires a
  // re-render after addResourceBundle), which unmounts the module component
  // mid-interaction and loses all unsaved user input.
  //
  // Retries a 404 a few times before giving up: right after a module (re)starts
  // (deno worker (re)start, npm dependency resolution in workerBootstrapScript,
  // egress reload, etc. — see backend/internal/modules/deno.go) there is a real
  // window where the worker/bundle isn't ready yet. A single fetch used to show
  // the "no frontend" fallback permanently for that window, only recovering on
  // a manual page reload — this makes the same window resolve on its own.
  useEffect(() => {
    if (!mod || mod.status !== "active") {
      // Not a shared-server-state fetch TanStack Query would fit well (see
      // the file-level migration note below) - this early-return guard just
      // sets a boolean once per `mod` change, no cascading/looping risk.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setBundleLoading(false);
      return;
    }

    const token = getSessionToken();
    if (!token) {
      setBundleLoading(false);
      return;
    }

    let cancelled = false;
    let blobUrl: string | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    const MAX_ATTEMPTS = 6;
    const RETRY_DELAY_MS = 1500;

    setBundleLoading(true);

    function attempt(attemptNum: number) {
      fetch(`/v1/modules/${encodeURIComponent(mod!.name)}/ui/bundle.js`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((r) => {
          if (cancelled) return null;
          if (!r.ok) {
            if (r.status === 404) {
              // Bundle/worker not ready yet — retry a few times before
              // treating this as "genuinely no bundle" (Tier 1 module).
              if (attemptNum < MAX_ATTEMPTS) {
                retryTimer = setTimeout(() => attempt(attemptNum + 1), RETRY_DELAY_MS);
                return null;
              }
              setBundleLoading(false); // exhausted retries — show fallback now
              return null;
            }
            throw new Error(`HTTP ${r.status}`);
          }
          return r.blob();
        })
        .then((blob) => {
          if (cancelled || !blob) return null;
          blobUrl = URL.createObjectURL(blob);
          return import(/* @vite-ignore */ blobUrl);
        })
        .then((m) => {
          if (cancelled || !m) return; // still-retrying or genuinely-no-bundle path
          if (m.default) {
            setModuleComponent(() => m.default as React.ComponentType<ModuleComponentProps>);
          } else {
            setLoadError("module_page.no_default_export");
          }
          setBundleLoading(false);
        })
        .catch((e) => {
          if (cancelled) return;
          setLoadError(`module_page.fetch_error:${e instanceof Error ? e.message : String(e)}`);
          setBundleLoading(false);
        })
        .finally(() => {
          if (blobUrl) URL.revokeObjectURL(blobUrl);
        });
    }

    attempt(1);

    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
    };
  }, [mod]);

  if (loading || !session) return null;
  if (!moduleName) {
    navigate("/", { replace: true });
    return null;
  }

  const token = getSessionToken() ?? "";
  const apiBase = moduleApiUrl(moduleName);

  return (
    <AppShell session={session}>
      {/* flex h-full lets a module opt into filling the remaining viewport height
          (e.g. my-places' map view); overflow-y-auto keeps today's behavior for
          modules whose content is naturally taller than the available space —
          this div scrolls internally instead of the whole page, so the AppShell
          header/footer stay pinned either way. */}
      <div className="mx-auto flex h-full max-w-5xl flex-col overflow-y-auto py-6 px-2">
        {(fetching || (!loadError && bundleLoading)) && (
          <p className="text-sm text-gray-400 dark:text-gray-500">{t("common.loading")}</p>
        )}

        {loadError && (
          <div className="rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
            {(() => {
              if (!loadError.startsWith("module_page.")) return loadError;
              // Split on the *first* colon only — the trailing part (a status
              // slug or a raw error message) may itself contain colons
              // (e.g. some fetch/network error strings), which a naive
              // split(":")[1] would truncate.
              const sep = loadError.indexOf(":");
              const key = sep === -1 ? loadError : loadError.slice(0, sep);
              const param = sep === -1 ? "" : loadError.slice(sep + 1);
              return key === "module_page.not_active"
                ? t(key, { status: param })
                : key === "module_page.fetch_error"
                  ? t(key, { message: param })
                  : t(key);
            })()}
          </div>
        )}

        {!fetching && !bundleLoading && !loadError && ModuleComponent && (
          <ModuleComponent moduleName={moduleName} apiBase={apiBase} token={token} initialQuery={searchParams} />
        )}

        {!fetching && !bundleLoading && !loadError && !ModuleComponent && mod && (
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
    description?: Record<string, string>;
    version?: string;
    author?: string;
  } | null;
  const lng = i18n.language?.slice(0, 2) ?? "en";
  const description = manifest?.description?.[lng] ?? manifest?.description?.["en"];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-semibold capitalize">{mod.name}</h1>
        {description && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{description}</p>
        )}
        <div className="mt-2 flex flex-wrap gap-2">
          {manifest?.version && (
            <span className="rounded-full bg-gray-100 px-2.5 py-0.5 text-xs text-gray-500 dark:bg-gray-800 dark:text-gray-400">
              v{manifest.version}
            </span>
          )}
          <span className="rounded-full bg-gray-100 px-2.5 py-0.5 text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-300">
            Tier {mod.tier}
          </span>
          <span className="rounded-full bg-teal-50 px-2.5 py-0.5 text-xs text-teal-700 dark:bg-teal-950 dark:text-teal-300">
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
