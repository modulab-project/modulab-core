import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import i18n, { ensureLanguage } from "../lib/i18n";
import {
  getHealthDetails,
  getUserPrefs,
  getSystemInfo,
  listAIProviders,
  setAIPreferredProvider,
  listInstalledModules,
  listUsers,
  logoutRequest,
  streamAIChat,
  updateUserPrefs,
  type AIUserProvider,
  type ChatMessage,
  type HealthDetailsResponse,
  type InstalledModule,
  type Session,
} from "../lib/api";
import { queryClient } from "../lib/queryClient";
import { useNotificationEvents, type ServerEvent } from "../lib/useEvents";
import { useNow } from "../lib/useNow";
import { isAdminRole, isSuperAdminRole } from "../lib/roles";
import { useToasts } from "../lib/toasts";
import { ToastStack } from "./Toast";
import { Logo } from "./AuthShell";
import packageJson from "../../package.json";

// Which slide panel (if any) is currently open - shared between AppShell
// and Header/FooterBar so either one can open/close any of them. Widened
// to include "notifications" alongside the original "profile"/"status".
type OpenPanel = "profile" | "status" | "notifications" | null;


// One entry in the notification feed (NotificationsPanelContent) - kept
// purely in memory for the life of this tab, not persisted anywhere: a
// reload starts the feed empty again. That is an accepted limitation, not
// an oversight - see AppShell's pendingCount handling below for why the
// one piece of information that actually matters (how many people are
// waiting *right now*) does not depend on this feed at all.
interface FeedItem {
  id: number;
  message: string;
  at: number;
  actionLabel?: string;
  onAction?: () => void;
}

let nextFeedItemID = 1;
const FEED_LIMIT = 20;

const FRONTEND_VERSION = packageJson.version;
const PROJECT_URL = "https://modulab.app";
const GITHUB_URL = "https://github.com/modulab-project/modulab-core";

// Light/Dark are explicit user choices; System defers to the OS/browser's
// prefers-color-scheme and stays live-updated if that changes while the
// tab is open (e.g. the OS switches to dark mode at sunset). No localStorage
// mirror any more - the authoritative value is users.theme (DB), applied by
// the getUserPrefs effect below once a session exists. Until that fetch
// resolves (or if there is no session yet), this renders as "light" - the
// same default a first-ever visit always had.
type Theme = "light" | "dark" | "system";

function systemPrefersDark(): boolean {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

// --- "Add to Home Screen" ---------------------------------------------
//
// Android/Chrome: the browser fires beforeinstallprompt once its own
// installability checks pass (valid manifest + service worker, both
// supplied by vite-plugin-pwa - see vite.config.ts). Capturing that event
// is the *only* way to trigger the native install dialog later from our
// own button instead of whatever mini-infobar Chrome would show on its own.
//
// iOS Safari: no beforeinstallprompt, no other programmatic trigger exists
// at all - Apple deliberately doesn't expose one. The only route to the
// home screen is Share -> "Zum Home-Bildschirm", so for iOS this hook just
// reports "show the manual instructions" instead of an install action.
interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

function isIOSDevice(): boolean {
  // iPadOS 13+ reports as "Macintosh" with touch support, not "iPad" -
  // maxTouchPoints is what distinguishes it from an actual Mac.
  return (
    /iphone|ipad|ipod/i.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
  );
}

function isStandaloneDisplay(): boolean {
  return (
    window.matchMedia?.("(display-mode: standalone)").matches === true ||
    // iOS Safari's own pre-manifest-standard flag - still the only signal
    // it exposes for "already added to the home screen".
    (navigator as unknown as { standalone?: boolean }).standalone === true
  );
}

function useInstallPrompt() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isStandalone, setIsStandalone] = useState(isStandaloneDisplay);

  useEffect(() => {
    function onBeforeInstallPrompt(e: Event) {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    }
    function onInstalled() {
      setDeferredPrompt(null);
      setIsStandalone(true);
    }
    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    window.addEventListener("appinstalled", onInstalled);
    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      window.removeEventListener("appinstalled", onInstalled);
    };
  }, []);

  const isIOS = isIOSDevice();
  // Android/Chrome (and other browsers implementing the same event) got a
  // real deferred prompt to trigger. iOS never fires beforeinstallprompt no
  // matter what, so it falls back to "show the manual instructions" instead
  // - anything else (desktop Safari/Firefox without install support) shows
  // neither.
  const canPromptInstall = !!deferredPrompt;
  const showIOSInstructions = isIOS && !isStandalone && !deferredPrompt;
  const visible = !isStandalone && (canPromptInstall || showIOSInstructions);

  async function promptInstall() {
    if (!deferredPrompt) return;
    await deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    // Chrome clears its own eligibility after one prompt regardless of the
    // user's choice - a dismissed prompt does not fire beforeinstallprompt
    // again until the page is reloaded, so there is nothing to keep here.
    setDeferredPrompt(null);
  }

  return { visible, canPromptInstall, showIOSInstructions, promptInstall };
}

// Shared chrome - header, profile/status slide panels, footer - for every
// page reachable once a user has a fully-approved session: Home ("/") and
// ProfilePage ("/profile") so far. Originally lived only in Home.tsx; moved
// out so a second page can look like part of the same app instead of a
// one-off screen you have to click "Back" to leave - the logo always goes
// home, the avatar always opens the same profile panel (which now also
// links to /profile itself), and the footer's status pill behaves
// identically everywhere. Each page supplies only its own main content via
// children.
export function AppShell({
  session,
  children,
  hideChrome = false,
}: {
  session: Session;
  children: ReactNode;
  // Lets a module's own fullscreen view (e.g. a single coupon/recipe detail
  // card) hide Core's header/footer entirely, so nothing but the module's
  // content shows on screen. Generic — any module can request it via
  // ModuleComponentProps.setChromeHidden, not specific to one module.
  hideChrome?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthDetailsResponse | null>(null);
  const [openPanel, setOpenPanel] = useState<OpenPanel>(null);
  const [theme, setTheme] = useState<Theme>("light");
  // The actual light/dark class always comes from this, never from `theme`
  // directly - `theme === "system"` still needs to resolve to a concrete
  // boolean before it can be applied to <html>.
  const [systemDark, setSystemDark] = useState(systemPrefersDark);
  const dark = theme === "system" ? systemDark : theme === "dark";
  const [activeModules, setActiveModules] = useState<InstalledModule[]>([]);
  // How many installed modules have an update waiting (available_version set).
  // Shown in the notification bell badge alongside pending-user count.
  // null = not yet fetched, 0 = all up to date, n = n updates available.
  const [moduleUpdateCount, setModuleUpdateCount] = useState<number | null>(null);
  // Whether a newer modulab-core release is known (GET /v1/admin/system/info's
  // cached coreupdate result, see coreupdate.CachedResult's doc comment) -
  // admin only, unlike moduleUpdateCount above: Core/system settings are
  // already an admin-exclusive concern elsewhere in this app (see
  // AdminSystemPage's own admin gate), so this deliberately does not fetch
  // or show for a plain user session.
  const [coreUpdateAvailable, setCoreUpdateAvailable] = useState(false);
  const [latestCoreVersion, setLatestCoreVersion] = useState<string | undefined>(undefined);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  // Only relevant while `theme === "system"`, but kept subscribed
  // unconditionally rather than mounting/unmounting the listener on every
  // theme switch - matchMedia listeners are cheap, and this avoids a
  // subtle bug where switching *away* from "system" and back without a
  // remount would miss an OS change that happened in between.
  useEffect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setSystemDark(mql.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  // frontendStale: true once a getHealthDetails() response reports a
  // backend version that no longer matches the JS bundle this tab actually
  // has loaded (FRONTEND_VERSION, baked in at build time from
  // package.json). That mismatch means a release happened after this tab's
  // page load - the running backend has moved on, but this tab is still
  // executing old frontend code. Added 2026-08-05 as a safety net alongside
  // disabling the service worker's app-shell precaching (vite.config.ts)
  // and adding real Cache-Control headers (now set by Core itself in
  // backend/internal/webui, previously by deploy/nginx.conf): those two
  // stop this
  // tab from being handed stale code on its *next* load, but do nothing
  // for a tab that was already open across a deploy - only reloading gets
  // it current code, and nothing prompts that without this check.
  //
  // Reads from GET /v1/health/details, not the public /healthz, since
  // 2026-08-11: version moved behind "any logged-in session" so an
  // unauthenticated caller can no longer read the build version off this
  // instance - see api.ts's HealthResponse/HealthDetailsResponse doc
  // comments.
  const [frontendStale, setFrontendStale] = useState(false);

  // Unconditional on mount, not gated behind a session effect of its own -
  // by the time AppShell renders, the caller has already resolved a
  // session (see lib/useSession.ts), so there is nothing left to wait on
  // here - which is also exactly why it's safe for this to call the
  // session-gated /v1/health/details instead of the public /healthz.
  useEffect(() => {
    const checkHealth = () => {
      getHealthDetails()
        .then((h) => {
          setHealth(h);
          setFrontendStale(h.version !== FRONTEND_VERSION);
        })
        .catch(() => setHealth(null));
    };

    checkHealth();

    // Two triggers, not one: a fixed interval alone would miss a deploy
    // that happens while this tab is backgrounded and never gets a
    // setInterval tick delayed past the throttling browsers apply to
    // hidden tabs; a visibilitychange listener alone would miss a deploy
    // during a long unattended foreground session (e.g. an always-on
    // shared browser homepage - see Home.tsx's top-of-file comment on
    // that intended use case). Together they cover both without needing a
    // short, battery/traffic-unfriendly interval.
    const intervalId = window.setInterval(checkHealth, 5 * 60 * 1000);
    const onVisible = () => {
      if (document.visibilityState === "visible") {
        checkHealth();
      }
    };
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  // Load active modules (for navigation links) and count pending updates
  // (for the notification badge). Merged into one call to avoid a second
  // round-trip. Re-runs via refreshModuleUpdateCount when the notification
  // panel is opened so the count is always fresh when the admin looks at it.
  const refreshModuleUpdateCount = useCallback(() => {
    listInstalledModules()
      .then((list) => {
        const all = list ?? [];
        setActiveModules(all.filter((m) => m.status === "active"));
        setModuleUpdateCount(all.filter((m) => !!m.available_version).length);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshModuleUpdateCount();
  }, [refreshModuleUpdateCount]);

  // Load the stored UI language and theme on first render for this user and
  // apply them so both preferences survive across browsers and devices -
  // users.ui_language / users.theme are the only place either lives now,
  // there is no client-side cache to fall back on. Best-effort: a failed
  // fetch leaves the render at its "light"/browser-language defaults until
  // the next successful fetch (e.g. next reload) picks up the real values.
  useEffect(() => {
    getUserPrefs()
      .then((prefs) => {
        if (prefs.ui_language && !i18n.language.startsWith(prefs.ui_language)) {
          ensureLanguage(prefs.ui_language).finally(() => {
            i18n.changeLanguage(prefs.ui_language);
          });
        }
        if (prefs.theme === "light" || prefs.theme === "dark" || prefs.theme === "system") {
          setTheme(prefs.theme);
        }
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.user_id]); // re-run if a different user logs in within the same tab

  async function handleLogout() {
    try {
      await logoutRequest();
    } catch {
      // Already invalid server-side - the local sign-out still succeeds.
    }
    // ModuLab is designed to run as a shared, always-on browser homepage
    // (see Home.tsx's top-of-file comment) - the TanStack Query cache is a
    // single instance for the tab's whole lifetime and survives the SPA
    // navigate("/login") below (no full page reload), so without this it
    // would otherwise keep serving the previous person's cached
    // feed/module/store data for a few seconds after the next person logs
    // in on the same tab. Used to live in lib/session.ts's
    // clearSessionToken(), which no longer exists now that there is no
    // locally-held token to clear - only this cache-reset concern remains.
    queryClient.clear();
    navigate("/login", { replace: true });
  }

  const isAdmin = isAdminRole(session.role);
  const isSuperAdmin = isSuperAdminRole(session.role);
  const [chatOpen, setChatOpen] = useState(false);
  const installPrompt = useInstallPrompt();
  const [iosInstallHelpOpen, setIosInstallHelpOpen] = useState(false);

  // pendingCount is the authoritative "how many people are waiting right
  // now" number, fetched straight from GET /v1/admin/users (the same data
  // AdminUsersPage shows) rather than ever being derived from SSE events
  // alone. This matters: notify.AdminChannel() only reaches an admin who
  // happens to be connected at the exact moment a new pending user is
  // created - someone who signed up earlier (before this tab connected,
  // before a restart, or while no admin was online at all) would
  // otherwise never show up anywhere. Refetched on mount, whenever a
  // "user.pending" event arrives (a likely change, and refetching beats
  // trusting a client-side increment to stay in sync with anything an
  // admin in a *different* tab approved in the meantime), and whenever the
  // notifications panel is opened (covers exactly that "approved
  // elsewhere" case for the count actively being looked at).
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [feed, setFeed] = useState<FeedItem[]>([]);
  // unreadModuleNotifications: a client-only "seen since last panel open"
  // counter for "module.notification" events (device waiting/approved/
  // deleted, gateway paused/online, etc.). Unlike pendingCount and
  // moduleUpdateCount, there is no authoritative server-side "how many
  // unread module events" query to refetch — Core deliberately does not
  // interpret module notifications (see ModuleNotification's doc comment),
  // so it has nothing to count from a DB. Reported 2026-07-04: the bell
  // badge never reflected an arriving module notification at all, only a
  // manual reload made it visible — because the badge total only ever
  // summed pendingCount + moduleUpdateCount. Reset to 0 whenever the
  // notifications panel is opened, same "seen it now" semantics as
  // refreshPendingCount/refreshModuleUpdateCount refetching on open.
  const [unreadModuleNotifications, setUnreadModuleNotifications] = useState(0);

  const refreshPendingCount = useCallback(() => {
    if (!isAdmin) {
      return;
    }
    listUsers()
      .then((users) => setPendingCount(users.filter((u) => !u.approved).length))
      .catch(() => {
        // Left at whatever it was before - a failed refresh should not
        // make the badge disappear or claim "zero" when the truth is
        // simply unknown right now.
      });
  }, [isAdmin]);

  useEffect(() => {
    refreshPendingCount();
  }, [refreshPendingCount]);

  // refreshCoreUpdateInfo: same "refetch on mount, on the matching SSE
  // event, and whenever the notifications panel is opened" treatment as
  // refreshPendingCount/refreshModuleUpdateCount above, just gated on
  // isSuperAdmin instead of isAdmin (see coreUpdateAvailable's own doc
  // comment for why) and reusing GET /v1/admin/system/info rather than a
  // dedicated endpoint - the same call AdminSystemInfoPage/AdminSystemPage
  // already make, just for the two fields this bell needs.
  const refreshCoreUpdateInfo = useCallback(() => {
    if (!isSuperAdmin) {
      return;
    }
    getSystemInfo()
      .then((info) => {
        setCoreUpdateAvailable(info.core_update_available);
        setLatestCoreVersion(info.latest_core_version);
      })
      .catch(() => {
        // Left at whatever it was before - same "unknown, not zero" reasoning
        // as refreshPendingCount's own catch above.
      });
  }, [isSuperAdmin]);

  useEffect(() => {
    refreshCoreUpdateInfo();
  }, [refreshCoreUpdateInfo]);

  // Spec section 3.5's real-time notifications: every authenticated page
  // using AppShell gets one SSE connection (lib/useEvents.ts), but only
  // admin sessions ever actually receive anything on
  // it today - "user.pending" and "module.updates_available" are both
  // published exclusively to notify.AdminChannel() (backend/internal/
  // auth/handlers.go and backend/internal/modules/status.go respectively),
  // so a plain "user" session's connection just sits idle, costing one
  // open connection for symmetry/future events rather than anything it
  // currently uses.
  const { toasts, push } = useToasts();
  useNotificationEvents(true, (event: ServerEvent) => {
    if (event.type === "user.pending" && isAdmin) {
      const data = (event.data ?? {}) as { email?: string; name?: string };
      const who = data.name?.trim() || data.email || t("shell.notifications_panel.someone_fallback");
      const goReview = () => navigate("/admin/users");
      const waitingMsg = t("shell.notifications_panel.waiting_toast", { name: who });
      const reviewLabel = t("shell.notifications_panel.review");
      push({ message: waitingMsg, actionLabel: reviewLabel, onAction: goReview });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: waitingMsg, at: Date.now(), actionLabel: reviewLabel, onAction: goReview },
        ...prev,
      ].slice(0, FEED_LIMIT));
      refreshPendingCount();
    }
    if (event.type === "module.updates_available" && isAdmin) {
      // Published by modules.RunUpdateCheckOnce (backend/internal/modules/
      // status.go) — triggered right after every registry sync, it found at
      // least one installed module with a newer version. Previously moduleUpdateCount
      // only ever refreshed on mount or when the notifications panel was
      // opened, so a background-discovered update sat invisible until an
      // admin happened to look; this makes it show up the same way
      // "user.pending" already does — live, via SSE, no reload needed.
      const data = (event.data ?? {}) as { count?: number };
      const count = data.count ?? 1;
      const goToModules = () => navigate("/admin/modules/installed");
      const updatesMsg = count === 1
        ? t("shell.notifications_panel.module_updates_one", { count })
        : t("shell.notifications_panel.module_updates_many", { count });
      const viewLabel = t("shell.notifications_panel.review");
      push({ message: updatesMsg, actionLabel: viewLabel, onAction: goToModules });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: updatesMsg, at: Date.now(), actionLabel: viewLabel, onAction: goToModules },
        ...prev,
      ].slice(0, FEED_LIMIT));
      refreshModuleUpdateCount();
    }
    if (event.type === "core.update_available" && isSuperAdmin) {
      // Published by coreupdate.CheckNow (backend/internal/coreupdate) to
      // notify.AdminChannel, same as the other events above (before
      // 2026-07-29's role-model change this used a narrower
      // SuperAdminChannel, since org-admin sessions were excluded - both
      // are gone now). Fires at most once per newer
      // version (dedup lives server-side), so this toast/feed entry is a
      // "look, something changed" nudge, not something that repeats on
      // every scheduled tick while the same version is still current.
      const data = (event.data ?? {}) as { version?: string };
      setCoreUpdateAvailable(true);
      setLatestCoreVersion(data.version);
      const goToSystemInfo = () => navigate("/admin/system/info");
      const updateMsg = data.version
        ? t("shell.notifications_panel.core_update_toast", { version: data.version })
        : t("shell.notifications_panel.core_update_toast_generic");
      const viewLabel = t("shell.notifications_panel.review");
      push({ message: updateMsg, actionLabel: viewLabel, onAction: goToSystemInfo });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: updateMsg, at: Date.now(), actionLabel: viewLabel, onAction: goToSystemInfo },
        ...prev,
      ].slice(0, FEED_LIMIT));
    }
    // Published by CallbackHandler (backend/internal/auth/handlers.go) on
    // notify.UserChannel - every session subscribes to its own channel
    // regardless of role (see events.go), so this is intentionally NOT
    // gated on isAdmin: the whole point is that any already-open tab for
    // this same account, admin or not, hears about a fresh login
    // immediately. anomaly/country/previous_country come from comparing
    // Cloudflare's CF-IPCountry header against the country remembered from
    // this subject's last login - both empty (and anomaly false) whenever
    // that header isn't present at all (e.g. local access bypassing
    // Cloudflare), in which case this degrades to a plain "new login"
    // notice with no country claim.
    if (event.type === "session.new") {
      const data = (event.data ?? {}) as {
        ip?: string;
        country?: string;
        anomaly?: boolean;
        previous_country?: string;
      };
      const ip = data.ip ?? "?";
      const msg = data.anomaly
        ? t("shell.notifications_panel.session_new_anomaly_toast", {
            ip,
            country: data.country ?? "?",
            previousCountry: data.previous_country ?? "?",
          })
        : t("shell.notifications_panel.session_new_toast", { ip });
      push({ message: msg });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: msg, at: Date.now() },
        ...prev,
      ].slice(0, FEED_LIMIT));
    }
    // Published by main.go's rateLimitMiddleware (auth/login/callback,
    // ai-chat-per-IP, global backstop) and ai.go's ChatHandler (per-user
    // chat RPM cap) whenever a limit actually trips - see those files' doc
    // comments for why this is gated server-side to fire once per trip, not
    // once per subsequent blocked retry. Durable detail (which IP/user,
    // exact count/max) always lands in the audit log regardless of whether
    // any admin tab is open to receive this live push - this is purely the
    // "notice it without having to go looking" layer on top of that.
    if (event.type === "rate_limit.exceeded" && isAdmin) {
      const data = (event.data ?? {}) as { label?: string; identifier?: string };
      const goToAudit = () => navigate("/admin/audit");
      const msg = t("shell.notifications_panel.rate_limit_toast", {
        label: data.label ?? "?",
        identifier: data.identifier ?? "?",
      });
      const reviewLabel = t("shell.notifications_panel.review");
      push({ message: msg, actionLabel: reviewLabel, onAction: goToAudit });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: msg, at: Date.now(), actionLabel: reviewLabel, onAction: goToAudit },
        ...prev,
      ].slice(0, FEED_LIMIT));
    }
    // Published by auth.recordReauthFailure (admin.go) once a caller's
    // step-up reauth (lock/unlock/approve/delete a user, self-delete,
    // SMTP/OIDC config, ending another session) fails repeatedly in a
    // short window - a single failure is routine and never reaches this
    // point, only a burst that looks more like a stale/stolen session
    // cookie being probed than someone who simply hasn't logged in
    // recently. Same "durable in the audit log regardless, this is just
    // the live notice" relationship as rate_limit.exceeded above.
    if (event.type === "reauth.repeated_failures" && isAdmin) {
      const data = (event.data ?? {}) as { email?: string; label?: string; count?: number };
      const goToAudit = () => navigate("/admin/audit");
      const msg = t("shell.notifications_panel.reauth_failures_toast", {
        email: data.email ?? "?",
        label: data.label ?? "?",
        count: data.count ?? "?",
      });
      const reviewLabel = t("shell.notifications_panel.review");
      push({ message: msg, actionLabel: reviewLabel, onAction: goToAudit });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: msg, at: Date.now(), actionLabel: reviewLabel, onAction: goToAudit },
        ...prev,
      ].slice(0, FEED_LIMIT));
    }
    // Module-triggered events (Core: WorkerResponse.Notifications, deno.go —
    // published from modules.JobRunner.dispatchJob, jobs.go, under the
    // single generic "module.notification" type). A module's own job code
    // decides when these fire (see unifi-network's poll-gateways.ts) and
    // renders the text itself in every language ModuLab's UI supports
    // ({de, en} — ModuleNotification.Message) before handing it to Core.
    // Core does NOT look up any translation for this: it only picks the
    // entry matching the viewer's current UI language client-side. This
    // replaces an earlier design where Core's own de.json/en.json hardcoded
    // a locale key per module event type — that required a Core change for
    // every new module notification, which violates the module system's
    // core promise that a module is developable without ever touching Core.
    if (event.type === "module.notification" && isAdmin) {
      const data = (event.data ?? {}) as { message?: Record<string, string>; actionPath?: string };
      const lang = i18n.language?.slice(0, 2) ?? "en";
      const message = data.message?.[lang] ?? data.message?.en;
      if (message) {
        // actionPath is supplied by the module itself (e.g.
        // "/modules/unifi-network?view=pending") — Core has no route table
        // for modules and cannot derive a sensible destination on its own.
        // Falls back to the installed-modules list only when a module
        // genuinely doesn't send one. Fixed 2026-07-04: every module
        // notification previously landed here regardless of what it was
        // actually about.
        const target = data.actionPath || "/admin/modules/installed";
        const goToTarget = () => navigate(target);
        const reviewLabel = t("shell.notifications_panel.review");
        push({ message, actionLabel: reviewLabel, onAction: goToTarget });
        setFeed((prev) => [
          { id: nextFeedItemID++, message, at: Date.now(), actionLabel: reviewLabel, onAction: goToTarget },
          ...prev,
        ].slice(0, FEED_LIMIT));
        setUnreadModuleNotifications((prev) => prev + 1);
      }
    }
  });

  function togglePanel(panel: Exclude<OpenPanel, null>) {
    setOpenPanel((current) => {
      const next = current === panel ? null : panel;
      if (next === "notifications") {
        refreshPendingCount();
        refreshModuleUpdateCount();
        refreshCoreUpdateInfo();
        setUnreadModuleNotifications(0);
      }
      return next;
    });
  }

  return (
    <div className="flex h-dvh flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      {frontendStale && (
        // Deliberately not a useToasts() toast: those auto-dismiss after
        // 6s (see lib/toasts.ts), which is exactly wrong for something the
        // user needs to actually act on to fix - a stale tab that never
        // gets reloaded will just keep re-triggering the same problem this
        // banner exists to solve. Shown regardless of hideChrome (a
        // module's fullscreen view is not exempt from running stale code
        // either).
        <div className="flex flex-none items-center justify-center gap-3 bg-amber-100 px-3 py-2 text-sm text-amber-900 dark:bg-amber-900/40 dark:text-amber-100">
          <span>{t("shell.stale_version_banner")}</span>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="flex-none rounded-md bg-amber-600 px-3 py-1 font-medium text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-400"
          >
            {t("shell.reload_now")}
          </button>
        </div>
      )}
      {!hideChrome && (
        <Header
          session={session}
          isAdmin={isAdmin}
          pendingCount={pendingCount}
          moduleUpdateCount={moduleUpdateCount}
          unreadModuleNotifications={unreadModuleNotifications}
          coreUpdateAvailable={coreUpdateAvailable}
          openPanel={openPanel}
          onTogglePanel={togglePanel}
          chatOpen={chatOpen}
          onToggleChat={() => setChatOpen((v) => !v)}
        />
      )}

      <main
        className={
          hideChrome
            ? "flex-1 min-h-0 overflow-y-auto"
            : "flex-1 min-h-0 overflow-y-auto px-3 sm:px-6"
        }
      >
        {children}
      </main>

      {!hideChrome && (
        <FooterBar isAdmin={isAdmin} health={health} onTogglePanel={togglePanel} />
      )}
      <ToastStack toasts={toasts} />

      {chatOpen && (
        <ChatPanel onClose={() => setChatOpen(false)} />
      )}

      {openPanel && (
        // Decorative click-outside-to-close backdrop - Escape (handled by
        // each SlidePanel) is the keyboard equivalent, so no separate
        // keydown handler is needed on this non-interactive, aria-hidden element.
        <div
          className="fixed inset-x-0 top-[60px] bottom-[44px] z-10 bg-black/35"
          onClick={() => setOpenPanel(null)}
          aria-hidden="true"
        />
      )}
      <SlidePanel open={openPanel === "profile"} onClose={() => setOpenPanel(null)} title={t("profile.title")}>
        <ProfilePanelContent
          session={session}
          isSuperAdmin={isSuperAdmin}
          theme={theme}
          setTheme={setTheme}
          onLogout={handleLogout}
          onClose={() => setOpenPanel(null)}
          activeModules={activeModules}
          installPrompt={installPrompt}
          onShowIOSInstallHelp={() => setIosInstallHelpOpen(true)}
        />
      </SlidePanel>
      {iosInstallHelpOpen && (
        <IOSInstallInstructions onClose={() => setIosInstallHelpOpen(false)} />
      )}
      <SlidePanel open={openPanel === "status"} onClose={() => setOpenPanel(null)} title={t("shell.system_status")}>
        {health && <StatusPanelContent health={health} />}
      </SlidePanel>
      <SlidePanel
        open={openPanel === "notifications"}
        onClose={() => setOpenPanel(null)}
        title={t("shell.notifications")}
      >
        <NotificationsPanelContent
          pendingCount={pendingCount}
          moduleUpdateCount={moduleUpdateCount}
          coreUpdateAvailable={coreUpdateAvailable}
          latestCoreVersion={latestCoreVersion}
          feed={feed}
          onReviewPending={() => {
            setOpenPanel(null);
            navigate("/admin/users");
          }}
          onViewModuleUpdates={() => {
            setOpenPanel(null);
            navigate("/admin/modules/installed");
          }}
          onViewCoreUpdate={() => {
            setOpenPanel(null);
            navigate("/admin/system/info");
          }}
        />
      </SlidePanel>
    </div>
  );
}

// --- Header --------------------------------------------------------------

function Header({
  session,
  isAdmin,
  pendingCount,
  moduleUpdateCount,
  unreadModuleNotifications,
  coreUpdateAvailable,
  openPanel,
  onTogglePanel,
  chatOpen,
  onToggleChat,
}: {
  session: Session;
  isAdmin: boolean;
  pendingCount: number | null;
  moduleUpdateCount: number | null;
  unreadModuleNotifications: number;
  coreUpdateAvailable: boolean;
  openPanel: OpenPanel;
  onTogglePanel: (panel: Exclude<OpenPanel, null>) => void;
  chatOpen: boolean;
  onToggleChat: () => void;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <header className="flex h-[60px] flex-none items-center justify-between border-b border-gray-200 px-3 sm:px-6 dark:border-gray-800">
      <button
        type="button"
        aria-label={t("shell.go_home")}
        onClick={() => navigate("/")}
        className="flex items-center gap-2 rounded-lg p-1 hover:bg-gray-100 dark:hover:bg-gray-900"
      >
        <Logo className="h-[30px] w-[30px]" />
        <span className="text-[clamp(17px,4vw,22px)] font-semibold tracking-tight">
          Modu<span className="text-teal-600 dark:text-teal-400">Lab</span>
        </span>
      </button>

      <div className="flex items-center gap-2">
        {isAdmin && (
          <button
            type="button"
            aria-label={t("shell.notifications")}
            aria-haspopup="true"
            aria-expanded={openPanel === "notifications"}
            onClick={() => onTogglePanel("notifications")}
            className="relative flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-bell text-[18px] text-gray-500 dark:text-gray-400" />
            {(() => {
              // unreadModuleNotifications included so the badge reflects a
              // live-arriving module event (device waiting/approved/
              // deleted, gateway paused/online, etc.) immediately, not just
              // after the next reload — see its declaration for why this is
              // a separate client-only counter rather than a server refetch
              // like the other two.
              const total = (pendingCount ?? 0) + (moduleUpdateCount ?? 0) + unreadModuleNotifications + (coreUpdateAvailable ? 1 : 0);
              if (total === 0) return null;
              // Red for pending users, amber otherwise (module updates
              // and/or unread module notifications)
              const color = (pendingCount ?? 0) > 0
                ? "bg-red-600"
                : "bg-amber-500";
              return (
                <span className={`absolute -right-0.5 -top-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full ${color} px-1 text-[10px] font-semibold leading-none text-white`}>
                  {total > 9 ? "9+" : total}
                </span>
              );
            })()}
          </button>
        )}
        <button
          type="button"
          aria-label={t("shell.ai_chat")}
          aria-expanded={chatOpen}
          onClick={onToggleChat}
          className={`flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900 ${
            chatOpen ? "bg-teal-50 text-teal-600 dark:bg-teal-950 dark:text-teal-400" : ""
          }`}
        >
          <i className={`ti ti-sparkles text-[18px] ${chatOpen ? "text-teal-600 dark:text-teal-400" : "text-gray-500 dark:text-gray-400"}`} />
        </button>
        <button
          type="button"
          aria-haspopup="true"
          aria-expanded={openPanel === "profile"}
          onClick={() => onTogglePanel("profile")}
          className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-full hover:opacity-80"
        >
          <Avatar session={session} className="h-8 w-8 text-xs" />
        </button>
      </div>
    </header>
  );
}

// --- Footer ---------------------------------------------------------------

function FooterBar({
  isAdmin,
  health,
  onTogglePanel,
}: {
  isAdmin: boolean;
  health: HealthDetailsResponse | null;
  onTogglePanel: (panel: Exclude<OpenPanel, null>) => void;
}) {
  const { t } = useTranslation();
  // Bugfix (2026-07-05): this previously only looked at postgres/valkey, so
  // the footer badge could say "all systems normal" while the System Status
  // page's own Infrastructure section showed SearXNG as unreachable right
  // next to it - the two disagreed about what "ok" means. Extended the same
  // day to also fold in every other per-instance signal already present in
  // this same /healthz payload (no extra request): searxng (only when
  // configured - an instance that never set it up isn't "broken"), ntp_drift
  // (only when the check actually ran - absent means it timed out/was
  // blocked, which is itself not evidence of drift), and degraded/failed
  // module workers. TLS cert expiry and Cosign availability are NOT included
  // here - they only exist in the fuller /v1/admin/system/info response,
  // fetching that just for this badge would reintroduce the extra
  // network round trip on every page that version.go's removal (2026-06-21)
  // was meant to avoid; those two stay System-Status-page-only.
  const allOk =
    !!health &&
    health.postgres_reachable &&
    health.valkey_reachable &&
    (!health.searxng_configured || !!health.searxng_reachable) &&
    (health.ntp_drift_ok === undefined || health.ntp_drift_ok) &&
    health.modules_degraded === 0 &&
    health.modules_failed === 0;

  return (
    <footer className="flex flex-none flex-wrap items-center justify-center gap-2 border-t border-gray-200 px-3 py-2 text-xs text-gray-500 sm:gap-6 dark:border-gray-800 dark:text-gray-400">
      {isAdmin && health && (
        <button
          type="button"
          onClick={() => onTogglePanel("status")}
          className={`flex items-center gap-1.5 rounded-xl px-3 py-1 font-medium ${
            allOk
              ? "bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-400"
              : "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-400"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 animate-pulse rounded-full ${allOk ? "bg-teal-700 dark:bg-teal-400" : "bg-red-700 dark:bg-red-400"}`}
          />
          {allOk ? t("shell.all_ok") : t("shell.attention")}
        </button>
      )}
      <span>
        {t("shell.versions", { version: health?.version ?? "…" })}
      </span>
      <span className="flex items-center gap-3">
        <a
          href={PROJECT_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-gray-700 dark:hover:text-gray-200"
        >
          modulab.app
        </a>
        <a
          href={GITHUB_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-gray-700 dark:hover:text-gray-200"
        >
          GitHub
        </a>
      </span>
    </footer>
  );
}

// --- Shared slide-in panel ------------------------------------------------

function SlidePanel({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div
      className={`fixed top-[60px] bottom-[44px] right-0 z-20 flex w-full flex-col border-l border-gray-200 bg-white shadow-xl transition-transform duration-200 sm:w-[420px] dark:border-gray-800 dark:bg-gray-950 ${
        open ? "translate-x-0" : "translate-x-full"
      }`}
    >
      {title && (
        <div className="flex flex-none items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-800">
          <h2 className="text-base font-semibold">{title}</h2>
          <button
            type="button"
            aria-label={t("shell.close")}
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-900"
          >
            <i className="ti ti-x" />
          </button>
        </div>
      )}
      <div className="flex-1 overflow-y-auto p-2.5">{open && children}</div>
    </div>
  );
}

// iOS Safari has no install API to call (see useInstallPrompt's doc
// comment) - this just walks the user through the manual Share ->
// "Zum Home-Bildschirm" steps instead of a broken/no-op button.
function IOSInstallInstructions({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center sm:items-center">
      {/* A real <button> rather than a div+onClick backdrop - natively
          keyboard-operable (satisfies jsx-a11y/click-events-have-key-events)
          without needing a manual onKeyDown handler, and its aria-label
          doubles as the "close" affordance for anyone tabbing to it. Sits
          behind the dialog box below via absolute positioning, so a click
          on the dialog itself lands on the dialog's own elements first
          instead of needing stopPropagation. */}
      <button
        type="button"
        aria-label={t("shell.close")}
        onClick={onClose}
        className="absolute inset-0 bg-black/40"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="ios-install-title"
        className="relative w-full max-w-sm rounded-t-2xl bg-white p-5 shadow-xl sm:rounded-2xl dark:bg-gray-900"
      >
        <div className="mb-3 flex items-center justify-between">
          <h3 id="ios-install-title" className="text-base font-semibold">{t("shell.ios_install.title")}</h3>
          <button
            type="button"
            aria-label={t("shell.close")}
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
          >
            <i className="ti ti-x" />
          </button>
        </div>
        <ol className="space-y-3 text-sm text-gray-700 dark:text-gray-300">
          <li className="flex items-start gap-2.5">
            <i className="ti ti-square-arrow-up mt-0.5 flex-none text-[16px] text-teal-600 dark:text-teal-400" />
            {t("shell.ios_install.step1")}
          </li>
          <li className="flex items-start gap-2.5">
            <i className="ti ti-square-rounded-plus mt-0.5 flex-none text-[16px] text-teal-600 dark:text-teal-400" />
            {t("shell.ios_install.step2")}
          </li>
          <li className="flex items-start gap-2.5">
            <i className="ti ti-check mt-0.5 flex-none text-[16px] text-teal-600 dark:text-teal-400" />
            {t("shell.ios_install.step3")}
          </li>
        </ol>
      </div>
    </div>
  );
}

// One collapsible group in the profile panel (Meine Module/Einstellungen/
// System) - only one group is open at a time (accordion behavior), height
// animated via a CSS grid-template-rows 0fr/1fr trick rather than a fixed
// max-height or a ResizeObserver, so it works for any content length
// without measuring anything.
function AccordionGroup({
  icon,
  label,
  caption,
  open,
  onToggle,
  children,
}: {
  icon: string;
  label: string;
  caption?: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <span className="flex flex-col items-start">
          <span className="flex items-center gap-2.5">
            <i className={`ti ${icon} text-[15px] text-gray-500`} />
            {label}
          </span>
          {caption && (
            <span className="ml-[26px] text-[10px] text-gray-400 dark:text-gray-500">{caption}</span>
          )}
        </span>
        <i
          className={`ti ti-chevron-down text-[15px] text-gray-400 transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>
      <div
        className="grid transition-[grid-template-rows] duration-200"
        style={{ gridTemplateRows: open ? "1fr" : "0fr" }}
      >
        <div className="overflow-hidden">{children}</div>
      </div>
    </div>
  );
}

// Shared class for every sub-item inside an AccordionGroup - indented past
// the group's own icon so it reads as nested, same treatment whether it's
// a real Link (navigates + closes the panel) or a button (drill-in trigger,
// stays inside the panel).
const SUB_ITEM_CLASS =
  "flex w-full items-center justify-between gap-2.5 rounded-lg py-2.5 pl-[34px] pr-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900";

function ProfilePanelContent({
  session,
  isSuperAdmin,
  theme,
  setTheme,
  onLogout,
  onClose,
  activeModules,
  installPrompt,
  onShowIOSInstallHelp,
}: {
  session: Session;
  isSuperAdmin: boolean;
  theme: Theme;
  setTheme: (t: Theme) => void;
  onLogout: () => void;
  onClose: () => void;
  activeModules: InstalledModule[];
  installPrompt: ReturnType<typeof useInstallPrompt>;
  onShowIOSInstallHelp: () => void;
}) {
  const { t, i18n: i18nInstance } = useTranslation();
  const displayName = session.name.trim() || session.email;

  // Which of the three groups (if any) is open - only one at a time.
  const [openGroup, setOpenGroup] = useState<"modules" | "settings" | "system" | null>(null);
  // Within the open System group, which of the five thematic categories (if
  // any) has been drilled into - mirrors the Instagram dropdown reference's
  // back-arrow submenu instead of yet another nested accordion. null means
  // the top-level pane (the five category rows) is showing.
  const [systemDrillGroup, setSystemDrillGroup] = useState<
    "access-security" | "comms-content" | "external-services" | "modules" | "system-ops" | null
  >(null);

  // Category rows and each category's own leaf links, sorted by locale
  // (Intl-aware localeCompare against the active i18n language) rather than
  // hardcoded - so switching language re-sorts both panes to that
  // language's alphabetical order instead of staying pinned to German.
  // Replaces the old fixed JSX ordering (2026-08); see feedback asking for
  // this to be generally dynamic rather than a one-off fix.
  const systemCategories = useMemo(() => {
    const locale = i18nInstance.language;
    const categories: {
      key: "access-security" | "comms-content" | "external-services" | "modules" | "system-ops";
      label: string;
      links: { to: string; label: string }[];
    }[] = [
      {
        key: "external-services",
        label: t("shell.system_group_external_services"),
        links: [
          { to: "/admin/system/ai", label: t("admin.ai.title") },
          { to: "/admin/system/search", label: t("admin.search.title") },
        ],
      },
      {
        key: "comms-content",
        label: t("shell.system_group_comms_content"),
        links: [
          { to: "/admin/system/smtp", label: t("shell.smtp_link") },
          { to: "/admin/feeds", label: t("shell.feed_sources_link") },
          { to: "/admin/quick-links", label: t("shell.quick_links_link") },
        ],
      },
      {
        key: "modules",
        label: t("shell.module_management_link"),
        links: [
          { to: "/admin/modules/installed", label: t("admin.modules.installed_title") },
          { to: "/admin/modules/store", label: t("admin.modules.store_title") },
        ],
      },
      {
        key: "system-ops",
        label: t("shell.system_group_operations"),
        links: [
          { to: "/admin/system/limits", label: t("admin.system_limits.title") },
          { to: "/admin/system/general", label: t("admin.system_general.title") },
          { to: "/admin/system/info", label: t("admin.system_info.title") },
        ],
      },
      {
        key: "access-security",
        label: t("shell.system_group_access_security"),
        links: [
          { to: "/admin/audit", label: t("shell.audit_link") },
          { to: "/admin/users", label: t("shell.system_users") },
          { to: "/admin/system/geoip", label: t("admin.geoip.title") },
          { to: "/admin/security/info", label: t("shell.security_info_link") },
          { to: "/admin/system/oidc", label: t("shell.oidc_link") },
        ],
      },
    ];
    return categories
      .map((c) => ({ ...c, links: [...c.links].sort((a, b) => a.label.localeCompare(b.label, locale)) }))
      .sort((a, b) => a.label.localeCompare(b.label, locale));
  }, [t, i18nInstance.language]);

  const activeSystemCategory = systemCategories.find((c) => c.key === systemDrillGroup) ?? null;

  function toggleGroup(group: "modules" | "settings" | "system") {
    setOpenGroup((prev) => (prev === group ? null : group));
    if (group !== "system") setSystemDrillGroup(null);
  }

  return (
    <div>
      {/* Name/avatar is itself the link to /profile (identity + sessions +
          account deletion) - no separate "view profile" row underneath. */}
      <Link
        to="/profile"
        onClick={onClose}
        className="flex items-center gap-3 rounded-lg px-2.5 py-2 hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <Avatar session={session} className="h-9 w-9 text-xs" />
        <p className="flex-1 text-sm font-semibold">{displayName}</p>
        <i className="ti ti-chevron-right text-[14px] text-gray-300 dark:text-gray-600" />
      </Link>

      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />

      {activeModules.length > 0 && (
        <AccordionGroup
          icon="ti-apps"
          label={t("shell.modules_section")}
          open={openGroup === "modules"}
          onToggle={() => toggleGroup("modules")}
        >
          {activeModules.map((mod) => (
            <Link key={mod.name} to={`/modules/${mod.name}`} onClick={onClose} className={SUB_ITEM_CLASS}>
              {(() => {
                const mf = mod.manifest as { display_name?: Record<string, string>; name?: string } | null;
                const lng = i18nInstance.language?.slice(0, 2) ?? "en";
                return mf?.display_name?.[lng] ?? mf?.display_name?.["en"] ?? mf?.name ?? mod.name;
              })()}
            </Link>
          ))}
        </AccordionGroup>
      )}

      <AccordionGroup
        icon="ti-adjustments-horizontal"
        label={t("shell.settings_section")}
        open={openGroup === "settings"}
        onToggle={() => toggleGroup("settings")}
      >
        <Link to="/user/feeds" onClick={onClose} className={SUB_ITEM_CLASS}>
          {t("shell.my_feeds")}
        </Link>
        <Link to="/user/ai-keys" onClick={onClose} className={SUB_ITEM_CLASS}>
          {t("shell.ai_providers")}
        </Link>
        <Link to="/user/search-prefs" onClick={onClose} className={SUB_ITEM_CLASS}>
          {t("shell.search_settings")}
        </Link>
      </AccordionGroup>

      {/* Admin-only. Before 2026-07-29's role-model change there was a
          separate, less-privileged org-admin tier with no reachable
          capability left in this group; that tier is gone now, and this is
          simply the one admin group. */}
      {isSuperAdmin && (
        <AccordionGroup
          icon="ti-server-cog"
          label={t("shell.system_section")}
          open={openGroup === "system"}
          onToggle={() => toggleGroup("system")}
        >
          {/* Horizontal drill-in: two panes side by side inside a clipped
              viewport, slid left/right with translateX instead of navigating
              away. Replaced the old single 13-item flat list (2026-08) with
              five thematic categories, grouped by what each page actually
              does rather than by name similarity - GeoIP looks
              search-adjacent by name but its output (city/ISP for a session
              IP) only ever feeds the audit log and Security Info, so it
              lives under Access & Security, not External Services. Both the
              category row order and each category's own leaf-link order are
              computed from systemCategories above, sorted by localeCompare
              against the active i18n language - so the order re-sorts
              itself on language switch instead of staying pinned to one
              hardcoded language's alphabet. */}
          <div className="overflow-hidden">
            <div
              className="flex transition-transform duration-200"
              style={{ width: "200%", transform: systemDrillGroup ? "translateX(-50%)" : "translateX(0)" }}
            >
              <div className="flex w-1/2 flex-none flex-col">
                {systemCategories.map((cat) => (
                  <button
                    key={cat.key}
                    type="button"
                    onClick={() => setSystemDrillGroup(cat.key)}
                    className={SUB_ITEM_CLASS}
                  >
                    <span>{cat.label}</span>
                    <i className="ti ti-chevron-right text-[13px] text-gray-400" />
                  </button>
                ))}
              </div>
              <div className="flex w-1/2 flex-none flex-col">
                <button
                  type="button"
                  onClick={() => setSystemDrillGroup(null)}
                  className={`${SUB_ITEM_CLASS} justify-start gap-2 pl-2.5 font-medium text-gray-800 dark:text-gray-200`}
                >
                  <i className="ti ti-chevron-left text-[14px]" />
                  {activeSystemCategory?.label}
                </button>

                {activeSystemCategory?.links.map((link) => (
                  <Link key={link.to} to={link.to} onClick={onClose} className={SUB_ITEM_CLASS}>
                    {link.label}
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </AccordionGroup>
      )}

      {installPrompt.visible && (
        <>
          <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
          <button
            type="button"
            onClick={() => {
              if (installPrompt.canPromptInstall) {
                installPrompt.promptInstall();
              } else if (installPrompt.showIOSInstructions) {
                onShowIOSInstallHelp();
              }
            }}
            className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-device-mobile-plus text-[15px] text-gray-500" />
            {t("shell.add_to_homescreen")}
          </button>
        </>
      )}
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <div className="flex items-center justify-between px-2.5 py-2.5 text-sm">
        <span className="flex items-center gap-2.5">
          <i className="ti ti-moon text-[15px] text-gray-500" /> {t("shell.dark_mode")}
        </span>
        {/* Three-way segmented control rather than the old single on/off
            switch - "system" has no natural "on" position of its own, so a
            boolean toggle had no honest way to represent it. */}
        <div className="flex rounded-full border border-gray-200 bg-gray-100 p-0.5 dark:border-gray-700 dark:bg-gray-900">
          {(
            [
              { value: "light", icon: "ti-sun", label: t("shell.theme_light") },
              { value: "dark", icon: "ti-moon", label: t("shell.theme_dark") },
              { value: "system", icon: "ti-device-desktop", label: t("shell.theme_system") },
            ] as const
          ).map((opt) => (
            <button
              key={opt.value}
              type="button"
              aria-label={opt.label}
              aria-pressed={theme === opt.value}
              onClick={() => {
                setTheme(opt.value);
                // Persist to DB so the preference survives across devices,
                // same pattern as the language <select> below. Best-effort:
                // a failed save leaves the in-browser change intact for this
                // tab, but it will not survive a reload since there is no
                // longer a local cache of it.
                updateUserPrefs({ theme: opt.value }).catch(() => {});
              }}
              className={`flex h-6 w-8 items-center justify-center rounded-full transition-colors ${
                theme === opt.value
                  ? "bg-white text-teal-600 shadow-sm dark:bg-gray-700 dark:text-teal-400"
                  : "text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300"
              }`}
            >
              <i className={`ti ${opt.icon} text-[14px]`} aria-hidden="true" />
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center justify-between px-2.5 py-2.5 text-sm">
        <span className="flex items-center gap-2.5">
          <i className="ti ti-language text-[15px] text-gray-500" /> {t("shell.language")}
        </span>
        <select
          value={i18nInstance.language.slice(0, 2)}
          onChange={(e) => {
            const lang = e.target.value;
            ensureLanguage(lang).finally(() => {
              i18n.changeLanguage(lang);
            });
            // Persist to DB so the preference survives across devices.
            // Best-effort: a failed save leaves the in-browser change intact.
            updateUserPrefs({ ui_language: lang }).catch(() => {});
          }}
          className="rounded-md border border-gray-300 bg-white px-2 py-0.5 text-base font-medium text-gray-700 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
        >
          {/* Native endonyms intentionally hardcoded, not run through t() -
              a language switcher must show each option in its own language
              regardless of the current UI locale (standard convention). */}
          <option value="en">English</option>
          <option value="de">Deutsch</option>
          <option value="fr">Français</option>
          <option value="es">Español</option>
          <option value="nl">Nederlands</option>
        </select>
      </div>
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <button
        type="button"
        onClick={onLogout}
        className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-left text-sm text-red-600 hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-logout" /> {t("shell.sign_out")}
      </button>
    </div>
  );
}

// Notification bell's slide panel: pendingCount up top (the authoritative
// "how many right now", see AppShell's refreshPendingCount comment) and
// the in-memory event feed below it (what actually arrived over SSE this
// tab session - lost on reload, see FeedItem's doc comment). The two are
// deliberately not the same list: pendingCount answers "is there anything
// to do", the feed answers "what happened, and when" - someone who missed
// every toast can still see an accurate count, even with an empty feed.
function NotificationsPanelContent({
  pendingCount,
  moduleUpdateCount,
  coreUpdateAvailable,
  latestCoreVersion,
  feed,
  onReviewPending,
  onViewModuleUpdates,
  onViewCoreUpdate,
}: {
  pendingCount: number | null;
  moduleUpdateCount: number | null;
  coreUpdateAvailable: boolean;
  latestCoreVersion: string | undefined;
  feed: FeedItem[];
  onReviewPending: () => void;
  onViewModuleUpdates: () => void;
  onViewCoreUpdate: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div>
      {/* Pending user approvals */}
      <button
        type="button"
        onClick={onReviewPending}
        className="flex w-full items-center justify-between rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <span className="flex items-center gap-2.5">
          <i className="ti ti-user-check text-[15px] text-gray-500" />
          {pendingCount === null
            ? t("shell.notifications_panel.checking")
            : pendingCount === 0
              ? t("shell.notifications_panel.none_waiting")
              : pendingCount === 1
                ? t("shell.notifications_panel.waiting_one", { count: pendingCount })
                : t("shell.notifications_panel.waiting_many", { count: pendingCount })}
        </span>
        {!!pendingCount && pendingCount > 0 && <i className="ti ti-chevron-right text-gray-400" />}
      </button>

      {/* Module updates */}
      <button
        type="button"
        onClick={onViewModuleUpdates}
        className="flex w-full items-center justify-between rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <span className="flex items-center gap-2.5">
          <i className={`ti ti-puzzle text-[15px] ${moduleUpdateCount ? "text-amber-500" : "text-gray-500"}`} />
          {moduleUpdateCount === null
            ? t("shell.notifications_panel.checking")
            : moduleUpdateCount === 0
              ? t("shell.notifications_panel.no_module_updates")
              : moduleUpdateCount === 1
                ? t("shell.notifications_panel.module_updates_one", { count: moduleUpdateCount })
                : t("shell.notifications_panel.module_updates_many", { count: moduleUpdateCount })}
        </span>
        {!!moduleUpdateCount && moduleUpdateCount > 0 && (
          <span className="flex items-center gap-1">
            <span className="rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:bg-amber-900 dark:text-amber-300">
              {moduleUpdateCount}
            </span>
            <i className="ti ti-chevron-right text-gray-400" />
          </span>
        )}
      </button>

      {/* Core update - only shown when one is actually known, unlike the
          pending/module rows above which always show a "none"/"n" state.
          super-admin only (coreUpdateAvailable is never fetched, so always
          false, for any other role - see AppShell's own doc comment on
          coreUpdateAvailable). */}
      {coreUpdateAvailable && (
        <button
          type="button"
          onClick={onViewCoreUpdate}
          className="flex w-full items-center justify-between rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
        >
          <span className="flex items-center gap-2.5">
            <i className="ti ti-arrow-big-up-lines text-[15px] text-teal-600 dark:text-teal-400" />
            {latestCoreVersion
              ? t("shell.notifications_panel.core_update_one", { version: latestCoreVersion })
              : t("shell.notifications_panel.core_update_generic")}
          </span>
          <i className="ti ti-chevron-right text-gray-400" />
        </button>
      )}

      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <p className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {t("shell.notifications_panel.recent_activity")}
      </p>
      {feed.length === 0 ? (
        <p className="px-2.5 py-3 text-sm text-gray-500 dark:text-gray-400">
          {t("shell.notifications_panel.nothing_yet")}
        </p>
      ) : (
        feed.map((item) => (
          <div
            key={item.id}
            className="flex items-start justify-between gap-3 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <div className="min-w-0">
              <p className="whitespace-pre-wrap break-words">{item.message}</p>
              <p className="text-xs text-gray-400 dark:text-gray-500">{relativeTime(item.at, t)}</p>
            </div>
            {item.actionLabel && item.onAction && (
              <button
                type="button"
                onClick={item.onAction}
                className="flex-none text-xs font-medium text-teal-600 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
              >
                {item.actionLabel}
              </button>
            )}
          </div>
        ))
      )}
    </div>
  );
}

function relativeTime(at: number, t: TFunction): string {
  const seconds = Math.max(0, Math.floor((Date.now() - at) / 1000));
  if (seconds < 60) {
    return t("shell.notifications_panel.time_just_now");
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return t("shell.notifications_panel.time_minutes_ago", { count: minutes });
  }
  const hours = Math.floor(minutes / 60);
  return t("shell.notifications_panel.time_hours_ago", { count: hours });
}

function StatusPanelContent({ health }: { health: HealthDetailsResponse }) {
  const { t } = useTranslation();

  // /v1/health/details's uptime_seconds is a snapshot from the moment it
  // was fetched (AppShell only calls getHealthDetails() once, on mount) -
  // without a ticker the panel would show a frozen number until the whole
  // page is reloaded.
  //
  // This used to count ticks (setElapsedTick(s => s + 1)) instead of reading
  // the clock. Bug found 2026-07-05: setInterval is throttled/paused by the
  // browser while the tab is backgrounded or the device sleeps, and missed
  // ticks are never made up - so after e.g. a laptop sleep, the counter fell
  // far behind Docker's real "Up X" uptime even though the backend process
  // itself never restarted. useNow() (lib/useNow.ts) anchors on Date.now()
  // instead of counting to fix this: the interval only forces a re-render,
  // the displayed value is always derived from the actual wall-clock
  // difference, so it self-heals the moment the tab wakes up again.
  const [fetchedAt] = useState(() => Date.now());
  const now = useNow();
  const uptimeSeconds = health.uptime_seconds + Math.floor((now - fetchedAt) / 1000);

  // Module worker health - see healthStatus's ModulesActive/Degraded/Failed
  // doc comment (main.go) for what "degraded" means. Hidden entirely when
  // no modules are installed at all (0/0/0), since a "0 active" row would
  // read as a problem to someone who simply hasn't installed anything yet.
  const modulesTotal = health.modules_active + health.modules_degraded + health.modules_failed;
  const modulesHaveIssues = health.modules_degraded > 0 || health.modules_failed > 0;
  const modulesValue = modulesHaveIssues
    ? t("shell.status.modules_issues", {
        active: health.modules_active,
        degraded: health.modules_degraded,
        failed: health.modules_failed,
      })
    : t("shell.status.modules_all_active", { count: health.modules_active });

  return (
    <div className="text-sm">
      {/* One version, because Core and the frontend ship in the same binary
          and are built from the same tree - there is no "backend version"
          and "frontend version" to compare anymore. The second row appears
          only when they disagree, which leaves exactly two ways to read it:
          a release landed while this tab was open (the stale-build prompt
          above says so too), or whoever bumped the version touched
          version.go and package.json inconsistently. Both are worth
          showing; neither is worth a permanent row. */}
      <StatusRow icon="ti-server" label={t("shell.status.version")} value={health.version} />
      {FRONTEND_VERSION !== health.version && (
        <StatusRow icon="ti-browser" label={t("shell.status.frontend_version")} value={FRONTEND_VERSION} />
      )}
      <StatusRow icon="ti-clock" label={t("shell.status.uptime")} value={formatUptime(uptimeSeconds)} />
      <StatusRow icon="ti-database" label={t("shell.status.postgres")} ok={health.postgres_reachable} />
      <StatusRow icon="ti-bolt" label={t("shell.status.valkey")} ok={health.valkey_reachable} />
      {health.searxng_configured ? (
        <StatusRow icon="ti-search" label={t("shell.status.searxng")} ok={health.searxng_reachable} />
      ) : (
        <StatusRow icon="ti-search" label={t("shell.status.searxng")} value={t("shell.status.not_configured")} />
      )}
      {health.ntp_drift_ok !== undefined && (
        <StatusRow icon="ti-clock-check" label={t("shell.status.ntp")} ok={health.ntp_drift_ok} />
      )}
      {modulesTotal > 0 && (
        <StatusRow
          icon="ti-puzzle"
          label={t("shell.status.modules")}
          value={modulesValue}
          tone={modulesHaveIssues ? "warn" : "ok"}
        />
      )}
    </div>
  );
}

function StatusRow({
  icon,
  label,
  value,
  ok,
  tone,
}: {
  icon: string;
  label: string;
  value?: string;
  ok?: boolean;
  // Only meaningful together with value (the ok/unreachable dot below
  // already has its own green/red logic) - lets a value row like the
  // module summary draw attention (warn) or confirm health (ok) instead of
  // always rendering as neutral gray text.
  tone?: "ok" | "warn";
}) {
  const { t } = useTranslation();
  const valueClass =
    tone === "warn"
      ? "text-amber-600 dark:text-amber-400 font-medium"
      : tone === "ok"
        ? "text-teal-700 dark:text-teal-400 font-medium"
        : "text-gray-500";
  return (
    <div className="flex items-center justify-between border-b border-gray-100 px-1 py-2.5 last:border-0 dark:border-gray-800">
      <span className="flex items-center gap-2.5">
        <i className={`ti ${icon} text-[15px] text-gray-400`} /> {label}
      </span>
      {value !== undefined ? (
        <span className={`text-xs ${valueClass}`}>{value}</span>
      ) : (
        <span
          className={`flex items-center gap-1.5 text-xs font-medium ${ok ? "text-teal-700 dark:text-teal-400" : "text-red-600"}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-teal-600" : "bg-red-600"}`} />
          {ok ? t("shell.status.reachable") : t("shell.status.unreachable")}
        </span>
      )}
    </div>
  );
}

// --- Avatar -----------------------------------------------------------

// Shows the OIDC provider's profile picture (session.picture, e.g. from
// PocketID) when one is set; otherwise falls back to initials derived
// from the real display name (session.name), and only falls back further
// to the email address if the IdP never populated a name either. className
// must include an explicit size (e.g. "h-8 w-8") since this is used at
// several different sizes (header button, profile panel, and now
// ProfilePage's own larger header) - exported so ProfilePage.tsx can reuse
// it instead of a fourth copy-pasted picture-or-initials fallback.
export function Avatar({ session, className }: { session: Session; className: string }) {
  if (session.picture) {
    return (
      <img
        src={session.picture}
        alt={session.name || session.email}
        className={`rounded-full object-cover ${className}`}
      />
    );
  }
  return (
    <span
      className={`flex items-center justify-center rounded-full bg-gray-100 font-semibold dark:bg-gray-800 ${className}`}
    >
      {initials(session)}
    </span>
  );
}

// --- Small helpers ---------------------------------------------------------

function initials(session: Session): string {
  const name = session.name.trim();
  if (name) {
    const parts = name.split(/\s+/).filter(Boolean);
    const letters = parts.length >= 2 ? `${parts[0][0]}${parts[1][0]}` : name.slice(0, 2);
    return letters.toUpperCase();
  }
  return initialsFromEmail(session.email);
}

function initialsFromEmail(email: string): string {
  const name = email.split("@")[0] ?? email;
  const parts = name.split(/[._-]/).filter(Boolean);
  const letters = parts.length >= 2 ? `${parts[0][0]}${parts[1][0]}` : name.slice(0, 2);
  return letters.toUpperCase();
}

function formatUptime(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  if (hours < 24) {
    return `${hours}h ${remMinutes}m`;
  }
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return `${days}d ${remHours}h`;
}

// --- ChatPanel --------------------------------------------------------------
// Floating chat panel that opens from the sparkles button in the header.
// Streams responses via SSE (streamAIChat in lib/api.ts). No persistence —
// messages live only in component state for the lifetime of this mount.

function ChatPanel({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [providers, setProviders] = useState<AIUserProvider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<AIUserProvider | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [modelPickerOpen, setModelPickerOpen] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  // Whether new content should auto-scroll the panel to the bottom. Starts
  // true (a fresh panel has nothing to scroll away from) and is kept in a
  // ref rather than state - it needs to be read from inside the
  // streaming-delta callback above without re-subscribing that callback on
  // every scroll tick, and writing it must not itself trigger a render.
  //
  // Bug (reported 2026-07-08): the old effect below scrolled to the bottom
  // unconditionally on every `messages` change, including every single
  // streamed token - so once a reply grew past one screenful, there was no
  // way to scroll up and read earlier text: the very next delta yanked the
  // view straight back down. Now a scroll handler on the message list
  // tracks whether the user is still near the bottom (stuckToBottomRef) and
  // the auto-scroll effect only fires while that holds - scroll up during
  // streaming and it stays put; scroll back down (or send a new message,
  // see handleSend) and it resumes following along.
  const stuckToBottomRef = useRef(true);
  // px of slack from the true bottom still counted as "at the bottom" - a
  // smooth-scroll animation or a fraction-of-a-pixel layout rounding
  // shouldn't be enough to count as "the user scrolled away".
  const BOTTOM_SLACK_PX = 48;

  function handleMessagesScroll() {
    const el = messagesContainerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    stuckToBottomRef.current = distanceFromBottom <= BOTTOM_SLACK_PX;
  }

  // Load available providers on mount and restore the user's last selection.
  useEffect(() => {
    listAIProviders()
      .then(({ providers: list, preferred_provider_id }) => {
        const available = list.filter((p) => p.available);
        setProviders(available);
        if (available.length === 0) return;
        const preferred = preferred_provider_id
          ? available.find((p) => p.id === preferred_provider_id)
          : null;
        setSelectedProvider(preferred ?? available[0]);
      })
      .catch(() => {});
  }, []);

  // Scroll to bottom whenever messages change - but only while the user is
  // still stuck to the bottom (see stuckToBottomRef's doc comment above).
  useEffect(() => {
    if (stuckToBottomRef.current) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  // Stop streaming when panel closes.
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  async function handleSend() {
    if (!input.trim() || streaming || !selectedProvider) return;

    // Sending a message is a deliberate action - resume following the
    // conversation even if the user had scrolled up to reread something
    // earlier, same as most chat UIs.
    stuckToBottomRef.current = true;

    const userMsg: ChatMessage = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setStreaming(true);

    // Placeholder assistant message that we stream into.
    setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      await streamAIChat(
        selectedProvider.id,
        "", // model is determined server-side based on key type
        newMessages,
        (delta) => {
          setMessages((prev) => {
            const copy = [...prev];
            const last = copy[copy.length - 1];
            if (last?.role === "assistant") {
              copy[copy.length - 1] = { ...last, content: last.content + delta };
            }
            return copy;
          });
        },
        ctrl.signal,
      );
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        setMessages((prev) => {
          const copy = [...prev];
          const last = copy[copy.length - 1];
          if (last?.role === "assistant" && last.content === "") {
            copy[copy.length - 1] = { ...last, content: t("shell.chat.error") };
          }
          return copy;
        });
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    // Below sm: inset-x-4 spans the panel edge-to-edge (minus a 16px margin
    // on each side) instead of the fixed 340px/right-4 floating box, which
    // on a narrow phone (iPhone SE and similar, ~320-375px wide) left next
    // to no margin on one side and could clip on the other. From sm up,
    // reverts to the original floating box anchored bottom-right.
    <div className="fixed inset-x-4 bottom-[52px] z-40 flex flex-col rounded-2xl border border-gray-200 bg-white shadow-xl dark:border-gray-800 dark:bg-gray-950 sm:inset-x-auto sm:right-4 sm:w-[340px]"
      style={{ maxHeight: "calc(100dvh - 120px)" }}
    >
      {/* Header */}
      <div className="flex flex-none items-center justify-between border-b border-gray-100 px-4 py-3 dark:border-gray-800">
        <div className="flex min-w-0 items-center gap-2">
          <i className="ti ti-sparkles flex-none text-[16px] text-teal-600 dark:text-teal-400" />
          <div className="min-w-0">
            <span className="text-sm font-semibold">{t("shell.ai_chat")}</span>
          </div>
        </div>
        <div className="flex flex-none items-center gap-1.5">
          {/* Provider selector */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setModelPickerOpen((v) => !v)}
              className="flex items-center gap-1 rounded-md border border-gray-200 bg-gray-50 px-2 py-1 text-[11px] text-gray-600 hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300"
            >
              <span className="max-w-[120px] break-words text-left leading-tight">{selectedProvider?.name ?? t("shell.chat.no_provider")}</span>
              <i className="ti ti-chevron-down text-[10px]" />
            </button>
            {modelPickerOpen && providers.length > 0 && (
              <div className="absolute right-0 top-full z-10 mt-1 w-56 rounded-xl border border-gray-200 bg-white shadow-lg dark:border-gray-700 dark:bg-gray-900">
                {providers.map((p) => {
                  const modelLabel = (p.has_user_key && p.preferred_model) ? p.preferred_model : p.default_model;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => {
                        setSelectedProvider(p);
                        setModelPickerOpen(false);
                        setAIPreferredProvider(p.id).catch(() => {});
                      }}
                      className={`flex w-full flex-col px-3 py-2 text-left text-xs hover:bg-gray-50 dark:hover:bg-gray-800 ${
                        p.id === selectedProvider?.id ? "text-teal-600 dark:text-teal-400" : "text-gray-700 dark:text-gray-300"
                      }`}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="flex-1 break-words font-medium">{p.name}</span>
                        {p.has_user_key && (
                          <span className="rounded-full bg-teal-50 px-1.5 py-0.5 text-[10px] text-teal-600 dark:bg-teal-950 dark:text-teal-400">
                            {t("shell.chat.own_key")}
                          </span>
                        )}
                      </div>
                      <span className="mt-0.5 break-words text-[10px] text-gray-400 dark:text-gray-500">
                        {modelLabel}
                        {!p.has_user_key && ` ${t("shell.chat.managed_by")}`}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          <button
            type="button"
            aria-label={t("shell.close_chat")}
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
          >
            <i className="ti ti-x text-[14px]" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div
        ref={messagesContainerRef}
        onScroll={handleMessagesScroll}
        className="flex-1 overflow-y-auto px-3 py-3"
        style={{ minHeight: "200px" }}
      >
        {messages.length === 0 ? (
          <p className="mt-8 text-center text-xs text-gray-400 dark:text-gray-600">
            {providers.length === 0
              ? t("shell.chat.no_providers_configured")
              : t("shell.chat.ask_anything")}
          </p>
        ) : (
          <div className="space-y-3">
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed ${
                    msg.role === "user"
                      ? "bg-teal-600 text-white"
                      : "border border-gray-100 bg-gray-50 text-gray-800 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200"
                  }`}
                  style={{ whiteSpace: "pre-wrap" }}
                >
                  {msg.content || (streaming && msg.role === "assistant" ? (
                    <span className="animate-pulse text-gray-400">…</span>
                  ) : "")}
                </div>
              </div>
            ))}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex flex-none items-end gap-2 border-t border-gray-100 p-3 dark:border-gray-800">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={providers.length === 0 ? t("shell.chat.no_providers_available") : t("shell.chat.placeholder")}
          disabled={streaming || providers.length === 0}
          rows={1}
          className="flex-1 resize-none rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 text-base outline-none placeholder:text-gray-400 focus:border-teal-400 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200"
          style={{ minHeight: "36px", maxHeight: "120px" }}
          onInput={(e) => {
            const el = e.currentTarget;
            el.style.height = "auto";
            el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
          }}
        />
        {streaming ? (
          <button
            type="button"
            onClick={() => abortRef.current?.abort()}
            aria-label={t("shell.chat.stop")}
            className="flex h-8 w-8 flex-none items-center justify-center rounded-full border border-red-200 text-red-500 hover:bg-red-50 dark:border-red-800 dark:hover:bg-red-950"
          >
            <i className="ti ti-square text-[14px]" />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSend}
            disabled={!input.trim() || providers.length === 0}
            aria-label={t("shell.chat.send")}
            className="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-teal-600 text-white hover:bg-teal-700 disabled:opacity-40"
          >
            <i className="ti ti-send text-[14px]" />
          </button>
        )}
      </div>
    </div>
  );
}
