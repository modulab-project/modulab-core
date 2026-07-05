import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate, Link } from "react-router";
import { useTranslation } from "react-i18next";
import i18n from "../lib/i18n";
import {
  getHealth,
  getUserPrefs,
  listAIProviders,
  setAIPreferredProvider,
  listInstalledModules,
  listUsers,
  logoutRequest,
  streamAIChat,
  updateUserPrefs,
  type AIUserProvider,
  type ChatMessage,
  type HealthResponse,
  type InstalledModule,
  type Session,
} from "../lib/api";
import { clearSessionToken, getSessionToken } from "../lib/session";
import { useNotificationEvents, type ServerEvent } from "../lib/useEvents";
import { useToasts, ToastStack } from "./Toast";
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
const THEME_KEY = "modulab_theme";
const ADMIN_ROLES = ["org-admin", "super-admin"];
const PROJECT_URL = "https://modulab.app";
const GITHUB_URL = "https://github.com/modulab-project/modulab-core";

// Exported so other admin-only pages (currently AdminUsersPage.tsx) can
// gate themselves with the exact same definition AppShell itself uses for
// the status panel and the profile menu's "Admin" section, instead of a
// second copy of this list drifting out of sync.
export function isAdminRole(role: string): boolean {
  return ADMIN_ROLES.includes(role);
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
}: {
  session: Session;
  children: ReactNode;
}) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [openPanel, setOpenPanel] = useState<OpenPanel>(null);
  const [dark, setDark] = useState(() => localStorage.getItem(THEME_KEY) === "dark");
  const [activeModules, setActiveModules] = useState<InstalledModule[]>([]);
  // How many installed modules have an update waiting (available_version set).
  // Shown in the notification bell badge alongside pending-user count.
  // null = not yet fetched, 0 = all up to date, n = n updates available.
  const [moduleUpdateCount, setModuleUpdateCount] = useState<number | null>(null);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem(THEME_KEY, dark ? "dark" : "light");
  }, [dark]);

  // Unconditional on mount, not gated behind a session effect of its own -
  // by the time AppShell renders, the caller has already resolved a
  // session (see lib/useSession.ts), so there is nothing left to wait on
  // here.
  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  // Load active modules (for navigation links) and count pending updates
  // (for the notification badge). Merged into one call to avoid a second
  // round-trip. Re-runs via refreshModuleUpdateCount when the notification
  // panel is opened so the count is always fresh when the admin looks at it.
  const refreshModuleUpdateCount = useCallback(() => {
    const token = getSessionToken();
    if (!token) return;
    listInstalledModules(token)
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

  // Load the stored UI language on first render for this user and apply it
  // so the preference survives across browsers and devices. Best-effort: a
  // failed fetch leaves the existing browser/localStorage language in place.
  useEffect(() => {
    const token = getSessionToken();
    if (!token) return;
    getUserPrefs(token)
      .then((prefs) => {
        if (prefs.ui_language && !i18n.language.startsWith(prefs.ui_language)) {
          i18n.changeLanguage(prefs.ui_language);
        }
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.user_id]); // re-run if a different user logs in within the same tab

  async function handleLogout() {
    const token = getSessionToken();
    clearSessionToken();
    if (token) {
      try {
        await logoutRequest(token);
      } catch {
        // Already invalid server-side - the local sign-out still succeeds.
      }
    }
    navigate("/login", { replace: true });
  }

  const isAdmin = isAdminRole(session.role);
  const [chatOpen, setChatOpen] = useState(false);

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
    const token = getSessionToken();
    if (!token) {
      return;
    }
    listUsers(token)
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

  // Spec section 3.5's real-time notifications: every authenticated page
  // using AppShell gets one SSE connection (lib/useEvents.ts), but only
  // org-admin/super-admin sessions ever actually receive anything on
  // it today - "user.pending" and "module.updates_available" are both
  // published exclusively to notify.AdminChannel() (backend/internal/
  // auth/handlers.go and backend/internal/modules/status.go respectively),
  // so a plain "user" session's connection just sits idle, costing one
  // open connection for symmetry/future events rather than anything it
  // currently uses.
  const { toasts, push } = useToasts();
  useNotificationEvents(getSessionToken(), (event: ServerEvent) => {
    if (event.type === "user.pending" && isAdmin) {
      const data = (event.data ?? {}) as { email?: string; name?: string };
      const who = data.name?.trim() || data.email || "Someone";
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
        setUnreadModuleNotifications(0);
      }
      return next;
    });
  }

  return (
    <div className="flex h-screen flex-col bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100">
      <Header
        session={session}
        isAdmin={isAdmin}
        pendingCount={pendingCount}
        moduleUpdateCount={moduleUpdateCount}
        unreadModuleNotifications={unreadModuleNotifications}
        openPanel={openPanel}
        onTogglePanel={togglePanel}
        chatOpen={chatOpen}
        onToggleChat={() => setChatOpen((v) => !v)}
      />

      <main className="flex-1 overflow-y-auto px-3 sm:px-6">{children}</main>

      <FooterBar isAdmin={isAdmin} health={health} onTogglePanel={togglePanel} />
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
          isAdmin={isAdmin}
          dark={dark}
          setDark={setDark}
          onLogout={handleLogout}
          onClose={() => setOpenPanel(null)}
          activeModules={activeModules}
        />
      </SlidePanel>
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
          feed={feed}
          onReviewPending={() => {
            setOpenPanel(null);
            navigate("/admin/users");
          }}
          onViewModuleUpdates={() => {
            setOpenPanel(null);
            navigate("/admin/modules/installed");
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
              const total = (pendingCount ?? 0) + (moduleUpdateCount ?? 0) + unreadModuleNotifications;
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
  health: HealthResponse | null;
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
        {t("shell.versions", { core: health?.version ?? "…", frontend: FRONTEND_VERSION })}
      </span>
      <span className="flex items-center gap-3">
        <a href={PROJECT_URL} className="hover:text-gray-700 dark:hover:text-gray-200">
          modulab.app
        </a>
        <a href={GITHUB_URL} className="hover:text-gray-700 dark:hover:text-gray-200">
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
            className="flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-x" />
          </button>
        </div>
      )}
      <div className="flex-1 overflow-y-auto p-2.5">{open && children}</div>
    </div>
  );
}

function ProfilePanelContent({
  session,
  isAdmin,
  dark,
  setDark,
  onLogout,
  onClose,
  activeModules,
}: {
  session: Session;
  isAdmin: boolean;
  dark: boolean;
  setDark: (d: boolean) => void;
  onLogout: () => void;
  onClose: () => void;
  activeModules: InstalledModule[];
}) {
  const { t, i18n: i18nInstance } = useTranslation();
  const displayName = session.name.trim() || session.email;

  return (
    <div>
      <div className="flex items-center gap-3 px-2.5 py-2">
        <Avatar session={session} className="h-9 w-9 text-xs" />
        <div>
          <p className="text-sm font-semibold">{displayName}</p>
        </div>
      </div>
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <Link
        to="/profile"
        onClick={onClose}
        className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-user text-[15px] text-gray-500" /> {t("shell.view_profile")}
      </Link>
      <Link
        to="/user/feeds"
        onClick={onClose}
        className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-rss text-[15px] text-gray-500" /> {t("shell.my_feeds")}
      </Link>
      <Link
        to="/user/search-prefs"
        onClick={onClose}
        className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-search text-[15px] text-gray-500" /> {t("shell.search_settings")}
      </Link>
      <Link
        to="/user/ai-keys"
        onClick={onClose}
        className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-sparkles text-[15px] text-gray-500" /> {t("shell.ai_providers")}
      </Link>
      {activeModules.length > 0 && (
        <>
          <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
          <p className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
            {t("shell.modules_section")}
          </p>
          {activeModules.map((mod) => (
            <Link
              key={mod.name}
              to={`/modules/${mod.name}`}
              onClick={onClose}
              className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
            >
              <i className="ti ti-puzzle text-[15px] text-gray-500" />
              {(() => {
                const mf = mod.manifest as { display_name?: Record<string, string>; name?: string } | null;
                const lng = i18nInstance.language?.slice(0, 2) ?? "en";
                return mf?.display_name?.[lng] ?? mf?.display_name?.["en"] ?? mf?.name ?? mod.name;
              })()}
            </Link>
          ))}
        </>
      )}
      {isAdmin && (
        <>
          <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
          <p className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
            {t("shell.admin_section")}
          </p>
          <Link
            to="/admin/users"
            onClick={onClose}
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-users text-[15px] text-gray-500" /> {t("shell.users_link")}
          </Link>
          <Link
            to="/admin/feeds"
            onClick={onClose}
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-rss text-[15px] text-gray-500" /> {t("shell.news_feeds_link")}
          </Link>
          <Link
            to="/admin/quick-links"
            onClick={onClose}
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-layout-grid text-[15px] text-gray-500" /> {t("shell.quick_links_link")}
          </Link>
          <Link
            to="/admin/modules"
            onClick={onClose}
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-puzzle text-[15px] text-gray-500" /> {t("shell.modules_link")}
          </Link>
          {session.role === "super-admin" && (
            <>
              <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
              <Link
                to="/admin/audit"
                onClick={onClose}
                className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
              >
                <i className="ti ti-shield-check text-[15px] text-gray-500" /> {t("shell.audit_link")}
              </Link>
              <Link
                to="/admin/system"
                onClick={onClose}
                className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
              >
                <i className="ti ti-settings text-[15px] text-gray-500" /> {t("shell.system_link")}
              </Link>
            </>
          )}
        </>
      )}
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <div className="flex items-center justify-between px-2.5 py-2.5 text-sm">
        <span className="flex items-center gap-2.5">
          <i className="ti ti-moon text-[15px] text-gray-500" /> {t("shell.dark_mode")}
        </span>
        <button
          type="button"
          aria-label={t("shell.toggle_dark")}
          onClick={() => setDark(!dark)}
          className={`relative h-[22px] w-10 rounded-full border transition-colors ${
            dark ? "border-teal-600 bg-teal-600" : "border-gray-300 bg-gray-100"
          }`}
        >
          <span
            className={`absolute top-[2px] h-4 w-4 rounded-full bg-white transition-all ${
              dark ? "left-[21px]" : "left-[2px]"
            }`}
          />
        </button>
      </div>
      <div className="flex items-center justify-between px-2.5 py-2.5 text-sm">
        <span className="flex items-center gap-2.5">
          <i className="ti ti-language text-[15px] text-gray-500" /> {t("shell.language")}
        </span>
        <select
          value={i18nInstance.language.slice(0, 2)}
          onChange={(e) => {
            const lang = e.target.value;
            i18n.changeLanguage(lang);
            // Persist to DB so the preference survives across devices.
            // Best-effort: a failed save leaves the in-browser change intact.
            const token = getSessionToken();
            if (token) {
              updateUserPrefs(token, { ui_language: lang }).catch(() => {});
            }
          }}
          className="rounded-md border border-gray-300 bg-white px-2 py-0.5 text-xs font-medium text-gray-700 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300"
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
  feed,
  onReviewPending,
  onViewModuleUpdates,
}: {
  pendingCount: number | null;
  moduleUpdateCount: number | null;
  feed: FeedItem[];
  onReviewPending: () => void;
  onViewModuleUpdates: () => void;
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
              <p className="text-xs text-gray-400 dark:text-gray-500">{relativeTime(item.at)}</p>
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

function relativeTime(at: number): string {
  const seconds = Math.max(0, Math.floor((Date.now() - at) / 1000));
  if (seconds < 60) {
    return "just now";
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function StatusPanelContent({ health }: { health: HealthResponse }) {
  const { t } = useTranslation();

  // /healthz's uptime_seconds is a snapshot from the moment it was fetched
  // (AppShell only calls getHealth() once, on mount) - without a ticker the
  // panel would show a frozen number until the whole page is reloaded.
  //
  // This used to count ticks (setElapsedTick(s => s + 1)) instead of reading
  // the clock. Bug found 2026-07-05: setInterval is throttled/paused by the
  // browser while the tab is backgrounded or the device sleeps, and missed
  // ticks are never made up - so after e.g. a laptop sleep, the counter fell
  // far behind Docker's real "Up X" uptime even though the backend process
  // itself never restarted. Anchoring on Date.now() instead of counting
  // fixes this: the interval only forces a re-render, the displayed value is
  // always derived from the actual wall-clock difference, so it self-heals
  // the moment the tab wakes up again.
  const fetchedAtRef = useRef(Date.now());
  const [, forceTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => forceTick((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);
  const uptimeSeconds =
    health.uptime_seconds + Math.floor((Date.now() - fetchedAtRef.current) / 1000);

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
      <StatusRow icon="ti-server" label={t("shell.status.backend_version")} value={health.version} />
      <StatusRow icon="ti-browser" label={t("shell.status.frontend_version")} value={FRONTEND_VERSION} />
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

  // Load available providers on mount and restore the user's last selection.
  useEffect(() => {
    const token = getSessionToken();
    if (!token) return;
    listAIProviders(token)
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

  // Scroll to bottom whenever messages change.
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Stop streaming when panel closes.
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  async function handleSend() {
    if (!input.trim() || streaming || !selectedProvider) return;
    const token = getSessionToken();
    if (!token) return;

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
        token,
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

  // Derive the active model label for display: user's preferred model when
  // they have their own key, otherwise the admin-set default.

  return (
    <div className="fixed bottom-[52px] right-4 z-40 flex w-[340px] flex-col rounded-2xl border border-gray-200 bg-white shadow-xl dark:border-gray-800 dark:bg-gray-950"
      style={{ maxHeight: "calc(100vh - 120px)" }}
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
              <span className="max-w-[80px] truncate">{selectedProvider?.name ?? t("shell.chat.no_provider")}</span>
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
                        const token = getSessionToken();
                        if (token) setAIPreferredProvider(token, p.id).catch(() => {});
                      }}
                      className={`flex w-full flex-col px-3 py-2 text-left text-xs hover:bg-gray-50 dark:hover:bg-gray-800 ${
                        p.id === selectedProvider?.id ? "text-teal-600 dark:text-teal-400" : "text-gray-700 dark:text-gray-300"
                      }`}
                    >
                      <div className="flex items-center gap-1.5">
                        <span className="flex-1 truncate font-medium">{p.name}</span>
                        {p.has_user_key && (
                          <span className="rounded-full bg-teal-50 px-1.5 py-0.5 text-[10px] text-teal-600 dark:bg-teal-950 dark:text-teal-400">
                            {t("shell.chat.own_key")}
                          </span>
                        )}
                      </div>
                      <span className="mt-0.5 truncate text-[10px] text-gray-400 dark:text-gray-500">
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
            className="flex h-7 w-7 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <i className="ti ti-x text-[14px] text-gray-500" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-3 py-3" style={{ minHeight: "200px" }}>
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
            className="flex h-8 w-8 flex-none items-center justify-center rounded-full border border-red-200 text-red-500 hover:bg-red-50 dark:border-red-800 dark:hover:bg-red-950"
          >
            <i className="ti ti-square text-[14px]" />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSend}
            disabled={!input.trim() || providers.length === 0}
            className="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-teal-600 text-white hover:bg-teal-700 disabled:opacity-40"
          >
            <i className="ti ti-send text-[14px]" />
          </button>
        )}
      </div>
    </div>
  );
}
