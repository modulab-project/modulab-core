import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useNavigate, Link } from "react-router-dom";
import { getHealth, listUsers, logoutRequest, type HealthResponse, type Session } from "../lib/api";
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
export function AppShell({ session, children }: { session: Session; children: ReactNode }) {
  const navigate = useNavigate();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [openPanel, setOpenPanel] = useState<OpenPanel>(null);
  const [dark, setDark] = useState(() => localStorage.getItem(THEME_KEY) === "dark");

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
  // it today - "user.pending" is published exclusively to
  // notify.AdminChannel() (backend/internal/auth/handlers.go), so a plain
  // "user" session's connection just sits idle, costing one open
  // connection for symmetry/future events rather than anything it
  // currently uses.
  const { toasts, push } = useToasts();
  useNotificationEvents(getSessionToken(), (event: ServerEvent) => {
    if (event.type === "user.pending" && isAdmin) {
      const data = (event.data ?? {}) as { email?: string; name?: string };
      const who = data.name?.trim() || data.email || "Someone";
      const goReview = () => navigate("/admin/users");
      push({ message: `${who} is waiting for approval.`, actionLabel: "Review", onAction: goReview });
      setFeed((prev) => [
        { id: nextFeedItemID++, message: `${who} is waiting for approval.`, at: Date.now(), actionLabel: "Review", onAction: goReview },
        ...prev,
      ].slice(0, FEED_LIMIT));
      refreshPendingCount();
    }
  });

  function togglePanel(panel: Exclude<OpenPanel, null>) {
    setOpenPanel((current) => {
      const next = current === panel ? null : panel;
      if (next === "notifications") {
        refreshPendingCount();
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
        openPanel={openPanel}
        onTogglePanel={togglePanel}
      />

      <main className="flex-1 overflow-y-auto px-3 sm:px-6">{children}</main>

      <FooterBar isAdmin={isAdmin} health={health} onTogglePanel={togglePanel} />
      <ToastStack toasts={toasts} />

      {openPanel && (
        <div
          className="fixed inset-x-0 top-[60px] bottom-[44px] z-10 bg-black/35"
          onClick={() => setOpenPanel(null)}
        />
      )}
      <SlidePanel open={openPanel === "profile"} onClose={() => setOpenPanel(null)}>
        <ProfilePanelContent
          session={session}
          isAdmin={isAdmin}
          dark={dark}
          setDark={setDark}
          onLogout={handleLogout}
        />
      </SlidePanel>
      <SlidePanel open={openPanel === "status"} onClose={() => setOpenPanel(null)} title="System status">
        {health && <StatusPanelContent health={health} />}
      </SlidePanel>
      <SlidePanel
        open={openPanel === "notifications"}
        onClose={() => setOpenPanel(null)}
        title="Notifications"
      >
        <NotificationsPanelContent
          pendingCount={pendingCount}
          feed={feed}
          onReviewPending={() => {
            setOpenPanel(null);
            navigate("/admin/users");
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
  openPanel,
  onTogglePanel,
}: {
  session: Session;
  isAdmin: boolean;
  pendingCount: number | null;
  openPanel: OpenPanel;
  onTogglePanel: (panel: Exclude<OpenPanel, null>) => void;
}) {
  const navigate = useNavigate();
  return (
    <header className="flex h-[60px] flex-none items-center justify-between border-b border-gray-200 px-3 sm:px-6 dark:border-gray-800">
      <button
        type="button"
        aria-label="Go to home"
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
            aria-label="Notifications"
            aria-haspopup="true"
            aria-expanded={openPanel === "notifications"}
            onClick={() => onTogglePanel("notifications")}
            className="relative flex h-8 w-8 items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-900"
          >
            <i className="ti ti-bell text-[18px] text-gray-500 dark:text-gray-400" />
            {!!pendingCount && pendingCount > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-semibold leading-none text-white">
                {pendingCount > 9 ? "9+" : pendingCount}
              </span>
            )}
          </button>
        )}
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
  const allOk = !!health && health.postgres_reachable && health.valkey_reachable;

  return (
    <footer className="flex flex-none flex-wrap items-center justify-center gap-2 border-t border-gray-200 px-3 py-2 text-xs text-gray-500 sm:gap-6 dark:border-gray-800 dark:text-gray-400">
      {isAdmin && health && (
        <button
          type="button"
          onClick={() => onTogglePanel("status")}
          className={`flex items-center gap-1.5 rounded-xl px-3 py-1 font-medium ${
            allOk
              ? "bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-400"
              : "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-400"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 animate-pulse rounded-full ${allOk ? "bg-green-700 dark:bg-green-400" : "bg-red-700 dark:bg-red-400"}`}
          />
          {allOk ? "All systems normal" : "Attention needed"}
        </button>
      )}
      <span>
        Core {health?.version ?? "…"} · Frontend {FRONTEND_VERSION}
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
            aria-label="Close"
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
}: {
  session: Session;
  isAdmin: boolean;
  dark: boolean;
  setDark: (d: boolean) => void;
  onLogout: () => void;
}) {
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
        className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-user text-[15px] text-gray-500" /> View profile
      </Link>
      {isAdmin && (
        <>
          <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
          <p className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
            Admin
          </p>
          <Link
            to="/admin/users"
            className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <i className="ti ti-users text-[15px] text-gray-500" /> Users
          </Link>
          {session.role === "super-admin" && (
            <Link
              to="/admin/smtp"
              className="flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
            >
              <i className="ti ti-mail text-[15px] text-gray-500" /> SMTP
            </Link>
          )}
        </>
      )}
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <div className="flex items-center justify-between px-2.5 py-2.5 text-sm">
        <span className="flex items-center gap-2.5">
          <i className="ti ti-moon text-[15px] text-gray-500" /> Dark mode
        </span>
        <button
          type="button"
          aria-label="Toggle dark mode"
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
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <button
        type="button"
        onClick={onLogout}
        className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-left text-sm text-red-600 hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <i className="ti ti-logout" /> Sign out
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
  feed,
  onReviewPending,
}: {
  pendingCount: number | null;
  feed: FeedItem[];
  onReviewPending: () => void;
}) {
  return (
    <div>
      <button
        type="button"
        onClick={onReviewPending}
        className="flex w-full items-center justify-between rounded-lg px-2.5 py-2.5 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
      >
        <span className="flex items-center gap-2.5">
          <i className="ti ti-user-check text-[15px] text-gray-500" />
          {pendingCount === null
            ? "Checking pending approvals…"
            : pendingCount === 0
              ? "No one waiting for approval"
              : `${pendingCount} ${pendingCount === 1 ? "person" : "people"} waiting for approval`}
        </span>
        {!!pendingCount && pendingCount > 0 && <i className="ti ti-chevron-right text-gray-400" />}
      </button>
      <div className="my-1 h-px bg-gray-200 dark:bg-gray-800" />
      <p className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500">
        Recent activity
      </p>
      {feed.length === 0 ? (
        <p className="px-2.5 py-3 text-sm text-gray-500 dark:text-gray-400">
          Nothing yet - this only shows what arrived while this tab was open.
        </p>
      ) : (
        feed.map((item) => (
          <div
            key={item.id}
            className="flex items-center justify-between gap-3 rounded-lg px-2.5 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-gray-900"
          >
            <div className="min-w-0">
              <p className="truncate">{item.message}</p>
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
  return (
    <div className="text-sm">
      <StatusRow icon="ti-server" label="Backend version" value={health.version} />
      <StatusRow icon="ti-browser" label="Frontend version" value={FRONTEND_VERSION} />
      <StatusRow icon="ti-clock" label="Uptime" value={formatUptime(health.uptime_seconds)} />
      <StatusRow icon="ti-database" label="PostgreSQL" ok={health.postgres_reachable} />
      <StatusRow icon="ti-bolt" label="Valkey" ok={health.valkey_reachable} />
    </div>
  );
}

function StatusRow({
  icon,
  label,
  value,
  ok,
  okLabel,
}: {
  icon: string;
  label: string;
  value?: string;
  ok?: boolean;
  okLabel?: string;
}) {
  return (
    <div className="flex items-center justify-between border-b border-gray-100 px-1 py-2.5 last:border-0 dark:border-gray-800">
      <span className="flex items-center gap-2.5">
        <i className={`ti ${icon} text-[15px] text-gray-400`} /> {label}
      </span>
      {value !== undefined ? (
        <span className="text-xs text-gray-500">{value}</span>
      ) : (
        <span
          className={`flex items-center gap-1.5 text-xs font-medium ${ok ? "text-green-700 dark:text-green-400" : "text-red-600"}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-green-600" : "bg-red-600"}`} />
          {ok ? okLabel ?? "Reachable" : "Unreachable"}
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
    return <img src={session.picture} alt="" className={`rounded-full object-cover ${className}`} />;
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
