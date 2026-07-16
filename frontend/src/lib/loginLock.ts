// Cross-tab lock coordinating the OIDC login redirect.
//
// The login flow leaves this origin entirely (the browser navigates to the
// IdP and back via /v1/auth/callback -> /auth/complete), so a same-page-only
// mechanism like BroadcastChannel cannot carry state across that gap - the
// tab that starts the redirect gets a brand-new JS context on return.
// localStorage is the one thing that does survive it (profile-backed, not
// tied to a live tab), so it's the lock's storage. Other tabs learn about
// lock changes via the native `storage` event, which fires automatically in
// every *other* same-origin tab whenever localStorage changes - no separate
// pub/sub channel needed on top of it.
//
// Exists to fix the "one browser ends up with several active sessions"
// issue found on the System Info page (2026-07-16): opening ModuLab in more
// than one tab at (or near) the same time could previously let each tab
// independently run a full OIDC round-trip and mint its own Valkey session,
// none of which get revoked by the others - see backend/internal/auth/
// session.go's CreateSession, which never invalidates a user's prior
// sessions on a new login.

const LOCK_KEY = "modulab_login_lock";

// Generous on purpose: this has to outlive the user actually typing their
// IdP credentials, not just the network round trip. If a tab dies mid-flow
// without releasing the lock (closed tab, browser crash, user abandons the
// IdP's login page), the lock simply expires after this long and the next
// tab to check reclaims it - better than a permanently stuck lock, at the
// cost of a slow fallback in that rare case.
const LOCK_TTL_MS = 3 * 60 * 1000;

interface LoginLock {
  owner: string;
  ts: number;
}

// One random ID per page load, so this tab can tell "my own lock" apart
// from "someone else's lock" without relying on timing. Regenerating it per
// module load (i.e. per tab) is deliberate - two tabs must never agree on
// the same owner id.
const ownerId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;

function readLock(): LoginLock | null {
  const raw = localStorage.getItem(LOCK_KEY);
  if (!raw) {
    return null;
  }
  try {
    const lock = JSON.parse(raw) as LoginLock;
    if (Date.now() - lock.ts > LOCK_TTL_MS) {
      return null; // expired - treat as if no lock were held at all
    }
    return lock;
  } catch {
    return null;
  }
}

// Returns true if this tab now holds the lock - either it was free/expired,
// or this same tab already held it (re-entrant on purpose, so an effect
// that happens to run twice, e.g. React StrictMode, doesn't fight itself).
// Returns false if another tab is genuinely mid-login right now.
export function acquireLoginLock(): boolean {
  const existing = readLock();
  if (existing && existing.owner !== ownerId) {
    return false;
  }
  localStorage.setItem(LOCK_KEY, JSON.stringify({ owner: ownerId, ts: Date.now() } satisfies LoginLock));
  return true;
}

// True if some tab (any tab, including this one) currently holds a live
// lock - used by Login.tsx to decide whether to show a clickable button or
// a "waiting on another tab" state.
export function isLoginLockHeld(): boolean {
  return readLock() !== null;
}

// Only clears the lock if this tab is the one holding it - a tab that never
// acquired the lock must not be able to clear someone else's mid-flight
// login out from under them.
export function releaseLoginLock(): void {
  const existing = readLock();
  if (existing && existing.owner === ownerId) {
    localStorage.removeItem(LOCK_KEY);
  }
}

// Fires callback whenever another tab changes the lock (acquires, releases,
// or refreshes it) - lets a waiting tab react immediately instead of
// polling on a fixed interval. Note the native `storage` event only ever
// fires in *other* tabs than the one that made the change, which is exactly
// the audience this needs (the tab that owns the lock doesn't need to be
// told about its own write). Returns an unsubscribe function.
export function onLoginLockChange(callback: () => void): () => void {
  function handler(event: StorageEvent) {
    if (event.key === LOCK_KEY) {
      callback();
    }
  }
  window.addEventListener("storage", handler);
  return () => window.removeEventListener("storage", handler);
}
