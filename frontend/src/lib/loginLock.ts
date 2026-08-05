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

// Identifies this browser tab across the OIDC round-trip itself - which is
// a full top-level navigation away to the IdP and back (see this file's
// top-of-file comment), landing on AuthComplete.tsx as a brand-new page
// load, not a client-side route change. A plain per-module-load random
// value (what this used to be) gets silently regenerated on that landing
// page, so releaseLoginLock() there was comparing against a different id
// than the one acquireLoginLock() stored before navigating away - the
// "same owner" check could never match, and the lock was never actually
// released by the flow that's supposed to release it. It just sat there
// until LOCK_TTL_MS's 3-minute expiry.
//
// Bug found 2026-08-05: every successful (or abandoned) login left its own
// lock stuck for up to 3 minutes, so logging out and back in within that
// window always hit the "another tab is mid-login" state, even though it
// was the very same tab.
//
// sessionStorage survives exactly this kind of same-tab full-page
// navigation while still never being shared with a genuinely different
// tab (same per-tab lifetime AUTH_RESULT_STORAGE_KEY/WEATHER_CACHE_KEY
// already rely on elsewhere) - reading/writing it once here, instead of a
// bare random constant, keeps "two tabs must never agree on the same
// owner id" true while also keeping "the same tab must agree with itself
// across the redirect" true, which the old approach didn't.
const OWNER_ID_STORAGE_KEY = "modulab_login_lock_owner_id";

function getOwnerId(): string {
  let id: string | null = null;
  try {
    id = sessionStorage.getItem(OWNER_ID_STORAGE_KEY);
  } catch {
    // sessionStorage inaccessible (disabled, privacy mode, etc.) - fall
    // through to a fresh id below every time this module loads. Degrades
    // to exactly the pre-fix behavior in that case, not to something worse.
  }
  if (!id) {
    id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    try {
      sessionStorage.setItem(OWNER_ID_STORAGE_KEY, id);
    } catch {
      // Same fallback as above - id is still usable for this page load,
      // it just won't survive a future navigation if storage is unusable.
    }
  }
  return id;
}

const ownerId = getOwnerId();

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
//
// `force` overrides someone else's live lock outright - used by the "sign
// in anyway" fallback a waiting tab offers after FORCE_WAIT_MS (see
// useLoginRedirect.ts). Deliberately a manual, user-triggered escape hatch
// rather than a shorter TTL or an unload-based auto-release: the lock's
// whole job is to survive this tab going away mid-redirect (that's the
// normal, successful path, not just the abandoned one), so nothing short of
// "a human decided the other tab's attempt is stale" can safely clear it
// early. See loginLock.ts's top-of-file comment for the bug this protects
// against.
export function acquireLoginLock(force = false): boolean {
  const existing = readLock();
  if (existing && existing.owner !== ownerId && !force) {
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
