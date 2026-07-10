// Where the long-lived bearer token lives between page loads for a user
// who has already completed login (wizard or ordinary). This is NOT the
// same key AuthComplete.tsx uses internally ("modulab_auth_result") - that
// one is a one-shot handoff consumed exactly once by whichever page reads
// it next, while this one persists for as long as the session is valid.
//
// Deliberately sessionStorage, not localStorage: spec section 3.2 calls
// for the bearer token to live in sessionStorage so it does not survive as
// a permanent, XSS-reachable artifact across browser restarts. The backend
// uses a 24-hour sliding window (see auth/session.go ValidateSession) - as
// long as the user has at least one tab open and making requests, their
// session auto-extends and never expires mid-use. Closing all tabs signs
// them out; a new tab after that requires a fresh OIDC login.
import { queryClient } from "./queryClient";

const SESSION_TOKEN_KEY = "modulab_session_token";

export function storeSessionToken(token: string): void {
  sessionStorage.setItem(SESSION_TOKEN_KEY, token);
}

export function getSessionToken(): string | null {
  return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

export function clearSessionToken(): void {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
  // ModuLab is designed to run as a shared, always-on browser homepage
  // (see Home.tsx's top-of-file comment) - the TanStack Query cache is a
  // single instance for the tab's whole lifetime and survives the SPA
  // navigate("/login") every logout/session-invalidation path uses (no
  // full page reload), so without this it would otherwise keep serving
  // the previous person's cached feed/module/store data for a few seconds
  // after the next person logs in on the same tab.
  queryClient.clear();
}
