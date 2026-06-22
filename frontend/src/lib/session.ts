// Where the long-lived bearer token lives between page loads for a user
// who has already completed login (wizard or ordinary). This is NOT the
// same key AuthComplete.tsx uses internally ("modulab_auth_result") - that
// one is a one-shot handoff consumed exactly once by whichever page reads
// it next, while this one persists for as long as the session is valid.
//
// Deliberately sessionStorage, not localStorage: spec section 7.2 calls
// for the bearer token to live in sessionStorage specifically so it does
// not survive as a permanent, XSS-reachable artifact across browser
// restarts - see backend/internal/auth/session.go's SessionTTL doc comment
// for the matching backend-side reasoning (opaque token, 24h TTL, no
// refresh flow yet). The practical trade-off: closing the tab signs the
// user out, a new tab needs a fresh login. That is intentional, not a bug.
const SESSION_TOKEN_KEY = "modulab_session_token";

export function storeSessionToken(token: string): void {
  sessionStorage.setItem(SESSION_TOKEN_KEY, token);
}

export function getSessionToken(): string | null {
  return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

export function clearSessionToken(): void {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
}
