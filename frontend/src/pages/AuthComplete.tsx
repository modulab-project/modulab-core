import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

// Mirrors what backend/internal/auth/handlers.go's CallbackHandler puts in
// the URL fragment - keep these two in sync.
export interface AuthResult {
  token?: string;
  email?: string;
  role?: string;
  error?: string;
}

const STORAGE_KEY = "modulab_auth_result";

// This page exists purely as the landing spot for the redirect
// CallbackHandler sends the browser to once the OIDC round-trip with the
// IdP is done (see redirectToFrontend's doc comment in handlers.go for why
// the result is in the URL fragment, not a query string or JSON body). It
// reads the fragment once, stashes the result in sessionStorage so
// SetupWizard can pick it up after the navigate() below, and immediately
// strips the fragment from the address bar so the bearer token does not
// linger in browser history.
export default function AuthComplete() {
  const navigate = useNavigate();
  // Guards against React 18 StrictMode's dev-only double-invocation of
  // effects. Without this, the second invocation re-reads
  // window.location.hash *after* the first invocation already cleared it
  // via replaceState below, parses an empty string into an
  // all-fields-undefined AuthResult, and overwrites the correctly-stored
  // result in sessionStorage with it - so SetupWizard's consumeAuthResult()
  // sees `role: undefined` and silently stays on step 6 with no error,
  // even though the login itself succeeded. The ref makes the parse/store/
  // navigate sequence run exactly once no matter how many times the effect
  // fires.
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) {
      return;
    }
    handled.current = true;

    const hash = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    const params = new URLSearchParams(hash);
    const result: AuthResult = {
      token: params.get("token") ?? undefined,
      email: params.get("email") ?? undefined,
      role: params.get("role") ?? undefined,
      error: params.get("error") ?? undefined,
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(result));
    window.history.replaceState(null, "", window.location.pathname);
    navigate("/setup", { replace: true });
  }, [navigate]);

  return <p className="p-8 text-center text-sm text-gray-500">Finishing login…</p>;
}

// consumeAuthResult reads and clears the stashed result - "consume" because
// a stale leftover result must never be replayed against a later step.
export function consumeAuthResult(): AuthResult | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }
  sessionStorage.removeItem(STORAGE_KEY);
  try {
    return JSON.parse(raw) as AuthResult;
  } catch {
    return null;
  }
}
