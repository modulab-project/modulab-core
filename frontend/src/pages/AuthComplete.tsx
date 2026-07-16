import { useEffect, useRef } from "react";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { getHealth } from "../lib/api";
import { AUTH_RESULT_STORAGE_KEY, type AuthResult } from "../lib/authResult";
import { releaseLoginLock } from "../lib/loginLock";

// This page is the single landing spot for the redirect CallbackHandler
// sends the browser to once the OIDC round-trip with the IdP is done (see
// redirectToFrontend's doc comment in handlers.go for why the result is in
// the URL fragment, not a query string or JSON body). It reads the
// fragment once, stashes the result in sessionStorage, strips the fragment
// from the address bar, and then decides where to send the browser next.
// The session token itself never appears here at all - it arrived as an
// httpOnly Set-Cookie header on this same redirect response (see
// setSessionCookie in handlers.go), so there is nothing for this page to
// persist or protect; the browser already has it and will attach it to
// every subsequent same-origin request on its own.
//
// Two genuinely different logins land here, distinguished by whether the
// Setup Wizard has completed yet (one /healthz call, not anything baked
// into the fragment itself):
//   - Still mid-wizard: this was step 5's super-admin login (or a retry of
//     it). Always go to /setup - SetupWizard's own mount effect reads the
//     stashed result via consumeAuthResult() and decides what to show
//     (step 6 on success, an error/retry prompt on failure). Unchanged
//     behavior from before /login, /pending and / existed.
//   - Already complete: this is an ordinary end-user login. The stashed
//     result is only used for a failure (Login.tsx reads it to show the
//     error); on success the browser goes straight to /pending or / based
//     on role - no detour through /setup.
export default function AuthComplete() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  // Guards against React 18 StrictMode's dev-only double-invocation of
  // effects. Without this, the second invocation re-reads
  // window.location.hash *after* the first invocation already cleared it
  // via replaceState below, parses an empty string into an
  // all-fields-undefined AuthResult, and overwrites the correctly-stored
  // result in sessionStorage with it - so whoever reads it next sees
  // `role: undefined` even though the login itself succeeded. The ref
  // makes the parse/store/decide sequence run exactly once no matter how
  // many times the effect fires.
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) {
      return;
    }
    handled.current = true;

    // This tab's OIDC round-trip is over now - success or failure, it
    // acquired the login lock in Login.tsx (or SetupWizard.tsx's retry
    // button) right before navigating away, and nothing else will release
    // it otherwise. Releasing it here, before the health/role branching
    // below, lets any other tab that was waiting on it (see Login.tsx's
    // onLoginLockChange handler) re-check its own session immediately
    // instead of sitting on the lock's full TTL.
    releaseLoginLock();

    const hash = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    const params = new URLSearchParams(hash);
    const result: AuthResult = {
      email: params.get("email") ?? undefined,
      role: params.get("role") ?? undefined,
      error: params.get("error") ?? undefined,
    };
    sessionStorage.setItem(AUTH_RESULT_STORAGE_KEY, JSON.stringify(result));
    window.history.replaceState(null, "", window.location.pathname);

    getHealth()
      .then((health) => {
        if (!health.setup_completed) {
          navigate("/setup", { replace: true });
          return;
        }
        if (result.error || !result.role) {
          navigate("/login", { replace: true });
          return;
        }
        // Nothing downstream reads the stashed result on this success path
        // (unlike the two branches above, which leave it for Login.tsx or
        // SetupWizard.tsx's consumeAuthResult() to pick up) - found during
        // a post-release check (2026-07-15) that it was sitting in
        // sessionStorage for the entire tab lifetime otherwise, holding the
        // user's email unnecessarily long after login already succeeded.
        sessionStorage.removeItem(AUTH_RESULT_STORAGE_KEY);
        navigate(result.role === "pending" ? "/pending" : "/", { replace: true });
      })
      .catch(() => navigate("/setup", { replace: true }));
  }, [navigate]);

  return <p className="p-8 text-center text-sm text-gray-500">{t("auth_complete.finishing")}</p>;
}
