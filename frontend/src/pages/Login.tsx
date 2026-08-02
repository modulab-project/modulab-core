import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { authErrorKey } from "../lib/authErrors";
import { consumeAuthResult } from "../lib/authResult";
import { useLoginRedirect } from "../lib/useLoginRedirect";
import { AuthButton, AuthShell } from "../components/AuthShell";

// Spec section 6.4's "/login" route ("OIDC Login-Screen", Public access).
// There is only ever one OIDC provider configured (the wizard's own
// provider-selection step was dropped on 2026-06-21 as purely
// informational - see SetupWizard.tsx's top-of-file comment), so this is
// just a single button, not a provider picker.
//
// Reached two ways: directly (someone hits "/" or "/pending" with no
// session and gets bounced here), or via AuthComplete after an ordinary
// (post-setup) login attempt that failed - in the second case
// consumeAuthResult() picks up the stashed error so it can be shown here
// rather than silently dropped.
export default function Login() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  // See lib/useLoginRedirect.ts: coordinates via a cross-tab localStorage
  // lock so opening this page in more than one tab at once can't fire two
  // independent OIDC round-trips (each minting its own Valkey session - the
  // "several active sessions for one browser" issue found on the System
  // Info page, 2026-07-16). If another tab is already mid-login, `waiting`
  // is true and this tab jumps straight to "/" the moment that other
  // login succeeds, without ever bothering the IdP itself.
  const { waiting, canForce, startLogin } = useLoginRedirect(() => navigate("/", { replace: true }));

  useEffect(() => {
    const result = consumeAuthResult();
    if (result?.error) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setError(authErrorKey(result.error));
    }
  }, []);

  return (
    <AuthShell
      title={t("login.title")}
      subtitle={t("login.subtitle")}
      centerText
    >
      {error && <p className="mb-4 text-center text-sm text-red-600 dark:text-red-400">{t(error)}</p>}
      <AuthButton type="button" onClick={() => startLogin()} disabled={waiting} className="w-full">
        {waiting ? t("login.waiting_other_tab") : t("login.button")}
      </AuthButton>
      {waiting && canForce && (
        <button
          type="button"
          onClick={() => startLogin(undefined, true)}
          className="mt-3 w-full text-center text-sm text-gray-500 underline hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
        >
          {t("login.force_button")}
        </button>
      )}
    </AuthShell>
  );
}
