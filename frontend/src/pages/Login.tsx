import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { loginRedirectUrl } from "../lib/api";
import { authErrorKey } from "../lib/authErrors";
import { consumeAuthResult } from "../lib/authResult";
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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const result = consumeAuthResult();
    if (result?.error) {
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
      <AuthButton
        type="button"
        onClick={() => {
          window.location.href = loginRedirectUrl();
        }}
        className="w-full"
      >
        {t("login.button")}
      </AuthButton>
    </AuthShell>
  );
}
