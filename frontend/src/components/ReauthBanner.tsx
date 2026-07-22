import { useTranslation } from "react-i18next";

interface ReauthBannerProps {
  waiting: boolean;
  onReauth: () => void;
  // Optional: lets the caller dismiss the banner without re-authenticating
  // (e.g. the user wants to keep editing other fields first, or just
  // clicked into this by accident). Purely a local UI dismiss - nothing
  // was queued server-side to roll back, since the gated action never
  // went through in the first place.
  onDismiss?: () => void;
}

// Shown whenever a super-admin/self-service action comes back with
// isReauthRequiredError (authErrors.ts) - the caller's session is valid but
// its original login is older than backend/internal/auth's reauthWindow
// (15 min), so a step-up action (SMTP/OIDC config, user lock/delete,
// self-delete) was refused. Deliberately not just a red one-liner: this is
// a routine, expected step (like GitHub's "sudo mode" prompt for sensitive
// actions), not an error the user did something wrong to cause - a plain
// red error banner reads as "you broke something", which was the original
// complaint (2026-07-22) that led to introducing this component in the
// first place. No mention of "passkey" specifically - the IdP is
// pluggable (OIDC provider compatibility check earlier this session) and
// not every provider/user is on passkeys.
export function ReauthBanner({ waiting, onReauth, onDismiss }: ReauthBannerProps) {
  const { t } = useTranslation();
  return (
    <div className="mb-4 flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/40">
      <span className="mt-0.5 flex h-8 w-8 flex-none items-center justify-center rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300">
        <i className="ti ti-shield-lock text-[16px]" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
          {t("common.reauth.title")}
        </p>
        <p className="mt-0.5 text-sm text-amber-800 dark:text-amber-300/90">
          {t("common.reauth.body")}
        </p>
        <div className="mt-2.5 flex items-center gap-2">
          <button
            type="button"
            onClick={onReauth}
            disabled={waiting}
            className="rounded-lg bg-teal-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-teal-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-teal-500 dark:hover:bg-teal-400"
          >
            {waiting ? t("login.waiting_other_tab") : t("common.reauth.button")}
          </button>
          {onDismiss && (
            <button
              type="button"
              onClick={onDismiss}
              disabled={waiting}
              className="rounded-md border border-gray-200 px-3 py-1.5 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
            >
              {t("common.cancel")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
