// Mirrors the error codes CallbackHandler's redirectToFrontend calls use in
// backend/internal/auth/handlers.go - keep these two in sync. Shared
// between SetupWizard's step 5 (super-admin login) and the ordinary /login
// page, since both can land on the same error codes via the same
// /auth/complete redirect - previously this lived duplicated in
// SetupWizard.tsx only, before /login existed.
//
// Returns a translation key rather than a hardcoded string - callers pass
// it through t() from react-i18next.
export function authErrorKey(code: string): string {
  const known = [
    "missing_state_or_code",
    "invalid_or_expired_state",
    "provider_unavailable",
    "exchange_failed",
    "group_prefix_unavailable",
    "access_denied",
  ];
  return known.includes(code)
    ? `auth.error.${code}`
    : "auth.error.unknown";
}
