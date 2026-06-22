// Mirrors the error codes CallbackHandler's redirectToFrontend calls use in
// backend/internal/auth/handlers.go - keep these two in sync. Shared
// between SetupWizard's step 5 (super-admin login) and the ordinary /login
// page, since both can land on the same error codes via the same
// /auth/complete redirect - previously this lived duplicated in
// SetupWizard.tsx only, before /login existed.
export function describeAuthError(code: string): string {
  switch (code) {
    case "missing_state_or_code":
      return "The login attempt was incomplete. Please try again.";
    case "invalid_or_expired_state":
      return "The login attempt expired. Please try again.";
    case "provider_unavailable":
      return "OIDC is not fully configured yet.";
    case "exchange_failed":
      return "Login with the identity provider failed.";
    case "group_prefix_unavailable":
      return "The group prefix is not configured yet.";
    case "access_denied":
      return "Your account is not authorized to access ModuLab. Contact your administrator.";
    default:
      return "An unexpected error occurred during login.";
  }
}
