// Mirrors what backend/internal/auth/handlers.go's CallbackHandler puts in
// the URL fragment - keep these two in sync.
export interface AuthResult {
  token?: string;
  email?: string;
  role?: string;
  error?: string;
}

export const AUTH_RESULT_STORAGE_KEY = "modulab_auth_result";

// consumeAuthResult reads and clears the stashed result - "consume" because
// a stale leftover result must never be replayed against a later step.
//
// Split out of pages/AuthComplete.tsx (which stashes the result here in the
// first place) so that page file only exports its default component,
// keeping react-refresh fast-refresh-friendly. Consumed by SetupWizard.tsx
// (step 5's super-admin login) and Login.tsx (ordinary end-user login
// errors) - see AuthComplete.tsx's top-level comment for the full flow.
export function consumeAuthResult(): AuthResult | null {
  const raw = sessionStorage.getItem(AUTH_RESULT_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  sessionStorage.removeItem(AUTH_RESULT_STORAGE_KEY);
  try {
    return JSON.parse(raw) as AuthResult;
  } catch {
    return null;
  }
}
