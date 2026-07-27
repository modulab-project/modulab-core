// Split out of components/AppShell.tsx so it can be imported by page
// components without also pulling in the (large) AppShell component itself,
// which trips react-refresh/only-export-components in dev (a file with a
// non-component export can't be fast-refreshed cleanly).
export const SUPER_ADMIN_ROLE = "super-admin";

const ADMIN_ROLES = ["org-admin", SUPER_ADMIN_ROLE];

// Shared definition of "is this an admin" - used by AppShell itself (status
// panel, profile menu's "Admin" section) and by every admin-only page to
// gate access, so the set of admin roles can never drift out of sync
// between the two.
export function isAdminRole(role: string): boolean {
  return ADMIN_ROLES.includes(role);
}

// Shared definition of "is this specifically a super-admin" (stricter than
// isAdminRole above) - every super-admin-only page (System/Security Info,
// OIDC/SMTP/Search/Limits settings, Audit log, the Store install gate, the
// setup wizard's initial-account step) used to reimplement
// `session.role !== "super-admin"` as its own raw string literal instead of
// importing this. Found 2026-07-27 alongside the __Host-modulab_session
// cookie-name duplication bug - same anti-pattern, lower blast radius so
// far only because the role name hasn't actually changed yet, but a future
// rename would have needed a correct grep-and-replace across every one of
// those ~15 call sites instead of one function body here.
export function isSuperAdminRole(role: string): boolean {
  return role === SUPER_ADMIN_ROLE;
}
