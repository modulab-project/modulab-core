// Split out of components/AppShell.tsx so it can be imported by page
// components without also pulling in the (large) AppShell component itself,
// which trips react-refresh/only-export-components in dev (a file with a
// non-component export can't be fast-refreshed cleanly).
const ADMIN_ROLES = ["org-admin", "super-admin"];

// Shared definition of "is this an admin" - used by AppShell itself (status
// panel, profile menu's "Admin" section) and by every admin-only page to
// gate access, so the set of admin roles can never drift out of sync
// between the two.
export function isAdminRole(role: string): boolean {
  return ADMIN_ROLES.includes(role);
}
