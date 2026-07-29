// Split out of components/AppShell.tsx so it can be imported by page
// components without also pulling in the (large) AppShell component itself,
// which trips react-refresh/only-export-components in dev (a file with a
// non-component export can't be fast-refreshed cleanly).
//
// Role model collapsed from three tiers (user, org-admin, super-admin) to
// two (user, admin) on 2026-07-29: the org-admin tier was removed
// entirely, and super-admin was renamed to plain "admin". ADMIN_ROLE
// replaces the old SUPER_ADMIN_ROLE name/value.
export const ADMIN_ROLE = "admin";

/** @deprecated kept as an alias of ADMIN_ROLE for call sites not yet swept - same value. */
export const SUPER_ADMIN_ROLE = ADMIN_ROLE;

// Shared definition of "is this an admin" - used by AppShell itself (status
// panel, profile menu's "Admin" section) and by every admin-only page to
// gate access, so the admin check can never drift out of sync between the
// two.
export function isAdminRole(role: string): boolean {
  return role === ADMIN_ROLE;
}

// isSuperAdminRole used to be the stricter of two checks, back when a
// separate org-admin tier existed alongside super-admin (every
// super-admin-only page - System/Security Info, OIDC/SMTP/Search/Limits
// settings, Audit log, the Store install gate, the setup wizard's
// initial-account step - imports this rather than reimplementing
// `session.role !== "super-admin"` as its own raw string literal, a
// duplication bug found 2026-07-27 alongside the __Host-modulab_session
// cookie-name one). Now that there is only one admin tier, this is
// identical to isAdminRole - kept as its own exported function rather than
// sweeping all ~15 call sites to import isAdminRole instead, since the two
// names still read correctly at each call site ("this page needs the admin
// role" either way).
export function isSuperAdminRole(role: string): boolean {
  return role === ADMIN_ROLE;
}
