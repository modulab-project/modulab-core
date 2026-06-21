// Package auth implements the runtime side of OIDC login that the Setup
// Wizard's configuration steps (internal/setup) only store the *inputs*
// for: deriving a role from the groups claim (spec section 3.3's Dynamic
// Prefix Hard Gate), session issuance/validation (session.go), the OIDC
// authorization-code flow itself (oidcclient.go), and the HTTP handlers
// that tie all of it together (handlers.go).
package auth

// The four roles spec section 3.3 defines. RolePending is not a real role -
// it means "authenticated, but not a member of any of the three configured
// groups yet", and exists so a future admin UI has something to assign.
// There is currently no enforcement anywhere that actually restricts
// RolePending users from anything, since no protected endpoints exist yet
// to restrict.
const (
	RoleSuperAdmin = "super-admin"
	RoleOrgAdmin   = "org-admin"
	RoleUser       = "user"
	RolePending    = "pending"
)

// DeriveRole implements spec section 3.3's Dynamic Prefix Hard Gate: a
// user's role is whichever of prefix+"super_admin", prefix+"org_admin", or
// prefix+"user" appears in their groups claim, checked in that priority
// order so membership in multiple groups resolves to the most privileged
// role rather than an arbitrary one. A user in none of the three groups
// gets RolePending.
//
// The group-name suffixes are lowercase snake_case rather than the
// Title-Case-with-hyphen form spec section 3.3's examples use - changed on
// the user's request to match how they actually name groups in their IdP
// (Pocket ID). RoleSuperAdmin/RoleOrgAdmin/RoleUser (the role *values*
// stored on the user and returned from the API) are unaffected; only the
// group-claim names this function matches against changed.
func DeriveRole(groups []string, prefix string) string {
	set := make(map[string]bool, len(groups))
	for _, g := range groups {
		set[g] = true
	}

	switch {
	case set[prefix+"super_admin"]:
		return RoleSuperAdmin
	case set[prefix+"org_admin"]:
		return RoleOrgAdmin
	case set[prefix+"user"]:
		return RoleUser
	default:
		return RolePending
	}
}
