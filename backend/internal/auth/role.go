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
// user's role is whichever of prefix+"Super-Admin", prefix+"Org-Admin", or
// prefix+"User" appears in their groups claim, checked in that priority
// order so membership in multiple groups resolves to the most privileged
// role rather than an arbitrary one. A user in none of the three groups
// gets RolePending.
func DeriveRole(groups []string, prefix string) string {
	set := make(map[string]bool, len(groups))
	for _, g := range groups {
		set[g] = true
	}

	switch {
	case set[prefix+"Super-Admin"]:
		return RoleSuperAdmin
	case set[prefix+"Org-Admin"]:
		return RoleOrgAdmin
	case set[prefix+"User"]:
		return RoleUser
	default:
		return RolePending
	}
}
