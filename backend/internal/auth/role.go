// Package auth implements the runtime side of OIDC login that the Setup
// Wizard's configuration steps (internal/setup) only store the *inputs*
// for: deriving a role from the groups claim (spec section 3.3's Dynamic
// Prefix Hard Gate), session issuance/validation (session.go), the OIDC
// authorization-code flow itself (oidcclient.go), and the HTTP handlers
// that tie all of it together (handlers.go).
package auth

// The three roles spec section 3.3 defines (collapsed from four on
// 2026-07-29: the org-admin tier was removed, and the former super-admin
// tier was renamed to plain "admin" - see role migration notes in
// db.go/groupprefix.go for why). RolePending covers two different
// situations, both ultimately "not in yet", handled by two different gates
// in handlers.go's CallbackHandler:
//
//   - Returned by DeriveRole itself, below: the user is not a member of
//     either of the two configured groups at all. CallbackHandler treats
//     this as an outright access denial (error=access_denied) - it is
//     never sent to the frontend as a session role, and no user row is
//     even created for them.
//   - Set explicitly by CallbackHandler, overriding an otherwise-valid
//     derived role: the user IS a member of one of the two groups, but
//     has not been approved yet (db.Pool.UserApproved) - a second,
//     independent gate on top of group membership, covering both "never
//     logged in before" and "logged in before, still not approved". This
//     exists specifically so that an operator accidentally adding someone
//     to a ModuLab group in the IdP does not hand them instant access -
//     someone still has to approve them first (today: a manual
//     UPDATE users SET approved = true, since there is no /admin/users UI
//     yet). This gate is skipped entirely while the Setup Wizard itself is
//     still incomplete, since the very first login has to bind the first
//     Admin and there is no admin yet who could approve them. This
//     is the only case where role "pending" is actually persisted to a
//     session and shown to the frontend (/pending).
const (
	RoleAdmin   = "admin"
	RoleUser    = "user"
	RolePending = "pending"
)

// DeriveRole implements spec section 3.3's Dynamic Prefix Hard Gate: a
// user's role is whichever of prefix+"admin" or prefix+"user" appears in
// their groups claim, checked in that priority order so membership in both
// groups resolves to the more privileged role rather than an arbitrary
// one. A user in neither group gets RolePending - see the doc comment
// above on RolePending for what CallbackHandler does with that (a hard
// rejection, not a "wait" state).
//
// The group-name suffixes are lowercase snake_case rather than the
// Title-Case-with-hyphen form spec section 3.3's examples use - changed on
// the user's request to match how they actually name groups in their IdP
// (Pocket ID). RoleAdmin/RoleUser (the role *values* stored on the user
// and returned from the API) are unaffected; only the group-claim names
// this function matches against changed.
func DeriveRole(groups []string, prefix string) string {
	set := make(map[string]bool, len(groups))
	for _, g := range groups {
		set[g] = true
	}

	switch {
	case set[prefix+"admin"]:
		return RoleAdmin
	case set[prefix+"user"]:
		return RoleUser
	default:
		return RolePending
	}
}
