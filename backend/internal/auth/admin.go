// This file implements the admin-only side of spec section 3.3's
// approval gate: until now, moving someone out of CallbackHandler's gate 2
// (handlers.go - approved = false) required a manual
// "UPDATE users SET approved = true" against the database directly. These
// two endpoints replace that with a real API an admin frontend can drive.
package auth

import (
	"net/http"
	"time"
)

// requireAdmin validates the request's Bearer token and confirms the
// resulting session's role is allowed to manage user approvals - reused by
// every /v1/admin/... handler below. On failure it writes the appropriate
// status itself (401 for a missing/invalid/expired token, 403 for a valid
// session whose role just isn't high enough) and returns ok = false;
// callers must return immediately without writing anything further.
func requireAdmin(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateSession(r.Context(), d.Valkey, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return Session{}, false
	}
	// Pending sessions never reach here in practice (the frontend bounces
	// them to /pending before they could call this), but checked
	// explicitly anyway rather than relying on that: RoleUser is also not
	// enough - approving users is org-admin/super-admin territory only.
	if sess.Role != RoleOrgAdmin && sess.Role != RoleSuperAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// PendingUserResponse is one entry in PendingUsersHandler's JSON array.
type PendingUserResponse struct {
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// PendingUsersHandler is GET /v1/admin/users/pending: every user row with
// approved = false (db.Pool.ListPendingUsers), for an org-admin/super-admin
// to review before deciding whether to let them in.
func PendingUsersHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(d, w, r); !ok {
			return
		}
		users, err := d.Pool.ListPendingUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := make([]PendingUserResponse, 0, len(users))
		for _, u := range users {
			resp = append(resp, PendingUserResponse{
				Subject:   u.Subject,
				Email:     u.Email,
				Name:      u.Name,
				Role:      u.Role,
				CreatedAt: u.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// ApproveUserHandler is POST /v1/admin/users/{id}/approve, where {id} is the
// target user's OIDC subject (db.Pool.ApproveUser). Takes effect on that
// user's *next* login, not retroactively on any session they may already
// be holding - CallbackHandler bakes the role into a session once at login
// and never revisits it (see role.go's doc comment on RolePending), so an
// already-issued pending session stays pending until they sign out and
// back in.
func ApproveUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(d, w, r); !ok {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.ApproveUser(r.Context(), subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if affected == 0 {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
