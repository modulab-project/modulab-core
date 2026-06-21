// This file implements the admin-only side of spec section 3.3's
// approval gate, plus the lock/delete actions that go alongside it: until
// now, moving someone out of CallbackHandler's gate 2 ("approved = false")
// required a manual "UPDATE users SET approved = true" against the
// database directly, and there was no way at all to revoke someone's
// access short of deleting their row by hand. These endpoints replace all
// of that with a real API an admin frontend can drive.
package auth

import (
	"context"
	"net/http"
	"time"
)

// requireAdmin validates the request's Bearer token and confirms the
// resulting session's role is allowed to manage users - reused by every
// /v1/admin/... handler below. On failure it writes the appropriate status
// itself (401 for a missing/invalid/expired token, 403 for a valid session
// whose role just isn't high enough) and returns ok = false; callers must
// return immediately without writing anything further.
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
	// enough - managing users is org-admin/super-admin territory only.
	if sess.Role != RoleOrgAdmin && sess.Role != RoleSuperAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// guardAgainstSelfOrLastSuperAdmin blocks an admin action (lock or delete)
// that would either act on the caller's own account, or strip the
// instance's last remaining super-admin of their elevated status, leaving
// no one able to manage it. blocked = true means the caller must not
// proceed; reason is a user-facing explanation for that case. A non-nil
// err means the safety check itself failed (a real DB error) and the
// caller should treat it as 500, not as a guard violation.
func guardAgainstSelfOrLastSuperAdmin(ctx context.Context, d Deps, actingSubject, targetSubject string) (blocked bool, reason string, err error) {
	if targetSubject == actingSubject {
		return true, "cannot perform this action on your own account", nil
	}
	role, exists, err := d.Pool.UserRole(ctx, targetSubject)
	if err != nil {
		return false, "", err
	}
	if !exists || role != RoleSuperAdmin {
		return false, "", nil
	}
	count, err := d.Pool.SuperAdminCount(ctx)
	if err != nil {
		return false, "", err
	}
	if count <= 1 {
		return true, "cannot lock or delete the last remaining super-admin", nil
	}
	return false, "", nil
}

// UserResponse is one entry in UsersHandler's JSON array - every column an
// admin frontend needs to derive a single status (Pending / Active /
// Locked) per row and decide which actions to offer for it.
type UserResponse struct {
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Approved  bool      `json:"approved"`
	Locked    bool      `json:"locked"`
	CreatedAt time.Time `json:"created_at"`
}

// UsersHandler is GET /v1/admin/users: every user row (db.Pool.ListUsers),
// for an org-admin/super-admin to review. Deliberately not filtered down
// to just pending users (as an earlier version of this endpoint was) - one
// list covering everyone means there is exactly one place an admin needs
// to look to approve, lock, unlock, or delete anyone.
func UsersHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(d, w, r); !ok {
			return
		}
		users, err := d.Pool.ListUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := make([]UserResponse, 0, len(users))
		for _, u := range users {
			resp = append(resp, UserResponse{
				Subject:   u.Subject,
				Email:     u.Email,
				Name:      u.Name,
				Role:      u.Role,
				Approved:  u.Approved,
				Locked:    u.Locked,
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

// LockUserHandler is POST /v1/admin/users/{id}/lock: revokes an
// already-approved user's access without forgetting who they are (unlike
// DeleteUserHandler below). Guarded against locking your own account or the
// last remaining super-admin (guardAgainstSelfOrLastSuperAdmin) - same
// caveat as approval, this takes effect on the target's *next* login, not
// retroactively.
func LockUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		blocked, reason, err := guardAgainstSelfOrLastSuperAdmin(r.Context(), d, sess.UserID, subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if blocked {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.LockUser(r.Context(), subject)
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

// UnlockUserHandler is POST /v1/admin/users/{id}/unlock. No self/last-
// super-admin guard needed: unlocking only ever restores access, it can
// never strand the instance the way locking or deleting could.
func UnlockUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(d, w, r); !ok {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.UnlockUser(r.Context(), subject)
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

// DeleteUserHandler is DELETE /v1/admin/users/{id}: forgets the user row
// entirely (db.Pool.DeleteUser) - see that method's doc comment for why
// this does not blocklist the OIDC subject itself. Same self/last-
// super-admin guard as LockUserHandler.
func DeleteUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		blocked, reason, err := guardAgainstSelfOrLastSuperAdmin(r.Context(), d, sess.UserID, subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if blocked {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.DeleteUser(r.Context(), subject)
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
