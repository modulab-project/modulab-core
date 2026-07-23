// This file implements the self-service counterpart to cmd/core's
// systemInfoHandler active-sessions table / session.go's RevokeSessionByID: any
// approved user (not just a super-admin) can see their own
// currently-logged-in devices and end one of them, from their own Profile
// page. Motivation: before this, "I lost my phone, is my session on it
// still valid?" or "kill that session" had exactly one answer - ask a
// super-admin to look it up and revoke it via System Info. Ordinary users
// and org-admins (not super-admin) had no self-service option at all
// beyond waiting out SessionAbsoluteMaxAge.
package auth

import (
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/httperr"
)

// MySessionsHandler is GET /v1/auth/sessions: every currently-active
// session belonging to the caller (ListActiveSessionsForUser), with
// Current set on whichever entry matches the token this very request
// carried - the frontend uses that to label "this device" and to disable
// its own "end this session" button (ending your own current session here
// is what /v1/auth/logout is for, and doing it through this endpoint
// instead would clear the cookie without the extra IdP-side refresh-token
// revocation LogoutHandler already does).
func MySessionsHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		sessions, err := ListActiveSessionsForUser(r.Context(), d, sess.UserID)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if currentID := SessionID(sessionToken(r)); currentID != "" {
			for i := range sessions {
				if sessions[i].ID == currentID {
					sessions[i].Current = true
				}
			}
		}
		writeJSON(w, http.StatusOK, sessions)
	}
}

// RevokeMySessionHandler is DELETE /v1/auth/sessions/{id}: ends exactly one
// of the caller's own sessions (RevokeOwnSessionByID's ownership check is
// what makes this safe to expose to any approved user, not just an admin -
// see that function's doc comment). ok = false is reported as 404, not
// 403/401 - from the caller's point of view "this ID belongs to someone
// else" and "this ID doesn't exist at all" must look identical, same
// reasoning as RevokeOwnSessionByID itself not distinguishing the two.
func RevokeMySessionHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing session id", http.StatusBadRequest)
			return
		}
		revoked, err := RevokeOwnSessionByID(r.Context(), d, sess.UserID, id)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !revoked {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
