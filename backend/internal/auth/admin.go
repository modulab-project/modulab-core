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
	"log"
	"net/http"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// reauthWindow bounds how "fresh" a session's original login has to be
// before it may perform an irreversible-ish account action (lock, delete,
// self-delete) - see requireRecentLogin. Sessions slide their TTL on every
// request (ValidateSession) and can stay alive for up to SessionTTL (24h)
// of intermittent use without a fresh login, which is fine for ordinary
// browsing but too stale a credential to trust for "forget this user
// forever" - a stolen/left-open tab hours after the real owner logged in
// would otherwise be just as capable of that as a fresh login. 15 minutes
// mirrors the module-token TTL (ModuleTokenTTL) in spirit - short enough to
// meaningfully require a deliberate, recent authentication, long enough
// not to make routine admin work annoying.
const reauthWindow = 15 * time.Minute

// requireRecentLogin returns true if sess's original login (Session.
// CreatedAt - stamped once at CreateSession, never touched by the sliding-
// window TTL refresh) is within reauthWindow. On failure it writes 403 with
// a machine-readable "reauth_required" body itself and returns false; the
// frontend (AdminUsersPage.tsx / ProfilePage.tsx) recognises exactly that
// body and offers a re-login link rather than showing a generic error.
func requireRecentLogin(w http.ResponseWriter, sess Session) bool {
	if time.Since(sess.CreatedAt) > reauthWindow {
		http.Error(w, "reauth_required", http.StatusForbidden)
		return false
	}
	return true
}

// logRevokeError logs a failed RevokeUserSessions call. Pulled out to one
// line since LockUserHandler and DeleteUserHandler both need it, and both
// treat it the same way - log and continue, see the call sites for why.
func logRevokeError(action, subject string, err error) {
	log.Printf("auth: %s: failed to revoke active sessions for %s: %v", action, subject, err)
}

// logNotifyError logs a failed notify.Publish call - same "log and
// continue" treatment as logRevokeError, and for the same reason: the
// admin action this is attached to already succeeded and is the source of
// truth, so a missed real-time notification should not surface as an
// error the admin has to do anything about.
func logNotifyError(action, subject string, err error) {
	log.Printf("auth: %s: failed to publish notification for %s: %v", action, subject, err)
}

// enqueueMail looks up subject's email/name and queues build(email, name)
// for delivery - the extension beyond spec section 3.5's own Mail-Queue
// table described in notify.go and mail/templates.go's doc comments: an
// approve/lock/unlock action also reaches a user who is not currently
// connected to /v1/events. name is passed through so the template can
// address the recipient by name (mail.greeting) rather than a bare
// "Hello," - same best-effort treatment as logRevokeError/logNotifyError
// throughout this file: called only after the admin action itself
// already succeeded, so any failure here (no such user - should not
// happen, this is always called right after a successful DB write for
// the same subject; no email on file; SMTP not configured; Valkey
// hiccup) is logged and swallowed rather than turning a successful admin
// action into a 500.
func enqueueMail(ctx context.Context, d Deps, action, subject string, build func(email, name string) mail.Message) {
	user, exists, err := d.Pool.GetUser(ctx, subject)
	if err != nil {
		log.Printf("auth: %s: failed to look up email for %s: %v", action, subject, err)
		return
	}
	if !exists || user.Email == "" {
		return
	}
	if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, build(user.Email, user.Name)); err != nil {
		log.Printf("auth: %s: failed to enqueue mail for %s: %v", action, subject, err)
	}
}

// logAudit appends one entry to the audit log - best-effort, same treatment
// as logRevokeError/logNotifyError: the admin action itself already succeeded
// and is the source of truth, so a failed audit write must not turn a
// successful approve/lock/unlock/delete into a 500 the admin has to retry.
func logAudit(ctx context.Context, d Deps, p audit.LogParams) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		log.Printf("auth: audit: failed to resolve master key for %s: %v", p.EventType, err)
		return
	}
	if err := audit.Log(ctx, d.Pool, masterKey, p); err != nil {
		log.Printf("auth: audit: failed to write %s: %v", p.EventType, err)
	}
}

// requireAdmin validates the request's Bearer token and confirms the
// resulting session's role is allowed to manage users - reused by every
// /v1/admin/... handler below. On failure it writes the appropriate status
// itself (401 for a missing/invalid/expired token, 403 for a valid session
// whose role just isn't high enough) and returns ok = false; callers must
// return immediately without writing anything further.
func requireAdmin(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := sessionToken(r)
	if token == "" {
		http.Error(w, "missing session cookie", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateSession(r.Context(), d, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return Session{}, false
	}
	// Re-issue the cookie so its own Max-Age slides forward together with
	// the Valkey-side TTL that ValidateSession just extended - otherwise
	// the browser drops the cookie exactly SessionTTL after login
	// regardless of activity, defeating the sliding-window design entirely.
	setSessionCookie(w, token)
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

// RequireSuperAdminMiddleware behaves like requireAdmin (above) but as
// reusable net/http middleware for routes that live outside this file's
// own handlers and need the stricter super-admin-only gate - today, only
// SMTP configuration (main.go wires setup.SMTPStatusHandler/
// SMTPConfigureHandler through this), matching the "Vollzugriff auf
// Systemebene: Infrastruktur, OIDC-Konfiguration" framing spec section
// 3.3's role table gives Super-Admin: SMTP credentials are exactly that
// kind of system-level infrastructure config, not something an org-admin
// (who only manages users day to day) needs to touch.
func RequireSuperAdminMiddleware(d Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := requireAdmin(d, w, r)
			if !ok {
				return
			}
			if sess.Role != RoleSuperAdmin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// Store the validated session in the context so downstream
			// handlers (e.g. SMTP/OIDC configure) can retrieve the actor
			// for audit logging without re-parsing the bearer token.
			next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), sess)))
		})
	}
}

// RequireSuperAdminReauthMiddleware layers the same step-up gate as
// LockUserHandler/DeleteUserHandler/ApproveUserHandler (requireRecentLogin)
// on top of RequireSuperAdminMiddleware, for the handful of super-admin
// actions consequential enough to warrant it even though they live outside
// this package (adminapi.OIDCUpdateHandler/OIDCDeleteHandler,
// setup.SMTPConfigureHandler/the SMTP delete handler in cmd/core) - see
// main.go's superAdminReauthOnly for exactly which routes use this instead
// of the plain superAdminOnly.
//
// Deliberately NOT applied to every super-admin route: read-only endpoints
// (system info, audit log, status/test checks) have nothing to step up
// for, and a few mutating ones are excluded on purpose - rate limits and
// AI/search provider keys are reversible, low-stakes settings, and ending
// an active session (DELETE /v1/admin/sessions/{id}) is itself an incident-
// response action that should never be made slower by an extra login step
// right when speed matters most.
//
// OIDC config is the highest-value target of the two routes this actually
// gates: it is the trust root the entire login flow depends on - whoever
// controls IssuerURL/ClientID/ClientSecret can point every future login at
// an IdP of their own choosing, and log in as anyone. SMTP config is lower
// stakes but still worth it - anyone who could quietly redirect the
// instance's outgoing mail could intercept its own pending-approval/
// account emails, or send convincing phishing "from" this instance.
func RequireSuperAdminReauthMiddleware(d Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireSuperAdminMiddleware(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				// Unreachable in practice - RequireSuperAdminMiddleware
				// always calls ContextWithSession before invoking next.
				// Handled explicitly anyway rather than assuming it, same
				// principle as requireAdmin's own belt-and-suspenders
				// checks elsewhere in this file.
				http.Error(w, "invalid or expired session", http.StatusUnauthorized)
				return
			}
			if !requireRecentLogin(w, sess) {
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
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
	return guardAgainstLastSuperAdmin(ctx, d, targetSubject)
}

// guardAgainstLastSuperAdmin is guardAgainstSelfOrLastSuperAdmin's
// last-remaining-super-admin check on its own, without the self-action
// block above it - shared with handlers.go's DeleteSelfHandler, which acts
// on the caller's own account *by definition* (that is the entire point of
// a self-delete endpoint) but must still not be allowed to delete the
// instance's only super-admin out from under it, leaving no one able to
// manage it afterward.
func guardAgainstLastSuperAdmin(ctx context.Context, d Deps, targetSubject string) (blocked bool, reason string, err error) {
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

// RequireActiveSession validates the request's bearer token and returns the
// session if it is valid, non-pending, and not locked. On failure it writes
// the appropriate error status itself and returns ok = false; callers must
// return immediately without writing anything further.
//
// This is the canonical session guard for all user-facing endpoints across
// every package - use it instead of a local copy so the Locked check is
// never accidentally omitted (the bug that motivated this: packages that
// checked only Role == RolePending would pass a session whose revocation
// failed due to a Valkey hiccup, since Locked is only set to true on a
// session that was never revoked).
func RequireActiveSession(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	return requireActiveSessionWithToken(d, w, r, sessionToken(r))
}

func requireActiveSessionWithToken(d Deps, w http.ResponseWriter, r *http.Request, token string) (Session, bool) {
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateSession(r.Context(), d, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return Session{}, false
	}
	// Same sliding-cookie reasoning as requireAdmin above.
	setSessionCookie(w, token)
	if sess.Role == RolePending || sess.Locked {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// RequireAdminSession is RequireActiveSession plus an org-admin/super-admin
// role check. Use for any endpoint that manages users, configuration, or
// other resources that regular users must not touch.
func RequireAdminSession(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	sess, ok := RequireActiveSession(d, w, r)
	if !ok {
		return Session{}, false
	}
	if sess.Role != RoleOrgAdmin && sess.Role != RoleSuperAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// UserResponse is one entry in UsersHandler's JSON array - every column an
// admin frontend needs to derive a single status (Pending / Active /
// Locked) per row and decide which actions to offer for it.
type UserResponse struct {
	Subject     string    `json:"subject"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	Approved    bool      `json:"approved"`
	Locked      bool      `json:"locked"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at"`
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
				Subject:     u.Subject,
				Email:       u.Email,
				Name:        u.Name,
				Role:        u.Role,
				Approved:    u.Approved,
				Locked:      u.Locked,
				CreatedAt:   u.CreatedAt,
				LastLoginAt: u.LastLoginAt,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// ApproveUserHandler is POST /v1/admin/users/{id}/approve, where {id} is the
// target user's OIDC subject (db.Pool.ApproveUser). Takes effect immediately
// for anyone already sitting on /pending with a session open, not just on
// their next login: CallbackHandler bakes the role into a session once at
// login and never revisits it on its own (see role.go's doc comment on
// RolePending), so this handler patches every session token already issued
// to subject in place (UpdateSessionsRole, session.go) with the role
// db.Pool.UserRole reports right now - the same value CallbackHandler
// derived and stored on the user row at their last login, gate 2 just
// wasn't satisfied yet for the session itself. The spec section 3.5
// "user.approved" notification still fires too: it is what makes
// Pending.tsx's re-check happen the instant this runs instead of waiting
// up to POLL_INTERVAL_MS for the next poll, but the actual unblocking now
// happens here, before that event is published, not on a subsequent login.
func ApproveUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		// Same step-up gate as LockUserHandler/DeleteUserHandler below -
		// granting someone real access is just as consequential as revoking
		// it: a compromised-but-still-within-SessionTTL admin session
		// approving a malicious pending signup hands that account a
		// legitimate, fully-privileged role, not just a nuisance.
		if !requireRecentLogin(w, sess) {
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
		// Best-effort, same reasoning as the notify.Publish/enqueueMail
		// calls below: the approval itself already succeeded and is the
		// source of truth, so a Valkey hiccup here should not turn it into
		// a 500 the admin has to retry - worst case, an already-open
		// session falls back to the pre-existing behavior of staying
		// pending until its holder signs out and back in.
		if role, exists, err := d.Pool.UserRole(r.Context(), subject); err != nil {
			logNotifyError("approve: look up role for session update", subject, err)
		} else if exists {
			if err := UpdateSessionsRole(r.Context(), d.Valkey, subject, role, false); err != nil {
				logNotifyError("approve: update live sessions", subject, err)
			}
		}
		// Best-effort, same reasoning as LockUserHandler's
		// RevokeUserSessions call below: the approval itself already
		// succeeded and is the source of truth, so a Valkey hiccup here
		// should not turn it into a 500 the admin has to retry.
		if err := notify.Publish(r.Context(), d.Valkey, notify.UserChannel(subject), notify.Event{Type: "user.approved"}); err != nil {
			logNotifyError("approve", subject, err)
		}
		enqueueMail(r.Context(), d, "approve", subject, func(email, name string) mail.Message {
			return mail.ApprovedMessage(email, name, d.FrontendBaseURL)
		})
		// Best-effort: include the target's email in the audit entry so the
		// log is readable without having to cross-reference UUIDs.
		targetEmail := ""
		if u, exists, err := d.Pool.GetUser(r.Context(), subject); err == nil && exists {
			targetEmail = u.Email
		}
		logAudit(r.Context(), d, audit.LogParams{
			EventType:   audit.EventUserApproved,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    subject,
			TargetEmail: targetEmail,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// LockUserHandler is POST /v1/admin/users/{id}/lock: revokes an
// already-approved user's access without forgetting who they are (unlike
// DeleteUserHandler below). Guarded against locking your own account or the
// last remaining super-admin (guardAgainstSelfOrLastSuperAdmin). Unlike
// approval, this takes effect immediately, not just on the target's next
// login attempt: RevokeUserSessions (session.go) kills every session token
// already issued to them, so a tab they currently have open stops working
// on its very next request instead of staying valid until SessionTTL runs
// out on its own.
func LockUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		if !requireRecentLogin(w, sess) {
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
		// Best-effort beyond this point on purpose: the lock itself already
		// succeeded and is the source of truth (it also blocks any future
		// login attempt via CallbackHandler's gate 2) - a Valkey hiccup here
		// should not turn an otherwise-successful lock into a 500 the admin
		// has to retry. Worst case, an already-open session survives until
		// it naturally expires, which is exactly the pre-existing behavior
		// this change improves on, not a regression.
		if err := RevokeUserSessions(r.Context(), d, subject); err != nil {
			logRevokeError("lock", subject, err)
		}
		enqueueMail(r.Context(), d, "lock", subject, func(email, name string) mail.Message {
			return mail.LockedMessage(email, name)
		})
		// Best-effort: include the target's email in the audit entry.
		lockedEmail := ""
		if u, exists, err := d.Pool.GetUser(r.Context(), subject); err == nil && exists {
			lockedEmail = u.Email
		}
		logAudit(r.Context(), d, audit.LogParams{
			EventType:   audit.EventUserLocked,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    subject,
			TargetEmail: lockedEmail,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// UnlockUserHandler is POST /v1/admin/users/{id}/unlock. No self/last-
// super-admin guard needed: unlocking only ever restores access, it can
// never strand the instance the way locking or deleting could.
func UnlockUserHandler(d Deps) http.HandlerFunc {
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
		affected, err := d.Pool.UnlockUser(r.Context(), subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if affected == 0 {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		enqueueMail(r.Context(), d, "unlock", subject, func(email, name string) mail.Message {
			return mail.UnlockedMessage(email, name, d.FrontendBaseURL)
		})
		// Best-effort: include the target's email in the audit entry.
		unlockedEmail := ""
		if u, exists, err := d.Pool.GetUser(r.Context(), subject); err == nil && exists {
			unlockedEmail = u.Email
		}
		logAudit(r.Context(), d, audit.LogParams{
			EventType:   audit.EventUserUnlocked,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    subject,
			TargetEmail: unlockedEmail,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// DeleteUserHandler is DELETE /v1/admin/users/{id}: forgets the user row
// entirely (db.Pool.DeleteUser) - see that method's doc comment for why
// this does not blocklist the OIDC subject itself. Same self/last-
// super-admin guard as LockUserHandler, and same immediate-effect session
// revocation: deleting someone should not leave their already-open tab
// working until SessionTTL runs out either.
func DeleteUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		if !requireRecentLogin(w, sess) {
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
		// Captured before the delete below, not via enqueueMail's usual
		// post-action d.Pool.GetUser lookup (ApproveUserHandler/
		// LockUserHandler/UnlockUserHandler all use that helper): by the
		// time the row is gone, there is nothing left to look the address
		// up from. target/targetExists/err are deliberately separate from
		// the err already in scope above - a failure here should not be
		// confused with a guard-check failure, even though both map to the
		// same 500 response.
		target, targetExists, err := d.Pool.GetUser(r.Context(), subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
		if err := RevokeUserSessions(r.Context(), d, subject); err != nil {
			logRevokeError("delete", subject, err)
		}
		// Best-effort, same reasoning as everywhere else in this file: the
		// deletion itself already succeeded and is the source of truth, so
		// a missed confirmation email must not turn it into a 500 the
		// admin has to retry.
		if targetExists && target.Email != "" {
			if err := mail.Enqueue(r.Context(), d.Valkey, d.Pool, d.MasterKeyEnv, mail.DeletedMessage(target.Email, target.Name)); err != nil {
				log.Printf("auth: delete: failed to enqueue mail for %s: %v", subject, err)
			}
		}
		targetEmail := ""
		if targetExists {
			targetEmail = target.Email
		}
		logAudit(r.Context(), d, audit.LogParams{
			EventType:   audit.EventUserDeleted,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    subject,
			TargetEmail: targetEmail,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}
