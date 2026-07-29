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
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
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

// reauthFailWindow/reauthFailAlertThreshold bound recordReauthFailure below.
// A single reauth_required response is completely ordinary - anyone who
// hasn't logged in within the last reauthWindow hits it on their very next
// step-up action, with nothing suspicious about it. Only *repeated*
// failures in a short burst are worth an admin's attention: that pattern
// looks less like "I forgot I'd been idle" and more like a stale/stolen
// session cookie being used to probe for something it can still get away
// with. 5 minutes/3 failures is deliberately tighter than reauthWindow
// itself (15 min) - this is about catching a burst of retries against the
// same still-stale session, not just "still not reauthenticated".
const (
	reauthFailWindow         = 5 * time.Minute
	reauthFailAlertThreshold = 3
)

// requireRecentLogin returns true if sess's original login (Session.
// CreatedAt - stamped once at CreateSession, never touched by the sliding-
// window TTL refresh) is within reauthWindow. On failure it writes 403 with
// a machine-readable "reauth_required" body itself and returns false; the
// frontend (AdminUsersPage.tsx / ProfilePage.tsx) recognises exactly that
// body and offers a re-login link rather than showing a generic error.
//
// label identifies which step-up-gated action was refused (e.g.
// "lock_user", "PATCH /v1/admin/oidc") - purely for recordReauthFailure's
// alert/audit payload, so an admin reviewing a repeated-failures notice
// knows what was actually being attempted, not just that something was.
func requireRecentLogin(ctx context.Context, d Deps, w http.ResponseWriter, sess Session, label string) bool {
	if time.Since(sess.CreatedAt) > reauthWindow {
		http.Error(w, "reauth_required", http.StatusForbidden)
		recordReauthFailure(ctx, d, sess, label)
		return false
	}
	return true
}

// recordReauthFailure counts failed step-up attempts per user (not per IP -
// unlike main.go's rateLimitMiddleware, this is about a session that is
// already authenticated but stale, not an anonymous caller, so the OIDC
// subject is the meaningful bucket key) and alerts admins once repeated
// failures cross reauthFailAlertThreshold within reauthFailWindow. Mirrors
// rateLimitMiddleware's own "notify + audit.Log" pair, including the
// gate to the exact request that crosses the threshold (count ==
// reauthFailAlertThreshold) rather than firing again on every subsequent
// failure while the window is still open. Best-effort throughout: a
// missed alert here must never turn an already-rejected 403 into
// something worse for the caller, so every failure past this point is
// only logged, never surfaced to the response.
func recordReauthFailure(ctx context.Context, d Deps, sess Session, label string) {
	if d.Valkey == nil {
		return
	}
	count, err := d.Valkey.IncrExpire(ctx, "reauthfail:"+sess.UserID, reauthFailWindow)
	if err != nil {
		log.Printf("auth: reauth-fail counter for %s: %v", sess.UserID, err)
		return
	}
	if count != reauthFailAlertThreshold {
		return
	}
	if pubErr := notify.Publish(ctx, d.Valkey, notify.AdminChannel(), notify.Event{
		Type: "reauth.repeated_failures",
		Data: map[string]any{"user_id": sess.UserID, "email": sess.Email, "label": label, "count": count},
	}); pubErr != nil {
		logNotifyError("reauth-fail-alert", sess.UserID, pubErr)
	}
	if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
		if auditErr := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
			EventType:  audit.EventReauthRepeatedFailures,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details:    fmt.Sprintf(`{"label":%q,"count":%d}`, label, count),
		}); auditErr != nil {
			log.Printf("auth: audit reauth repeated failures for %s: %v", sess.UserID, auditErr)
		}
	} else {
		log.Printf("auth: audit reauth repeated failures for %s: resolve master key: %v", sess.UserID, mkErr)
	}
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

// csrfHeaderName is the header the admin frontend attaches its CSRF token
// under for every state-changing request - see validateCSRF below and
// frontend/src/lib/api.ts's request().
const csrfHeaderName = "X-CSRF-Token"

// csrfProtectedMethod reports whether method can mutate anything, and
// therefore needs the CSRF check below at all. GET/HEAD/OPTIONS never
// change server state, so there is nothing for a same-origin module fetch
// to forge here that the ambient session cookie doesn't already expose via
// plain read access regardless of any token.
func csrfProtectedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// validateCSRF is requireAdmin/RequireAdminSession's second check, layered
// on top of the session cookie itself.
//
// The problem this closes (feedback_modulab_cookie_same_origin_risk,
// flagged 2026-07-14): Core's session cookie is httpOnly and SameSite=Lax,
// but same-origin fetches - including one issued by an installed module's
// own UI bundle, which runs in the same window/JS realm as the host SPA
// (no iframe isolation) - carry it automatically too. The cookie alone
// cannot tell a legitimate admin-panel mutation apart from one a module's
// JS triggered on its own.
//
// sess.CSRFToken (minted once per session by CreateSession) is handed to
// the frontend only in GET /v1/auth/me's JSON response body. The admin SPA
// holds it in memory and echoes it back as the X-CSRF-Token header on
// every mutating request; a module bundle has no route to that response
// body of its own. This is not a hard guarantee in a shared-JS-realm
// architecture - a module could still specifically intercept the host's
// own fetch of /v1/auth/me - but it meaningfully raises the bar over the
// realistic threat this was first scoped for: an accidental bug in one of
// ModuLab's own first-party modules hitting an admin route it never meant
// to, not a targeted attack. Full origin isolation (a sandboxed iframe) is
// the harder guarantee, deliberately not pursued yet - see that same
// memory entry - since every installed module today is first-party and
// Cosign-signed, not third-party code.
func validateCSRF(w http.ResponseWriter, r *http.Request, sess Session) bool {
	if !csrfProtectedMethod(r.Method) {
		return true
	}
	got := r.Header.Get(csrfHeaderName)
	if got == "" || sess.CSRFToken == "" ||
		subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
		http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// originAllowed is a lightweight, best-effort second line of defense
// alongside validateCSRF: browsers attach an Origin header to same-origin
// state-changing fetches, so a *present but mismatched* Origin is a strong
// signal something is off. Deliberately does not fail closed when Origin
// is absent - some browsers/proxies omit it even for legitimate requests,
// and validateCSRF above is already the primary, deterministic guard; this
// only ever adds an extra rejection, never a bypass.
func originAllowed(d Deps, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	origin = strings.TrimRight(origin, "/")
	return origin == strings.TrimRight(d.PublicBaseURL, "/") ||
		origin == strings.TrimRight(d.FrontendBaseURL, "/")
}

// requireAdmin validates the request's Bearer token and confirms the
// resulting session's role is allowed to manage users - reused by every
// /v1/admin/... handler below. On failure it writes the appropriate status
// itself (401 for a missing/invalid/expired token, 403 for a valid session
// whose role just isn't high enough, or whose CSRF token/Origin failed the
// checks above) and returns ok = false; callers must return immediately
// without writing anything further.
func requireAdmin(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := sessionToken(r)
	if token == "" {
		http.Error(w, "missing session cookie", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateSession(r.Context(), d, token)
	if err != nil {
		httperr.Internal(w, err)
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
	// enough - managing users is admin territory only.
	if sess.Role != RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	if !originAllowed(d, r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return Session{}, false
	}
	if !validateCSRF(w, r, sess) {
		return Session{}, false
	}
	return sess, true
}

// RequireAdminMiddleware behaves like requireAdmin (above) but as reusable
// net/http middleware for routes that live outside this file's own
// handlers - today, SMTP/OIDC configuration, system info, audit log, and
// other system-level settings (main.go wires these through it). Named
// RequireAdminMiddleware before 2026-07-29's role-model change, back
// when a separate org-admin tier existed and this gate was reserved for
// the stricter super-admin-only role; now that org-admin is gone and
// super-admin was renamed to plain "admin", this is functionally the same
// check as requireAdmin, kept as its own middleware only because it also
// stores the session in context for downstream handlers.
func RequireAdminMiddleware(d Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := requireAdmin(d, w, r)
			if !ok {
				return
			}
			// Store the validated session in the context so downstream
			// handlers (e.g. SMTP/OIDC configure) can retrieve the actor
			// for audit logging without re-parsing the bearer token.
			next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), sess)))
		})
	}
}

// RequireAdminReauthMiddleware layers the same step-up gate as
// LockUserHandler/DeleteUserHandler/ApproveUserHandler (requireRecentLogin)
// on top of RequireAdminMiddleware, for the handful of admin actions
// consequential enough to warrant it even though they live outside this
// package (adminapi.OIDCUpdateHandler/OIDCDeleteHandler,
// setup.SMTPConfigureHandler/the SMTP delete handler in cmd/core, and -
// since 2026-07-22 - ending another user's active session, main.go's
// revokeSessionHandler) - see main.go's adminReauthOnly for exactly
// which routes use this instead of the plain adminOnly.
//
// Deliberately NOT applied to every admin route: read-only endpoints
// (system info, audit log, status/test checks) have nothing to step up
// for, and rate limits/AI/search provider keys are excluded on purpose -
// reversible, low-stakes settings, unlike the credential/trust-root actions
// this actually gates.
//
// OIDC config is the highest-value target of the routes this actually
// gates: it is the trust root the entire login flow depends on - whoever
// controls IssuerURL/ClientID/ClientSecret can point every future login at
// an IdP of their own choosing, and log in as anyone. SMTP config is lower
// stakes but still worth it - anyone who could quietly redirect the
// instance's outgoing mail could intercept its own pending-approval/
// account emails, or send convincing phishing "from" this instance. Ending
// another user's session was added later: it has the same immediate,
// hard-to-undo-for-them effect as locking their account, which already got
// this treatment - see main.go's route registration comment.
func RequireAdminReauthMiddleware(d Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAdminMiddleware(d)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := SessionFromContext(r.Context())
			if !ok {
				// Unreachable in practice - RequireAdminMiddleware
				// always calls ContextWithSession before invoking next.
				// Handled explicitly anyway rather than assuming it, same
				// principle as requireAdmin's own belt-and-suspenders
				// checks elsewhere in this file.
				http.Error(w, "invalid or expired session", http.StatusUnauthorized)
				return
			}
			// label is the route itself, not a fixed name - this middleware
			// wraps several distinct routes (SMTP/OIDC configure+delete,
			// admin session revoke), and the method+path is the cheapest
			// accurate label available at this generic a layer.
			if !requireRecentLogin(r.Context(), d, w, sess, r.Method+" "+r.URL.Path) {
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// guardAgainstSelfOrLastAdmin blocks an admin action (lock or delete)
// that would either act on the caller's own account, or strip the
// instance's last remaining admin of their elevated status, leaving
// no one able to manage it. blocked = true means the caller must not
// proceed; reason is a user-facing explanation for that case. A non-nil
// err means the safety check itself failed (a real DB error) and the
// caller should treat it as 500, not as a guard violation.
func guardAgainstSelfOrLastAdmin(ctx context.Context, d Deps, actingSubject, targetSubject string) (blocked bool, reason string, err error) {
	if targetSubject == actingSubject {
		return true, "cannot perform this action on your own account", nil
	}
	return guardAgainstLastAdmin(ctx, d, targetSubject)
}

// guardAgainstLastAdmin is guardAgainstSelfOrLastAdmin's
// last-remaining-admin check on its own, without the self-action
// block above it - shared with handlers.go's DeleteSelfHandler, which acts
// on the caller's own account *by definition* (that is the entire point of
// a self-delete endpoint) but must still not be allowed to delete the
// instance's only admin out from under it, leaving no one able to
// manage it afterward.
func guardAgainstLastAdmin(ctx context.Context, d Deps, targetSubject string) (blocked bool, reason string, err error) {
	role, exists, err := d.Pool.UserRole(ctx, targetSubject)
	if err != nil {
		return false, "", err
	}
	if !exists || role != RoleAdmin {
		return false, "", nil
	}
	count, err := d.Pool.AdminCount(ctx)
	if err != nil {
		return false, "", err
	}
	if count <= 1 {
		return true, "cannot lock or delete the last remaining admin", nil
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
//
// Mutating requests also get the Origin/CSRF checks (2026-07-28). When those
// were introduced they were scoped to the admin guards only, on the reading
// that a module bug hitting an *admin* route was the risk worth closing. That
// left every user-facing mutation open to the same thing: an installed
// module's UI bundle runs in this SPA's own JS realm and its fetches carry
// the session cookie automatically, so nothing stopped module code from
// overwriting a user's AI/search provider keys, rewriting their quick links,
// changing feed subscriptions, ending their sessions, or deleting their
// account outright. Those are lower-severity than user management, but not
// low enough to leave as the one unguarded surface once the mechanism to
// guard them already existed.
//
// Costs nothing on the client: lib/api.ts's request() has always attached
// X-CSRF-Token to every mutating call rather than only admin ones (see the
// csrfHeaders doc comment there), precisely so this could be tightened
// without a coordinated frontend change.
func RequireActiveSession(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	sess, ok := requireActiveSessionWithToken(d, w, r, sessionToken(r))
	if !ok {
		return Session{}, false
	}
	if !originAllowed(d, r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return Session{}, false
	}
	if !validateCSRF(w, r, sess) {
		return Session{}, false
	}
	return sess, true
}

func requireActiveSessionWithToken(d Deps, w http.ResponseWriter, r *http.Request, token string) (Session, bool) {
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateSession(r.Context(), d, token)
	if err != nil {
		httperr.Internal(w, err)
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

// RequireAdminSession is RequireActiveSession plus an admin
// role check - use for any endpoint that manages users, configuration, or
// other resources that regular users must not touch. This is the choke point
// every /v1/admin/... handler across every package (store, quicklinks,
// news, modules, adminapi, search, ...) already calls.
//
// The Origin/CSRF checks used to be repeated here; they now come from
// RequireActiveSession itself, which applies them to every session-guarded
// mutation rather than only admin ones (see its doc comment). Repeating them
// would be harmless but would also suggest admin routes are the only ones
// covered, which is exactly the assumption that left the user-facing routes
// unguarded in the first place.
func RequireAdminSession(d Deps, w http.ResponseWriter, r *http.Request) (Session, bool) {
	sess, ok := RequireActiveSession(d, w, r)
	if !ok {
		return Session{}, false
	}
	if sess.Role != RoleAdmin {
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
// for an admin to review. Deliberately not filtered down
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
			httperr.Internal(w, err)
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
		if !requireRecentLogin(r.Context(), d, w, sess, "approve_user") {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.ApproveUser(r.Context(), subject)
		if err != nil {
			httperr.Internal(w, err)
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
// last remaining admin (guardAgainstSelfOrLastAdmin). Unlike
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
		if !requireRecentLogin(r.Context(), d, w, sess, "lock_user") {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		blocked, reason, err := guardAgainstSelfOrLastAdmin(r.Context(), d, sess.UserID, subject)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if blocked {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.LockUser(r.Context(), subject)
		if err != nil {
			httperr.Internal(w, err)
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
// never strand the instance the way locking or deleting could. Does get
// the same requireRecentLogin step-up gate as ApproveUserHandler though -
// missed when that one was added (2026-07-22) even though restoring a
// locked account's access is exactly as consequential as approving a new
// one: a compromised-but-still-within-SessionTTL admin session could
// otherwise reinstate an account another admin deliberately locked.
func UnlockUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		if !requireRecentLogin(r.Context(), d, w, sess, "unlock_user") {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		affected, err := d.Pool.UnlockUser(r.Context(), subject)
		if err != nil {
			httperr.Internal(w, err)
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
// admin guard as LockUserHandler, and same immediate-effect session
// revocation: deleting someone should not leave their already-open tab
// working until SessionTTL runs out either.
func DeleteUserHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireAdmin(d, w, r)
		if !ok {
			return
		}
		if !requireRecentLogin(r.Context(), d, w, sess, "delete_user") {
			return
		}
		subject := r.PathValue("id")
		if subject == "" {
			http.Error(w, "missing user id", http.StatusBadRequest)
			return
		}
		blocked, reason, err := guardAgainstSelfOrLastAdmin(r.Context(), d, sess.UserID, subject)
		if err != nil {
			httperr.Internal(w, err)
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
			httperr.Internal(w, err)
			return
		}
		affected, err := d.Pool.DeleteUser(r.Context(), subject)
		if err != nil {
			httperr.Internal(w, err)
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
