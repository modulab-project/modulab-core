// This file implements the actual end-user OIDC login flow (spec section
// 6.5's wizard step 6, and the runtime side of spec section 3.3): redirect
// to the IdP, handle its callback, verify the ID token, derive a role,
// JIT-provision the user, and issue a Core-managed session.
//
// None of these routes are wrapped in bootstrap.Manager's middleware -
// that gate exists for the operator-only Setup Wizard API
// (/v1/setup/...), not for end users authenticating against their own
// IdP account.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"golang.org/x/oauth2"
)

// oauthStateTTL is deliberately short: a state value is only ever supposed
// to live between the redirect to the IdP and the user completing login
// there, normally a matter of seconds.
const oauthStateTTL = 5 * time.Minute

const oauthStateKeyPrefix = "oauthstate:"

// Deps bundles what the login/callback/logout/me handlers need.
// MasterKeyEnv is the one remaining raw environment value (config.Config's
// MasterKey) - resolution against what the Setup Wizard may have persisted
// instead happens fresh on every request (see setup.ResolveMasterKey), so a
// wizard change takes effect immediately without a Core restart. Neither
// OIDC configuration nor the group prefix have an environment-variable
// field anymore (group prefix removed 2026-06-21 alongside OIDC, on
// request): both only ever come from what the wizard persisted to the
// database - see setup.ResolveOIDCConfig / ResolveGroupPrefix.
type Deps struct {
	Pool   *db.Pool
	Valkey *valkey.Client

	MasterKeyEnv string

	// PublicBaseURL is Core's externally reachable base URL (e.g.
	// "https://modulab.example.com"), used to build the OIDC redirect_uri.
	// It must match what is registered with the IdP exactly.
	PublicBaseURL string

	// FrontendBaseURL is where the SPA is served from - CallbackHandler
	// sends the browser here once the OIDC round-trip is done, success or
	// not. In production this is typically the same origin as
	// PublicBaseURL (Core serves the built frontend itself); in local dev
	// it points at the Vite dev server instead (e.g. "http://localhost:5173"),
	// which is why this is a separate field rather than reusing PublicBaseURL.
	FrontendBaseURL string
}

func (d Deps) redirectURL() string {
	return strings.TrimRight(d.PublicBaseURL, "/") + "/v1/auth/callback"
}

// frontendCallbackURL is where CallbackHandler sends the browser once the
// OIDC round-trip is done. The SPA route at this path (spec section 6.5
// step 6 / section 6.4's planned routes) reads the outcome from
// window.location.hash - see redirectToFrontend for why a fragment, not a
// query string.
func (d Deps) frontendCallbackURL() string {
	return strings.TrimRight(d.FrontendBaseURL, "/") + "/auth/complete"
}

// redirectToFrontend sends the browser to target with fragment encoded
// after "#", never as a query string: a URL fragment is never transmitted
// to any server - not Core's access log, not an intermediate proxy - which
// is what makes it an acceptable place to carry a one-time bearer token.
// The SPA reads window.location.hash on load and then clears it from
// history immediately, so the token does not linger in browser history
// either.
func redirectToFrontend(w http.ResponseWriter, r *http.Request, target string, fragment url.Values) {
	http.Redirect(w, r, target+"#"+fragment.Encode(), http.StatusFound)
}

// resolveProvider resolves the master key, then the OIDC configuration
// (Setup-Wizard-persisted-and-decrypted), then builds a fresh Provider via
// OIDC discovery. Shared by LoginHandler and CallbackHandler so both see the
// same configuration within a given request.
func (d Deps) resolveProvider(ctx context.Context) (*Provider, error) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return nil, err
	}
	oidcCfg, err := setup.ResolveOIDCConfig(ctx, d.Pool, masterKey)
	if err != nil {
		return nil, err
	}
	return NewProvider(ctx, oidcCfg.IssuerURL, oidcCfg.ClientID, oidcCfg.ClientSecret, d.redirectURL())
}

// LoginHandler starts the OIDC authorization-code flow: it resolves the
// currently configured OIDC provider (returns 412 if the Setup Wizard's
// steps 2-3 have not been completed yet), generates a CSRF/replay state
// value plus a PKCE code verifier (RFC 7636), stores the verifier in Valkey
// keyed by state for oauthStateTTL, and redirects the browser to the IdP's
// authorization endpoint with the verifier's S256 challenge attached.
func LoginHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		provider, err := d.resolveProvider(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		state, err := randomToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		codeVerifier := oauth2.GenerateVerifier()
		// The verifier itself is stored, not just a marker - CallbackHandler
		// needs it back to complete the PKCE exchange. It never leaves Core:
		// the browser only ever sees the state value and the S256 challenge.
		if err := d.Valkey.SetWithTTL(ctx, oauthStateKeyPrefix+state, codeVerifier, oauthStateTTL); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, provider.AuthCodeURL(state, codeVerifier), http.StatusFound)
	}
}

// CallbackHandler completes the flow LoginHandler started: it validates
// the state value (consuming it so it cannot be replayed), exchanges the
// authorization code for a verified ID token, derives a role from the
// groups claim against the configured group prefix (spec section 3.3's
// Dynamic Prefix Hard Gate), JIT-provisions the user row, and issues a
// session - subject to two access gates, checked in order:
//
//  1. Group membership: anyone not in any of the three configured groups
//     (DeriveRole returns RolePending) is rejected outright with
//     error=access_denied. No session, no user row, no "pending" screen -
//     spec section 3.3's hard gate means literally no access for them.
//  2. Approval and lock state: everyone who passes gate 1 still does not
//     get their real role on a session unless db.Pool.UserApproved returns
//     true AND db.Pool.UserLocked returns false for their OIDC subject.
//     Until approved, they get Role: RolePending (landing on /pending) -
//     this exists so an operator accidentally adding someone to a ModuLab
//     group in the IdP does not hand them instant access. If locked
//     instead (an admin revoked access after a previous approval), they
//     also get Role: RolePending, but with Locked: true on the session as
//     well, so the frontend's /pending screen can tell the two situations
//     apart and show the right message for each. The one exception to all
//     of this is while the Setup Wizard itself is still incomplete
//     (setup.WizardComplete == false): the very first login has to bind
//     the first Super-Admin, and there is no admin yet who could have
//     approved or locked them, so gate 2 is skipped entirely until the
//     wizard finishes.
//
// Every outcome - success or failure - ends in a redirect to
// d.frontendCallbackURL(), never a JSON body: this handler is only ever
// reached via the IdP's own browser redirect, so there is no API caller
// to return JSON to, only a browser tab to send somewhere useful. On
// success the bearer token, email, and (possibly gate-2-overridden) role
// are carried in the URL fragment (see redirectToFrontend's doc comment
// for why a fragment and not a query string); on failure a
// machine-readable error code is sent the same way so the SPA can show a
// message without parsing a plaintext HTTP error body. The SPA route
// handling this path is responsible for spec section 6.5 step 6's
// specific UX: if role is not "super-admin" during initial setup, show
// the "not a member of {prefix}super_admin" message and offer to retry
// login, rather than treating RolePending as a hard failure (ordinary end
// users legitimately land here as RolePending too, outside the wizard).
func CallbackHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		target := d.frontendCallbackURL()

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			redirectToFrontend(w, r, target, url.Values{"error": {"missing_state_or_code"}})
			return
		}

		codeVerifier, stateValid, err := d.Valkey.Get(ctx, oauthStateKeyPrefix+state)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}
		// Consumed immediately, success or not: a given state (and its
		// PKCE verifier) must never be replayable, including against a
		// second callback attempt with the same code.
		_ = d.Valkey.Del(ctx, oauthStateKeyPrefix+state)
		if !stateValid {
			redirectToFrontend(w, r, target, url.Values{"error": {"invalid_or_expired_state"}})
			return
		}

		provider, err := d.resolveProvider(ctx)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"provider_unavailable"}})
			return
		}

		claims, err := provider.Exchange(ctx, code, codeVerifier)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"exchange_failed"}})
			return
		}

		prefix, err := setup.ResolveGroupPrefix(ctx, d.Pool)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"group_prefix_unavailable"}})
			return
		}
		derivedRole := DeriveRole(claims.Groups, prefix)

		// Gate 1: not in any of the three configured groups at all - no
		// access whatsoever, not even a pending session.
		if derivedRole == RolePending {
			redirectToFrontend(w, r, target, url.Values{"error": {"access_denied"}})
			return
		}

		// Gate 2: approval and lock state, skipped entirely while the
		// wizard itself is still incomplete (see doc comment above for
		// why).
		wizardDone, err := setup.WizardComplete(ctx, d.Pool)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		approved := true
		locked := false
		if wizardDone {
			approved, err = d.Pool.UserApproved(ctx, claims.Subject)
			if err != nil {
				redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
				return
			}
			locked, err = d.Pool.UserLocked(ctx, claims.Subject)
			if err != nil {
				redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
				return
			}
		}

		// The row always stores the live derived role and the current
		// display name, even on a login that ends up with a RolePending
		// session below - so the moment an admin approves this subject,
		// their very next login immediately grants whichever role the
		// IdP's groups claim calls for right then, not whatever was true
		// back when this row was first created. name is included so an
		// admin reviewing approved = false rows in the database can tell
		// who someone actually is, not just their email address.
		wasNew, err := d.Pool.UpsertUser(ctx, claims.Subject, claims.Email, claims.Name, derivedRole, approved)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		sessionRole := derivedRole
		sessionLocked := false
		switch {
		case locked:
			// Checked before "not approved": a locked subject was, by
			// definition, approved at some point - locked takes priority
			// so the frontend shows "your account was locked", not "your
			// account is still pending approval", for someone an admin
			// has deliberately revoked rather than someone still waiting
			// on their very first review.
			sessionRole = RolePending
			sessionLocked = true
		case !approved:
			sessionRole = RolePending
		}

		// Spec section 3.5's "Neuer Pending-User" notification: fired only
		// for a genuinely brand-new row landing in pending state (wasNew
		// && !approved), not on every subsequent login attempt by someone
		// still waiting on review - see UpsertUser's doc comment on wasNew
		// for why that distinction needs a row-existence check at all.
		// Best-effort: a Valkey hiccup here must not turn an otherwise-
		// successful login into a failed one, so it is logged and ignored,
		// the same tradeoff LockUserHandler/DeleteUserHandler make for
		// RevokeUserSessions (admin.go).
		if wasNew && !approved {
			if err := notify.Publish(ctx, d.Valkey, notify.AdminChannel(), notify.Event{
				Type: "user.pending",
				Data: map[string]string{
					"subject": claims.Subject,
					"email":   claims.Email,
					"name":    claims.Name,
				},
			}); err != nil {
				log.Printf("auth: failed to publish user.pending notification for %s: %v", claims.Subject, err)
			}

			// Mail to every current admin, alongside the SSE event above:
			// notify.AdminChannel() only reaches whoever happens to have
			// /v1/events open at this exact moment - an admin who is not
			// online right now would otherwise have no way to learn about
			// this signup short of opening /admin/users on a hunch. Same
			// best-effort treatment as everywhere else in this file: a
			// lookup or enqueue failure here must not turn an otherwise-
			// successful login into a failed one.
			if admins, err := d.Pool.ListAdmins(ctx); err != nil {
				log.Printf("auth: failed to list admins for pending-approval mail: %v", err)
			} else {
				for _, admin := range admins {
					if admin.Email == "" {
						continue
					}
					msg := mail.PendingApprovalMessage(admin.Email, admin.Name, d.FrontendBaseURL, claims.Name, claims.Email)
					if err := mail.Enqueue(ctx, d.Valkey, msg); err != nil {
						log.Printf("auth: failed to enqueue pending-approval mail for %s: %v", admin.Email, err)
					}
				}
			}
		}

		token, err := CreateSession(ctx, d.Valkey, Session{
			UserID:            claims.Subject,
			Email:             claims.Email,
			EmailVerified:     claims.EmailVerified,
			Name:              claims.Name,
			PreferredUsername: claims.PreferredUsername,
			Picture:           claims.Picture,
			Role:              sessionRole,
			Locked:            sessionLocked,
		})
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		// Best-effort: audit the successful login. A failed write must not
		// block an otherwise-successful login — log the error and continue.
		if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
			if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventAuthLogin,
				ActorID:    claims.Subject,
				ActorEmail: claims.Email,
				Details:    fmt.Sprintf(`{"role":%q}`, sessionRole),
			}); err != nil {
				log.Printf("auth: audit login for %s: %v", claims.Subject, err)
			}
		}

		redirectToFrontend(w, r, target, url.Values{
			"token": {token},
			"email": {claims.Email},
			"role":  {sessionRole},
		})
	}
}

// MeResponse is the body of GET /v1/auth/me: every Session field
// (embedded, so they appear flat in the JSON - no nested "session" key),
// plus AccountSettingsURL, computed fresh on every request rather than
// baked into the session at login time, since it depends only on the
// currently configured OIDC issuer, not on anything about this particular
// user.
type MeResponse struct {
	Session
	// AccountSettingsURL points at the IdP's own account-management page
	// (Pocket ID's /settings/account) so the frontend's profile page
	// (spec section 6.4) can link out to it - Core has no UI of its own
	// for editing profile fields, since it does not own them; the IdP
	// does. Empty if OIDC's issuer URL cannot be resolved for some reason
	// (should not happen by the time a session exists, but resolved
	// defensively rather than assumed) - the frontend treats an empty
	// value as "no link to show", not an error.
	AccountSettingsURL string `json:"account_settings_url,omitempty"`
}

// MeHandler returns the session bound to the request's Bearer token, plus
// AccountSettingsURL (see MeResponse).
func MeHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		sess, ok, err := ValidateSession(ctx, d.Valkey, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}

		resp := MeResponse{Session: sess}
		if issuer, exists, err := setup.IssuerURL(ctx, d.Pool, d.MasterKeyEnv); err == nil && exists {
			resp.AccountSettingsURL = strings.TrimRight(issuer, "/") + "/settings/account"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// DeleteSelfHandler is DELETE /v1/auth/me: lets an already-authenticated
// user remove their own account entirely (db.Pool.DeleteUser) - the
// self-service counterpart to admin.go's DeleteUserHandler, which
// explicitly refuses to act on the caller's own account
// (guardAgainstSelfOrLastSuperAdmin) - without this endpoint there was no
// way at all for someone to remove themselves short of an admin doing it
// for them, or a manual DELETE FROM users. Still guarded against deleting
// the instance's last remaining super-admin (guardAgainstLastSuperAdmin,
// admin.go) - someone has to be left who can manage the instance
// afterward. Works regardless of the caller's session role (including a
// RolePending session - a pending user has just as much right to delete
// their own unfinished signup as an approved one), since the guard checks
// the stored row's real role via db.Pool.UserRole, not the session's
// possibly-overridden one. If this person logs in again later, they are
// JIT-provisioned as a brand-new pending user, exactly as
// DeleteUserHandler's doc comment describes for the admin-driven case.
// Sends mail.DeletedMessage to the caller's own address on success, same
// as DeleteUserHandler now does for the admin-driven case - a deletion
// confirmation, not an alert the recipient needs to act on.
func DeleteSelfHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		sess, ok, err := ValidateSession(ctx, d.Valkey, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}

		blocked, reason, err := guardAgainstLastSuperAdmin(ctx, d, sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if blocked {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}

		affected, err := d.Pool.DeleteUser(ctx, sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if affected == 0 {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		// Best-effort, same reasoning as admin.go's DeleteUserHandler:
		// the deletion itself already succeeded and is the source of
		// truth - a Valkey hiccup revoking the (now pointless, since the
		// row is gone) remaining sessions should not turn an otherwise-
		// successful self-delete into a 500 the user has to retry. This
		// also invalidates the very token used to make this request,
		// which is fine: the caller is about to discard it anyway.
		if err := RevokeUserSessions(ctx, d.Valkey, sess.UserID); err != nil {
			logRevokeError("delete-self", sess.UserID, err)
		}
		// Best-effort: audit the self-deletion. The row is already gone and
		// sessions are revoked; a failed write must not turn this into a 500.
		if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
			if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventUserSelfDeleted,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
			}); err != nil {
				log.Printf("auth: audit self-delete for %s: %v", sess.UserID, err)
			}
		}
		// sess.Email/sess.Name, not a fresh d.Pool.GetUser lookup: the row
		// is already gone by this point, so there is nothing left in the
		// database to look the address up from. The session loaded at the
		// top of this handler is the only copy of that information still
		// available - same best-effort treatment as everywhere else mail
		// is enqueued in this package: the deletion itself already
		// succeeded and is the source of truth, so a missed confirmation
		// email must not turn it into a 500 the caller has to retry.
		if sess.Email != "" {
			if err := mail.Enqueue(ctx, d.Valkey, mail.DeletedMessage(sess.Email, sess.Name)); err != nil {
				log.Printf("auth: delete-self: failed to enqueue mail for %s: %v", sess.UserID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// LogoutHandler invalidates the request's Bearer token immediately.
func LogoutHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		if err := DeleteSession(r.Context(), d.Valkey, token); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
