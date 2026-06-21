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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"golang.org/x/oauth2"
)

// oauthStateTTL is deliberately short: a state value is only ever supposed
// to live between the redirect to the IdP and the user completing login
// there, normally a matter of seconds.
const oauthStateTTL = 5 * time.Minute

const oauthStateKeyPrefix = "oauthstate:"

// Deps bundles what the login/callback/logout/me handlers need. The
// MasterKeyEnv/OIDC*Env/GroupPrefixEnv fields are the raw environment
// values (config.Config's MasterKey, OIDCIssuerURL, OIDCClientID,
// OIDCClientSecret, GroupPrefix) - resolution against what the Setup
// Wizard may have persisted instead happens fresh on every request (see
// setup.ResolveMasterKey / ResolveOIDCConfig / ResolveGroupPrefix), so a
// wizard change takes effect immediately without a Core restart.
type Deps struct {
	Pool   *db.Pool
	Valkey *valkey.Client

	MasterKeyEnv        string
	OIDCIssuerEnv       string
	OIDCClientIDEnv     string
	OIDCClientSecretEnv string
	GroupPrefixEnv      string

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
// (env, or Setup-Wizard-persisted-and-decrypted), then builds a fresh
// Provider via OIDC discovery. Shared by LoginHandler and CallbackHandler
// so both see the same configuration within a given request.
func (d Deps) resolveProvider(ctx context.Context) (*Provider, error) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return nil, err
	}
	oidcCfg, err := setup.ResolveOIDCConfig(ctx, d.Pool, masterKey, d.OIDCIssuerEnv, d.OIDCClientIDEnv, d.OIDCClientSecretEnv)
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
// Dynamic Prefix Hard Gate - returns 412 if the wizard's step 5 has not
// been completed yet), JIT-provisions the user row, and issues a session.
//
// Every outcome - success or failure - ends in a redirect to
// d.frontendCallbackURL(), never a JSON body: this handler is only ever
// reached via the IdP's own browser redirect, so there is no API caller
// to return JSON to, only a browser tab to send somewhere useful. On
// success the bearer token, email, and role are carried in the URL
// fragment (see redirectToFrontend's doc comment for why a fragment and
// not a query string); on failure a machine-readable error code is sent
// the same way so the SPA can show a message without parsing a plaintext
// HTTP error body. The SPA route handling this path is responsible for
// spec section 6.5 step 6's specific UX: if role is not "super-admin"
// during initial setup, show the "not a member of {prefix}super_admin"
// message and offer to retry login, rather than treating RolePending as a
// hard failure (ordinary end users legitimately land here as RolePending
// too, outside the wizard).
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

		prefix, err := setup.ResolveGroupPrefix(ctx, d.Pool, d.GroupPrefixEnv)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"group_prefix_unavailable"}})
			return
		}
		role := DeriveRole(claims.Groups, prefix)

		if err := d.Pool.UpsertUser(ctx, claims.Subject, claims.Email, role); err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		token, err := CreateSession(ctx, d.Valkey, Session{UserID: claims.Subject, Email: claims.Email, Role: role})
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		redirectToFrontend(w, r, target, url.Values{
			"token": {token},
			"email": {claims.Email},
			"role":  {role},
		})
	}
}

// MeHandler returns the session bound to the request's Bearer token.
// Mainly useful for testing the flow end-to-end without a frontend yet -
// there is no other consumer of a session today.
func MeHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		sess, ok, err := ValidateSession(r.Context(), d.Valkey, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, sess)
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
