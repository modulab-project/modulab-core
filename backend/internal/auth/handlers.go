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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/geoip"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
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

// oauthStatePayload is what LoginHandler stores in Valkey under
// oauthStateKeyPrefix+state, and CallbackHandler reads back and consumes.
// Replaces an earlier version of this codebase that stored the bare PKCE
// codeVerifier string directly - widened to a small JSON envelope so the
// step-up reauth flow (LoginHandler's ?reauth=1&return=... query params)
// can carry its own two extra fields through the same round trip without a
// second Valkey key. Reauth/ReturnPath are simply absent (Go zero values)
// for an ordinary login, so every existing call site that doesn't know
// about step-up reauth at all keeps working unchanged.
type oauthStatePayload struct {
	CodeVerifier string `json:"code_verifier"`
	// Reauth marks this round-trip as a step-up reauth (see AuthCodeURL's
	// forceReauth doc comment), not a fresh login - CallbackHandler uses it
	// to decide whether to log an auth_time freshness check.
	Reauth bool `json:"reauth,omitempty"`
	// ReturnPath is where the SPA should navigate back to once this
	// round-trip completes, instead of its normal post-login landing page -
	// e.g. "/admin/users", the page whose delete/lock action originally
	// triggered requireRecentLogin's 403. Validated by sanitizeReturnPath
	// before it is ever stored or echoed back to the browser.
	ReturnPath string `json:"return_path,omitempty"`
	// Nonce is the OIDC nonce sent with this round trip's authorization
	// request, kept here so CallbackHandler can check the returned ID
	// token's nonce claim against it (Provider.Exchange). Stored server-side
	// alongside the PKCE verifier rather than round-tripped through the
	// browser for the same reason that one is: the client must never be able
	// to choose or observe the value it will later be checked against.
	//
	// omitempty plus Exchange's skip-on-empty behaviour makes the deploy that
	// introduced this a non-event: a state written by the previous version
	// decodes with Nonce == "" and simply keeps working for the remaining
	// few minutes of its oauthStateTTL.
	Nonce string `json:"nonce,omitempty"`
}

// sanitizeReturnPath validates raw (the ?return= query parameter
// LoginHandler receives from the SPA) before it is trusted enough to be
// stored in oauthStatePayload and later echoed back into
// redirectToFrontend's URL fragment. Only ever needs to permit an
// in-app path, so the bar is deliberately strict rather than trying to
// enumerate every unsafe pattern: must start with exactly one "/" (a
// leading "//" is protocol-relative - e.g. "//evil.example" - and browsers
// resolve it as an absolute URL to a different host, the classic open-
// redirect trick this exists to block), must not itself start a new
// origin, and is capped at a sane length. Returns "" for anything that
// fails this - callers treat that exactly like "no return path was
// requested at all", never as an error worth surfacing to the user.
func sanitizeReturnPath(raw string) string {
	if raw == "" || len(raw) > 256 {
		return ""
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	if strings.ContainsAny(raw, " \t\n\r") {
		return ""
	}
	return raw
}

// lastCountryKeyPrefix indexes the two-letter country (from Cloudflare's
// CF-IPCountry header - see loginCountry below) of a subject's most recent
// login, keyed by UserID. Deliberately NOT tied to SessionTTL/
// SessionAbsoluteMaxAge: the whole point is to remember "where did this
// person usually log in from" across the gap between sessions (e.g. a
// login once a week), so it gets its own long, independent TTL
// (lastCountryTTL) instead of expiring alongside whatever session happened
// to create it. A two-letter country code is coarse-grained enough (millions
// of people share it) that it is not treated as PII requiring GCM
// encryption here, unlike Session.IP itself - same reasoning as Role/
// Locked staying plaintext in storedSession.
const lastCountryKeyPrefix = "lastcountry:"

// lastCountryTTL bounds how long a remembered login country survives with
// no new login at all - a year is generous enough that a returning user
// essentially never loses their baseline, while still not keeping the key
// around forever for an account nobody uses anymore.
const lastCountryTTL = 365 * 24 * time.Hour

// loginCountry reads Cloudflare's CF-IPCountry header, set on every request
// that actually passes through Cloudflare's proxy (not present for a
// DNS-only/"grey cloud" setup, or for local/direct access bypassing it).
// Returns "" if absent - callers must treat that as "anomaly detection not
// available for this request" and skip the check entirely (fail open),
// never as evidence of anything by itself.
func loginCountry(r *http.Request) string {
	return r.Header.Get("CF-IPCountry")
}

// LoginCountry exports loginCountry for main.go's identifyBySessionOrIP,
// the one caller of auth.ValidateSession outside this package - every
// in-package caller uses the unexported loginCountry directly.
func LoginCountry(r *http.Request) string {
	return loginCountry(r)
}

// loginCity looks up the city/region for a login's client IP via
// internal/geoip's lazily-opened GeoLite2 City reader. Takes the
// already-resolved client IP (clientIP(r) below), not the raw request -
// geoip2-golang needs a real IP to parse, not a header name to re-derive
// one from. Both return values are "" (ok=false) whenever GeoIP has not
// been configured/downloaded yet, or the address simply has no city-level
// data - same fail-open, "just don't show it" treatment loginCountry's own
// doc comment already describes for a missing CF-IPCountry header. Only
// ever used for the "logged in from" display on Session (captured once at
// login, exactly like Country), never for any access-control decision.
func loginCity(ip string) (city, region string) {
	city, region, _ = geoip.LookupCity(ip)
	return city, region
}

// loginASN looks up the autonomous-system organization (ISP/hosting
// provider) for a login's client IP via internal/geoip's lazily-opened
// GeoLite2 ASN reader. Same fail-open contract as loginCity.
func loginASN(ip string) (org string) {
	org, _ = geoip.LookupASN(ip)
	return org
}

// mailLocation combines a GeoIP city (possibly "") with a CF-IPCountry code
// (possibly "") into the single display value LoginMessage/AnomalyMessage
// show for "where this happened" - "Frankfurt am Main, DE" when both are
// known, just the country when city lookup found nothing (the common case -
// see loginCity's doc comment), just the city in the rare case GeoIP has
// data but Cloudflare's header is absent, or "" (both templates' own
// unknownText fallback takes over) when neither is available. Deliberately
// NOT used for the country-only anomaly-detection comparisons elsewhere in
// this file/session.go (checkAndRecordLoginCountry, sessionBaselineChanged)
// - those must keep comparing the plain two-letter code, never this
// human-readable string.
func mailLocation(city, country string) string {
	switch {
	case city == "":
		return country
	case country == "":
		return city
	default:
		return city + ", " + country
	}
}

// checkAndRecordLoginCountry compares country (this login's CF-IPCountry,
// possibly "") against the last country remembered for subject, then
// records country as the new baseline for next time. Returns anomaly=true
// only when both the previous and current country are known and they
// differ - a first-ever login (no baseline yet) or a request with no
// CF-IPCountry header at all is never flagged, since there is nothing
// meaningful to compare. previous is returned alongside purely so the
// caller can include it in the notification text ("previously DE, now
// US") without a second Valkey round trip.
func checkAndRecordLoginCountry(ctx context.Context, vk *valkey.Client, subject, country string) (anomaly bool, previous string) {
	if country == "" {
		return false, ""
	}
	key := lastCountryKeyPrefix + subject
	prev, exists, err := vk.Get(ctx, key)
	if err != nil {
		log.Printf("auth: read last login country for %s: %v", subject, err)
	} else if exists && prev != "" && prev != country {
		anomaly, previous = true, prev
	}
	if err := vk.SetWithTTL(ctx, key, country, lastCountryTTL); err != nil {
		log.Printf("auth: record last login country for %s: %v", subject, err)
	}
	return anomaly, previous
}

// auditLoginFailure records a security-relevant login failure that happened
// before Core could identify who was attempting it (nonce_mismatch,
// exchange_failed - see audit.EventAuthLoginFailed's doc comment) - ActorID
// is the client IP, same "bucketed by IP" treatment
// audit.EventRateLimitExceeded's own doc comment already describes for the
// same reason: there is no subject to attribute this to yet. Best-effort,
// like every other audit.Log call site in this file - a failure here must
// never turn into a second error response on top of the one already being
// returned to the browser.
func auditLoginFailure(ctx context.Context, d Deps, reason, ip, country, asnOrg string) {
	auditLoginFailureWithSubject(ctx, d, reason, ip, country, asnOrg, "", "")
}

// auditLoginFailureWithSubject is auditLoginFailure's counterpart for the
// one failure reason (access_denied) where Core does know who this was: the
// IdP successfully authenticated them, they are simply not a member of any
// of either of the two configured groups. subject/email, when non-empty, are
// recorded as both ActorID/ActorEmail (they are the one who attempted this)
// and TargetID/TargetEmail (they are also who the outcome applies to) -
// same "no separate actor" shape audit.EventUserSelfDeleted's doc comment
// already describes for an account acting on itself.
func auditLoginFailureWithSubject(ctx context.Context, d Deps, reason, ip, country, asnOrg, subject, email string) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		log.Printf("auth: resolve master key for login-failure audit (%s): %v", reason, err)
		return
	}
	actorID := ip
	if subject != "" {
		actorID = subject
	}
	params := audit.LogParams{
		EventType:  audit.EventAuthLoginFailed,
		ActorID:    actorID,
		ActorEmail: email,
		Details: fmt.Sprintf(`{"reason":%q,"country":%q,"asn_org":%q,"hosting_or_vpn":%t,"ip":%q}`,
			reason, country, asnOrg, geoip.IsHostingOrVPN(asnOrg), ip),
	}
	if subject != "" {
		params.TargetID = subject
		params.TargetEmail = email
	}
	if err := audit.Log(ctx, d.Pool, masterKey, params); err != nil {
		log.Printf("auth: audit login failure (%s) for %s: %v", reason, actorID, err)
	}
}

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
// to any server - not Core's access log, not an intermediate proxy. Used
// to be how the one-time bearer token itself reached the SPA; now that the
// token travels as an httpOnly Set-Cookie header on this same response
// instead (see setSessionCookie), the fragment only ever carries
// email/role/error - still worth keeping off a query string on general
// principle, but no longer a secret-transport concern. The SPA reads
// window.location.hash on load and then clears it from history
// immediately.
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
// value plus a PKCE code verifier (RFC 7636), stores the verifier (plus the
// step-up reauth flags below) in Valkey keyed by state for oauthStateTTL,
// and redirects the browser to the IdP's authorization endpoint with the
// verifier's S256 challenge attached.
//
// ?reauth=1 and ?return=<path> are set by the frontend's "please log in
// again" links (AdminUsersPage.tsx/ProfilePage.tsx, via
// useLoginRedirect.ts's startLogin options) whenever a destructive action
// was refused for needing a more recent login (requireRecentLogin,
// admin.go) - reauth=1 makes AuthCodeURL below force a genuine fresh IdP
// authentication instead of a silent SSO round-trip, and return carries
// the page the user was on so CallbackHandler can send them straight back
// to it (see oauthStatePayload/sanitizeReturnPath) instead of the ordinary
// post-login landing page. Both are simply absent for every other login on
// this instance (main login screen, Setup Wizard step 5), which behave
// exactly as before.
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
			httperr.Internal(w, err)
			return
		}
		codeVerifier := oauth2.GenerateVerifier()
		// Same entropy as state and the session token itself - see
		// randomToken. Deliberately independent of state: the two bind
		// different things (state binds the callback to this browser's
		// redirect, nonce binds the ID token to this authorization request),
		// and deriving one from the other would collapse both into a single
		// value an attacker only has to learn once.
		nonce, err := randomToken()
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		reauth := r.URL.Query().Get("reauth") == "1"
		returnPath := sanitizeReturnPath(r.URL.Query().Get("return"))

		payload, err := json.Marshal(oauthStatePayload{
			CodeVerifier: codeVerifier,
			Reauth:       reauth,
			ReturnPath:   returnPath,
			Nonce:        nonce,
		})
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		// The verifier (and the two step-up flags above) are stored, not
		// just a marker - CallbackHandler needs them back to complete the
		// PKCE exchange and to know how to finish the round trip. None of
		// this ever leaves Core: the browser only ever sees the state value
		// and the S256 challenge.
		if err := d.Valkey.SetWithTTL(ctx, oauthStateKeyPrefix+state, string(payload), oauthStateTTL); err != nil {
			httperr.Internal(w, err)
			return
		}

		http.Redirect(w, r, provider.AuthCodeURL(state, codeVerifier, nonce, reauth), http.StatusFound)
	}
}

// CallbackHandler completes the flow LoginHandler started: it validates
// the state value (consuming it so it cannot be replayed), exchanges the
// authorization code for a verified ID token, derives a role from the
// groups claim against the configured group prefix (spec section 3.3's
// Dynamic Prefix Hard Gate), JIT-provisions the user row, and issues a
// session - subject to two access gates, checked in order:
//
//  1. Group membership: anyone not in either of the two configured groups
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
//     the first Admin, and there is no admin yet who could have
//     approved or locked them, so gate 2 is skipped entirely until the
//     wizard finishes.
//
// Every outcome - success or failure - ends in a redirect to
// d.frontendCallbackURL(), never a JSON body: this handler is only ever
// reached via the IdP's own browser redirect, so there is no API caller
// to return JSON to, only a browser tab to send somewhere useful. On
// success the session token is set as an httpOnly cookie on this same
// response (see setSessionCookie) - the SPA never sees the raw token -
// while email and the (possibly gate-2-overridden) role are carried in the
// URL fragment (see redirectToFrontend's doc comment) purely so the SPA
// can decide where to navigate next without an extra round-trip; on
// failure a machine-readable error code is sent the same way so the SPA
// can show a message without parsing a plaintext HTTP error body. The SPA route
// handling this path is responsible for spec section 6.5 step 6's
// specific UX: if role is not "admin" during initial setup, show
// the "not a member of {prefix}admin" message and offer to retry
// login, rather than treating RolePending as a hard failure (ordinary end
// users legitimately land here as RolePending too, outside the wizard).
func CallbackHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		target := d.frontendCallbackURL()

		// Computed up front (not just at the success path further down, as
		// before) so the security-relevant failure branches below
		// (nonce_mismatch, exchange_failed, access_denied) can audit the
		// same country/ASN context a successful login already records - see
		// audit.EventAuthLoginFailed's doc comment. Cheap either way (one
		// header read, two already-lazy GeoIP lookups), so computing it here
		// unconditionally rather than only on the paths that end up needing
		// it keeps this single source of truth instead of two.
		ip := clientIP(r)
		country := loginCountry(r)
		asnOrg := loginASN(ip)

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			redirectToFrontend(w, r, target, url.Values{"error": {"missing_state_or_code"}})
			return
		}

		rawState, stateValid, err := d.Valkey.Get(ctx, oauthStateKeyPrefix+state)
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
		var statePayload oauthStatePayload
		if err := json.Unmarshal([]byte(rawState), &statePayload); err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"invalid_or_expired_state"}})
			return
		}

		provider, err := d.resolveProvider(ctx)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"provider_unavailable"}})
			return
		}

		claims, refreshToken, err := provider.Exchange(ctx, code, statePayload.CodeVerifier, statePayload.Nonce)
		if err != nil {
			// A nonce failure gets its own code rather than folding into
			// exchange_failed: it is the one Exchange error whose likely
			// cause is the IdP itself being non-conformant rather than
			// anything about this login attempt, and an operator who has
			// just deployed the nonce check needs to be able to tell those
			// apart from the login screen alone. Logged too, since the
			// fragment only carries the code and not the offending value.
			if errors.Is(err, ErrNonceMismatch) {
				log.Printf("auth: callback: %v", err)
				auditLoginFailure(ctx, d, "nonce_mismatch", ip, country, asnOrg)
				redirectToFrontend(w, r, target, url.Values{"error": {"nonce_mismatch"}})
				return
			}
			auditLoginFailure(ctx, d, "exchange_failed", ip, country, asnOrg)
			redirectToFrontend(w, r, target, url.Values{"error": {"exchange_failed"}})
			return
		}
		// Step-up reauth (statePayload.Reauth, set by LoginHandler's
		// ?reauth=1): best-effort informational check only, never a hard
		// gate - see AuthCodeURL's forceReauth doc comment for why real-world
		// auth_time/max_age conformance varies across IdPs, and why failing
		// this closed would risk locking out the instance's only admin over
		// a protocol quirk rather than an actual security problem. A missing
		// AuthTime (0) means this IdP simply doesn't return the claim -
		// nothing to compare, logged as such rather than as a mismatch.
		// Session.CreatedAt is what requireRecentLogin actually re-checks
		// (via the brand-new session CreateSession mints below, same as any
		// other login) - this block only adds visibility into whether the
		// IdP genuinely forced fresh authentication or silently reused its
		// own SSO session, it does not itself gate anything.
		if statePayload.Reauth {
			if claims.AuthTime == 0 {
				log.Printf("auth: step-up reauth for %s: IdP returned no auth_time claim, cannot verify freshness", claims.Subject)
			} else if age := time.Since(time.Unix(claims.AuthTime, 0)); age > 2*time.Minute {
				log.Printf("auth: step-up reauth for %s: auth_time is %s old despite prompt=login/max_age=0 - IdP may have silently reused an existing session instead of forcing fresh authentication", claims.Subject, age.Round(time.Second))
			}
		}

		prefix, err := setup.ResolveGroupPrefix(ctx, d.Pool)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"group_prefix_unavailable"}})
			return
		}
		derivedRole := DeriveRole(claims.Groups, prefix)

		// Gate 1: not in either of the two configured groups at all - no
		// access whatsoever, not even a pending session. Unlike
		// nonce_mismatch/exchange_failed above, Core does know who this was
		// (the IdP successfully authenticated them) - see
		// auditLoginFailureWithSubject's doc comment for why this one call
		// site carries ActorID/ActorEmail while the other two don't.
		if derivedRole == RolePending {
			auditLoginFailureWithSubject(ctx, d, "access_denied", ip, country, asnOrg, claims.Subject, claims.Email)
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
				pendingBranding := mail.CurrentBranding(ctx, d.Pool)
				for _, admin := range admins {
					if admin.Email == "" {
						continue
					}
					msg := mail.PendingApprovalMessage(admin.Email, admin.Name, d.FrontendBaseURL, claims.Name, claims.Email, pendingBranding)
					if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
						log.Printf("auth: failed to enqueue pending-approval mail for %s: %v", admin.Email, err)
					}
				}
			}
		}

		// ip/country/asnOrg were already resolved at the top of this handler
		// (see that doc comment for why) - only the city/region lookup is
		// specific to the success path (the failure branches above have no
		// use for it), so that's still done here.
		city, region := loginCity(ip)

		token, err := CreateSession(ctx, d, Session{
			UserID:            claims.Subject,
			Email:             claims.Email,
			EmailVerified:     claims.EmailVerified,
			Name:              claims.Name,
			PreferredUsername: claims.PreferredUsername,
			Picture:           claims.Picture,
			Role:              sessionRole,
			Locked:            sessionLocked,
			CreatedAt:         time.Now(),
			IP:                ip,
			UserAgent:         r.Header.Get("User-Agent"),
			Country:           country,
			City:              city,
			Region:            region,
			ASNOrg:            asnOrg,
		}, refreshToken)
		if err != nil {
			redirectToFrontend(w, r, target, url.Values{"error": {"server_error"}})
			return
		}

		// Best-effort: audit the successful login. A failed write must not
		// block an otherwise-successful login — log the error and continue.
		//
		// refresh_token_issued records only the fact, never the token value
		// itself (that stays GCM-encrypted in the session, see
		// storedSession.RefreshTokenEnc) - this is the supported way to
		// confirm the IdP actually granted one (e.g. after changing the
		// requested scopes), via the Admin Audit Log UI, instead of adding
		// it to Core's stdout log, which never logs token contents/secrets
		// by policy.
		if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
			// country/asn_org/hosting_or_vpn (added alongside
			// audit.EventAuthLoginFailed) let an admin filter/search the
			// audit log for where successful logins are coming from, the
			// same context a failed attempt now also carries - previously
			// only the live session tables (System Info/Profile) showed
			// this, with no way to search or filter by it after the fact.
			if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventAuthLogin,
				ActorID:    claims.Subject,
				ActorEmail: claims.Email,
				Details: fmt.Sprintf(`{"role":%q,"refresh_token_issued":%t,"country":%q,"asn_org":%q,"hosting_or_vpn":%t,"ip":%q}`,
					sessionRole, refreshToken != "", country, asnOrg, geoip.IsHostingOrVPN(asnOrg), ip),
			}); err != nil {
				log.Printf("auth: audit login for %s: %v", claims.Subject, err)
			}
		}

		// Live "you just logged in" push to any other already-open tab/
		// device for this same subject (notify.UserChannel, subscribed to
		// by every session regardless of role - see events.go). This is
		// the one signal a stolen/replayed session token itself can never
		// suppress: if someone else is using your account from a second
		// browser, a tab you already have open elsewhere sees it
		// immediately instead of you finding out from the System Info
		// active-sessions table days later, if ever. anomaly/previous come
		// from comparing Cloudflare's CF-IPCountry header (loginCountry)
		// against the last country remembered for this subject - both are
		// "" when no CF-IPCountry header is present at all (e.g. local
		// access bypassing Cloudflare), in which case anomaly is always
		// false and this degrades to a plain "new login" notice with no
		// country claim.
		anomaly, previousCountry := checkAndRecordLoginCountry(ctx, d.Valkey, claims.Subject, country)
		if pubErr := notify.Publish(ctx, d.Valkey, notify.UserChannel(claims.Subject), notify.Event{
			Type: "session.new",
			Data: map[string]any{
				"ip":               clientIP(r),
				"user_agent":       r.Header.Get("User-Agent"),
				"country":          country,
				"anomaly":          anomaly,
				"previous_country": previousCountry,
			},
		}); pubErr != nil {
			log.Printf("auth: notify session.new for %s: %v", claims.Subject, pubErr)
		}
		// Loaded once, used to gate every mail this login can produce below
		// (LoginMessage, AnomalyMessage) - never the live push above (that
		// one is not user-configurable, same reasoning notify.Publish call
		// sites elsewhere in this package give: an in-app toast is not the
		// kind of thing worth an opt-out) or the audit_log write below (a
		// user disabling their own anomaly mail must never also suppress the
		// admin-facing trail of the same event - that would make the
		// account-owner's own preference a way to hide evidence of token
		// misuse from an admin reviewing System Info/Audit Log later).
		// GetNotificationPrefs itself already fails open (all-true) on error,
		// so no separate error handling is needed here.
		notifyPrefs, _ := d.Pool.GetNotificationPrefs(ctx, claims.Subject)
		// Loaded once and reused by both LoginMessage and AnomalyMessage
		// below - see mail.CurrentBranding's doc comment on why this is
		// cheap to re-resolve per login rather than cached.
		loginBranding := mail.CurrentBranding(ctx, d.Pool)
		// Unconditional-per-login mail (not gated on anomaly at all) - see
		// mail.LoginMessage's own doc comment on how this differs from
		// AnomalyMessage below.
		if notifyPrefs.NewLogin && claims.Email != "" {
			msg := mail.LoginMessage(claims.Email, claims.Name, clientIP(r), mailLocation(city, country), r.Header.Get("User-Agent"), d.FrontendBaseURL, loginBranding)
			if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
				log.Printf("auth: enqueue login mail for %s: %v", claims.Subject, err)
			}
		}
		// Same gap AnomalyMessage's own doc comment describes: the live push
		// just above only reaches an already-open second tab/device, so mail
		// plus a durable audit_log row (EventAuthCountryAnomaly) are added
		// here too rather than leaving a login-time anomaly with a weaker
		// trail than the mid-session one (session.go's
		// checkSessionCountryAnomaly, which does the same). Both best-effort,
		// same reasoning as the login audit entry above - neither should ever
		// fail an otherwise-successful login.
		if anomaly {
			if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
				if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
					EventType:   audit.EventAuthCountryAnomaly,
					ActorID:     claims.Subject,
					ActorEmail:  claims.Email,
					TargetID:    claims.Subject,
					TargetEmail: claims.Email,
					Details:     fmt.Sprintf(`{"source":"login","country":%q,"previous_country":%q,"ip":%q}`, country, previousCountry, clientIP(r)),
				}); err != nil {
					log.Printf("auth: audit login country anomaly for %s: %v", claims.Subject, err)
				}
			} else {
				log.Printf("auth: audit login country anomaly for %s: resolve master key: %v", claims.Subject, mkErr)
			}
			if notifyPrefs.CountryAnomaly && claims.Email != "" {
				msg := mail.AnomalyMessage(claims.Email, claims.Name, clientIP(r), mailLocation(city, country), previousCountry, d.FrontendBaseURL, loginBranding)
				if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
					log.Printf("auth: enqueue login country anomaly mail for %s: %v", claims.Subject, err)
				}
			}
		}

		// The session cookie is set directly on this redirect response,
		// never carried in the URL fragment the way the bearer token used
		// to be (see setSessionCookie's doc comment) - httpOnly means the
		// SPA never needs to see the raw token at all, only email/role for
		// its immediate "where do I send the browser next" decision.
		setSessionCookie(w, token)

		fragment := url.Values{
			"email": {claims.Email},
			"role":  {sessionRole},
		}
		// Only set when LoginHandler's ?return= produced a validated path
		// (statePayload.ReturnPath, via sanitizeReturnPath) - AuthComplete.tsx
		// treats an absent value exactly like an ordinary login, landing on
		// its normal role-based default instead.
		if statePayload.ReturnPath != "" {
			fragment.Set("return", statePayload.ReturnPath)
		}
		redirectToFrontend(w, r, target, fragment)
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

// MeHandler returns the session bound to the request's session cookie, plus
// AccountSettingsURL (see MeResponse).
func MeHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		sess, ok, err := SessionFromRequest(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !ok {
			// Used to carry a TEMP DIAGNOSTIC log here for an iOS Safari
			// swipe-logout bug tied to sessionStorage's per-tab, bfcache-
			// fragile nature (see frontend/src/lib/useSession.ts's matching
			// removed "[auth-diag]" logs). The session cookie this now reads
			// from is httpOnly and not page-scoped storage at all, so that
			// failure class doesn't apply here anymore - removed rather than
			// carried forward.
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		// Same sliding-cookie reasoning as requireActiveSessionWithToken
		// (admin.go): ValidateSession already extended the Valkey-side TTL
		// above, so the cookie's own Max-Age must slide forward with it too,
		// otherwise a tab that only ever calls GET /v1/auth/me (e.g. on app
		// boot, or while idle) has its cookie expire exactly SessionTTL after
		// login regardless of activity - the same bug that motivated adding
		// this call to requireAdmin/requireActiveSessionWithToken in the
		// first place, just missed here.
		setSessionCookie(w, token)

		resp := MeResponse{Session: sess}
		if issuer, exists, err := setup.IssuerURL(ctx, d.Pool, d.MasterKeyEnv); err == nil && exists {
			resp.AccountSettingsURL = strings.TrimRight(issuer, "/") + "/settings/account"
		}
		httperr.JSON(w, http.StatusOK, resp)
	}
}

// DeleteSelfHandler is DELETE /v1/auth/me: lets an already-authenticated
// user remove their own account entirely (db.Pool.DeleteUser) - the
// self-service counterpart to admin.go's DeleteUserHandler, which
// explicitly refuses to act on the caller's own account
// (guardAgainstSelfOrLastAdmin) - without this endpoint there was no
// way at all for someone to remove themselves short of an admin doing it
// for them, or a manual DELETE FROM users. Still guarded against deleting
// the instance's last remaining admin (guardAgainstLastAdmin,
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
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		sess, ok, err := SessionFromRequest(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		// Same sliding-cookie reasoning as MeHandler above.
		setSessionCookie(w, token)
		// Same Origin/CSRF checks as RequireActiveSession (admin.go). This
		// handler validates the session itself rather than going through
		// RequireActiveSession because that helper also rejects RolePending
		// sessions, and DeleteSelf deliberately does not - see the doc
		// comment above. The CSRF/Origin guard is independent of that role
		// exception, so it is inlined here rather than skipped: without it,
		// an installed module's JS (same realm, no iframe isolation) could
		// delete the calling user's account via a same-origin fetch that
		// carries the session cookie automatically.
		if !originAllowed(d, r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if !validateCSRF(w, r, sess) {
			return
		}
		if !requireRecentLogin(ctx, d, w, sess, "delete_self") {
			return
		}

		blocked, reason, err := guardAgainstLastAdmin(ctx, d, sess.UserID)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if blocked {
			http.Error(w, reason, http.StatusBadRequest)
			return
		}

		affected, err := d.Pool.DeleteUser(ctx, sess.UserID)
		if err != nil {
			httperr.Internal(w, err)
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
		if err := RevokeUserSessions(ctx, d, sess.UserID); err != nil {
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
			if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, mail.DeletedMessage(sess.Email, sess.Name, mail.CurrentBranding(ctx, d.Pool))); err != nil {
				log.Printf("auth: delete-self: failed to enqueue mail for %s: %v", sess.UserID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserPrefsResponse is the body of GET /v1/user/preferences.
type UserPrefsResponse struct {
	UILanguage string `json:"ui_language"` // "en", "de", or "" (browser default)
	Theme      string `json:"theme"`       // "light", "dark", "system", or "" (client default)
	db.NotificationPrefs
}

// UserPrefsHandler handles GET and PATCH /v1/user/preferences.
//
// GET returns the caller's stored UI language and theme preferences.
// PATCH accepts a partial body - any subset of {"ui_language": "en"|"de"|"",
// "theme": "light"|"dark"|"system"|""} - and persists only the fields
// present in the request; responds 204.
//
// Both methods require a valid non-pending session (validated via Valkey, same
// pattern as MeHandler). Both fields are stored as plaintext (ui_language on
// users.ui_language, theme on users.theme) - neither is PII and neither
// needs GCM encryption.
func UserPrefsHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		sess, ok, err := SessionFromRequest(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		// Same sliding-cookie reasoning as MeHandler above.
		setSessionCookie(w, token)
		// Same Origin/CSRF checks as RequireActiveSession (admin.go), inlined
		// rather than delegated because this handler validates the session
		// itself instead of going through RequireActiveSession. validateCSRF
		// is a no-op for GET (csrfProtectedMethod), so this is safe to call
		// unconditionally for both methods this handler serves. Without it,
		// an installed module's JS (same realm, no iframe isolation) could
		// silently rewrite the calling user's UI language/theme via a
		// same-origin PATCH that carries the session cookie automatically.
		if !originAllowed(d, r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if !validateCSRF(w, r, sess) {
			return
		}

		switch r.Method {
		case http.MethodGet:
			lang, err := d.Pool.GetUserLanguage(ctx, sess.UserID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			theme, err := d.Pool.GetUserTheme(ctx, sess.UserID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			notifyPrefs, err := d.Pool.GetNotificationPrefs(ctx, sess.UserID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			httperr.JSON(w, http.StatusOK, UserPrefsResponse{UILanguage: lang, Theme: theme, NotificationPrefs: notifyPrefs})

		case http.MethodPatch:
			// Pointer fields, not plain strings: the frontend now sends a
			// partial body (e.g. {"theme": "dark"} alone, from the theme
			// toggle, without ui_language). A plain string field would
			// decode a missing "ui_language" key as "" and SetUserLanguage
			// below would then silently wipe out the stored language on
			// every theme-only PATCH. nil means "field not present in this
			// request, leave the stored value alone".
			var body struct {
				UILanguage *string `json:"ui_language"`
				Theme      *string `json:"theme"`
				// The four notify_* toggles (db.NotificationPrefs' own JSON
				// tags) - same partial-update, pointer-means-"untouched"
				// semantics as UILanguage/Theme above, passed straight through
				// to SetNotificationPrefs' own COALESCE-based partial update.
				NewLogin              *bool `json:"notify_new_login"`
				CountryAnomaly        *bool `json:"notify_country_anomaly"`
				NewDevice             *bool `json:"notify_new_device"`
				SessionRevokedByAdmin *bool `json:"notify_session_revoked_by_admin"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			// Validation for both is delegated to the Set* methods (they
			// reset unrecognized values to "").
			if body.UILanguage != nil {
				if err := d.Pool.SetUserLanguage(ctx, sess.UserID, *body.UILanguage); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
			if body.Theme != nil {
				if err := d.Pool.SetUserTheme(ctx, sess.UserID, *body.Theme); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
			if body.NewLogin != nil || body.CountryAnomaly != nil || body.NewDevice != nil || body.SessionRevokedByAdmin != nil {
				if err := d.Pool.SetNotificationPrefs(ctx, sess.UserID, body.NewLogin, body.CountryAnomaly, body.NewDevice, body.SessionRevokedByAdmin); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ExportSelfHandler handles GET /v1/auth/me/export — the DSGVO data portability
// endpoint (GDPR Article 20). It collects every piece of personal data Core
// stores for the calling user and returns it as a JSON file download.
//
// Intentionally comprehensive: the response includes the user's profile, UI
// preferences, search preferences, which AI providers they have a key for
// (never the key material itself), news feed subscriptions, and personal quick
// links. No admin data (audit log, other users) is included.
func ExportSelfHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		sess, ok, err := SessionFromRequest(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		// Same sliding-cookie reasoning as MeHandler above.
		setSessionCookie(w, token)

		// Profile row (decrypted).
		user, found, err := d.Pool.GetUserExportRow(ctx, sess.UserID)
		if err != nil || !found {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		// Search preferences.
		searchPrefs, _ := d.Pool.GetSearchPrefs(ctx, sess.UserID)

		// AI provider key flags (never key material).
		aiProviders, _ := d.Pool.ListAIProvidersForUser(ctx, sess.UserID)
		type aiEntry struct {
			ProviderID string `json:"provider_id"`
			Name       string `json:"name"`
			HasUserKey bool   `json:"has_user_key"`
		}
		aiEntries := make([]aiEntry, 0, len(aiProviders))
		for _, p := range aiProviders {
			if p.HasUserKey {
				aiEntries = append(aiEntries, aiEntry{
					ProviderID: p.ID,
					Name:       p.Name,
					HasUserKey: true,
				})
			}
		}

		// Feed subscriptions.
		feeds, _ := d.Pool.ListFeedsForUser(ctx, sess.UserID)
		type feedEntry struct {
			Label   string `json:"label"`
			URL     string `json:"url"`
			Enabled bool   `json:"enabled"`
		}
		feedEntries := make([]feedEntry, 0)
		for _, f := range feeds {
			feedEntries = append(feedEntries, feedEntry{
				Label:   f.Label,
				URL:     f.URL,
				Enabled: f.Enabled,
			})
		}

		// Personal quick links.
		userLinks, _ := d.Pool.ListUserQuickLinks(ctx, sess.UserID)
		type linkEntry struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description,omitempty"`
		}
		linkEntries := make([]linkEntry, 0, len(userLinks))
		for _, l := range userLinks {
			linkEntries = append(linkEntries, linkEntry{
				Title:       l.Title,
				URL:         l.URL,
				Description: l.Description,
			})
		}

		type profileSection struct {
			UserID      string `json:"user_id"`
			Email       string `json:"email"`
			Name        string `json:"name"`
			Role        string `json:"role"`
			Approved    bool   `json:"approved"`
			UILanguage  string `json:"ui_language"`
			Theme       string `json:"theme"`
			CreatedAt   string `json:"created_at"`
			LastLoginAt string `json:"last_login_at"`
		}
		type searchSection struct {
			Language   string `json:"language"`
			Safesearch int    `json:"safesearch"`
		}
		type exportDoc struct {
			ExportedAt         string         `json:"exported_at"`
			Profile            profileSection `json:"profile"`
			SearchPreferences  searchSection  `json:"search_preferences"`
			AIProviderKeys     []aiEntry      `json:"ai_provider_keys"`
			FeedSubscriptions  []feedEntry    `json:"feed_subscriptions"`
			PersonalQuickLinks []linkEntry    `json:"personal_quick_links"`
		}

		doc := exportDoc{
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
			Profile: profileSection{
				UserID:      user.Subject,
				Email:       user.Email,
				Name:        user.Name,
				Role:        user.Role,
				Approved:    user.Approved,
				UILanguage:  user.UILanguage,
				Theme:       user.Theme,
				CreatedAt:   user.CreatedAt.UTC().Format(time.RFC3339),
				LastLoginAt: user.LastLoginAt.UTC().Format(time.RFC3339),
			},
			SearchPreferences: searchSection{
				Language:   searchPrefs.Language,
				Safesearch: searchPrefs.Safesearch,
			},
			AIProviderKeys:     aiEntries,
			FeedSubscriptions:  feedEntries,
			PersonalQuickLinks: linkEntries,
		}

		// Use the OIDC subject as a filename fragment — it's stable, unique,
		// and not PII in the filename context (the user is downloading their own
		// data and already knows their own sub).
		filename := "modulab-export.json"
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
	}
}

// LogoutHandler invalidates the request's Bearer token immediately.
//
// Looks the session up (ValidateSession) before deleting it purely to have
// an actor to audit - login has always produced an audit.EventAuthLogin
// entry, but logout previously produced no trail at all, an asymmetry
// found during the pre-V1 re-audit. If the token is already invalid/expired
// by the time this runs (e.g. a double-click, or it was already revoked
// elsewhere), ValidateSession's ok=false just skips the audit write - the
// actual deletion below still runs unconditionally, since a client asking
// to log out with a token that turns out to be already-dead should still
// get a clean 204, not an error.
func LogoutHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Enforced explicitly (main.go registers this route without a
		// method prefix, so it would otherwise accept a GET too): a plain
		// GET logout endpoint is a cross-site top-level navigation away
		// from being CSRF-able via a naked <a href> or auto-redirect, since
		// SameSite=Lax still allows the cookie on that specific case (see
		// corsMiddleware's doc comment for the fuller picture). Logging
		// someone out against their will is low-severity compared to the
		// admin-action endpoints that doc comment is really about, but
		// there is no reason to leave this one open too now that it's
		// cheap to close.
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}

		sess, ok, err := SessionFromRequest(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))

		// Best-effort: also invalidate this session's refresh token at the
		// IdP itself (see Provider.Revoke's doc comment), not just delete
		// Core's own copy below. Fetched separately from ValidateSession's
		// Session, which deliberately does not carry RefreshTokenEnc (see
		// storedSession's doc comment) - a decode failure here just skips
		// IdP revocation, it never blocks the actual logout.
		if raw, exists, getErr := d.Valkey.Get(ctx, sessionKeyPrefix+token); getErr == nil && exists {
			var stored storedSession
			if jsonErr := json.Unmarshal([]byte(raw), &stored); jsonErr == nil {
				bestEffortRevokeAtIdP(ctx, d, []storedSession{stored})
			}
		}

		if err := DeleteSession(ctx, d.Valkey, token); err != nil {
			httperr.Internal(w, err)
			return
		}
		// The token itself is gone from Valkey above - this makes sure the
		// browser stops sending it too, on every tab sharing this cookie
		// (see setSessionCookie's doc comment on why one cookie now covers
		// every tab), rather than continuing to present an already-dead
		// token until the cookie's own Max-Age lapses on its original
		// schedule.
		clearSessionCookie(w)

		// Best-effort, same tradeoff as every other audit.Log call in this
		// package: the logout itself already succeeded above - a failed or
		// skipped audit write must not turn it into an error for the caller.
		if err == nil && ok {
			if masterKey, mkErr := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv); mkErr == nil {
				if auditErr := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
					EventType:  audit.EventAuthLogout,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
				}); auditErr != nil {
					log.Printf("auth: audit logout for %s: %v", sess.UserID, auditErr)
				}
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

// sessionCookieName is the httpOnly cookie the browser holds the caller's
// full session bearer token in - see setSessionCookie's doc comment for why
// this replaced the earlier "Bearer token in sessionStorage" transport.
// Deliberately NOT reused for module-scoped tokens (auth.BearerToken /
// bearerToken above stay header-only, see moduletoken.go) - a module's own
// UI bundle must keep attaching its own narrower token explicitly, never
// inherit whatever this cookie happens to hold.
//
// The __Host- prefix is a browser-enforced contract (RFC 6265bis), not just
// a naming convention: a cookie named with this prefix is only accepted by
// the browser if it also carries Secure, Path=/, and no Domain attribute -
// exactly the three properties setSessionCookie already sets below, so this
// costs nothing and gives an extra, browser-side guarantee against a
// subdomain (or same-site sibling app) ever setting or overriding this
// cookie out from under Core.
const sessionCookieName = "__Host-modulab_session"

// SessionCookieName exposes sessionCookieName to callers outside this
// package - same reasoning as SessionKeyPrefix in session.go. main.go used
// to keep its own hardcoded copy of this string for its package-local
// sessionToken(r) (identifyBySessionOrIP's rate-limit bucketing and
// systemInfoHandler's "is this row the caller's own session" check); that
// copy silently fell out of sync when this cookie picked up its __Host-
// prefix (found 2026-07-27, via Security Info never flagging the caller's
// own row as current) and would have been caught immediately by using this
// constant instead of a second string literal.
const SessionCookieName = sessionCookieName

// sessionToken reads the caller's full session bearer token from its
// httpOnly cookie. This is the one and only place that does so - every
// session-consuming handler in this package (MeHandler, LogoutHandler,
// DeleteSelfHandler, UserPrefsHandler, ExportSelfHandler,
// RequireActiveSession, requireAdmin, moduletoken.go's exported
// BearerToken) calls this instead of bearerToken(r) above, which remains
// header-only and is reserved for module-scoped tokens.
func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// setSessionCookie writes token to the browser as an httpOnly, Secure,
// SameSite=Lax cookie with the same lifetime as the session itself
// (SessionTTL) - called once, by CallbackHandler, right after CreateSession
// mints the token.
//
// httpOnly means JavaScript cannot read this cookie at all, not even from
// same-origin code - unlike the previous sessionStorage-held bearer token,
// an XSS payload running in the page can no longer exfiltrate it. The
// cookie is also automatically sent by the browser for every same-origin
// request from every tab, not just the one that logged in - which is what
// actually fixes the "one row per open tab" active-sessions clutter this
// change was originally scoped to solve: a second tab now reuses the
// existing cookie instead of running its own OIDC round-trip and minting a
// second, independent Valkey session.
//
// SameSite=Lax (not Strict) so the cookie is still sent on the top-level
// GET redirect the IdP itself performs to land the browser back on
// CallbackHandler - Strict would drop it on that cross-site navigation and
// break login. Secure is unconditional (no dev-mode exception): the
// project's own test environment always runs behind TLS, so there is no
// plain-HTTP deployment target this needs to accommodate.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(SessionTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie is setSessionCookie's inverse - called by LogoutHandler
// right after DeleteSession, so the browser actually discards the cookie
// instead of continuing to send an already-revoked token on every
// subsequent request until it naturally expires.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clientIP extracts the originating client address for the session's
// IP field below. Same X-Forwarded-For-first logic as cmd/core/main.go's
// own clientIP (Core sits behind Traefik, which sets that header - using
// r.RemoteAddr directly would just record Traefik's own container address
// for every login) - duplicated here rather than exported from main,
// since main imports this package and not the other way around, and it's
// a handful of lines.
//
// X-Forwarded-For is only trusted when the immediate peer (r.RemoteAddr) is
// itself a private/loopback address (same fix as cmd/core/main.go and
// internal/bootstrap/manager.go's identical helpers, 2026-07-05/2026-07-23
// security passes) - i.e. the request arrived over the internal Docker
// network from Traefik, not from a client that reached Core directly.
// Without this check, anyone able to connect to Core's port directly could
// put any value they like in X-Forwarded-For and have it recorded as the
// session's IP, defeating IP-based auditing/anomaly checks entirely. A
// client that connects directly always falls through to its real
// RemoteAddr instead.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && isTrustedProxyPeer(host) {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host != "" {
		return host
	}
	return r.RemoteAddr
}

// isTrustedProxyPeer reports whether host (the immediate TCP peer, before
// any X-Forwarded-For is considered) is a loopback or private-range
// address - Traefik reaches Core over the Docker-internal network, which
// uses exactly these ranges. Duplicated from cmd/core/main.go /
// internal/bootstrap/manager.go rather than exported, same reasoning as
// clientIP above.
func isTrustedProxyPeer(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// BearerTokenAllowQuery is bearerToken plus a ?t= query-parameter fallback,
// for the one route where an Authorization header genuinely cannot be sent:
// <img src>-style browser-initiated GETs against module storage files.
// Every other endpoint must use RequireActiveSession/RequireAdminSession or
// header-only RequireModuleToken, because a token in the URL ends up in
// access logs, browser history, and any Referer header sent onward — and a
// module token is not a read-only asset key, it authenticates against that
// module's whole API for the rest of its TTL.
//
// ModuleBundleHandler used to be a second caller; the fallback was removed
// there on 2026-07-28 after confirming nothing ever used it (ModulePage.tsx
// fetches the bundle with a real Authorization header, and a module never
// loads its own bundle). Adding a third caller here should be treated as a
// design decision, not a convenience: see router.go's ModuleStorageHandler
// for the full exposure and for the signed-URL replacement that is meant to
// retire this function entirely.
func BearerTokenAllowQuery(r *http.Request) string {
	if t := bearerToken(r); t != "" {
		return t
	}
	return r.URL.Query().Get("t")
}
