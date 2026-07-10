// This file wraps OIDC discovery and ID-token verification (coreos/go-oidc)
// together with the OAuth2 authorization-code flow (golang.org/x/oauth2)
// for the login flow in handlers.go.
//
// A new Provider is built fresh on every /v1/auth/login and
// /v1/auth/callback request rather than cached at startup, since OIDC
// configuration can change at runtime via the Setup Wizard (spec section
// 6.5) without a Core restart (see setup.ResolveOIDCConfig). This costs one
// extra discovery HTTP request per login attempt - caching the *.Provider
// per (issuer, clientID) pair is a reasonable follow-up once that latency
// matters; not done here to keep this commit reviewable.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider bundles what one OIDC login round-trip (redirect + callback)
// needs against a single, already-resolved provider configuration.
//
// oidcProvider (the underlying *oidc.Provider, distinct from this wrapper
// type) is kept around, not just its Endpoint()/Verifier(), so Revalidate
// below can call its UserInfo endpoint - go-oidc only exposes that as a
// method on the provider itself.
type Provider struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	oidcProvider *oidc.Provider
}

// NewProvider performs OIDC discovery against issuerURL (one HTTP request
// to {issuerURL}/.well-known/openid-configuration) and returns a Provider
// configured for the authorization-code flow with redirectURL as the
// callback target.
func NewProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc discovery against %q: %w", issuerURL, err)
	}

	return &Provider{
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			// "groups" is not a standard OIDC scope, but it is the
			// conventional claim name spec section 3.3's Dynamic Prefix
			// Hard Gate reads from, and most IdPs (Pocket ID included)
			// only populate it in the ID token when explicitly scoped.
			// An IdP that does not recognize the scope just omits the
			// claim - handled in handlers.go as an empty groups list
			// (-> RolePending), not an error. "profile" is also requested
			// so Name/Picture below are populated whenever the IdP has
			// them; "email" additionally brings EmailVerified.
			// "offline_access" is what makes the token response in
			// Exchange actually include a refresh_token at all - per the
			// OIDC/OAuth2 convention most IdPs (Pocket ID, Keycloak,
			// Authentik, Google, ...) follow, a refresh token is only
			// issued when this scope is explicitly requested, even for a
			// confidential client. Needed for RunSessionRevalidateWorker
			// (revalidate.go) to be able to periodically re-check a
			// session against the IdP without asking the user to log in
			// again. An IdP that does not support it simply omits the
			// refresh_token from the response - handled as "nothing to
			// revalidate against" (see storedSession.RefreshTokenEnc),
			// not an error.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"},
		},
		verifier:     p.Verifier(&oidc.Config{ClientID: clientID}),
		oidcProvider: p,
	}, nil
}

// AuthCodeURL returns the URL to redirect the browser to, with state as the
// CSRF/replay-binding value the callback must see again unchanged, and
// codeVerifier as the PKCE (RFC 7636) proof - its S256 hash is sent here as
// code_challenge; the plain verifier must be presented again in Exchange.
// PKCE is used even though this is a confidential client (it has a client
// secret): it is cheap, defends against authorization-code interception,
// and is the current best practice for every client type, not just public
// ones.
func (p *Provider) AuthCodeURL(state, codeVerifier string) string {
	return p.oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))
}

// Claims is the subset of ID token claims the login flow needs. Name and
// Picture come from the standard OIDC "profile" claims (already in the
// requested scope above) - PocketID and most other IdPs populate Name from
// whatever display name is configured there; Picture is the URL to a
// profile photo, or empty if the IdP/account has none. PreferredUsername is
// also a "profile"-scope claim (the IdP's separate, usually-stable login
// handle, distinct from Name which is meant to change freely as a display
// name) - same optionality as Name/Picture, and the same Go zero value
// ("") when an IdP simply does not populate it, which go-oidc's
// idToken.Claims(&claims) already gives for free for any claim missing
// from the token: there is nothing in this struct that requires a claim to
// be present, including Subject, Email, and Groups - DeriveRole/handlers.go
// already treat an empty/missing Groups as RolePending, and an empty
// Email/Name simply renders as "" wherever they're shown. The one
// exception CallbackHandler enforces itself, not this struct, is Subject -
// see Exchange's empty-Subject check below; every other field is allowed
// to come back empty and callers (handlers.go, the frontend) must treat
// that the same way Name/Picture already are: "not available", never an
// error. EmailVerified comes from the "email" scope alongside Email itself
// - the frontend's profile page (spec section 6.4) shows it as-is, Core
// does not gate anything on it.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
}

// Exchange completes the authorization-code flow: it trades code for
// tokens (presenting codeVerifier so the IdP can validate it against the
// code_challenge sent in AuthCodeURL), then verifies the ID token's
// signature, issuer, audience, and expiry against the IdP's published JWKS
// (spec section 3.3: "Core validates JWTs statelessly via the IdP's public
// key") before trusting any claim inside it.
//
// The second return value is the response's refresh_token, if the IdP
// issued one (see the "offline_access" scope comment on NewProvider) -
// empty string if not. CallbackHandler stores it (encrypted) on the new
// session so RunSessionRevalidateWorker can later re-check this login
// against the IdP without a fresh interactive login.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (Claims, string, error) {
	token, err := p.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return Claims{}, "", fmt.Errorf("auth: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return Claims{}, "", fmt.Errorf("auth: token response had no id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, "", fmt.Errorf("auth: verify id_token: %w", err)
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return Claims{}, "", fmt.Errorf("auth: decode id_token claims: %w", err)
	}
	if claims.Subject == "" {
		return Claims{}, "", fmt.Errorf("auth: id_token has no sub claim")
	}
	return claims, token.RefreshToken, nil
}

// Revalidate re-checks a previously issued refresh token against the IdP:
// it exchanges refreshToken for a fresh access token (the refresh grant
// itself is the actual "is this login still valid" check - a revoked or
// expired refresh token makes this call fail) and then calls the IdP's
// UserInfo endpoint to get the account's current claims. Used by
// RunSessionRevalidateWorker (revalidate.go), not by the interactive login
// flow.
//
// An error here means the refresh token was rejected by the IdP - the
// caller's job is to treat that as "this session is no longer valid there
// either" and revoke it locally, not to retry.
//
// The returned refreshToken is what should be persisted going forward:
// some IdPs rotate the refresh token on every use (OAuth2 refresh token
// rotation, RFC 6819 §5.2.2.3) - if so it differs from the one passed in,
// and re-using the old one on the next revalidation would then fail even
// though nothing is actually wrong. If the IdP does not rotate it, this is
// simply the same value passed in.
func (p *Provider) Revalidate(ctx context.Context, refreshToken string) (claims Claims, newRefreshToken string, err error) {
	tokenSource := p.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := tokenSource.Token()
	if err != nil {
		return Claims{}, "", fmt.Errorf("auth: refresh access token: %w", err)
	}

	userInfo, err := p.oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return Claims{}, "", fmt.Errorf("auth: fetch userinfo: %w", err)
	}
	if err := userInfo.Claims(&claims); err != nil {
		return Claims{}, "", fmt.Errorf("auth: decode userinfo claims: %w", err)
	}

	newRefreshToken = tok.RefreshToken
	if newRefreshToken == "" {
		// Not rotated by this IdP - keep using the same one next time.
		newRefreshToken = refreshToken
	}
	return claims, newRefreshToken, nil
}

// revocationEndpoint returns the RFC 7009 token revocation endpoint from the
// discovery document, if the IdP publishes one. "revocation_endpoint" is not
// part of the core OpenID Connect Discovery spec, but is a near-universal
// extension (RFC 8414 §2, and OAuth 2.0 Authorization Server Metadata) that
// go-oidc does not surface as a typed field - only via the raw discovery
// document, which oidc.Provider.Claims can decode into an arbitrary struct.
func (p *Provider) revocationEndpoint() (string, bool) {
	var doc struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := p.oidcProvider.Claims(&doc); err != nil || doc.RevocationEndpoint == "" {
		return "", false
	}
	return doc.RevocationEndpoint, true
}

// Revoke tells the IdP to invalidate refreshToken immediately (RFC 7009
// token revocation) instead of letting it sit valid until its own natural
// expiry (often 30 days). Called whenever a session holding this refresh
// token is killed locally (logout, admin "end session", lock/delete user) -
// without this, deleting Core's own encrypted copy of the token was
// cosmetic: anyone who separately obtained that same token before the
// session was killed (e.g. via a Valkey + master-key compromise) could
// still use it directly against the IdP for the rest of its own lifetime,
// regardless of what Core's session store said.
//
// Best-effort by design, matching how every caller treats this: an IdP that
// does not publish a revocation_endpoint is a silent no-op, not an error -
// RFC 7009 support is common but not universal. A revocation call that
// fails (network error, IdP rejects it) is returned as an error for the
// caller to log, not to retry or to block the local session deletion on -
// this is defense in depth, not the primary safeguard.
func (p *Provider) Revoke(ctx context.Context, refreshToken string) error {
	endpoint, ok := p.revocationEndpoint()
	if !ok {
		return nil
	}
	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("auth: build revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.oauth2Config.ClientID, p.oauth2Config.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth: revoke request: %w", err)
	}
	defer resp.Body.Close()
	// RFC 7009 §2.2: the endpoint MUST return 200 for both a successfully
	// revoked token and one it does not recognize (already expired,
	// invalid, or unknown) - a client cannot and should not try to
	// distinguish those cases. Only a non-2xx here indicates an actual
	// problem (e.g. bad client credentials).
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("auth: revoke request: IdP returned %s", resp.Status)
	}
	return nil
}
