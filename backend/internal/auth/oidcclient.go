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

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider bundles what one OIDC login round-trip (redirect + callback)
// needs against a single, already-resolved provider configuration.
type Provider struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
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
			Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
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
// profile photo, or empty if the IdP/account has none. Both are optional by
// nature: callers (handlers.go, the frontend) must treat an empty value as
// "no display name/picture available", never as an error. EmailVerified
// comes from the "email" scope alongside Email itself - the frontend's
// profile page (spec section 6.4) shows it as-is, Core does not gate
// anything on it.
type Claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Groups        []string `json:"groups"`
}

// Exchange completes the authorization-code flow: it trades code for
// tokens (presenting codeVerifier so the IdP can validate it against the
// code_challenge sent in AuthCodeURL), then verifies the ID token's
// signature, issuer, audience, and expiry against the IdP's published JWKS
// (spec section 3.3: "Core validates JWTs statelessly via the IdP's public
// key") before trusting any claim inside it.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (Claims, error) {
	token, err := p.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return Claims{}, fmt.Errorf("auth: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return Claims{}, fmt.Errorf("auth: token response had no id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("auth: verify id_token: %w", err)
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return Claims{}, fmt.Errorf("auth: decode id_token claims: %w", err)
	}
	if claims.Subject == "" {
		return Claims{}, fmt.Errorf("auth: id_token has no sub claim")
	}
	return claims, nil
}
