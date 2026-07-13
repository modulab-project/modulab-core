// Module-scoped session tokens.
//
// Background: until now, ModulePage.tsx handed a module's UI bundle the
// caller's full session bearer token (see ModuleComponentProps.token) so the
// module component could call its own /v1/modules/{name}/api/* endpoints.
// But module bundles are loaded via fetch()+Blob-URL dynamic import() into
// the SAME top-level JS realm as the host app (no iframe sandbox - see
// ModulePage.tsx's doc comment and the Core security review, 2026-07,
// "Modul-Rendering ohne Sandbox") - so a buggy or compromised module had the
// same API access as the logged-in user themselves, including every
// admin/user-management endpoint, not just its own.
//
// A module-scoped token narrows that: it is a short-lived, random,
// unrelated string that only ever resolves back to the caller's session
// when presented alongside the exact module name it was minted for
// (ValidateModuleToken). A module holding one can call its own API and load
// its own bundle/locale/storage files, and nothing else. This does not
// replace the planned iframe-sandboxed rendering (that remains the stronger
// fix - a scoped token still doesn't stop a malicious module from reading
// unrelated DOM/localStorage in the host page), but it removes the single
// biggest piece of blast radius - the full session token - from every
// module's reach, for comparatively little work.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const moduleTokenKeyPrefix = "moduletoken:"

// ModuleTokenTTL is deliberately short (much shorter than SessionTTL): a
// module token is minted fresh by the frontend every time it loads a
// module page (see ModulePage.tsx), not something a user is meant to carry
// around all day. 20 minutes gives comfortable headroom for a single
// module-page visit (including the frontend's own proactive refresh well
// before expiry) without leaving a long-lived, widely-scoped-down-but-still-
// real credential sitting in a module's memory for hours.
const ModuleTokenTTL = 20 * time.Minute

// moduleTokenRecord is what's stored in Valkey for a minted module token.
// SessionToken is the caller's own real session bearer token - not
// duplicated/re-encrypted PII, just a reference so ValidateModuleToken can
// delegate back to ValidateSession (and therefore automatically inherit
// revocation: if the underlying session is logged out or locked before this
// module token expires, ValidateModuleToken starts failing too, with no
// separate revocation bookkeeping needed here). This is never returned to
// the browser - only the random moduletoken: key is.
type moduleTokenRecord struct {
	Module       string `json:"module"`
	SessionToken string `json:"session_token"`
}

// CreateModuleToken mints a new module-scoped token for module, delegating
// to sessionToken (the caller's own already-validated session bearer
// token). Called by modules.ModuleTokenHandler (GET
// /v1/modules/{name}/token), which itself requires a full active session
// first - this function does not re-validate sessionToken, that is the
// caller's job.
func CreateModuleToken(ctx context.Context, d Deps, sessionToken, module string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	rec := moduleTokenRecord{Module: module, SessionToken: sessionToken}
	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("auth: marshal module token: %w", err)
	}
	if err := d.Valkey.SetWithTTL(ctx, moduleTokenKeyPrefix+token, string(data), ModuleTokenTTL); err != nil {
		return "", fmt.Errorf("auth: store module token: %w", err)
	}
	return token, nil
}

// ValidateModuleToken resolves token back to the Session it was minted
// for, but only if it was issued for exactly module - a token minted for
// "recipes" presented against "unifi-network"'s routes is rejected the same
// as an unknown token, not just logged. Piggybacks on ValidateSession for
// the actual session lookup (see moduleTokenRecord's doc comment), so a
// module token is never valid for longer than both its own TTL AND the
// underlying session's remain true.
func ValidateModuleToken(ctx context.Context, d Deps, token, module string) (Session, bool, error) {
	raw, exists, err := d.Valkey.Get(ctx, moduleTokenKeyPrefix+token)
	if err != nil {
		return Session{}, false, err
	}
	if !exists {
		return Session{}, false, nil
	}
	var rec moduleTokenRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return Session{}, false, fmt.Errorf("auth: decode module token: %w", err)
	}
	if rec.Module != module {
		return Session{}, false, nil
	}
	return ValidateSession(ctx, d, rec.SessionToken)
}

// RequireModuleToken is the module-token equivalent of RequireActiveSession:
// validates the request's bearer (or, if allowQuery, ?t=) token as a
// module-scoped token minted for exactly module, and writes the appropriate
// error status itself on failure. Use for every route a module's own UI
// bundle/component calls directly (proxy API, bundle, locale, storage).
//
// Two host-only informational endpoints (GET /v1/modules/{name} and GET
// /v1/modules/{name}/egress-hosts) are the one exception: use
// RequireSessionOrModuleToken for those instead - see its doc comment.
func RequireModuleToken(d Deps, module string, w http.ResponseWriter, r *http.Request, allowQuery bool) (Session, bool) {
	token := bearerToken(r)
	if token == "" && allowQuery {
		token = r.URL.Query().Get("t")
	}
	if token == "" {
		http.Error(w, "missing module token", http.StatusUnauthorized)
		return Session{}, false
	}
	sess, ok, err := ValidateModuleToken(r.Context(), d, token, module)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired module token", http.StatusUnauthorized)
		return Session{}, false
	}
	if sess.Role == RolePending || sess.Locked {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// RequireSessionOrModuleToken accepts either a full session bearer token OR
// a module-scoped token minted for exactly module. Needed because every
// module's own UI bundle (e.g. unifi-network/recipes' ModuleInfoView "info"
// tab) only ever holds the module-scoped token (see ModulePage.tsx /
// ModuleComponentProps.token), never the caller's full session - yet the
// info card calls Core's GET /v1/modules/{name} and GET
// /v1/modules/{name}/egress-hosts directly to show version/status/egress
// info. Those two routes previously required RequireActiveSession only, so
// every module-info-card load 401'd ("invalid or expired session") and the
// UI showed a permanent load error. Safe to accept the module token here
// because both routes only ever return read-only data about the exact
// module the token was scoped to - never anything cross-module or
// privileged. Reported by the user 2026-07-13.
func RequireSessionOrModuleToken(d Deps, module string, w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return Session{}, false
	}

	// Try as a full session first - the common case for Core's own pages.
	if sess, ok, err := ValidateSession(r.Context(), d, token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	} else if ok {
		if sess.Role == RolePending || sess.Locked {
			http.Error(w, "forbidden", http.StatusForbidden)
			return Session{}, false
		}
		return sess, true
	}

	// Fall back to a module-scoped token minted for exactly `module`.
	sess, ok, err := ValidateModuleToken(r.Context(), d, token, module)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return Session{}, false
	}
	if sess.Role == RolePending || sess.Locked {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Session{}, false
	}
	return sess, true
}

// BearerToken exposes the package-private bearerToken() to other packages
// (modules.ModuleTokenHandler needs the caller's raw session token to pass
// to CreateModuleToken, not just the validated Session RequireActiveSession
// returns).
func BearerToken(r *http.Request) string {
	return bearerToken(r)
}
