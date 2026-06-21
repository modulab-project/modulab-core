package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

// SessionTTL is how long an issued session token remains valid. There is no
// refresh mechanism yet - once this expires, the user has to log in again
// via the IdP. Revisit once Phase 2's frontend exists and can react to a
// 401 by re-triggering /v1/auth/login.
const SessionTTL = 24 * time.Hour

const sessionKeyPrefix = "session:"

// Session is what's stored in Valkey for a logged-in user, and handed back
// by ValidateSession on every authenticated request.
//
// This is deliberately an opaque, server-side session (a Valkey lookup per
// request) rather than a self-contained signed JWT, even though spec
// section 7.4 talks about "a JWT held in sessionStorage": an opaque token
// makes logout and forced-expiry trivial (just delete the Valkey key)
// without needing a separate revocation list alongside a session-signing
// key. The actual transport spec section 7.4 cares about - a Bearer token
// in sessionStorage, not a cookie - is preserved; only the token's internal
// format differs from a literal JWT. Flagged here deliberately - revisit
// if a future requirement needs the session token to be independently
// verifiable without a Valkey round trip (e.g. multiple Core instances
// without a shared Valkey).
//
// Name and Picture are copied from the OIDC ID token's claims at login time
// (see oidcclient.go's Claims) and are NOT re-fetched from the IdP for the
// life of the session - if the user changes their display name/photo at
// the IdP, it only shows up here after their next login. That is an
// acceptable staleness window given SessionTTL is only 24h and there is no
// refresh-token flow yet to silently re-pull claims anyway.
type Session struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Role    string `json:"role"`
}

// CreateSession mints a new opaque bearer token for sess and stores it in
// Valkey with TTL SessionTTL. The token is 256 bits of randomness,
// base64url-encoded.
func CreateSession(ctx context.Context, vk *valkey.Client, sess Session) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("auth: marshal session: %w", err)
	}
	if err := vk.SetWithTTL(ctx, sessionKeyPrefix+token, string(data), SessionTTL); err != nil {
		return "", fmt.Errorf("auth: store session: %w", err)
	}
	return token, nil
}

// ValidateSession looks up token in Valkey and returns the session it maps
// to, if any. A missing or expired token is not an error - ok is simply
// false.
func ValidateSession(ctx context.Context, vk *valkey.Client, token string) (Session, bool, error) {
	raw, exists, err := vk.Get(ctx, sessionKeyPrefix+token)
	if err != nil {
		return Session{}, false, err
	}
	if !exists {
		return Session{}, false, nil
	}
	var sess Session
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return Session{}, false, fmt.Errorf("auth: decode session: %w", err)
	}
	return sess, true, nil
}

// DeleteSession invalidates token immediately (logout).
func DeleteSession(ctx context.Context, vk *valkey.Client, token string) error {
	return vk.Del(ctx, sessionKeyPrefix+token)
}

// randomToken generates 256 bits of randomness, base64url-encoded. Used for
// both session tokens and OAuth2 state values (handlers.go) - the entropy
// requirement is the same for either.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
