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

// userSessionsKeyPrefix indexes session tokens by the subject they belong
// to (key: userSessionsKeyPrefix+UserID, value: a Valkey set of tokens) -
// see CreateSession and RevokeUserSessions. Needed because the session key
// itself (sessionKeyPrefix+token) is only ever looked up by token, never by
// user; without this index, an admin lock/delete action would have no way
// to find and kill an already-issued session, and the user could keep
// using it normally until it naturally expired (up to SessionTTL later).
const userSessionsKeyPrefix = "usersessions:"

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
// Name, PreferredUsername, Picture, and EmailVerified are copied from the
// OIDC ID token's claims at login time (see oidcclient.go's Claims) and are
// NOT re-fetched from the IdP for the life of the session - if the user
// changes their display name/username/photo/email at the IdP, it only
// shows up here after their next login. That is an acceptable staleness
// window given SessionTTL is only 24h and there is no refresh-token flow
// yet to silently re-pull claims anyway.
//
// Locked is the one field NOT copied from the IdP - it reflects Core's own
// users.locked column at the moment CallbackHandler issued this session
// (see that doc comment for the full gate 2 logic). It is only ever true
// alongside Role == RolePending, distinguishing "locked by an admin" from
// the more common "never approved yet" case so the frontend's /pending
// screen can show the right message for each. omitempty keeps it out of
// the JSON entirely for the (overwhelming majority) of sessions where it's
// false, rather than spelling out "locked": false on every response.
type Session struct {
	UserID            string `json:"user_id"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
	Role              string `json:"role"`
	Locked            bool   `json:"locked,omitempty"`
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
	// Indexed by subject too, so RevokeUserSessions can find this token
	// later if an admin locks or deletes this user before it naturally
	// expires. Not fatal if this second write fails - the session itself
	// was already created successfully above - but it does mean a lock
	// action against this user would not catch this particular session
	// until it expires on its own, so it is still surfaced as an error
	// rather than silently swallowed.
	if err := vk.AddSetMember(ctx, userSessionsKeyPrefix+sess.UserID, token, SessionTTL); err != nil {
		return "", fmt.Errorf("auth: index session by user: %w", err)
	}
	return token, nil
}

// RevokeUserSessions immediately invalidates every session currently issued
// to subject, regardless of how much of SessionTTL each one has left. Called
// by LockUserHandler and DeleteUserHandler (admin.go) so an admin action
// takes effect right away for anyone already logged in, not just on their
// next login attempt - locking someone out should mean locking them out,
// not "they keep their current tab open until tomorrow." Looking up zero
// tokens (a user who never logged in, or whose sessions already expired) is
// not an error.
func RevokeUserSessions(ctx context.Context, vk *valkey.Client, subject string) error {
	tokens, err := vk.SetMembers(ctx, userSessionsKeyPrefix+subject)
	if err != nil {
		return fmt.Errorf("auth: list sessions for revocation: %w", err)
	}
	for _, token := range tokens {
		if err := vk.Del(ctx, sessionKeyPrefix+token); err != nil {
			return fmt.Errorf("auth: revoke session: %w", err)
		}
	}
	return vk.Del(ctx, userSessionsKeyPrefix+subject)
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
