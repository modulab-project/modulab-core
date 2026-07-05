package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

// SessionTTL is the sliding-window duration for session tokens. Every
// authenticated request resets the expiry back to this value (see
// ValidateSession below), so an actively-used session never expires.
// A session that goes completely unused for SessionTTL - e.g. the user
// closes all their tabs and is away for 24 hours - will require a new
// login. This is the simplest form of "silent renewal": no OIDC refresh
// token flow needed, no client-side timer, no extra round-trip.
const SessionTTL = 24 * time.Hour

const sessionKeyPrefix = "session:"

// SessionKeyPrefix exposes sessionKeyPrefix to callers outside this package
// (the GET /v1/admin/system/info handler in cmd/core, which counts active
// sessions via valkey.CountKeysWithPrefix) without duplicating the literal
// string in a second place that could silently drift out of sync.
const SessionKeyPrefix = sessionKeyPrefix

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

// storedSession is the on-the-wire (Valkey) representation of a Session.
// Email, Name, PreferredUsername, and Picture are AES-256-GCM encrypted
// before being written to Valkey — Session's own doc comment says these are
// copied verbatim from the OIDC ID token's claims, i.e. the same class of
// PII the project's encryption policy already covers for the users table,
// OIDC/SMTP config, quicklinks, and news-feed URLs (see
// feedback_encrypt_at_implementation_time). Found during the pre-V1 re-audit:
// this was the one remaining PII store still in plaintext.
//
// UserID stays plaintext: it is an opaque OIDC subject identifier, not PII,
// and is also used as a Valkey/DB lookup key elsewhere
// (userSessionsKeyPrefix+UserID) — same treatment as audit_log's actor_id.
// EmailVerified, Role, and Locked are booleans/enums, exempt by the same
// policy.
//
// Deploying this is a one-time, self-healing transition: any session
// created by the previous plaintext format will fail to populate the *_enc
// fields on the next read (unknown old JSON keys are silently ignored by
// json.Unmarshal), so decryptSession returns "" for Email/Name/
// PreferredUsername/Picture until that session's next login — UserID/Role
// still round-trip correctly, so access itself is unaffected. No migration
// needed given SessionTTL is only 24h.
type storedSession struct {
	UserID               string `json:"user_id"`
	EmailEnc             string `json:"email_enc"`
	EmailVerified        bool   `json:"email_verified"`
	NameEnc              string `json:"name_enc"`
	PreferredUsernameEnc string `json:"preferred_username_enc"`
	PictureEnc           string `json:"picture_enc"`
	Role                 string `json:"role"`
	Locked               bool   `json:"locked,omitempty"`
}

// encryptSession converts a plaintext Session into its encrypted-at-rest
// storedSession form.
func encryptSession(masterKey string, sess Session) (storedSession, error) {
	emailEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.Email)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt email: %w", err)
	}
	nameEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.Name)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt name: %w", err)
	}
	preferredEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.PreferredUsername)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt preferred_username: %w", err)
	}
	pictureEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.Picture)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt picture: %w", err)
	}
	return storedSession{
		UserID:               sess.UserID,
		EmailEnc:             emailEnc,
		EmailVerified:        sess.EmailVerified,
		NameEnc:              nameEnc,
		PreferredUsernameEnc: preferredEnc,
		PictureEnc:           pictureEnc,
		Role:                 sess.Role,
		Locked:               sess.Locked,
	}, nil
}

// decryptSession is encryptSession's inverse, used by ValidateSession.
func decryptSession(masterKey string, s storedSession) (Session, error) {
	email, err := crypto.DecryptIfNotEmpty(masterKey, s.EmailEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt email: %w", err)
	}
	name, err := crypto.DecryptIfNotEmpty(masterKey, s.NameEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt name: %w", err)
	}
	preferred, err := crypto.DecryptIfNotEmpty(masterKey, s.PreferredUsernameEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt preferred_username: %w", err)
	}
	picture, err := crypto.DecryptIfNotEmpty(masterKey, s.PictureEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt picture: %w", err)
	}
	return Session{
		UserID:            s.UserID,
		Email:             email,
		EmailVerified:     s.EmailVerified,
		Name:              name,
		PreferredUsername: preferred,
		Picture:           picture,
		Role:              s.Role,
		Locked:            s.Locked,
	}, nil
}

// CreateSession mints a new opaque bearer token for sess and stores it
// (encrypted, see storedSession) in Valkey with TTL SessionTTL. The token is
// 256 bits of randomness, base64url-encoded.
func CreateSession(ctx context.Context, d Deps, sess Session) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return "", fmt.Errorf("auth: resolve master key: %w", err)
	}
	stored, err := encryptSession(masterKey, sess)
	if err != nil {
		return "", fmt.Errorf("auth: encrypt session: %w", err)
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return "", fmt.Errorf("auth: marshal session: %w", err)
	}
	if err := d.Valkey.SetWithTTL(ctx, sessionKeyPrefix+token, string(data), SessionTTL); err != nil {
		return "", fmt.Errorf("auth: store session: %w", err)
	}
	// Indexed by subject too, so RevokeUserSessions can find this token
	// later if an admin locks or deletes this user before it naturally
	// expires. Not fatal if this second write fails - the session itself
	// was already created successfully above - but it does mean a lock
	// action against this user would not catch this particular session
	// until it expires on its own, so it is still surfaced as an error
	// rather than silently swallowed.
	if err := d.Valkey.AddSetMember(ctx, userSessionsKeyPrefix+sess.UserID, token, SessionTTL); err != nil {
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
//
// Sliding window: on every successful lookup the TTL of both the session
// key and the per-user session index are reset to SessionTTL. This means
// an actively-used session never expires mid-use; only a session that
// goes completely untouched for 24 hours will require a new login. TTL
// extension failures are non-fatal: the session was already read
// successfully, so the caller gets a valid response regardless. Worst
// case the session expires on its original schedule rather than sliding.
func ValidateSession(ctx context.Context, d Deps, token string) (Session, bool, error) {
	raw, exists, err := d.Valkey.Get(ctx, sessionKeyPrefix+token)
	if err != nil {
		return Session{}, false, err
	}
	if !exists {
		return Session{}, false, nil
	}
	var stored storedSession
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return Session{}, false, fmt.Errorf("auth: decode session: %w", err)
	}

	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return Session{}, false, fmt.Errorf("auth: resolve master key: %w", err)
	}
	sess, err := decryptSession(masterKey, stored)
	if err != nil {
		return Session{}, false, fmt.Errorf("auth: decrypt session: %w", err)
	}

	// Slide the window - best effort, non-fatal if Valkey hiccups here.
	_ = d.Valkey.Expire(ctx, sessionKeyPrefix+token, SessionTTL)
	_ = d.Valkey.Expire(ctx, userSessionsKeyPrefix+sess.UserID, SessionTTL)

	return sess, true, nil
}

// ActiveSession is one entry in ListActiveSessions' result - the fields the
// System Info page (GET /v1/admin/system/info) shows for each currently
// logged-in browser tab/device. Deliberately does not include the session
// token itself (no reason for that to ever leave Valkey/the browser that
// holds it) or Name/PreferredUsername/Picture (Email + Role is already
// enough to identify who's logged in where, matching the level of detail
// AdminUsersPage already shows for every user - not exposing more PII here
// than that page does).
type ActiveSession struct {
	Email            string `json:"email,omitempty"`
	Role             string `json:"role"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

// ListActiveSessions decrypts and returns every currently active session
// (one entry per logged-in browser tab/device - a user on both phone and
// laptop appears twice). Best-effort per entry: a session key that has
// expired between the SCAN and the Get, or fails to decode/decrypt, is
// silently skipped rather than failing the whole list - same reasoning as
// RevokeUserSessions treating a missing key as "already gone", not an error.
func ListActiveSessions(ctx context.Context, d Deps) ([]ActiveSession, error) {
	keys, err := d.Valkey.ScanKeysWithPrefix(ctx, sessionKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("auth: list active sessions: scan: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}

	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return nil, fmt.Errorf("auth: list active sessions: resolve master key: %w", err)
	}

	out := make([]ActiveSession, 0, len(keys))
	for _, key := range keys {
		raw, exists, err := d.Valkey.Get(ctx, key)
		if err != nil || !exists {
			continue
		}
		var stored storedSession
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			continue
		}
		sess, err := decryptSession(masterKey, stored)
		if err != nil {
			continue
		}
		as := ActiveSession{Email: sess.Email, Role: sess.Role}
		if ttl, ok, err := d.Valkey.TTL(ctx, key); err == nil && ok {
			as.ExpiresInSeconds = int64(ttl / time.Second)
		}
		out = append(out, as)
	}
	return out, nil
}

// DeleteSession invalidates token immediately (logout).
func DeleteSession(ctx context.Context, vk *valkey.Client, token string) error {
	return vk.Del(ctx, sessionKeyPrefix+token)
}

// UpdateSessionsRole rewrites Role (and Locked) on every currently active
// session token belonging to subject (found via the userSessionsKeyPrefix
// index, same as RevokeUserSessions), in place - the token itself does not
// change, so a tab that already has it stored does not need a new one.
// Used by ApproveUserHandler (admin.go) so an already-issued pending
// session picks up the user's real role the moment an admin approves them,
// instead of only on their next login. Each rewritten session gets a fresh
// SessionTTL, the same as a brand-new login would - approval is enough of
// a deliberate, meaningful event that treating it like one is acceptable,
// and simpler than threading the token's remaining TTL through here.
// Looking up zero tokens (no active session for subject right now) is not
// an error, same reasoning as RevokeUserSessions.
func UpdateSessionsRole(ctx context.Context, vk *valkey.Client, subject, role string, locked bool) error {
	tokens, err := vk.SetMembers(ctx, userSessionsKeyPrefix+subject)
	if err != nil {
		return fmt.Errorf("auth: list sessions for role update: %w", err)
	}
	for _, token := range tokens {
		raw, exists, err := vk.Get(ctx, sessionKeyPrefix+token)
		if err != nil {
			return fmt.Errorf("auth: load session for role update: %w", err)
		}
		if !exists {
			// Already expired on its own - nothing to rewrite, and not
			// worth treating as an error (the set itself is cleaned up
			// lazily, same as RevokeUserSessions).
			continue
		}
		// Unmarshals into storedSession, not Session: Role/Locked are the
		// only fields this rewrite touches and both stay plaintext in the
		// stored form (see storedSession's doc comment), so this never
		// needs the master key to decrypt/re-encrypt the PII fields it
		// isn't touching - they round-trip through *_enc untouched.
		var stored storedSession
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return fmt.Errorf("auth: decode session for role update: %w", err)
		}
		stored.Role = role
		stored.Locked = locked
		data, err := json.Marshal(stored)
		if err != nil {
			return fmt.Errorf("auth: marshal session for role update: %w", err)
		}
		if err := vk.SetWithTTL(ctx, sessionKeyPrefix+token, string(data), SessionTTL); err != nil {
			return fmt.Errorf("auth: store updated session: %w", err)
		}
	}
	return nil
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
