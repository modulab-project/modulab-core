package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

// SessionTTL is the sliding-window duration for session tokens. Every
// authenticated request resets the expiry back to this value (see
// ValidateSession below), so an actively-used session never expires on its
// own - subject to SessionAbsoluteMaxAge below, which bounds that
// indefinitely-renewing lifetime.
// A session that goes completely unused for SessionTTL - e.g. the user
// closes all their tabs and is away for 24 hours - will require a new
// login. This is the simplest form of "silent renewal": no OIDC refresh
// token flow needed, no client-side timer, no extra round-trip.
const SessionTTL = 24 * time.Hour

// SessionAbsoluteMaxAge is a hard ceiling on how long a session may live at
// all, measured from Session.CreatedAt, independent of how recently it was
// used. Without this, SessionTTL's sliding window means an actively-used
// session never expires - fine for the threat model of "you forgot to
// close a tab", but not for "this exact bearer token was copied out of the
// browser once (stolen cookie, compromised device) and is now being kept
// alive indefinitely by whoever holds it". Login itself is PocketID
// passkey-only (phishing-resistant, no password to steal), so this is a
// second line of defense against token theft specifically, not password
// compromise. 30 days is generous enough that a real user essentially
// never notices it (a login roughly monthly), while still bounding a
// stolen token's usable lifetime to a known, finite window instead of
// "forever, as long as someone keeps using it." See ValidateSession for
// where this is enforced.
const SessionAbsoluteMaxAge = 30 * 24 * time.Hour

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
// CreatedAt, IP, and UserAgent are captured once at login time (see
// CreateSession's callers) purely for display on the System Info page's
// active-sessions table ("logged in since", "from which address/device") -
// none of the three are ever read back for any access-control decision, so
// getting one wrong or missing (e.g. IP absent in a local dev setup with no
// reverse proxy in front) only degrades a diagnostic display, never login
// itself.
type Session struct {
	UserID            string    `json:"user_id"`
	Email             string    `json:"email"`
	EmailVerified     bool      `json:"email_verified"`
	Name              string    `json:"name"`
	PreferredUsername string    `json:"preferred_username"`
	Picture           string    `json:"picture"`
	Role              string    `json:"role"`
	Locked            bool      `json:"locked,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	IP                string    `json:"ip,omitempty"`
	UserAgent         string    `json:"user_agent,omitempty"`
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
// IPEnc and UserAgentEnc get the same AES-256-GCM treatment as Email/Name/
// PreferredUsername/Picture above - an IP address and a browser/OS string
// are just as identifying as an email address, so the same
// feedback_encrypt_at_implementation_time policy applies. CreatedAt stays
// plaintext: it's a timestamp, explicitly exempt by that same policy (like
// EmailVerified/Role/Locked below).
// RefreshTokenEnc holds the OIDC refresh token issued alongside this
// session (empty if the IdP did not grant one - see NewProvider's
// "offline_access" scope comment), GCM-encrypted like every other secret/
// PII field here. Deliberately NOT mirrored onto the public Session struct
// above: MeResponse (handlers.go) embeds Session directly into GET
// /v1/auth/me's JSON response, so anything added to Session is sent to the
// browser - a refresh token must never leave Valkey. It is only ever read
// back by RevalidateSession (revalidate.go), which works against
// storedSession directly for exactly this reason.
type storedSession struct {
	UserID               string    `json:"user_id"`
	EmailEnc             string    `json:"email_enc"`
	EmailVerified        bool      `json:"email_verified"`
	NameEnc              string    `json:"name_enc"`
	PreferredUsernameEnc string    `json:"preferred_username_enc"`
	PictureEnc           string    `json:"picture_enc"`
	Role                 string    `json:"role"`
	Locked               bool      `json:"locked,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	IPEnc                string    `json:"ip_enc,omitempty"`
	UserAgentEnc         string    `json:"user_agent_enc,omitempty"`
	RefreshTokenEnc      string    `json:"refresh_token_enc,omitempty"`
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
	ipEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.IP)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt ip: %w", err)
	}
	userAgentEnc, err := crypto.EncryptIfNotEmpty(masterKey, sess.UserAgent)
	if err != nil {
		return storedSession{}, fmt.Errorf("encrypt user_agent: %w", err)
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
		CreatedAt:            sess.CreatedAt,
		IPEnc:                ipEnc,
		UserAgentEnc:         userAgentEnc,
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
	ip, err := crypto.DecryptIfNotEmpty(masterKey, s.IPEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt ip: %w", err)
	}
	userAgent, err := crypto.DecryptIfNotEmpty(masterKey, s.UserAgentEnc)
	if err != nil {
		return Session{}, fmt.Errorf("decrypt user_agent: %w", err)
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
		CreatedAt:         s.CreatedAt,
		IP:                ip,
		UserAgent:         userAgent,
	}, nil
}

// CreateSession mints a new opaque bearer token for sess and stores it
// (encrypted, see storedSession) in Valkey with TTL SessionTTL. The token is
// 256 bits of randomness, base64url-encoded.
//
// sess.CreatedAt is stamped here if the caller left it zero, rather than
// requiring every call site to remember time.Now() - CallbackHandler is
// currently the only caller, but making this the one place that can't
// forget it means a future second login path (e.g. a password-based flow)
// gets a correct "logged in since" for free too.
//
// refreshToken is the OIDC refresh token from the same token response as
// sess's claims (Provider.Exchange's second return value), or "" if the
// IdP did not issue one. Stored encrypted, never decrypted back into the
// public Session struct - see storedSession.RefreshTokenEnc's doc comment.
func CreateSession(ctx context.Context, d Deps, sess Session, refreshToken string) (string, error) {
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now()
	}
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
	if refreshToken != "" {
		refreshTokenEnc, err := crypto.EncryptIfNotEmpty(masterKey, refreshToken)
		if err != nil {
			return "", fmt.Errorf("auth: encrypt refresh token: %w", err)
		}
		stored.RefreshTokenEnc = refreshTokenEnc
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
func RevokeUserSessions(ctx context.Context, d Deps, subject string) error {
	tokens, err := d.Valkey.SetMembers(ctx, userSessionsKeyPrefix+subject)
	if err != nil {
		return fmt.Errorf("auth: list sessions for revocation: %w", err)
	}

	// Best-effort: also invalidate each session's refresh token at the IdP
	// itself (see Provider.Revoke's doc comment), not just delete Core's own
	// copy below. Decoded up front, before any Del, so a decode failure on
	// one session can't skip revocation for the others.
	var stored []storedSession
	for _, token := range tokens {
		raw, exists, err := d.Valkey.Get(ctx, sessionKeyPrefix+token)
		if err != nil || !exists {
			continue
		}
		var s storedSession
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			stored = append(stored, s)
		}
	}
	bestEffortRevokeAtIdP(ctx, d, stored)

	for _, token := range tokens {
		if err := d.Valkey.Del(ctx, sessionKeyPrefix+token); err != nil {
			return fmt.Errorf("auth: revoke session: %w", err)
		}
	}
	return d.Valkey.Del(ctx, userSessionsKeyPrefix+subject)
}

// RevokeSessionByID ends exactly one active session, identified by the
// opaque, non-reversible id ActiveSession.ID/SessionID(token) returns -
// never the raw token itself, which never leaves Valkey/the browser that
// holds it. Used by the System Info page's per-row "end session" action:
// unlike RevokeUserSessions (which kills every session belonging to a user,
// for the existing lock/delete-user admin actions), this targets a single
// row and leaves that same user's other active sessions alone.
//
// Since the session token now travels in a single httpOnly cookie shared
// by every tab of one browser (see handlers.go's setSessionCookie), one row
// here corresponds to one signed-in browser/device, not one open tab the
// way it did when each tab held its own independent sessionStorage token -
// ending this row signs out every tab of that browser at once.
//
// Has to scan every active session and recompute each one's ID to find the
// match, since Valkey only indexes these keys by token and by user, never
// by this derived ID - acceptable because the admin calling this already
// paid that same scan cost once just to load the list this ID came from.
// ok is false (not an error) if no session with that ID is currently
// active - it may have expired or been revoked already between the admin
// loading the page and clicking the button.
func RevokeSessionByID(ctx context.Context, d Deps, id string) (bool, error) {
	keys, err := d.Valkey.ScanKeysWithPrefix(ctx, sessionKeyPrefix)
	if err != nil {
		return false, fmt.Errorf("auth: revoke session by id: scan: %w", err)
	}
	for _, key := range keys {
		token := strings.TrimPrefix(key, sessionKeyPrefix)
		if SessionID(token) != id {
			continue
		}
		raw, exists, err := d.Valkey.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("auth: revoke session by id: get: %w", err)
		}
		if !exists {
			return false, nil
		}
		var stored storedSession
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return false, fmt.Errorf("auth: revoke session by id: decode: %w", err)
		}
		// Best-effort: also invalidate the refresh token at the IdP itself,
		// same reasoning as RevokeUserSessions - before deleting Core's own
		// copy below, though either order is fine here since this is not
		// atomic with the Del anyway.
		bestEffortRevokeAtIdP(ctx, d, []storedSession{stored})
		if err := d.Valkey.Del(ctx, key); err != nil {
			return false, fmt.Errorf("auth: revoke session by id: delete: %w", err)
		}
		if err := d.Valkey.RemoveSetMember(ctx, userSessionsKeyPrefix+stored.UserID, token); err != nil {
			return true, fmt.Errorf("auth: revoke session by id: unindex: %w", err)
		}
		return true, nil
	}
	return false, nil
}

// RevokeOwnSessionByID is RevokeSessionByID's self-service counterpart: any
// approved user can end one of their own currently-active sessions (e.g.
// "I lost my phone, kill that session") from their own Profile page,
// without needing an admin. Deliberately a separate function rather than
// reusing RevokeSessionByID with an extra parameter - the two have
// different trust levels (any approved session vs. super-admin-only) and
// keeping them syntactically distinct means a future change to one can
// never accidentally loosen the other's ownership check.
//
// The ownership check (stored.UserID == subject) is the entire reason this
// exists instead of just exposing RevokeSessionByID more widely: an ID is a
// one-way hash of a token (SessionID), not a per-user-scoped value, so
// without this check a self-service caller could pass any other session's
// ID (e.g. found by guessing, or the same ID shown in an admin
// screenshot) and end a stranger's session. A mismatch is treated
// identically to "no session with that ID" (ok = false, no error) - not
// distinguishing "wrong owner" from "doesn't exist" avoids confirming to
// the caller that some other, inaccessible session ID is currently valid.
func RevokeOwnSessionByID(ctx context.Context, d Deps, subject, id string) (bool, error) {
	keys, err := d.Valkey.ScanKeysWithPrefix(ctx, sessionKeyPrefix)
	if err != nil {
		return false, fmt.Errorf("auth: revoke own session by id: scan: %w", err)
	}
	for _, key := range keys {
		token := strings.TrimPrefix(key, sessionKeyPrefix)
		if SessionID(token) != id {
			continue
		}
		raw, exists, err := d.Valkey.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("auth: revoke own session by id: get: %w", err)
		}
		if !exists {
			return false, nil
		}
		var stored storedSession
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return false, fmt.Errorf("auth: revoke own session by id: decode: %w", err)
		}
		if stored.UserID != subject {
			return false, nil
		}
		bestEffortRevokeAtIdP(ctx, d, []storedSession{stored})
		if err := d.Valkey.Del(ctx, key); err != nil {
			return false, fmt.Errorf("auth: revoke own session by id: delete: %w", err)
		}
		if err := d.Valkey.RemoveSetMember(ctx, userSessionsKeyPrefix+subject, token); err != nil {
			return true, fmt.Errorf("auth: revoke own session by id: unindex: %w", err)
		}
		return true, nil
	}
	return false, nil
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

	// Absolute ceiling, checked before the sliding-window renewal below: a
	// session past SessionAbsoluteMaxAge is force-expired here regardless of
	// how recently it was used, rather than having its TTL extended yet
	// again. Deletes both Valkey keys outright instead of just letting this
	// one lookup fail, so the very next request (from this browser or a
	// replayed/stolen token) gets the same "invalid or expired session"
	// result everywhere else already returns, not just this one call site.
	// Best-effort on the deletes themselves - if Valkey hiccups here the
	// keys simply age out on their existing TTL instead, same fallback as
	// the renewal path below.
	if !sess.CreatedAt.IsZero() && time.Since(sess.CreatedAt) > SessionAbsoluteMaxAge {
		_ = d.Valkey.Del(ctx, sessionKeyPrefix+token)
		_ = d.Valkey.RemoveSetMember(ctx, userSessionsKeyPrefix+sess.UserID, token)
		return Session{}, false, nil
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
// holds it) or PreferredUsername/Picture (Name + Email + Role is already
// enough to identify who's logged in where, matching the level of detail
// AdminUsersPage already shows for every user - not exposing more PII here
// than that page does).
//
// ID is SessionID(token) - a one-way hash, never the token itself - so the
// frontend can target one specific row (highlighting "this is you", or
// requesting DELETE /v1/admin/sessions/{id}) without the actual bearer
// token ever reaching a page that renders other admins' data alongside it.
// Current is set by the caller (systemInfoHandler), not by
// ListActiveSessions itself, which has no notion of "the request that's
// asking" - only whoever holds the incoming request's own token can know
// that.
type ActiveSession struct {
	ID                   string `json:"id"`
	Name                 string `json:"name,omitempty"`
	Email                string `json:"email,omitempty"`
	Role                 string `json:"role"`
	CreatedAt            string `json:"created_at,omitempty"`
	IP                   string `json:"ip,omitempty"`
	UserAgent            string `json:"user_agent,omitempty"`
	LastActiveSecondsAgo int64  `json:"last_active_seconds_ago,omitempty"`
	ExpiresInSeconds     int64  `json:"expires_in_seconds,omitempty"`
	Current              bool   `json:"current,omitempty"`
}

// SessionID returns a stable, non-reversible identifier for token (the hex
// SHA-256 digest). Exposed to the frontend as ActiveSession.ID instead of
// the token itself, and recomputed by RevokeSessionByID to find the
// matching key again - same one-way-hash approach used to let an admin
// reference one specific session without it ever being possible to work
// backwards from the ID to a token that could be replayed.
func SessionID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
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
		token := strings.TrimPrefix(key, sessionKeyPrefix)
		as := ActiveSession{
			ID:        SessionID(token),
			Name:      sess.Name,
			Email:     sess.Email,
			Role:      sess.Role,
			IP:        sess.IP,
			UserAgent: sess.UserAgent,
		}
		if !sess.CreatedAt.IsZero() {
			as.CreatedAt = sess.CreatedAt.UTC().Format(time.RFC3339)
		}
		if ttl, ok, err := d.Valkey.TTL(ctx, key); err == nil && ok {
			as.ExpiresInSeconds = int64(ttl / time.Second)
			// "Last active" is derived from the sliding-window TTL rather
			// than stored separately: ValidateSession resets the TTL back
			// to SessionTTL on every authenticated request, so however much
			// of that window has already been used up (SessionTTL - ttl) is
			// exactly how long ago the last request on this session was -
			// no extra Valkey write needed on every single request just to
			// track this.
			if elapsed := SessionTTL - ttl; elapsed > 0 {
				as.LastActiveSecondsAgo = int64(elapsed / time.Second)
			}
		}
		out = append(out, as)
	}
	return out, nil
}

// ListActiveSessionsForUser is ListActiveSessions' self-service counterpart
// (Profile page's "my devices" section, MySessionsHandler) - every
// approved user can already see this same information about themselves
// via GET /v1/auth/me plus the active-sessions table admins see on System
// Info; this just exposes it to the session's own owner directly, without
// a super-admin role.
//
// Deliberately does NOT reuse ListActiveSessions' full ScanKeysWithPrefix
// over every session in the system plus an in-memory filter - that would
// mean a non-admin-triggered code path still walks every other user's
// session key on every call. Instead it goes through the same per-user
// index RevokeUserSessions/UpdateSessionsRole already rely on
// (userSessionsKeyPrefix+subject), so this function is scoped to the
// caller's own tokens by construction, not just by a filter that a future
// edit could accidentally drop.
func ListActiveSessionsForUser(ctx context.Context, d Deps, subject string) ([]ActiveSession, error) {
	tokens, err := d.Valkey.SetMembers(ctx, userSessionsKeyPrefix+subject)
	if err != nil {
		return nil, fmt.Errorf("auth: list active sessions for user: %w", err)
	}
	if len(tokens) == 0 {
		return nil, nil
	}

	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return nil, fmt.Errorf("auth: list active sessions for user: resolve master key: %w", err)
	}

	out := make([]ActiveSession, 0, len(tokens))
	for _, token := range tokens {
		key := sessionKeyPrefix + token
		raw, exists, err := d.Valkey.Get(ctx, key)
		if err != nil {
			// A transient Valkey error, not evidence the token is actually
			// dead - skip this entry for this call, but don't unindex it.
			continue
		}
		if !exists {
			// Genuinely expired/revoked on its own - opportunistic cleanup,
			// same reasoning as UpdateSessionsRole's stale-token removal
			// above, instead of only ever relying on the whole set's TTL to
			// eventually drop it.
			if err := d.Valkey.RemoveSetMember(ctx, userSessionsKeyPrefix+subject, token); err != nil {
				log.Printf("auth: list active sessions for user: unindex stale token for %s: %v", subject, err)
			}
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
		as := ActiveSession{
			ID:        SessionID(token),
			Name:      sess.Name,
			Email:     sess.Email,
			Role:      sess.Role,
			IP:        sess.IP,
			UserAgent: sess.UserAgent,
		}
		if !sess.CreatedAt.IsZero() {
			as.CreatedAt = sess.CreatedAt.UTC().Format(time.RFC3339)
		}
		if ttl, ok, err := d.Valkey.TTL(ctx, key); err == nil && ok {
			as.ExpiresInSeconds = int64(ttl / time.Second)
			if elapsed := SessionTTL - ttl; elapsed > 0 {
				as.LastActiveSecondsAgo = int64(elapsed / time.Second)
			}
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
			// Already expired on its own - nothing to rewrite. Opportunistic
			// cleanup: drop this dead token from the per-user index now
			// instead of leaving it to linger until the whole set's own TTL
			// lapses - best-effort, since a failed removal here is no worse
			// than the lazy cleanup this used to rely on exclusively.
			if err := vk.RemoveSetMember(ctx, userSessionsKeyPrefix+subject, token); err != nil {
				log.Printf("auth: update sessions role: unindex stale token for %s: %v", subject, err)
			}
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
