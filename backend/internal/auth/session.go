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
	"net"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
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

// sessionCountryKeyPrefix tracks the most recently observed CF-IPCountry
// (see handlers.go's loginCountry) for one specific active session token,
// separately from that session's own Session.Country - which stays frozen
// at whatever country the session was created in, purely for the "logged in
// from" display (see Session's doc comment). This second, sliding value is
// what ValidateSession's mid-session anomaly check (below) compares each
// request's country against, since ValidateSession runs on every single
// authenticated request (including main.go's identifyBySessionOrIP rate-
// limit bucketing) - comparing against a baseline that itself slides
// forward is what lets a *second* country change during the same session's
// lifetime be caught too, not just a change away from the original login
// country. TTL is kept in step with SessionTTL (see ValidateSession) so
// this key never outlives the session it shadows and needs no separate
// cleanup path. Not PII (a two-letter country code), same exemption
// checkAndRecordLoginCountry's doc comment already gives for the
// per-*user* equivalent this mirrors - this one is scoped per-session
// instead, since a session, not a user, is what ValidateSession is
// validating.
const sessionCountryKeyPrefix = "sessioncountry:"

// sessionDeviceKeyPrefix is sessionCountryKeyPrefix's User-Agent counterpart:
// tracks the most recently observed User-Agent for one specific active
// session token, so checkSessionDeviceAnomaly (below) can catch a session
// suddenly being used from a different device/browser - a signal
// country-based detection misses entirely (same country, different device),
// and one a legitimate single-device session should never produce on its
// own mid-lifetime. Same TTL-synced-to-SessionTTL reasoning as
// sessionCountryKeyPrefix. Not PII by the same reasoning
// storedSession.UserAgentEnc's doc comment gives for encrypting it at rest
// there - but this key stores it in plaintext regardless, same tradeoff
// sessionCountryKeyPrefix already makes for country (a short-lived,
// session-scoped cache key, not the durable PII store storedSession is).
const sessionDeviceKeyPrefix = "sessiondevice:"

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
	// Country is Cloudflare's CF-IPCountry header (see handlers.go's
	// loginCountry), captured once at login time alongside IP/UserAgent for
	// the exact same "logged in from" display purpose - "" whenever the
	// request didn't pass through Cloudflare (local/direct access), same
	// caveat as loginCountry's own doc comment. Never read back for any
	// access-control decision, only for the sessions tables on the Profile
	// and System Info pages.
	Country string `json:"country,omitempty"`
	// CSRFToken is minted once per session by CreateSession and never
	// changes for the session's lifetime. Deliberately included here (and
	// therefore sent to the browser in GET /v1/auth/me's response body,
	// since MeResponse embeds Session) - unlike the session token itself,
	// this one is *meant* to be readable by the frontend, which echoes it
	// back as the X-CSRF-Token header on every mutating (non-GET/HEAD/
	// OPTIONS) admin request. See admin.go's validateCSRF for why this
	// exists: same-origin fetches from an installed module's own UI bundle
	// carry the httpOnly session cookie automatically (see
	// feedback_modulab_cookie_same_origin_risk), so the cookie alone cannot
	// distinguish a legitimate admin-panel mutation from one triggered by
	// module code. A session created before this field existed decodes with
	// CSRFToken == "" (unknown JSON keys are silently ignored, same
	// self-healing pattern as storedSession's *_enc fields) and is treated
	// as failing every CSRF check until its next login - a one-time,
	// no-migration-needed bump for anyone already logged in when this
	// shipped.
	CSRFToken string `json:"csrf_token,omitempty"`
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
// EmailVerified/Role/Locked below). Country also stays plaintext: a
// two-letter country code is coarse-grained enough (millions of people
// share it) that it does not meet that policy's bar, same reasoning
// lastCountryTTL's doc comment already gives for the separate
// "lastcountry:" Valkey key this mirrors.
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
	Country              string    `json:"country,omitempty"`
	RefreshTokenEnc      string    `json:"refresh_token_enc,omitempty"`
	// CSRFToken stays plaintext, same exemption as Role/Locked/CreatedAt
	// above: it is random security material, not PII, so the
	// feedback_encrypt_at_implementation_time policy does not apply.
	CSRFToken string `json:"csrf_token,omitempty"`
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
		Country:              sess.Country,
		CSRFToken:            sess.CSRFToken,
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
		Country:           s.Country,
		CSRFToken:         s.CSRFToken,
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
	// CSRFToken is minted here, once per session, same as the bearer token
	// itself - see Session.CSRFToken's doc comment for why this exists and
	// why it deliberately does NOT reuse randomness or lifetime from that
	// bearer token (the two travel through completely different channels:
	// httpOnly cookie vs. JSON response body, and must be independently
	// unguessable from one another).
	if sess.CSRFToken == "" {
		csrfToken, err := randomToken()
		if err != nil {
			return "", fmt.Errorf("auth: generate csrf token: %w", err)
		}
		sess.CSRFToken = csrfToken
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
	if err := d.Valkey.Del(ctx, userSessionsKeyPrefix+subject); err != nil {
		return err
	}

	// Best-effort live push (H-3, PERFORMANCE_AUDIT.md) so any open tab
	// notices the revocation immediately instead of waiting on
	// useAuthenticatedSession's safety-net poll (frontend/src/lib/
	// useSession.ts) - that hook re-checks GET /v1/auth/me the moment this
	// event arrives. Failure here is not fatal: the sessions themselves are
	// already gone above, so the caller's action (lock/delete/logout) has
	// already fully succeeded regardless of whether this notification is
	// delivered.
	if pubErr := notify.Publish(ctx, d.Valkey, notify.UserChannel(subject), notify.Event{Type: "session.changed"}); pubErr != nil {
		log.Printf("auth: notify session revoked for %s: %v", subject, pubErr)
	}
	return nil
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
		notifySessionRevokedByAdmin(ctx, d, stored)
		return true, nil
	}
	return false, nil
}

// notifySessionRevokedByAdmin sends mail.SessionRevokedByAdminMessage to the
// owner of a session RevokeSessionByID just ended - best-effort, called
// after that session's Valkey keys are already gone, so a failure here never
// blocks the revocation itself from taking effect. Gated by
// notify_session_revoked_by_admin (db.NotificationPrefs, default true).
// Never called from RevokeOwnSessionByID (ending your own session needs no
// mail about it) or RevokeUserSessions (lock/delete already send their own,
// higher-severity LockedMessage/DeletedMessage for that event).
func notifySessionRevokedByAdmin(ctx context.Context, d Deps, stored storedSession) {
	prefs, err := d.Pool.GetNotificationPrefs(ctx, stored.UserID)
	if err != nil {
		log.Printf("auth: read notification prefs for %s: %v", stored.UserID, err)
		return
	}
	if !prefs.SessionRevokedByAdmin {
		return
	}
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		log.Printf("auth: notify session revoked for %s: resolve master key: %v", stored.UserID, err)
		return
	}
	sess, err := decryptSession(masterKey, stored)
	if err != nil {
		log.Printf("auth: notify session revoked for %s: decrypt: %v", stored.UserID, err)
		return
	}
	if sess.Email == "" {
		return
	}
	msg := mail.SessionRevokedByAdminMessage(sess.Email, sess.Name, sess.IP, sess.UserAgent, d.FrontendBaseURL, mail.CurrentBranding(ctx, d.Pool))
	if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
		log.Printf("auth: enqueue session revoked mail for %s: %v", stored.UserID, err)
	}
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
// The ownership check (stored.UserID == subject) is defense in depth, not
// the primary guard: this now only ever looks at subject's own tokens (see
// below), so it should always hold - but keeping it means a future bug in
// the per-user index can never turn into ending a stranger's session
// instead of just failing closed. A mismatch is treated identically to "no
// session with that ID" (ok = false, no error) - not distinguishing "wrong
// owner" from "doesn't exist" avoids confirming to the caller that some
// other, inaccessible session ID is currently valid.
//
// Scoped to subject's own tokens via the userSessionsKeyPrefix index
// (M-2, PERFORMANCE_AUDIT.md; same pattern ListActiveSessionsForUser
// above already uses), not a ScanKeysWithPrefix over every session in the
// system - this is a self-service, any-approved-user action, so before
// this fix every call to "end this one session of mine" walked every
// other user's session key too just to find its own.
func RevokeOwnSessionByID(ctx context.Context, d Deps, subject, id string) (bool, error) {
	tokens, err := d.Valkey.SetMembers(ctx, userSessionsKeyPrefix+subject)
	if err != nil {
		return false, fmt.Errorf("auth: revoke own session by id: list: %w", err)
	}
	for _, token := range tokens {
		if SessionID(token) != id {
			continue
		}
		key := sessionKeyPrefix + token
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

// SessionFromRequest returns the session already validated for this exact
// request by globalRateLimitMiddleware's identifyBySessionOrIP
// (cmd/core/main.go), if ctx carries one (see ContextWithSession/
// SessionFromContext, context.go) - avoiding a second full ValidateSession
// call per request. Before this helper, every one of this package's
// session-requiring handlers called ValidateSession a second time on top of
// the one the global middleware already ran, doubling the ~7 Valkey round
// trips (session GET, two sliding-window EXPIREs, two anomaly-baseline
// GET/SET pairs) and the AES-GCM decrypt ValidateSession does per call (see
// H-1, PERFORMANCE_AUDIT.md). Falls back to a full ValidateSession when no
// context session is present - a request that reaches a handler without
// having gone through the global middleware first, or one whose session
// cookie only appears after that middleware already ran (neither happens in
// the current wiring, but this keeps every call site correct regardless).
func SessionFromRequest(ctx context.Context, d Deps, token, currentIP, currentCountry, currentUserAgent string) (Session, bool, error) {
	if sess, ok := SessionFromContext(ctx); ok {
		return sess, true, nil
	}
	return ValidateSession(ctx, d, token, currentIP, currentCountry, currentUserAgent)
}

// ValidateSession looks up token in Valkey and returns the session it maps
// to, if any. A missing or expired token is not an error - ok is simply
// false.
//
// currentIP/currentCountry/currentUserAgent are this request's
// clientIP(r)/loginCountry(r)/r.Header.Get("User-Agent") (handlers.go),
// threaded in by every caller purely so the mid-session anomaly checks
// below have something to compare against - unlike CreateSession's IP/
// Country/UserAgent (captured once, at login, for display only), these
// three are never stored on the Session itself. currentCountry/
// currentUserAgent == "" (no CF-IPCountry header - local/dev access
// bypassing Cloudflare, or a grey-clouded DNS-only setup; or no User-Agent
// header at all, unusual but possible for a non-browser client) always
// skips the respective check entirely, same fail-open behavior as
// checkAndRecordLoginCountry's own doc comment describes for the
// login-time equivalent this mirrors.
//
// Sliding window: on every successful lookup the TTL of both the session
// key and the per-user session index are reset to SessionTTL. This means
// an actively-used session never expires mid-use; only a session that
// goes completely untouched for 24 hours will require a new login. TTL
// extension failures are non-fatal: the session was already read
// successfully, so the caller gets a valid response regardless. Worst
// case the session expires on its original schedule rather than sliding.
func ValidateSession(ctx context.Context, d Deps, token, currentIP, currentCountry, currentUserAgent string) (Session, bool, error) {
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

	checkSessionCountryAnomaly(ctx, d, token, sess, masterKey, currentIP, currentCountry)
	checkSessionDeviceAnomaly(ctx, d, token, sess, masterKey, currentIP, currentUserAgent)

	return sess, true, nil
}

// sessionBaselineChanged is the pure decision shared by
// checkSessionCountryAnomaly and checkSessionDeviceAnomaly below: true only
// when both baseline and current are known (non-empty) and they differ - a
// first-ever check (no baseline yet) or a request with no CF-IPCountry
// header/User-Agent at all must never be flagged, since there is nothing
// meaningful to compare. Split out from those two (which also do
// Valkey/notify/mail/audit I/O and are therefore awkward to unit test
// directly) purely so this one decision has a test of its own - see
// TestSessionBaselineChanged. Same logic handlers.go's
// checkAndRecordLoginCountry inlines for the login-time case; kept as a
// separate, differently-shaped call site rather than folded in here, since
// that one also owns writing its own per-*user* baseline back to Valkey,
// which this function deliberately has no side effects for at all.
func sessionBaselineChanged(baseline, current string) bool {
	return baseline != "" && current != "" && baseline != current
}

// checkSessionCountryAnomaly is ValidateSession's mid-session counterpart to
// handlers.go's checkAndRecordLoginCountry: that one only ever fires once,
// at login, so a session token that gets copied out and used from a second
// location *without* a new login (the actual token-theft scenario a stolen
// bearer token, not a stolen password, would look like - PocketID passkey
// login already makes the latter far harder) would otherwise never be
// flagged for as long as that token remains valid. This closes that gap by
// re-running the same comparison on every request that reaches here, against
// a baseline (sessionCountryKeyPrefix+token) that itself slides forward -
// see that key's doc comment for why a fixed baseline is not enough.
//
// masterKey is passed in rather than re-resolved here - ValidateSession
// already resolved it once (to decrypt sess) just above, and mail/audit
// both need it too (mail.Enqueue resolves its own internally regardless,
// but audit.Log takes it directly).
//
// Best-effort throughout, like the TTL renewal just above: a Valkey hiccup
// here degrades to "this particular check was skipped this once", never to
// a failed request - the session was already successfully validated by the
// time this runs.
func checkSessionCountryAnomaly(ctx context.Context, d Deps, token string, sess Session, masterKey, currentIP, currentCountry string) {
	if currentCountry == "" {
		return
	}
	key := sessionCountryKeyPrefix + token
	baseline := sess.Country // first check of this session: fall back to the login-time country
	if prev, exists, err := d.Valkey.Get(ctx, key); err != nil {
		log.Printf("auth: read session country baseline: %v", err)
	} else if exists && prev != "" {
		baseline = prev
	}

	if sessionBaselineChanged(baseline, currentCountry) {
		// Same "session.new" event shape CallbackHandler already publishes at
		// login (handlers.go), reused rather than introducing a second event
		// type - AppShell.tsx's frontend handler already renders the
		// anomaly-toast branch for exactly this shape (ip/country/anomaly/
		// previous_country), so nothing there needs to change.
		if pubErr := notify.Publish(ctx, d.Valkey, notify.UserChannel(sess.UserID), notify.Event{
			Type: "session.new",
			Data: map[string]any{
				"ip":               currentIP,
				"user_agent":       sess.UserAgent,
				"country":          currentCountry,
				"anomaly":          true,
				"previous_country": baseline,
			},
		}); pubErr != nil {
			log.Printf("auth: notify mid-session anomaly for %s: %v", sess.UserID, pubErr)
		}
		// Durable, admin-reviewable trail - the live push above only reaches
		// an already-open second tab/device, and nothing before this wrote
		// anything to audit_log for a mid-session anomaly at all. Best-effort,
		// same reasoning as every other audit.Log call site in this package.
		if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
			EventType:   audit.EventAuthCountryAnomaly,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    sess.UserID,
			TargetEmail: sess.Email,
			Details:     fmt.Sprintf(`{"source":"mid_session","country":%q,"previous_country":%q,"ip":%q}`, currentCountry, baseline, currentIP),
		}); err != nil {
			log.Printf("auth: audit mid-session country anomaly for %s: %v", sess.UserID, err)
		}
		// Unlike the live push above, this reaches the account owner even if
		// they have no other tab/device connected right now to receive it -
		// see AnomalyMessage's doc comment. Gated on notify_country_anomaly
		// (default true) - unlike the audit.Log call just above, which is
		// never user-suppressible (see ValidateSession's own doc comment on
		// why). sess.Email may also be "" for an IdP that never populated it,
		// in which case there is no address to send to and this is silently
		// skipped, same as every other mail.Enqueue call site treats a
		// missing recipient.
		if prefs, err := d.Pool.GetNotificationPrefs(ctx, sess.UserID); err != nil {
			log.Printf("auth: read notification prefs for %s: %v", sess.UserID, err)
		} else if prefs.CountryAnomaly && sess.Email != "" {
			msg := mail.AnomalyMessage(sess.Email, sess.Name, currentIP, currentCountry, baseline, d.FrontendBaseURL, mail.CurrentBranding(ctx, d.Pool))
			if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
				log.Printf("auth: enqueue anomaly mail for %s: %v", sess.UserID, err)
			}
		}
	}

	// Only actually rewrite the baseline value when it changed (M-1,
	// PERFORMANCE_AUDIT.md) - the overwhelmingly common case on every one of
	// these mid-session checks is "still the same country", which used to
	// mean writing back the exact value just read on every single
	// authenticated request. An unchanged check still needs *some* TTL
	// refresh so this key doesn't expire out from under a session that
	// slides on indefinitely (ValidateSession's own SessionTTL renewal just
	// above) - a bare Expire is far cheaper than a full SET, and is a
	// harmless no-op on a key that was never written in the first place
	// (nothing to refresh yet: baseline fell back to sess.Country above,
	// which stays correct on its own for as long as nothing has changed).
	if baseline == currentCountry {
		if err := d.Valkey.Expire(ctx, key, SessionTTL); err != nil {
			log.Printf("auth: refresh session country baseline ttl: %v", err)
		}
		return
	}
	if err := d.Valkey.SetWithTTL(ctx, key, currentCountry, SessionTTL); err != nil {
		log.Printf("auth: record session country baseline: %v", err)
	}
}

// checkSessionDeviceAnomaly is checkSessionCountryAnomaly's User-Agent-based
// sibling: catches a session suddenly being used from a different device/
// browser, a signal country detection misses entirely (same country,
// different device - e.g. a token copied to another machine on the same
// network/ISP) and one a legitimate single-device session should never
// produce on its own mid-lifetime, unlike an IP/country drift a mobile
// network or VPN can cause innocently. Structurally identical to
// checkSessionCountryAnomaly (same baseline-in-Valkey, notify/audit/mail
// pattern) but kept as a separate function rather than a parameterized
// shared one - the two differ in event Type, audit Details shape, and which
// notification-preference field and mail template they use, which would
// otherwise need to be threaded through as several more parameters than the
// shared logic saves.
func checkSessionDeviceAnomaly(ctx context.Context, d Deps, token string, sess Session, masterKey, currentIP, currentUserAgent string) {
	if currentUserAgent == "" {
		return
	}
	key := sessionDeviceKeyPrefix + token
	baseline := sess.UserAgent // first check of this session: fall back to the login-time device
	if prev, exists, err := d.Valkey.Get(ctx, key); err != nil {
		log.Printf("auth: read session device baseline: %v", err)
	} else if exists && prev != "" {
		baseline = prev
	}

	if sessionBaselineChanged(baseline, currentUserAgent) {
		if pubErr := notify.Publish(ctx, d.Valkey, notify.UserChannel(sess.UserID), notify.Event{
			Type: "session.new",
			Data: map[string]any{
				"ip":                  currentIP,
				"user_agent":          currentUserAgent,
				"anomaly":             true,
				"previous_user_agent": baseline,
			},
		}); pubErr != nil {
			log.Printf("auth: notify mid-session device anomaly for %s: %v", sess.UserID, pubErr)
		}
		if err := audit.Log(ctx, d.Pool, masterKey, audit.LogParams{
			EventType:   audit.EventAuthDeviceAnomaly,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    sess.UserID,
			TargetEmail: sess.Email,
			Details:     fmt.Sprintf(`{"user_agent":%q,"previous_user_agent":%q,"ip":%q}`, currentUserAgent, baseline, currentIP),
		}); err != nil {
			log.Printf("auth: audit mid-session device anomaly for %s: %v", sess.UserID, err)
		}
		if prefs, err := d.Pool.GetNotificationPrefs(ctx, sess.UserID); err != nil {
			log.Printf("auth: read notification prefs for %s: %v", sess.UserID, err)
		} else if prefs.NewDevice && sess.Email != "" {
			msg := mail.NewDeviceMessage(sess.Email, sess.Name, currentIP, baseline, currentUserAgent, d.FrontendBaseURL, mail.CurrentBranding(ctx, d.Pool))
			if err := mail.Enqueue(ctx, d.Valkey, d.Pool, d.MasterKeyEnv, msg); err != nil {
				log.Printf("auth: enqueue new-device mail for %s: %v", sess.UserID, err)
			}
		}
	}

	// Same M-1 fix (PERFORMANCE_AUDIT.md) as checkSessionCountryAnomaly
	// above: skip the rewrite when the baseline is unchanged, just refresh
	// its TTL instead.
	if baseline == currentUserAgent {
		if err := d.Valkey.Expire(ctx, key, SessionTTL); err != nil {
			log.Printf("auth: refresh session device baseline ttl: %v", err)
		}
		return
	}
	if err := d.Valkey.SetWithTTL(ctx, key, currentUserAgent, SessionTTL); err != nil {
		log.Printf("auth: record session device baseline: %v", err)
	}
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
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at,omitempty"`
	IP        string `json:"ip,omitempty"`
	// Hostname is IP's reverse-DNS (PTR) name, if any - resolveHostname's
	// result. Omitted (empty) whenever IP has no PTR record, IP is empty
	// (local dev with no real client address), or the lookup itself failed;
	// the frontend falls back to showing just the IP in that case, same as
	// Country already does when Cloudflare didn't supply one.
	Hostname             string `json:"hostname,omitempty"`
	UserAgent            string `json:"user_agent,omitempty"`
	Country              string `json:"country,omitempty"`
	LastActiveSecondsAgo int64  `json:"last_active_seconds_ago,omitempty"`
	ExpiresInSeconds     int64  `json:"expires_in_seconds,omitempty"`
	Current              bool   `json:"current,omitempty"`
}

// rdnsCacheKeyPrefix namespaces resolveHostname's Valkey cache entries from
// every other "prefix:" key this package uses (sessionKeyPrefix,
// userSessionsKeyPrefix, oauthStateKeyPrefix, ...).
const rdnsCacheKeyPrefix = "rdns:"

// rdnsCacheTTL bounds how long a resolved (or negative) reverse-DNS result
// is trusted before resolveHostname looks it up again. An hour is generous
// enough that ListActiveSessions/ListActiveSessionsForUser - both called on
// every page load of System Info / Profile - essentially never re-resolve
// the same IP twice in a row, while still picking up rDNS changes (a
// residential IP getting reassigned, a reverse zone being fixed) well
// within a day.
const rdnsCacheTTL = time.Hour

// rdnsLookupTimeout bounds a single uncached net.LookupAddr call. Reverse
// DNS for a dead/unreachable resolver can otherwise hang for many seconds;
// this is a best-effort display field, not something worth blocking (or
// failing) either sessions endpoint over, so a slow lookup degrades to
// "no hostname" rather than delaying the whole response.
const rdnsLookupTimeout = 2 * time.Second

// resolveHostname returns ip's reverse-DNS name (PTR record), or "" if ip is
// empty, has no PTR record, or the lookup fails/times out. Results -
// including the negative "no hostname" case, so a PTR-less IP is not
// re-looked-up on every single request - are cached in Valkey under
// rdnsCacheKeyPrefix+ip for rdnsCacheTTL. Best-effort throughout: a Valkey
// error reading or writing the cache just means this call falls back to (or
// skips) caching, it never fails the caller.
func resolveHostname(ctx context.Context, d Deps, ip string) string {
	if ip == "" {
		return ""
	}
	key := rdnsCacheKeyPrefix + ip
	if cached, exists, err := d.Valkey.Get(ctx, key); err == nil && exists {
		return cached
	}

	lookupCtx, cancel := context.WithTimeout(ctx, rdnsLookupTimeout)
	defer cancel()
	var hostname string
	if names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	if err := d.Valkey.SetWithTTL(ctx, key, hostname, rdnsCacheTTL); err != nil {
		log.Printf("auth: resolve hostname for %s: cache set: %v", ip, err)
	}
	return hostname
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
			Hostname:  resolveHostname(ctx, d, sess.IP),
			UserAgent: sess.UserAgent,
			Country:   sess.Country,
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
			Hostname:  resolveHostname(ctx, d, sess.IP),
			UserAgent: sess.UserAgent,
			Country:   sess.Country,
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

	// Best-effort live push (H-3, PERFORMANCE_AUDIT.md), same reasoning as
	// RevokeUserSessions's own "session.changed" push above - lets an
	// already-open tab pick up its new role immediately via
	// useAuthenticatedSession instead of waiting on the safety-net poll.
	// Published even when tokens was empty (no active session right now) -
	// harmless, since nothing is subscribed to notify.UserChannel(subject)
	// in that case anyway.
	if pubErr := notify.Publish(ctx, vk, notify.UserChannel(subject), notify.Event{Type: "session.changed"}); pubErr != nil {
		log.Printf("auth: notify session role update for %s: %v", subject, pubErr)
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
