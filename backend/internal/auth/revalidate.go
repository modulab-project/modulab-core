// This file periodically re-checks every active session against the
// configured OIDC provider, closing a gap Session's doc comment (session.go)
// already flagged: without this, an account revoked, disabled, or deleted at
// the IdP kept working here completely unnoticed until the session naturally
// expired - up to SessionTTL (24h), reset on every request by the sliding
// window in ValidateSession. A session whose IdP-side account is gone now
// gets caught within one revalidateTickInterval instead.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// revalidateTickInterval is how often RunSessionRevalidateWorker re-checks
// every active session against the IdP. A homelab-scale instance has at
// most a handful of concurrently active sessions, so this can afford to be
// infrequent - 6h keeps the worst-case staleness window (an IdP-side
// revocation not yet noticed here) well under SessionTTL's 24h, without
// hammering the IdP's token/userinfo endpoints on every tick.
const revalidateTickInterval = 6 * time.Hour

// RunSessionRevalidateWorker runs for Core's entire lifetime as a single
// background goroutine, same pattern as mail.RunWorker (cmd/core/main.go) -
// started unconditionally at boot. A tick where OIDC is not yet configured
// (fresh instance still in the Setup Wizard) or momentarily unreachable is
// simply a no-op, logged and retried on the next tick, not fatal.
func RunSessionRevalidateWorker(ctx context.Context, d Deps) {
	ticker := time.NewTicker(revalidateTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			revalidateAllSessions(ctx, d)
		}
	}
}

// revalidateAllSessions resolves the current OIDC provider once and checks
// every currently active session against it. Each session is independent -
// one failing to decode/decrypt or one IdP rejection does not stop the
// others from being checked, same "best-effort per entry" treatment
// ListActiveSessions (session.go) already uses for this same key scan.
func revalidateAllSessions(ctx context.Context, d Deps) {
	provider, err := d.resolveProvider(ctx)
	if err != nil {
		log.Printf("auth: session revalidation: resolve provider: %v", err)
		return
	}

	keys, err := d.Valkey.ScanKeysWithPrefix(ctx, sessionKeyPrefix)
	if err != nil {
		log.Printf("auth: session revalidation: scan sessions: %v", err)
		return
	}

	var checked, revokedCount int
	for _, key := range keys {
		token := strings.TrimPrefix(key, sessionKeyPrefix)
		revoked, err := RevalidateSession(ctx, d, token, provider)
		if err != nil {
			log.Printf("auth: session revalidation: %v", err)
			continue
		}
		checked++
		if revoked {
			revokedCount++
		}
	}
	if revokedCount > 0 {
		log.Printf("auth: session revalidation: checked %d session(s), revoked %d rejected by the IdP", checked, revokedCount)
	}
}

// RevalidateSession re-checks one active session (by token) against the IdP
// using its stored, encrypted refresh token: it exchanges that refresh
// token for a fresh access token and calls the IdP's UserInfo endpoint (see
// Provider.Revalidate). If the IdP rejects the refresh token - revoked,
// account disabled/deleted at the IdP, or the IdP simply no longer
// recognizes it - the local session is killed immediately, the same way
// RevokeUserSessions kills one, rather than waiting out the rest of
// SessionTTL. If the IdP still honors it, this also refreshes the cached
// Name/Email/Picture/PreferredUsername claims (otherwise these only update
// on next login, per Session's doc comment) and rotates the stored refresh
// token if the IdP issued a new one.
//
// Returns revoked=true if the session was killed as a result of this check.
// A session with no stored refresh token (predates this feature, or the
// IdP did not grant one - e.g. it does not support the "offline_access"
// scope) is left untouched, not revoked: there is nothing to check it
// against, and silently no-op-ing is safer than treating "we don't know"
// as "revoke it".
func RevalidateSession(ctx context.Context, d Deps, token string, provider *Provider) (revoked bool, err error) {
	raw, exists, err := d.Valkey.Get(ctx, sessionKeyPrefix+token)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: get session: %w", err)
	}
	if !exists {
		return false, nil // expired/logged out between the scan and here - nothing to do
	}

	var stored storedSession
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return false, fmt.Errorf("auth: revalidate: decode session: %w", err)
	}
	if stored.RefreshTokenEnc == "" {
		return false, nil
	}

	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: resolve master key: %w", err)
	}
	refreshToken, err := crypto.DecryptIfNotEmpty(masterKey, stored.RefreshTokenEnc)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: decrypt refresh token: %w", err)
	}

	claims, newRefreshToken, err := provider.Revalidate(ctx, refreshToken)
	if err != nil {
		// The IdP rejected the refresh token - treat this exactly like an
		// admin-initiated revoke of this one session (RevokeSessionByID).
		if delErr := d.Valkey.Del(ctx, sessionKeyPrefix+token); delErr != nil {
			return false, fmt.Errorf("auth: revalidate: revoke after IdP rejection: %w", delErr)
		}
		if remErr := d.Valkey.RemoveSetMember(ctx, userSessionsKeyPrefix+stored.UserID, token); remErr != nil {
			// The session itself is already gone (the Del above succeeded) -
			// a stale entry left behind in the per-user index is a minor,
			// self-healing inconsistency (RevokeUserSessions/UpdateSessionsRole
			// already tolerate a token in that set with no matching session
			// key), not worth failing this call over.
			log.Printf("auth: revalidate: unindex revoked session for %s: %v", stored.UserID, remErr)
		}
		return true, nil
	}

	// Still valid at the IdP - refresh the cached claims and rotate the
	// refresh token in place. Preserves whatever TTL the session already
	// has: this is a background health check, not user activity, so it
	// must not itself extend the sliding window ValidateSession manages.
	emailEnc, err := crypto.EncryptIfNotEmpty(masterKey, claims.Email)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: encrypt email: %w", err)
	}
	nameEnc, err := crypto.EncryptIfNotEmpty(masterKey, claims.Name)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: encrypt name: %w", err)
	}
	preferredEnc, err := crypto.EncryptIfNotEmpty(masterKey, claims.PreferredUsername)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: encrypt preferred_username: %w", err)
	}
	pictureEnc, err := crypto.EncryptIfNotEmpty(masterKey, claims.Picture)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: encrypt picture: %w", err)
	}
	refreshTokenEnc, err := crypto.EncryptIfNotEmpty(masterKey, newRefreshToken)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: encrypt refresh token: %w", err)
	}

	stored.EmailEnc = emailEnc
	stored.EmailVerified = claims.EmailVerified
	stored.NameEnc = nameEnc
	stored.PreferredUsernameEnc = preferredEnc
	stored.PictureEnc = pictureEnc
	stored.RefreshTokenEnc = refreshTokenEnc

	data, err := json.Marshal(stored)
	if err != nil {
		return false, fmt.Errorf("auth: revalidate: marshal session: %w", err)
	}

	ttl, ttlOK, err := d.Valkey.TTL(ctx, sessionKeyPrefix+token)
	if err != nil || !ttlOK || ttl <= 0 {
		// Lookup failed, or lost a race with the key expiring naturally
		// between the Get above and here - fall back to a full SessionTTL
		// rather than writing back a key with an unintended (e.g. zero/
		// negative) TTL.
		ttl = SessionTTL
	}
	if err := d.Valkey.SetWithTTL(ctx, sessionKeyPrefix+token, string(data), ttl); err != nil {
		return false, fmt.Errorf("auth: revalidate: store session: %w", err)
	}
	return false, nil
}
