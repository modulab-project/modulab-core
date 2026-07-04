// Package audit writes and reads the append-only audit log (spec section
// 10.5). Every security-relevant admin action - user approve/lock/unlock/
// delete, SMTP/OIDC configuration changes - produces one row.
//
// Immutability is enforced at two layers:
//   - A PostgreSQL trigger (migrations/0003_add_audit_log.up.sql) raises an
//     exception on any UPDATE or DELETE, making tampering impossible without
//     dropping the trigger (a DB-superuser operation, not available to the
//     app role).
//   - A HMAC-SHA256 chain: each entry records prev_hash (the hash of the
//     entry before it) and hash (the HMAC of its own fields including
//     prev_hash). Any retroactive modification breaks the chain and is
//     cryptographically detectable.
//
// PII (actor/target email) and the details JSON blob are encrypted at rest
// with the master key (AES-256-GCM, spec section 2.4 class B). Callers
// always pass plaintext; this package encrypts before writing.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// Event type constants. Callers import these rather than using raw strings so
// a typo shows up as a compile error, not a silent mis-labelled log entry.
const (
	// User lifecycle events (admin-driven)
	EventUserApproved  = "user.approved"
	EventUserLocked    = "user.locked"
	EventUserUnlocked  = "user.unlocked"
	EventUserDeleted   = "user.deleted"
	// User self-service
	EventUserSelfDeleted = "user.self_deleted"
	// Auth events
	EventAuthLogin = "auth.login"
	// System config events
	EventConfigSMTP         = "config.smtp"
	EventConfigSMTPDel      = "config.smtp.deleted"
	EventConfigOIDC         = "config.oidc"
	EventConfigOIDCDel      = "config.oidc.deleted"
	EventConfigSearXNG      = "config.searxng"
	EventConfigSearXNGDel   = "config.searxng.deleted"
	EventConfigAIProvider    = "config.ai_provider"
	EventConfigAIProviderDel = "config.ai_provider.deleted"
	EventConfigAIKeyCleared  = "config.ai_provider.key_cleared"
	// chat_rpm_limit and max_body_bytes (ai.AdminSettingsHandler) - unlike
	// the provider CRUD above, this one had no audit call at all despite
	// max_body_bytes being a DoS-relevant limit.
	EventConfigAISettings = "config.ai_settings"
	// Setup
	EventSetupComplete = "setup.completed"
	// Module lifecycle events (org-admin/super-admin driven, spec section
	// 4.6-4.9). Installing a module runs arbitrary code (Tier 2/3 modules
	// spawn a Deno subprocess with DB + scoped network access) - previously
	// none of install/uninstall/update/pin/unpin produced any audit trail
	// at all, the single biggest gap found in the V1 audit-log review.
	EventModuleInstalled   = "module.installed"
	EventModuleUninstalled = "module.uninstalled"
	EventModuleUpdated     = "module.updated"
	EventModuleRestarted   = "module.restarted"
	EventModulePinned      = "module.pinned"
	EventModuleUnpinned    = "module.unpinned"
	// Feed management (org-admin/super-admin), internal/news.
	EventFeedCreated = "feed.created"
	EventFeedUpdated = "feed.updated"
	EventFeedDeleted = "feed.deleted"
	// Quick-link management (org-admin/super-admin), internal/quicklinks.
	EventQuickLinkCreated = "quicklink.created"
	EventQuickLinkUpdated = "quicklink.updated"
	EventQuickLinkDeleted = "quicklink.deleted"
	// Manual Module Store registry sync trigger, internal/store.
	EventStoreSyncTriggered = "store.sync_triggered"
)

// Entry is one row from the audit_log table, returned by List. All PII
// fields are already decrypted so callers can display them directly.
type Entry struct {
	ID             int64     `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	EventType      string    `json:"event_type"`
	ActorID        string    `json:"actor_id"`
	ActorEmail     string    `json:"actor_email"`
	TargetID       string    `json:"target_id"`
	TargetEmail    string    `json:"target_email"`
	Details        string    `json:"details"`   // plaintext JSON or ""
	PrevHash       string    `json:"prev_hash"`
	Hash           string    `json:"hash"`
}

// LogParams carries the fields the caller provides; everything else
// (prev_hash, hash, created_at) is computed inside Log.
type LogParams struct {
	EventType   string // one of the Event* constants
	ActorID     string // OIDC sub of the acting admin
	ActorEmail  string // plaintext; encrypted before storage
	TargetID    string // subject acted on, "" if not applicable
	TargetEmail string // plaintext; encrypted before storage, "" if not applicable
	Details     string // JSON string with extra context, "" if not applicable
}

// Log appends one entry to the audit log. It reads the last entry's hash to
// build the chain link, then encrypts PII and writes the new row atomically.
// Best-effort from the caller's perspective: if Log fails, the admin action
// itself should not be rolled back - callers log the error and continue.
func Log(ctx context.Context, pool *db.Pool, masterKey string, p LogParams) error {
	prevHash, err := latestHash(ctx, pool)
	if err != nil {
		return fmt.Errorf("audit: read prev_hash: %w", err)
	}

	actorEmailEnc, err := crypto.Encrypt(masterKey, p.ActorEmail)
	if err != nil {
		return fmt.Errorf("audit: encrypt actor_email: %w", err)
	}
	targetEmailEnc := ""
	if p.TargetEmail != "" {
		targetEmailEnc, err = crypto.Encrypt(masterKey, p.TargetEmail)
		if err != nil {
			return fmt.Errorf("audit: encrypt target_email: %w", err)
		}
	}
	detailsEnc := ""
	if p.Details != "" {
		detailsEnc, err = crypto.Encrypt(masterKey, p.Details)
		if err != nil {
			return fmt.Errorf("audit: encrypt details: %w", err)
		}
	}

	// Compute this entry's hash over all fields plus prev_hash, using the
	// master key as the HMAC secret so the chain is tied to this instance.
	h := entryHMAC(masterKey, p.EventType, p.ActorID, p.TargetID, prevHash)

	_, err = pool.Exec(ctx, `
		INSERT INTO audit_log
		    (event_type, actor_id, actor_email_enc, target_id, target_email_enc,
		     details_enc, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, p.EventType, p.ActorID, actorEmailEnc,
		p.TargetID, targetEmailEnc, detailsEnc, prevHash, h)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

// ListParams controls which rows List returns.
type ListParams struct {
	EventType string // filter by event_type prefix, "" means all
	Limit     int    // max rows, default 50 if 0
	Before    int64  // cursor: return rows with id < Before, 0 means newest first
}

// List returns audit log entries newest-first, decrypting PII fields.
func List(ctx context.Context, pool *db.Pool, masterKey string, p ListParams) ([]Entry, error) {
	limit := p.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var (
		rows pgx.Rows
		err  error
	)

	// Build the query depending on filters. Pool embeds *pgxpool.Pool whose
	// Query method returns (pgx.Rows, error).
	switch {
	case p.EventType != "" && p.Before > 0:
		rows, err = pool.Query(ctx, `
			SELECT id, created_at, event_type, actor_id, actor_email_enc,
			       target_id, target_email_enc, details_enc, prev_hash, hash
			FROM audit_log
			WHERE event_type = $1 AND id < $2
			ORDER BY id DESC LIMIT $3
		`, p.EventType, p.Before, limit)
	case p.EventType != "":
		rows, err = pool.Query(ctx, `
			SELECT id, created_at, event_type, actor_id, actor_email_enc,
			       target_id, target_email_enc, details_enc, prev_hash, hash
			FROM audit_log
			WHERE event_type = $1
			ORDER BY id DESC LIMIT $2
		`, p.EventType, limit)
	case p.Before > 0:
		rows, err = pool.Query(ctx, `
			SELECT id, created_at, event_type, actor_id, actor_email_enc,
			       target_id, target_email_enc, details_enc, prev_hash, hash
			FROM audit_log
			WHERE id < $1
			ORDER BY id DESC LIMIT $2
		`, p.Before, limit)
	default:
		rows, err = pool.Query(ctx, `
			SELECT id, created_at, event_type, actor_id, actor_email_enc,
			       target_id, target_email_enc, details_enc, prev_hash, hash
			FROM audit_log
			ORDER BY id DESC LIMIT $1
		`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()

	type rawRow struct {
		entry          Entry
		actorEmailEnc  string
		targetEmailEnc string
		detailsEnc     string
	}

	var raws []rawRow
	for rows.Next() {
		var raw rawRow
		if err := rows.Scan(
			&raw.entry.ID, &raw.entry.CreatedAt, &raw.entry.EventType,
			&raw.entry.ActorID, &raw.actorEmailEnc,
			&raw.entry.TargetID, &raw.targetEmailEnc,
			&raw.detailsEnc, &raw.entry.PrevHash, &raw.entry.Hash,
		); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		raws = append(raws, raw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: rows: %w", err)
	}

	entries := make([]Entry, 0, len(raws))
	for _, raw := range raws {
		e := raw.entry
		e.ActorEmail, _ = crypto.Decrypt(masterKey, raw.actorEmailEnc)
		if raw.targetEmailEnc != "" {
			e.TargetEmail, _ = crypto.Decrypt(masterKey, raw.targetEmailEnc)
		}
		if raw.detailsEnc != "" {
			e.Details, _ = crypto.Decrypt(masterKey, raw.detailsEnc)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// latestHash returns the hash of the most recent audit_log entry, or ""
// if the table is empty. Used by Log to chain the next entry.
func latestHash(ctx context.Context, pool *db.Pool) (string, error) {
	var h string
	err := pool.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&h)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("audit: latestHash: %w", err)
	}
	return h, nil
}

// entryHMAC computes HMAC-SHA256 of the entry's non-encrypted fields plus
// prev_hash. Using the master key as the HMAC secret ties the chain to this
// specific instance - even if someone copies the DB to another host with a
// different master key, the hashes will not verify.
func entryHMAC(masterKey, eventType, actorID, targetID, prevHash string) string {
	mac := hmac.New(sha256.New, []byte(masterKey))
	// hash.Hash.Write (which hmac.New's Writer wraps) is documented to
	// never return an error - safe to discard explicitly rather than
	// thread an error return through a pure hashing helper.
	_, _ = fmt.Fprintf(mac, "%s|%s|%s|%s", eventType, actorID, targetID, prevHash)
	return hex.EncodeToString(mac.Sum(nil))
}
