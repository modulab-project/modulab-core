// Package audit writes and reads the append-only audit log (spec section
// 10.5). Every security-relevant admin action - user approve/lock/unlock/
// delete, SMTP/OIDC configuration changes - produces one row.
//
// Immutability is enforced at two layers:
//   - A PostgreSQL trigger (created in EnsureAuditSchema, internal/db/db.go)
//     raises an exception on any UPDATE or DELETE, making tampering
//     impossible without dropping the trigger (a DB-superuser operation,
//     not available to the app role).
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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// Event type constants. Callers import these rather than using raw strings so
// a typo shows up as a compile error, not a silent mis-labelled log entry.
const (
	// User lifecycle events (admin-driven)
	EventUserApproved = "user.approved"
	EventUserLocked   = "user.locked"
	EventUserUnlocked = "user.unlocked"
	EventUserDeleted  = "user.deleted"
	// User self-service
	EventUserSelfDeleted = "user.self_deleted"
	// Auth events
	EventAuthLogin = "auth.login"
	// Fired by LogoutHandler on an explicit logout - previously only login
	// produced an audit trail, so a full "when was this account active"
	// timeline had start events but no end events. Not fired for a session
	// that simply expires unused (SessionTTL) or is revoked by an admin
	// action (those already have their own trail: EventUserLocked/
	// EventUserDeleted, or EventSessionRevokedByAdmin below) - only for the
	// user's own deliberate "log me out" action.
	EventAuthLogout = "auth.logout"
	// Fired by RevokeSessionByID's caller (admin.go's EndSessionHandler)
	// when an admin ends one specific active session (System Info page's
	// per-row action) - distinct from EventUserLocked/EventUserDeleted
	// (which also revoke sessions, but as a side effect of a users-table
	// change) and from EventSessionRevokedByIdP (revalidate.go, no human
	// actor at all): this is an admin choosing to end one session while
	// leaving the account itself untouched.
	EventSessionRevokedByAdmin = "auth.session_revoked_by_admin"
	// Fired by auth.RevalidateSession (revalidate.go) when the periodic IdP
	// re-check finds a session's refresh token rejected - account
	// disabled/deleted/revoked at the IdP - and kills it early instead of
	// letting it run out the rest of SessionTTL. Distinct from
	// EventUserLocked/EventUserDeleted: those are Core-admin-driven actions
	// on the users table; this is Core noticing, on its own, that the IdP
	// no longer considers the login valid - worth its own trail so an admin
	// can tell "I locked them" apart from "the IdP revoked them and Core
	// caught it automatically".
	EventSessionRevokedByIdP = "auth.session_revoked_by_idp"
	// Fired by auth.recordReauthFailure (admin.go) once a caller's step-up
	// reauth attempts (requireRecentLogin - lock/unlock/approve/delete a
	// user, self-delete, SMTP/OIDC config, ending another session) fail
	// repeatedly in a short window. A single failure is routine (session
	// just hasn't been refreshed recently) and produces no audit entry at
	// all - only reaching reauthFailAlertThreshold does, since that pattern
	// looks less like an idle session and more like something probing a
	// stale/stolen cookie for whatever it can still get away with. Details
	// carries the specific action label and the failure count.
	EventReauthRepeatedFailures = "auth.reauth_repeated_failures"
	// System config events
	EventConfigSMTP          = "config.smtp"
	EventConfigSMTPDel       = "config.smtp.deleted"
	EventConfigOIDC          = "config.oidc"
	EventConfigOIDCDel       = "config.oidc.deleted"
	EventConfigSearXNG       = "config.searxng"
	EventConfigSearXNGDel    = "config.searxng.deleted"
	EventConfigAIProvider    = "config.ai_provider"
	EventConfigAIProviderDel = "config.ai_provider.deleted"
	EventConfigAIKeyCleared  = "config.ai_provider.key_cleared"
	// Legacy: used to cover chat_rpm_limit and max_body_bytes
	// (ai.AdminSettingsHandler). Both fields have since moved to
	// EventConfigSystemLimits below (max_body_bytes first, chat_rpm_limit
	// later once its single-field admin endpoint was folded into
	// adminapi.AdminLimitsHandler). Kept, not removed, so historic
	// audit_log rows written before either move still decode to a
	// recognizable event type - same reasoning as the legacy
	// config.searxng* constants further down.
	EventConfigAISettings = "config.ai_settings"
	// User-owned AI provider key events (internal/ai) - distinct from the
	// config.ai_provider* family above, which is exclusively admin-driven
	// (provider CRUD, the shared admin key). These cover a user's own
	// override key for a provider (PUT /v1/ai/keys/{id}, DELETE
	// /v1/ai/keys/{id}) - previously unaudited despite being a credential
	// write, unlike its admin-key sibling (EventConfigAIKeyCleared) right
	// above. The key value itself is never included in Details, only which
	// provider_id was touched.
	EventAIUserKeySet     = "ai.user_key_set"
	EventAIUserKeyDeleted = "ai.user_key_deleted"
	// Search provider config events (internal/search) - replaces the old
	// config.searxng/config.searxng.deleted pair now that web search can be
	// backed by more than one provider (SearXNG, Serper.dev, and whatever
	// gets added later). The two legacy constants above are kept (not
	// removed) purely so historic audit_log rows written before this change
	// still decode to a recognizable event type.
	EventConfigSearchProvider   = "config.search_provider"
	EventConfigSearchKeyCleared = "config.search_provider.key_cleared"
	EventConfigSearchSettings   = "config.search_settings"
	EventSearchUserKeySet       = "search.user_key_set"
	EventSearchUserKeyDeleted   = "search.user_key_deleted"
	// Cross-cutting operational limits (adminapi.AdminLimitsHandler):
	// upload size caps, rate limits (including chat_rpm_limit, moved here
	// from EventConfigAISettings above), worker pool size. See that
	// handler's doc comment for the full list - all DoS/availability-
	// relevant, hence audited the same way max_body_bytes is above.
	EventConfigSystemLimits = "config.system_limits"
	// Setup
	EventSetupComplete = "setup.completed"
	// Wizard steps that write config before the wizard itself is marked
	// complete (POST /v1/setup/oidc/configure, POST
	// /v1/setup/group-prefix/configure) - gated by the one-time bootstrap
	// token rather than an admin session (no session/role exists yet this
	// early), so ActorID/ActorEmail are left empty on these two entries.
	// Lower-severity than the post-wizard config.oidc update path (single
	// operator, pre-launch), but previously had no trail at all, unlike
	// every config write after setup completes.
	EventSetupOIDCConfigured        = "setup.oidc_configured"
	EventSetupGroupPrefixConfigured = "setup.group_prefix_configured"
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
	// Global news display settings (PATCH /v1/admin/news/settings:
	// news_max_articles, news_home_count, news_show_images) - same category
	// of cross-cutting config mutation as EventConfigSystemLimits/
	// EventConfigAISettings above, both of which are audited; this one was
	// simply missed when feed CRUD got its audit calls.
	EventNewsSettings = "config.news_settings"
	// Quick-link management (org-admin/super-admin), internal/quicklinks.
	EventQuickLinkCreated = "quicklink.created"
	EventQuickLinkUpdated = "quicklink.updated"
	EventQuickLinkDeleted = "quicklink.deleted"
	// Manual Module Store registry sync trigger, internal/store.
	EventStoreSyncTriggered = "store.sync_triggered"
	// Custom module source management. Super-admin only since 2026-07-22
	// (previously org-admin/super-admin - elevated alongside adding the
	// step-up reauth gate on update/delete below: a GitHub token plus the
	// ability to point Core at arbitrary third-party code is a higher-
	// value target than typical org-admin-level config). Details includes
	// the repo URL so a later audit review can see exactly which third-
	// party source was trusted/changed/removed and when - unlike most
	// audited resources, custom_sources has no separate "list" UI of its own
	// history once a row is deleted, so this is the only record that survives.
	EventCustomSourceAdded   = "store.custom_source_added"
	EventCustomSourceUpdated = "store.custom_source_updated"
	EventCustomSourceRemoved = "store.custom_source_removed"
	// A per-client rate limit (login/callback/ai-chat/global/chat, see
	// cmd/core/main.go's rateLimitMiddleware) was exceeded. ActorID is
	// whatever the limiter bucketed by: the client IP for login/callback/
	// ai-chat and for any anonymous request against the global backstop, or
	// "user:<OIDC sub>" for the per-user AI chat limiter and for the global
	// backstop once a request carries a valid session (added 2026-07-05,
	// see identifyBySessionOrIP) - there is often no authenticated session
	// yet at all (login/callback trip before auth succeeds), so the IP is
	// the only "who" available in that case.
	// Added 2026-07-05 alongside the System Info "rate limits" section, so a
	// trip is discoverable after the fact even once the live Valkey counter
	// itself has expired.
	EventRateLimitExceeded = "rate_limit.exceeded"
)

// Entry is one row from the audit_log table, returned by List. All PII
// fields are already decrypted so callers can display them directly.
type Entry struct {
	ID         int64     `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	EventType  string    `json:"event_type"`
	ActorID    string    `json:"actor_id"`
	ActorEmail string    `json:"actor_email"`
	// ActorName/TargetName (added 2026-07-05) resolve actor_id/target_id
	// (the OIDC subject) against the current users.name via a LEFT JOIN in
	// List - "" if the subject never matched a row (e.g. a purely IP-keyed
	// rate-limit entry) or no longer does (the account was since deleted).
	// A name is friendlier to read than a bare email, so callers should
	// prefer ActorName/TargetName over the *Email fields when non-empty,
	// falling back to email, then to the raw ID.
	ActorName   string `json:"actor_name,omitempty"`
	TargetID    string `json:"target_id"`
	TargetEmail string `json:"target_email"`
	TargetName  string `json:"target_name,omitempty"`
	Details     string `json:"details"` // plaintext JSON or ""
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
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
	h := entryHMAC(masterKey, p.EventType, p.ActorID, p.TargetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash)

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

// ListParams controls which rows List returns. All filters are ANDed
// together; zero values mean "no restriction" on that dimension.
type ListParams struct {
	EventType string    // filter by exact event_type, "" means all
	ActorID   string    // filter by exact actor_id (OIDC sub or IP), "" means all
	Since     time.Time // created_at >= Since, zero value means no lower bound
	Until     time.Time // created_at <= Until, zero value means no upper bound
	// Search is a case-insensitive substring match against every decrypted
	// text field (event_type, actor/target id, name, email, details JSON).
	// Because those fields are encrypted at rest (see the package doc
	// comment), this cannot be pushed into the SQL WHERE clause - List runs
	// it as a Go-side scan-and-filter loop instead. See the Search-mode
	// branch below for the scan cap this implies.
	Search string
	Limit  int   // max rows returned, default 50 if 0, capped at 200
	Before int64 // cursor: only consider rows with id < Before, 0 means newest first
}

// searchScanBatch is how many rows List fetches per round-trip while
// scanning for a Search match. searchScanCap is the hard ceiling on total
// rows examined for a single List call in Search mode - a safety valve, not
// a expected limit: ModuLab is a homelab-scale deployment (see Verify's doc
// comment on the same assumption), so an audit_log with more than this many
// rows between two matches is not a realistic case today. If that ever
// changes, this needs a real search index instead of decrypt-and-scan.
const (
	searchScanBatch = 500
	searchScanCap   = 20_000
)

// List returns audit log entries newest-first, decrypting PII fields and
// applying every non-zero field of p. Without Search set, this is a single
// SQL round-trip. With Search set, it transparently scans batches (in the
// same id-descending order) until Limit matches are found, the table is
// exhausted, or searchScanCap rows have been examined - so the returned
// slice always represents a contiguous, gap-free window even though the
// admin only sees the ones that matched.
func List(ctx context.Context, pool *db.Pool, masterKey string, p ListParams) ([]Entry, error) {
	limit := p.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	needle := strings.ToLower(strings.TrimSpace(p.Search))
	if needle == "" {
		return queryPage(ctx, pool, masterKey, p, limit, p.Before)
	}

	var results []Entry
	cursor := p.Before
	scanned := 0
	for scanned < searchScanCap {
		batch, err := queryPage(ctx, pool, masterKey, p, searchScanBatch, cursor)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		scanned += len(batch)
		for _, e := range batch {
			if entryMatches(e, needle) {
				results = append(results, e)
				if len(results) >= limit {
					// Stop mid-batch: results[len-1] is also the last row
					// we examined, so its ID is a valid cursor for the next
					// page - rows after it in this batch are simply
					// deferred to that next call, not skipped.
					return results, nil
				}
			}
		}
		cursor = batch[len(batch)-1].ID
		if len(batch) < searchScanBatch {
			break // reached the actual end of the table
		}
	}
	return results, nil
}

// entryMatches reports whether needle (already lowercased) occurs in any of
// entry e's human-readable text fields.
func entryMatches(e Entry, needle string) bool {
	fields := [...]string{
		e.EventType, e.ActorID, e.ActorEmail, e.ActorName,
		e.TargetID, e.TargetEmail, e.TargetName, e.Details,
	}
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

// queryPage runs one SQL round-trip: build a WHERE clause from whichever of
// p.EventType/ActorID/Since/Until are set, plus the id < before cursor, and
// decrypt every returned row. Used directly by List for the non-Search case,
// and repeatedly (with the narrower searchScanBatch limit) by List's
// Search-mode scan loop.
func queryPage(ctx context.Context, pool *db.Pool, masterKey string, p ListParams, limit int, before int64) ([]Entry, error) {
	// LEFT JOIN users twice (once per subject column) to resolve ActorName/
	// TargetName (added 2026-07-05) - LEFT, not INNER, because actor_id/
	// target_id may be a bare IP (rate-limit entries), "" (no target), or a
	// subject whose users row was since deleted; any of those should still
	// return the audit row itself, just without a name to show.
	// COALESCE(..., '') turns the LEFT JOIN's possible NULL into an empty
	// string so Scan can read straight into a plain string, no
	// sql.NullString needed.
	var (
		conds []string
		args  []any
	)
	addCond := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if p.EventType != "" {
		addCond("a.event_type = $%d", p.EventType)
	}
	if p.ActorID != "" {
		addCond("a.actor_id = $%d", p.ActorID)
	}
	if !p.Since.IsZero() {
		addCond("a.created_at >= $%d", p.Since)
	}
	if !p.Until.IsZero() {
		addCond("a.created_at <= $%d", p.Until)
	}
	if before > 0 {
		addCond("a.id < $%d", before)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT a.id, a.created_at, a.event_type, a.actor_id, a.actor_email_enc,
		       a.target_id, a.target_email_enc, a.details_enc, a.prev_hash, a.hash,
		       COALESCE(au.name, ''), COALESCE(tu.name, '')
		FROM audit_log a
		LEFT JOIN users au ON au.id = a.actor_id
		LEFT JOIN users tu ON tu.id = a.target_id
		%s
		ORDER BY a.id DESC LIMIT $%d
	`, where, len(args))

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()

	type rawRow struct {
		entry          Entry
		actorEmailEnc  string
		targetEmailEnc string
		detailsEnc     string
		actorNameEnc   string
		targetNameEnc  string
	}

	var raws []rawRow
	for rows.Next() {
		var raw rawRow
		if err := rows.Scan(
			&raw.entry.ID, &raw.entry.CreatedAt, &raw.entry.EventType,
			&raw.entry.ActorID, &raw.actorEmailEnc,
			&raw.entry.TargetID, &raw.targetEmailEnc,
			&raw.detailsEnc, &raw.entry.PrevHash, &raw.entry.Hash,
			&raw.actorNameEnc, &raw.targetNameEnc,
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
		if raw.actorNameEnc != "" {
			e.ActorName, _ = crypto.Decrypt(masterKey, raw.actorNameEnc)
		}
		if raw.targetNameEnc != "" {
			e.TargetName, _ = crypto.Decrypt(masterKey, raw.targetNameEnc)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ActorOption is one entry in the actor filter dropdown: a distinct
// actor_id that has ever appeared in the audit log, plus its resolved name
// where available.
type ActorOption struct {
	ID string `json:"id"`
	// Name is "" when actor_id never matched a users row (an IP-keyed
	// rate-limit entry) or no longer does (the account was since deleted) -
	// callers should fall back to displaying the raw ID in that case.
	Name string `json:"name,omitempty"`
}

// ListActors returns every distinct actor_id seen in the audit log, newest
// activity first is not tracked here - ordered by name (named actors first,
// alphabetically) then by ID, so the filter dropdown groups real accounts
// together ahead of bare IPs/subs from rate-limit entries.
func ListActors(ctx context.Context, pool *db.Pool) ([]ActorOption, error) {
	rows, err := pool.Query(ctx, `
		SELECT actor_id, name FROM (
			SELECT DISTINCT a.actor_id, COALESCE(u.name, '') AS name
			FROM audit_log a
			LEFT JOIN users u ON u.id = a.actor_id
			WHERE a.actor_id <> ''
		) sub
		ORDER BY (name = '') ASC, name ASC, actor_id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("audit: list actors: %w", err)
	}
	defer rows.Close()

	var actors []ActorOption
	for rows.Next() {
		var a ActorOption
		if err := rows.Scan(&a.ID, &a.Name); err != nil {
			return nil, fmt.Errorf("audit: list actors scan: %w", err)
		}
		actors = append(actors, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list actors rows: %w", err)
	}
	return actors, nil
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

// entryHMAC computes HMAC-SHA256 of every stored field (including the
// encrypted actor/target email and details ciphertexts) plus prev_hash.
// Using the master key as the HMAC secret ties the chain to this specific
// instance - even if someone copies the DB to another host with a different
// master key, the hashes will not verify.
//
// actorEmailEnc/targetEmailEnc/detailsEnc were not originally covered here
// (2026-07-23 security pass) - only eventType/actorID/targetID/prevHash
// were. That let anyone able to write directly to the audit_log table
// (compromised DB credentials, a future SQL-injection bug elsewhere)
// silently rewrite the encrypted email/details columns of an existing row
// without Verify's chain-integrity check ever noticing, since the HMAC
// didn't depend on those columns' contents. Including the ciphertexts here
// closes that gap: any edit to them now breaks the stored hash the same way
// editing eventType/actorID/targetID already did.
func entryHMAC(masterKey, eventType, actorID, targetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash string) string {
	mac := hmac.New(sha256.New, []byte(masterKey))
	// hash.Hash.Write (which hmac.New's Writer wraps) is documented to
	// never return an error - safe to discard explicitly rather than
	// thread an error return through a pure hashing helper.
	_, _ = fmt.Fprintf(mac, "%s|%s|%s|%s|%s|%s|%s", eventType, actorID, targetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyResult reports the outcome of walking the whole hash chain.
type VerifyResult struct {
	OK             bool  `json:"ok"`
	EntriesChecked int64 `json:"entries_checked"`
	// BrokenAtID is the id of the first entry whose stored hash does not
	// match its recomputed value, or whose prev_hash does not match the
	// previous entry's hash - 0 if OK is true.
	BrokenAtID int64 `json:"broken_at_id,omitempty"`
}

// Verify walks every audit_log row in insertion order (oldest first) and
// recomputes each entry's HMAC from its own fields and the previous row's
// hash, comparing it against what's stored. Any mismatch - a tampered field,
// a hash edited in place, or a row deleted/inserted out of band - breaks the
// chain from that point forward, since every later entry's prev_hash was
// computed against the untampered original. Read-only: this never writes
// anything, purely a diagnostic for the Security Info page's "verify
// integrity" action.
func Verify(ctx context.Context, pool *db.Pool, masterKey string) (VerifyResult, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, event_type, actor_id, target_id,
		       actor_email_enc, target_email_enc, details_enc, prev_hash, hash
		FROM audit_log
		ORDER BY id ASC
	`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	var (
		checked  int64
		expected string // prev_hash the current row must carry
		first    = true
	)
	for rows.Next() {
		var (
			id                                        int64
			eventType, actorID, targetID              string
			actorEmailEnc, targetEmailEnc, detailsEnc string
			prevHash, hash                            string
		)
		if err := rows.Scan(&id, &eventType, &actorID, &targetID,
			&actorEmailEnc, &targetEmailEnc, &detailsEnc, &prevHash, &hash); err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify scan: %w", err)
		}
		checked++
		if !first && prevHash != expected {
			return VerifyResult{OK: false, EntriesChecked: checked, BrokenAtID: id}, nil
		}
		first = false
		if entryHMAC(masterKey, eventType, actorID, targetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash) != hash {
			return VerifyResult{OK: false, EntriesChecked: checked, BrokenAtID: id}, nil
		}
		expected = hash
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify rows: %w", err)
	}
	return VerifyResult{OK: true, EntriesChecked: checked}, nil
}
