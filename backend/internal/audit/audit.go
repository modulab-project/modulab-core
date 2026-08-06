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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
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
	// EventAuthCountryAnomaly is fired whenever a login or an already-active
	// session is suddenly seen from a CF-IPCountry different from the one
	// last recorded for it - handlers.go's checkAndRecordLoginCountry (a new
	// login, compared against the account's last-known country) and
	// session.go's checkSessionCountryAnomaly (a mid-session request,
	// compared against that session's own sliding baseline) both write this
	// same event type, distinguished by a "source":"login"|"mid_session"
	// field in Details rather than a second constant - both represent the
	// exact same finding ("this credential/token is now being used from
	// somewhere new"), just caught at two different points in a session's
	// lifetime. Previously this only ever produced a live SSE push
	// (internal/notify) and, as of the mail addition alongside this
	// constant, an email to the account owner - neither of which leaves a
	// durable, admin-reviewable trail the way every other security-relevant
	// event here does. ActorID/TargetID are both the affected user's own
	// subject - there is no separate "actor" here, the account is acting on
	// itself, same reasoning as EventUserSelfDeleted.
	EventAuthCountryAnomaly = "auth.country_anomaly"
	// EventAuthDeviceAnomaly is session.go's checkSessionDeviceAnomaly's
	// counterpart to EventAuthCountryAnomaly above - same "this
	// credential/token is now being used from somewhere new" finding, but
	// via a User-Agent mismatch instead of a CF-IPCountry one. Kept as its
	// own constant rather than reusing EventAuthCountryAnomaly with a
	// different Details.source: an admin filtering the audit log by event
	// type should be able to tell "new country" and "new device" trails
	// apart without parsing Details first. There is no login-time
	// equivalent of this one (unlike EventAuthCountryAnomaly, which also
	// fires from CallbackHandler) - a brand-new login always starts a
	// brand-new session with no device baseline yet, so there is nothing to
	// compare against until at least one mid-session request has run.
	EventAuthDeviceAnomaly = "auth.device_anomaly"
	// EventAuthLoginFailed covers the security-relevant ways CallbackHandler
	// (handlers.go) can end a login attempt without issuing a session:
	// nonce_mismatch, exchange_failed (both pre-authentication - Core does
	// not yet know who this was, so ActorID is the client IP, same "bucketed
	// by IP" treatment EventRateLimitExceeded's doc comment already
	// describes), and access_denied (the IdP authenticated them, but they
	// are not a member of any of the three configured groups - ActorID/
	// ActorEmail are the subject/email in that one case, since Core does
	// know who this was). Deliberately does NOT cover missing_state_or_code/
	// invalid_or_expired_state/provider_unavailable/group_prefix_unavailable/
	// server_error - the first two are high-volume and low-signal (a user
	// simply took too long on the IdP's own login page, or double-clicked
	// back), and the rest are infrastructure faults rather than anything
	// about the login attempt itself. Details carries "reason" (one of the
	// codes above) plus the same country/asn_org/hosting_or_vpn context
	// EventAuthLogin's Details carries below, so a burst of failures from
	// one country/network is discoverable the same way a successful
	// anomaly already is.
	EventAuthLoginFailed = "auth.login_failed"
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
	EventConfigGeoIP         = "config.geoip"
	EventConfigGeoIPDel      = "config.geoip.deleted"
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
	// System language + instance identity (adminapi.AdminGeneralHandler,
	// GET/PATCH /v1/admin/system/general) - the "Sprache & Region" /
	// "Instanz-Identität" settings page. Neither field is secret (see
	// mail.Branding's doc comment), but both are worth a durable trail same
	// as EventConfigSystemLimits: a language change silently reshapes every
	// outgoing system mail from that point on, and an instance rename shows
	// up in every one of them too.
	EventConfigSystemGeneral = "config.system_general"
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
	// Module lifecycle events (admin driven, spec section
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
	// EventModuleEgressDenied is the one module event with no admin actor
	// behind it: a running Tier 2/3 worker asked Core to grant it network
	// access to a host outside its manifest's dynamic_egress_allow, and Core
	// refused (see modules/egresspolicy.go). Audited rather than only logged
	// because the two cases it covers are far apart in severity - a manifest
	// that needs one more host, versus a module deliberately reaching past
	// the bound it declared at install time - and telling them apart later
	// needs a durable record with a timestamp, not a container log line that
	// has since rotated away. ActorID is left empty: the "actor" is module
	// code, not a user.
	EventModuleEgressDenied = "module.egress_denied"
	// EventGeoIPDownloadSucceeded/Failed cover internal/geoip's daily
	// database refresh (RunScheduler) and the immediate one-off triggered
	// right after an admin saves new credentials (TriggerNow) - same "no
	// human actor behind an automatic background action" shape as
	// EventModuleEgressDenied above: ActorID/ActorEmail are left empty, the
	// only thing worth recording is what happened and why. Audited (not
	// just log.Printf'd, which internal/geoip already also does) because a
	// silently-failing daily download is otherwise invisible anywhere an
	// admin would think to look - core_settings' geoip_last_update_error
	// value (surfaced on the GeoIP settings page) already answers "is it
	// broken right now", but not "when did it start failing, and did it
	// ever recover in between" the way a durable, timestamped audit trail
	// does.
	EventGeoIPDownloadSucceeded = "geoip.download_succeeded"
	EventGeoIPDownloadFailed    = "geoip.download_failed"
	// EventModulePIIKeyMigrated marks the one-time admin action that asks a
	// module's own migrate-pii-key handler to re-encrypt its PII columns
	// (and, where applicable, blind-index hashes) under its HKDF-derived
	// per-module key and retire the legacy shared MODULAB_MODULE_PII_KEY
	// grant. See docs/Modul-DB-Sandbox_Plan_2026-08-02.md Part B - this is
	// the only PII-bearing action gated by adminReauthOnly instead of the
	// regular RequireAdminSession check, same tier as revoking a session.
	EventModulePIIKeyMigrated = "module.pii_key_migrated"
	// Feed management (admin), internal/news.
	EventFeedCreated = "feed.created"
	EventFeedUpdated = "feed.updated"
	EventFeedDeleted = "feed.deleted"
	// Global news display settings (PATCH /v1/admin/news/settings:
	// news_max_articles, news_home_count, news_show_images) - same category
	// of cross-cutting config mutation as EventConfigSystemLimits/
	// EventConfigAISettings above, both of which are audited; this one was
	// simply missed when feed CRUD got its audit calls.
	EventNewsSettings = "config.news_settings"
	// Quick-link management (admin), internal/quicklinks.
	EventQuickLinkCreated = "quicklink.created"
	EventQuickLinkUpdated = "quicklink.updated"
	EventQuickLinkDeleted = "quicklink.deleted"
	// Manual Module Store registry sync trigger, internal/store.
	EventStoreSyncTriggered = "store.sync_triggered"
	// Custom module source management. Admin-only since 2026-07-22
	// (elevated alongside adding the step-up reauth gate on update/delete
	// below: a GitHub token plus the ability to point Core at arbitrary
	// third-party code is a higher-value target than typical config
	// change). Details includes
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

// auditChainLockKey is the fixed pg_advisory_xact_lock key used to serialize
// every audit_log write across the whole instance (see Log's doc comment on
// the race this closes). Derived from a stable string rather than a literal
// magic number so its origin is obvious to anyone grepping the DB logs for
// this lock ID; the truncation to int64 is safe/expected for
// pg_advisory_xact_lock's bigint key parameter.
var auditChainLockKey = func() int64 {
	sum := sha256.Sum256([]byte("audit_log_chain"))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}()

// Log appends one entry to the audit log. It reads the last entry's hash to
// build the chain link, then encrypts PII and writes the new row atomically.
// Best-effort from the caller's perspective: if Log fails, the admin action
// itself should not be rolled back - callers log the error and continue.
//
// The prev_hash read and the INSERT run inside one transaction, additionally
// serialized by pg_advisory_xact_lock(auditChainLockKey): without this, two
// concurrent Log calls (e.g. two admins acting at the same instant) could
// each read the same latestHash() before either had inserted, then both
// write rows claiming that same prev_hash - a real, if narrow, hash-chain
// race. The advisory lock is instance-wide (one fixed key, not per-row), so
// audit writes are already infrequent enough for this to add no meaningful
// contention; pg_advisory_xact_lock auto-releases at COMMIT/ROLLBACK, no
// separate unlock call needed.
func Log(ctx context.Context, pool *db.Pool, masterKey string, p LogParams) error {
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

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() {
		// No-op if the transaction was already committed below - Rollback on
		// an already-committed/closed tx returns pgx.ErrTxClosed, which is
		// expected here and not worth surfacing.
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return fmt.Errorf("audit: advisory lock: %w", err)
	}

	var prevHash string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("audit: read prev_hash: %w", err)
	}

	// Compute this entry's hash over all fields plus prev_hash, using the
	// master key as the HMAC secret so the chain is tied to this instance.
	h := entryHMAC(masterKey, p.EventType, p.ActorID, p.TargetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash)

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log
		    (event_type, actor_id, actor_email_enc, target_id, target_email_enc,
		     details_enc, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, p.EventType, p.ActorID, actorEmailEnc,
		p.TargetID, targetEmailEnc, detailsEnc, prevHash, h); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
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

	const decryptFailedMarker = "<decryption failed>"

	entries := make([]Entry, 0, len(raws))
	for _, raw := range raws {
		e := raw.entry
		var err error
		if e.ActorEmail, err = crypto.Decrypt(masterKey, raw.actorEmailEnc); err != nil {
			log.Printf("audit: decrypt failed for row id=%v field=actor_email: %v", e.ID, err)
			e.ActorEmail = decryptFailedMarker
		}
		if raw.targetEmailEnc != "" {
			if e.TargetEmail, err = crypto.Decrypt(masterKey, raw.targetEmailEnc); err != nil {
				log.Printf("audit: decrypt failed for row id=%v field=target_email: %v", e.ID, err)
				e.TargetEmail = decryptFailedMarker
			}
		}
		if raw.detailsEnc != "" {
			if e.Details, err = crypto.Decrypt(masterKey, raw.detailsEnc); err != nil {
				log.Printf("audit: decrypt failed for row id=%v field=details: %v", e.ID, err)
				e.Details = decryptFailedMarker
			}
		}
		if raw.actorNameEnc != "" {
			if e.ActorName, err = crypto.Decrypt(masterKey, raw.actorNameEnc); err != nil {
				log.Printf("audit: decrypt failed for row id=%v field=actor_name: %v", e.ID, err)
				e.ActorName = decryptFailedMarker
			}
		}
		if raw.targetNameEnc != "" {
			if e.TargetName, err = crypto.Decrypt(masterKey, raw.targetNameEnc); err != nil {
				log.Printf("audit: decrypt failed for row id=%v field=target_name: %v", e.ID, err)
				e.TargetName = decryptFailedMarker
			}
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
func ListActors(ctx context.Context, pool *db.Pool, masterKey string) ([]ActorOption, error) {
	// users.name is stored encrypted at rest (see internal/db's users-table
	// migration), so the raw SQL result here is ciphertext, not a name -
	// unlike queryPage's actor_name resolution, this used to be returned
	// (and sorted on) without ever calling crypto.Decrypt, so the dropdown
	// showed the encrypted blob instead of the account's display name for
	// every actor that resolved to a real user. Sorting also has to happen
	// in Go, after decryption - sorting ciphertext alphabetically is
	// meaningless.
	// Bounded to the last 90 days (H-3, performance review 2026-08): without
	// this, ListActors was a full table scan of the whole audit_log history
	// on every load of the admin audit-log page's actor filter dropdown - a
	// distinct-actor list only needs to be "who has acted recently", not
	// every actor ever recorded since day one. idx_audit_log_created_at
	// (db.go's EnsureAuditSchema) makes this an index-range scan instead of
	// a full scan.
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT a.actor_id, COALESCE(u.name, '') AS name_enc
		FROM audit_log a
		LEFT JOIN users u ON u.id = a.actor_id
		WHERE a.actor_id <> '' AND a.created_at > now() - interval '90 days'
	`)
	if err != nil {
		return nil, fmt.Errorf("audit: list actors: %w", err)
	}
	defer rows.Close()

	var actors []ActorOption
	for rows.Next() {
		var a ActorOption
		var nameEnc string
		if err := rows.Scan(&a.ID, &nameEnc); err != nil {
			return nil, fmt.Errorf("audit: list actors scan: %w", err)
		}
		if nameEnc != "" {
			var err error
			if a.Name, err = crypto.Decrypt(masterKey, nameEnc); err != nil {
				log.Printf("audit: decrypt failed for actor_id=%s field=name: %v", a.ID, err)
				a.Name = "<decryption failed>"
			}
		}
		actors = append(actors, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list actors rows: %w", err)
	}
	sort.Slice(actors, func(i, j int) bool {
		if (actors[i].Name == "") != (actors[j].Name == "") {
			return actors[i].Name != "" // named actors first
		}
		if actors[i].Name != actors[j].Name {
			return actors[i].Name < actors[j].Name
		}
		return actors[i].ID < actors[j].ID
	})
	return actors, nil
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

// legacyEntryHMAC reproduces the pre-2026-07-23 HMAC formula (eventType/
// actorID/targetID/prevHash only, no ciphertext fields). Every entry written
// before that security pass (see entryHMAC's doc comment) was hashed this
// way, so Verify must still be able to recognize them as valid - otherwise
// every pre-existing audit_log row, including entry #1, permanently reads as
// "chain broken" even though nothing was tampered with. Rows can't be
// re-hashed in place to close this gap properly: audit_log's whole point is
// that nothing, including an internal migration, silently rewrites a stored
// hash after the fact. New entries are unaffected - Log always uses the
// current (wider) entryHMAC.
func legacyEntryHMAC(masterKey, eventType, actorID, targetID, prevHash string) string {
	mac := hmac.New(sha256.New, []byte(masterKey))
	_, _ = fmt.Fprintf(mac, "%s|%s|%s|%s", eventType, actorID, targetID, prevHash)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyResult reports the outcome of walking the hash chain.
type VerifyResult struct {
	OK             bool  `json:"ok"`
	EntriesChecked int64 `json:"entries_checked"`
	// BrokenAtID is the id of the first entry whose stored hash does not
	// match its recomputed value, or whose prev_hash does not match the
	// previous entry's hash - 0 if OK is true.
	BrokenAtID int64 `json:"broken_at_id,omitempty"`
	// Complete is true if every row in audit_log was examined (i.e. the
	// table has fewer rows than the limit Verify was called with), false if
	// the walk stopped early after hitting that limit. A caller that gets
	// Complete: false and OK: true should not read that as "the whole chain
	// is intact" - only the first EntriesChecked rows were actually checked.
	Complete bool `json:"complete"`
}

// defaultVerifyLimit is the row cap Verify uses when called with limit <= 0.
// Verify reads and HMAC-recomputes every row up to this cap in a single
// request/response cycle (H-3, performance review 2026-08) - unbounded, this
// was a full-table read-and-recompute per call with no pagination, which at
// large enough audit_log sizes could tie up the request (and the connection
// serving it) for a long time. 50,000 rows keeps a single Verify call fast
// at any realistic homelab-scale audit_log size while still covering years
// of typical activity in one pass; a caller that legitimately has more than
// that can re-run Verify starting from BrokenAtID's neighborhood, or this
// can grow a real cursor-based continuation later if that ever becomes
// necessary — deliberately not built now, see this fix's own review notes.
const defaultVerifyLimit = 50_000

// Verify walks up to limit audit_log rows in insertion order (oldest first)
// and recomputes each entry's HMAC from its own fields and the previous
// row's hash, comparing it against what's stored. Any mismatch - a tampered
// field, a hash edited in place, or a row deleted/inserted out of band -
// breaks the chain from that point forward, since every later entry's
// prev_hash was computed against the untampered original. Read-only: this
// never writes anything, purely a diagnostic for the Security Info page's
// "verify integrity" action.
//
// limit <= 0 falls back to defaultVerifyLimit. See VerifyResult.Complete for
// how a caller tells a full walk apart from one that stopped at the limit.
func Verify(ctx context.Context, pool *db.Pool, masterKey string, limit int64) (VerifyResult, error) {
	if limit <= 0 {
		limit = defaultVerifyLimit
	}
	// Ask for one row more than limit so we can tell "exactly limit rows in
	// the table" (Complete: true) apart from "more than limit rows, stopped
	// early" (Complete: false) without a separate COUNT(*) round-trip.
	rows, err := pool.Query(ctx, `
		SELECT id, event_type, actor_id, target_id,
		       actor_email_enc, target_email_enc, details_enc, prev_hash, hash
		FROM audit_log
		ORDER BY id ASC
		LIMIT $1
	`, limit+1)
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
		if checked >= limit {
			// This is the "one extra row" fetched above - its presence means
			// the table has more rows than limit, so the walk is incomplete.
			// Stop without examining it (it hasn't been chain-verified).
			return VerifyResult{OK: true, EntriesChecked: checked, Complete: false}, nil
		}
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
			return VerifyResult{OK: false, EntriesChecked: checked, BrokenAtID: id, Complete: false}, nil
		}
		first = false
		// Try the current formula first (covers every entry written since
		// the 2026-07-23 security pass, i.e. virtually all of them at
		// steady state); fall back to the pre-pass formula so legitimate
		// older rows aren't flagged as tampered - see legacyEntryHMAC's doc
		// comment.
		if entryHMAC(masterKey, eventType, actorID, targetID, actorEmailEnc, targetEmailEnc, detailsEnc, prevHash) != hash &&
			legacyEntryHMAC(masterKey, eventType, actorID, targetID, prevHash) != hash {
			return VerifyResult{OK: false, EntriesChecked: checked, BrokenAtID: id, Complete: false}, nil
		}
		expected = hash
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify rows: %w", err)
	}
	return VerifyResult{OK: true, EntriesChecked: checked, Complete: true}, nil
}
