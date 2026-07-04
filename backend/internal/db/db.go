// Package db wraps a Postgres connection pool (pgx) and provides the
// minimal key/value access Core needs for its own bootstrap state
// (core_settings), the users table populated by OIDC JIT provisioning
// (spec section 3.3), and module bookkeeping (installed_modules). Module
// schemas and per-module roles (spec section 4.3) are handled elsewhere,
// once the module installation pipeline lands.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// Pool wraps *pgxpool.Pool so Core-specific helper methods can be attached
// without polluting the pgx API surface everywhere it's used.
// masterKey is the AES-256 master key used to encrypt/decrypt all PII stored
// in the users table (email, name) transparently - callers pass and receive
// plaintext; the encrypt/decrypt happens inside each method.
type Pool struct {
	*pgxpool.Pool
	masterKey string
}

// Connect opens a pooled connection to Postgres and verifies it is reachable.
// masterKey is the AES-256 hex key (MODULAB_MASTER_KEY) used to encrypt/
// decrypt user PII transparently in UpsertUser, GetUser, ListUsers, and
// ListAdmins - the same key that protects OIDC/SMTP/DNS secrets in
// core_settings.
func Connect(ctx context.Context, dsn, masterKey string) (*Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{Pool: pool, masterKey: masterKey}, nil
}

// EnsureCoreSchema creates Core's bootstrap tables if they do not exist yet.
// This is the schema mechanism for the whole project (see "Schema changes"
// in the README): every future additive change (new column/table/index)
// is added here as another idempotent statement, so a running instance
// picks it up automatically on its next boot - no separate migration
// tool or step to run.
func (p *Pool) EnsureCoreSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS core_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure core_settings: %w", err)
	}

	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS installed_modules (
			name TEXT PRIMARY KEY,
			version TEXT NOT NULL,
			tier SMALLINT NOT NULL CHECK (tier IN (1, 2, 3)),
			scope TEXT NOT NULL CHECK (scope IN ('per-location', 'cross-location')),
			status TEXT NOT NULL DEFAULT 'installing' CHECK (status IN ('installing', 'active', 'degraded', 'failed', 'isolated')),
			installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules: %w", err)
	}
	// status had no CHECK constraint at all before this (unlike tier/scope
	// right above it in the same table) despite the ModuleStatus* constants
	// below implying one always existed - CREATE TABLE IF NOT EXISTS above
	// is a no-op against any database that already has this table, so an
	// existing deployment needs this added separately. Postgres has no
	// ADD CONSTRAINT IF NOT EXISTS, hence the pg_constraint check (same
	// pattern as EnsureAuditSchema's trigger check below).
	if _, err := p.Exec(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conname = 'installed_modules_status_check'
				  AND conrelid = 'installed_modules'::regclass
			) THEN
				ALTER TABLE installed_modules
					ADD CONSTRAINT installed_modules_status_check
					CHECK (status IN ('installing', 'active', 'degraded', 'failed', 'isolated'));
			END IF;
		END $$
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.status check: %w", err)
	}

	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL CHECK (role IN ('super-admin', 'org-admin', 'user', 'pending')),
			approved BOOLEAN NOT NULL DEFAULT false,
			locked BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure users: %w", err)
	}

	// approved, name, and locked were all added after the table itself -
	// CREATE TABLE IF NOT EXISTS above is a no-op against an
	// already-existing table from before any of them existed, so separate
	// idempotent ALTERs are needed to pick them up on an upgrade rather than
	// just on a fresh database.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN NOT NULL DEFAULT false
	`); err != nil {
		return fmt.Errorf("db: ensure users.approved: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure users.name: %w", err)
	}
	// locked is independent of approved: approved = false means "never let
	// in yet" (CallbackHandler's gate 2, /pending screen); locked = true
	// means "was let in before, an admin has since revoked that" - kept as
	// its own column rather than reusing approved so a deliberately locked
	// user does not get visually indistinguishable from a brand-new
	// pending signup in the admin user list.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT false
	`); err != nil {
		return fmt.Errorf("db: ensure users.locked: %w", err)
	}
	// ui_language stores the user's preferred UI locale ("en" or "de").
	// Plaintext — it is not PII (just a locale code) and therefore does not
	// need GCM encryption. Empty string means "use browser default".
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS ui_language TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure users.ui_language: %w", err)
	}

	if err := p.EnsureNewsSchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureAISchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureQuickLinksSchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureAuditSchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureModuleStoreSchema(ctx); err != nil {
		return err
	}

	return nil
}

// EnsureAuditSchema creates the audit_log table and its immutable-row trigger
// if they do not exist yet. Called from EnsureCoreSchema so a fresh instance
// has the table on first boot without running a separate migration step.
func (p *Pool) EnsureAuditSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_log (
			id               BIGSERIAL   PRIMARY KEY,
			created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			event_type       TEXT        NOT NULL,
			actor_id         TEXT        NOT NULL,
			actor_email_enc  TEXT        NOT NULL,
			target_id        TEXT        NOT NULL DEFAULT '',
			target_email_enc TEXT        NOT NULL DEFAULT '',
			details_enc      TEXT        NOT NULL DEFAULT '',
			prev_hash        TEXT        NOT NULL DEFAULT '',
			hash             TEXT        NOT NULL DEFAULT ''
		)
	`); err != nil {
		return fmt.Errorf("db: ensure audit_log: %w", err)
	}

	// audit.List (internal/audit/audit.go) filters "WHERE event_type = $1 AND
	// id < $2 ORDER BY id DESC" for the admin audit-log page's per-type,
	// keyset-paginated view - without this index that query does a full
	// table scan once audit_log grows past a trivial size. id itself is
	// already indexed via the BIGSERIAL PRIMARY KEY, so the composite index
	// here only needs to lead with event_type; Postgres can use the same
	// index for the event_type-only query too (no filter on id).
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_audit_log_event_type_id ON audit_log (event_type, id DESC)
	`); err != nil {
		return fmt.Errorf("db: ensure idx_audit_log_event_type_id: %w", err)
	}

	// Trigger function: raises an exception on any UPDATE or DELETE attempt.
	// CREATE OR REPLACE is idempotent so safe to run on every boot.
	if _, err := p.Exec(ctx, `
		CREATE OR REPLACE FUNCTION audit_log_immutable()
		RETURNS TRIGGER LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'audit_log rows are immutable and cannot be modified or deleted';
		END;
		$$
	`); err != nil {
		return fmt.Errorf("db: ensure audit_log_immutable fn: %w", err)
	}

	// CREATE TRIGGER does not have IF NOT EXISTS before PG 17, so use a
	// DO block that checks pg_trigger and skips the CREATE if it already
	// exists — fully idempotent on PG 14+ (the minimum supported version).
	if _, err := p.Exec(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgname = 'audit_log_before_change'
				  AND tgrelid = 'audit_log'::regclass
			) THEN
				CREATE TRIGGER audit_log_before_change
					BEFORE UPDATE OR DELETE ON audit_log
					FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
			END IF;
		END $$
	`); err != nil {
		return fmt.Errorf("db: ensure audit_log trigger: %w", err)
	}

	return nil
}

// GetSetting returns the stored value for key and whether it was present.
func (p *Pool) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := p.QueryRow(ctx, `SELECT value FROM core_settings WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("db: get setting %q: %w", key, err)
	}
	return value, true, nil
}

// SetSetting upserts key/value into core_settings.
func (p *Pool) SetSetting(ctx context.Context, key, value string) error {
	_, err := p.Exec(ctx, `
		INSERT INTO core_settings (key, value, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, key, value)
	if err != nil {
		return fmt.Errorf("db: set setting %q: %w", key, err)
	}
	return nil
}

// DeleteSetting removes key from core_settings, if present. Unlike
// SetSetting(key, "") - which would leave the row in place with an empty
// value, so GetSetting/SMTPConfigured-style "exists" checks would still
// report it as configured - this is a real delete, used by
// setup.SMTPDeleteHandler so an admin can clear SMTP configuration back
// to "not configured" rather than only ever being able to overwrite it
// with different values.
func (p *Pool) DeleteSetting(ctx context.Context, key string) error {
	_, err := p.Exec(ctx, `DELETE FROM core_settings WHERE key = $1`, key)
	if err != nil {
		return fmt.Errorf("db: delete setting %q: %w", key, err)
	}
	return nil
}

// UpsertUser inserts a new user row keyed by OIDC subject, or updates the
// existing one's email, name, role, and last_login_at if the subject was
// already known. Called once per successful OIDC login (spec section 3.3's
// JIT provisioning) - there is no separate "create account" step.
//
// name is kept fresh on every login (unlike approved, below) - it exists
// purely so an admin reviewing approved = false rows can tell who someone
// is without the email address always making that obvious, so there is no
// reason to prefer a stale value over whatever the IdP reports now.
//
// approved is only ever written on the INSERT branch - deliberately absent
// from the ON CONFLICT ... DO UPDATE SET clause below, so a later login by
// an already-known user can never silently reset whatever an admin (or the
// bootstrap/wizard flow) previously set it to. Callers pass the value they
// want a brand-new row to start with; for an existing row it is ignored.
// locked has no equivalent parameter here: a brand-new row is never
// locked (the column's own DEFAULT false covers it), and like approved it
// must never be reset by a later login either - LockUser/UnlockUser below
// are the only things that ever change it after creation.
//
// wasNew reports whether this call created a brand-new row, as opposed to
// updating an existing one - CallbackHandler (handlers.go) uses this to
// decide whether to fire spec section 3.5's "new pending user" admin
// notification: without it, every subsequent login attempt by a user
// who is still waiting on approval would re-notify admins, not just their
// very first one. Determined with a separate existence check rather than a
// single RETURNING-based trick (e.g. "xmax = 0"), to keep this readable
// for anyone not already fluent in Postgres's MVCC internals - the
// existence check and the upsert are not wrapped in an explicit
// transaction, so there is in principle a race between the two queries
// under concurrent logins by the same brand-new subject, but the
// consequence of losing it is "admins get notified about this signup
// twice", never an incorrect approved/locked value - an acceptable risk
// for a homelab-scale, single-instance deployment.
func (p *Pool) UpsertUser(ctx context.Context, subject, email, name, role string, approved bool) (wasNew bool, err error) {
	var existed bool
	if err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, subject).Scan(&existed); err != nil {
		return false, fmt.Errorf("db: check existing user %q: %w", subject, err)
	}

	encEmail, err := crypto.EncryptIfNotEmpty(p.masterKey, email)
	if err != nil {
		return false, fmt.Errorf("db: encrypt email for %q: %w", subject, err)
	}
	encName, err := crypto.EncryptIfNotEmpty(p.masterKey, name)
	if err != nil {
		return false, fmt.Errorf("db: encrypt name for %q: %w", subject, err)
	}

	_, err = p.Exec(ctx, `
		INSERT INTO users (id, email, name, role, approved, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			role = EXCLUDED.role,
			last_login_at = now()
	`, subject, encEmail, encName, role, approved)
	if err != nil {
		return false, fmt.Errorf("db: upsert user %q: %w", subject, err)
	}
	return !existed, nil
}

// GetUser returns the single user row for subject (exists = false, not an
// error, if no such row). Added alongside the mail-on-approve/lock/unlock
// notifications (admin.go) - those need the target's email address, which
// none of the narrower existing lookups (UserApproved/UserLocked/UserRole)
// expose; reuses UserRow rather than introducing a second per-user struct.
func (p *Pool) GetUser(ctx context.Context, subject string) (UserRow, bool, error) {
	var u UserRow
	err := p.QueryRow(ctx, `
		SELECT id, email, name, role, approved, locked, created_at, last_login_at
		FROM users WHERE id = $1
	`, subject).Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRow{}, false, nil
		}
		return UserRow{}, false, fmt.Errorf("db: get user %q: %w", subject, err)
	}
	if u.Email, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Email); err != nil {
		return UserRow{}, false, fmt.Errorf("db: decrypt email for %q: %w", subject, err)
	}
	if u.Name, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Name); err != nil {
		return UserRow{}, false, fmt.Errorf("db: decrypt name for %q: %w", subject, err)
	}
	return u, true, nil
}

// UserApproved reports whether subject's user row has approved = true. A
// subject with no row at all (never logged in before) reports false, not
// an error - from CallbackHandler's perspective "unknown" and "known but
// not yet approved" require exactly the same response (RolePending), so
// there is no need for callers to distinguish the two.
func (p *Pool) UserApproved(ctx context.Context, subject string) (bool, error) {
	var approved bool
	err := p.QueryRow(ctx, `SELECT approved FROM users WHERE id = $1`, subject).Scan(&approved)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("db: check approval for %q: %w", subject, err)
	}
	return approved, nil
}

// UserLocked reports whether subject's user row has locked = true. Like
// UserApproved, a subject with no row at all reports false rather than an
// error - someone who has never logged in cannot be locked.
func (p *Pool) UserLocked(ctx context.Context, subject string) (bool, error) {
	var locked bool
	err := p.QueryRow(ctx, `SELECT locked FROM users WHERE id = $1`, subject).Scan(&locked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("db: check lock state for %q: %w", subject, err)
	}
	return locked, nil
}

// UserRole returns subject's current role and whether a row exists at all -
// used by the admin lock/delete handlers to decide whether the target is a
// super-admin before allowing an action that could otherwise strand the
// instance with zero super-admins.
func (p *Pool) UserRole(ctx context.Context, subject string) (string, bool, error) {
	var role string
	err := p.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, subject).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("db: get role for %q: %w", subject, err)
	}
	return role, true, nil
}

// HasSuperAdmin reports whether at least one user with role 'super-admin'
// exists. Used by setup.CompleteHandler to verify the wizard's step 6
// (spec section 6.5: "Super-Admin binden") actually succeeded before
// allowing step 7 to invalidate the bootstrap token - a user merely
// attempting login is not enough, since spec section 3.3's Dynamic Prefix
// Hard Gate can still leave them as RolePending.
func (p *Pool) HasSuperAdmin(ctx context.Context) (bool, error) {
	var exists bool
	err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE role = 'super-admin')`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("db: check super-admin existence: %w", err)
	}
	return exists, nil
}

// SuperAdminCount returns how many user rows currently have role =
// 'super-admin', regardless of approved/locked state. Used by the admin
// lock/delete handlers' last-super-admin guard - unlike HasSuperAdmin
// (a yes/no check used once during setup), this needs the actual count to
// tell "locking/deleting this one is fine, there are others" apart from
// "this is the only one left".
func (p *Pool) SuperAdminCount(ctx context.Context) (int, error) {
	var count int
	err := p.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'super-admin'`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: count super-admins: %w", err)
	}
	return count, nil
}

// UserRow is one row of the full user list (ListUsers) - every column an
// admin needs to decide what action (approve / lock / unlock / delete)
// applies to this person.
type UserRow struct {
	Subject     string
	Email       string
	Name        string
	Role        string
	Approved    bool
	Locked      bool
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// ListUsers returns every user row, oldest first. Unlike the narrower
// ListPendingUsers this replaces, this includes already-approved and
// locked users too - the admin frontend derives a single status (Pending /
// Active / Locked) per row from Approved+Locked itself, rather than this
// method pre-filtering, so there is exactly one place an admin needs to
// look to manage anyone.
func (p *Pool) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, email, name, role, approved, locked, created_at, last_login_at
		FROM users
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list users: %w", err)
	}
	defer rows.Close()

	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, fmt.Errorf("db: scan user: %w", err)
		}
		var err error
		if u.Email, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Email); err != nil {
			return nil, fmt.Errorf("db: decrypt email for %q: %w", u.Subject, err)
		}
		if u.Name, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Name); err != nil {
			return nil, fmt.Errorf("db: decrypt name for %q: %w", u.Subject, err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: list users: %w", err)
	}
	return out, nil
}

// ListAdmins returns every user row with role org-admin or super-admin,
// oldest first - used by CallbackHandler (handlers.go) to email every
// current admin when a brand-new pending signup needs review, alongside
// the "user.pending" SSE event (notify.AdminChannel) it already
// publishes: SSE only reaches whoever happens to be connected at that
// exact moment, mail still reaches everyone else afterwards.
func (p *Pool) ListAdmins(ctx context.Context) ([]UserRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, email, name, role, approved, locked, created_at
		FROM users
		WHERE role IN ('org-admin', 'super-admin')
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list admins: %w", err)
	}
	defer rows.Close()

	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan admin: %w", err)
		}
		var err error
		if u.Email, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Email); err != nil {
			return nil, fmt.Errorf("db: decrypt email for %q: %w", u.Subject, err)
		}
		if u.Name, err = crypto.DecryptIfNotEmpty(p.masterKey, u.Name); err != nil {
			return nil, fmt.Errorf("db: decrypt name for %q: %w", u.Subject, err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: list admins: %w", err)
	}
	return out, nil
}

// ApproveUser sets approved = true for subject and reports how many rows
// were affected, so the caller (ApproveUserHandler) can tell "approved"
// apart from "no such user" (0 rows) without a separate existence check.
// Takes effect on that user's next login, not retroactively on any session
// they may already be holding - see role.go's doc comment on RolePending
// for why CallbackHandler never revisits an already-issued session.
func (p *Pool) ApproveUser(ctx context.Context, subject string) (int64, error) {
	tag, err := p.Exec(ctx, `UPDATE users SET approved = true WHERE id = $1`, subject)
	if err != nil {
		return 0, fmt.Errorf("db: approve user %q: %w", subject, err)
	}
	return tag.RowsAffected(), nil
}

// LockUser sets locked = true for subject. Unlike ApproveUser, this is not
// the only thing that needs to happen for the lock to take effect right
// away: LockUserHandler (admin.go) additionally calls
// auth.RevokeUserSessions after this succeeds, so a session already
// issued before this call stops working on its very next request instead
// of staying valid until it naturally expires. This method itself only
// ever touches the database row - the immediate-effect part lives
// entirely in the handler, since this package has no reason to know about
// Valkey sessions at all.
func (p *Pool) LockUser(ctx context.Context, subject string) (int64, error) {
	tag, err := p.Exec(ctx, `UPDATE users SET locked = true WHERE id = $1`, subject)
	if err != nil {
		return 0, fmt.Errorf("db: lock user %q: %w", subject, err)
	}
	return tag.RowsAffected(), nil
}

// UnlockUser sets locked = false for subject, restoring whatever role/
// approved state they already had - unlike approving a brand-new pending
// user, unlocking does not need a separate "what role should they get"
// decision, since locking never touched role or approved in the first
// place.
func (p *Pool) UnlockUser(ctx context.Context, subject string) (int64, error) {
	tag, err := p.Exec(ctx, `UPDATE users SET locked = false WHERE id = $1`, subject)
	if err != nil {
		return 0, fmt.Errorf("db: unlock user %q: %w", subject, err)
	}
	return tag.RowsAffected(), nil
}

// DeleteUser removes subject's row entirely. There is no soft-delete flag
// to check elsewhere afterwards: if this person logs in again later, JIT
// provisioning (UpsertUser) just creates a brand-new row for them, exactly
// like someone who has never logged in before - deleting does not
// blocklist the OIDC subject itself, it only forgets Core's own approval/
// lock history for them.
func (p *Pool) DeleteUser(ctx context.Context, subject string) (int64, error) {
	tag, err := p.Exec(ctx, `DELETE FROM users WHERE id = $1`, subject)
	if err != nil {
		return 0, fmt.Errorf("db: delete user %q: %w", subject, err)
	}
	return tag.RowsAffected(), nil
}

// GetUserLanguage returns the stored UI language preference for userID, or ""
// when no preference has been saved yet. Callers treat "" as "browser default".
func (p *Pool) GetUserLanguage(ctx context.Context, userID string) (string, error) {
	var lang string
	err := p.QueryRow(ctx, `SELECT ui_language FROM users WHERE id = $1`, userID).Scan(&lang)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("db: get ui_language for %q: %w", userID, err)
	}
	return lang, nil
}

// SetUserLanguage persists the UI language preference for userID. Only "en"
// and "de" are accepted; any other value is stored as "" (reset to default).
func (p *Pool) SetUserLanguage(ctx context.Context, userID, lang string) error {
	if lang != "en" && lang != "de" {
		lang = ""
	}
	_, err := p.Exec(ctx, `UPDATE users SET ui_language = $1 WHERE id = $2`, lang, userID)
	if err != nil {
		return fmt.Errorf("db: set ui_language for %q: %w", userID, err)
	}
	return nil
}

// UserExportRow collects all personal data stored for one user — used by the
// DSGVO data-export endpoint (GET /v1/auth/me/export). All encrypted fields
// are returned as plaintext (already decrypted by this method).
type UserExportRow struct {
	Subject     string
	Email       string
	Name        string
	Role        string
	Approved    bool
	Locked      bool
	UILanguage  string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// GetUserExportRow returns the DSGVO export row for userID, decrypting PII.
func (p *Pool) GetUserExportRow(ctx context.Context, userID string) (UserExportRow, bool, error) {
	var u UserExportRow
	err := p.QueryRow(ctx, `
		SELECT id, email, name, role, approved, locked, ui_language, created_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked,
		&u.UILanguage, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserExportRow{}, false, nil
		}
		return UserExportRow{}, false, fmt.Errorf("db: get user export row %q: %w", userID, err)
	}
	var decErr error
	if u.Email, decErr = crypto.DecryptIfNotEmpty(p.masterKey, u.Email); decErr != nil {
		return UserExportRow{}, false, fmt.Errorf("db: decrypt email for export %q: %w", userID, decErr)
	}
	if u.Name, decErr = crypto.DecryptIfNotEmpty(p.masterKey, u.Name); decErr != nil {
		return UserExportRow{}, false, fmt.Errorf("db: decrypt name for export %q: %w", userID, decErr)
	}
	return u, true, nil
}

// ---- News feeds -------------------------------------------------------------

// FeedRow is one row of the news_feeds table.
type FeedRow struct {
	ID        int
	URL       string
	Label     string
	CreatedAt time.Time
}

// FeedWithSub pairs a feed row with the requesting user's current
// subscription state, returned by ListFeedsForUser.
type FeedWithSub struct {
	ID        int
	URL       string
	Label     string
	Enabled   bool
	CreatedAt time.Time
}

// EnsureNewsSchema creates the news_feeds and user_feed_subscriptions tables
// if they do not exist yet. Called from EnsureCoreSchema, after the users
// table, so the foreign key on user_feed_subscriptions.user_id resolves.
func (p *Pool) EnsureNewsSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS news_feeds (
			id         SERIAL PRIMARY KEY,
			url        TEXT NOT NULL,
			label      TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure news_feeds: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_feed_subscriptions (
			user_id TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			feed_id INTEGER NOT NULL REFERENCES news_feeds(id) ON DELETE CASCADE,
			enabled BOOLEAN NOT NULL DEFAULT false,
			PRIMARY KEY (user_id, feed_id)
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_feed_subscriptions: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_news_preferences (
			user_id           TEXT    PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			home_article_count INTEGER NOT NULL DEFAULT 5,
			show_images       BOOLEAN NOT NULL DEFAULT true
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_news_preferences: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_search_preferences (
			user_id    TEXT    PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			safesearch INTEGER NOT NULL DEFAULT 0,
			language   TEXT    NOT NULL DEFAULT 'all'
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_search_preferences: %w", err)
	}
	return nil
}

// NewsPrefs holds a user's news-display preferences.
type NewsPrefs struct {
	HomeArticleCount int  `json:"home_article_count"`
	ShowImages       bool `json:"show_images"`
}

// GetNewsPrefs returns the stored preferences for userID, or the defaults
// (5 articles, images on) if no row exists yet.
func (p *Pool) GetNewsPrefs(ctx context.Context, userID string) (NewsPrefs, error) {
	var prefs NewsPrefs
	err := p.QueryRow(ctx, `
		SELECT home_article_count, show_images
		FROM   user_news_preferences
		WHERE  user_id = $1
	`, userID).Scan(&prefs.HomeArticleCount, &prefs.ShowImages)
	if err != nil {
		// No row yet → return defaults.
		return NewsPrefs{HomeArticleCount: 5, ShowImages: true}, nil
	}
	return prefs, nil
}

// SetNewsPrefs upserts the preferences for userID.
func (p *Pool) SetNewsPrefs(ctx context.Context, userID string, prefs NewsPrefs) error {
	if prefs.HomeArticleCount < 1 {
		prefs.HomeArticleCount = 1
	}
	if prefs.HomeArticleCount > 50 {
		prefs.HomeArticleCount = 50
	}
	_, err := p.Exec(ctx, `
		INSERT INTO user_news_preferences (user_id, home_article_count, show_images)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		  SET home_article_count = EXCLUDED.home_article_count,
		      show_images        = EXCLUDED.show_images
	`, userID, prefs.HomeArticleCount, prefs.ShowImages)
	return err
}

// ListFeeds returns every feed row, sorted alphabetically by label. Used by
// the admin CRUD and by the news aggregator to look up feed URLs. url is
// stored encrypted (see CreateFeed's doc comment) and decrypted here so
// every caller keeps seeing plaintext, same as before this field was
// encrypted.
func (p *Pool) ListFeeds(ctx context.Context) ([]FeedRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, url, label, created_at FROM news_feeds ORDER BY lower(label) ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list feeds: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		var f FeedRow
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan feed: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFeed inserts a new feed and returns the created row (with its
// server-assigned id and created_at). feedURL is a PII-adjacent field (it
// can reveal a user's/org's reading habits and, for private feeds, internal
// infrastructure hostnames) and is stored encrypted at rest via
// crypto.Encrypt, matching the project's PII/URL encryption convention
// already used for SearXNG's URL and SMTP host - see MigrateToEncryptedStorage
// for the one-time backfill of rows created before this change.
func (p *Pool) CreateFeed(ctx context.Context, feedURL, label string) (FeedRow, error) {
	encURL, err := crypto.Encrypt(p.masterKey, feedURL)
	if err != nil {
		return FeedRow{}, fmt.Errorf("db: encrypt feed url: %w", err)
	}
	var f FeedRow
	err = p.QueryRow(ctx, `
		INSERT INTO news_feeds (url, label) VALUES ($1, $2)
		RETURNING id, url, label, created_at
	`, encURL, label).Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt)
	if err != nil {
		return FeedRow{}, fmt.Errorf("db: create feed: %w", err)
	}
	f.URL = feedURL
	return f, nil
}

// UpdateFeed sets url and label for the given feed id. Returns found = false
// (not an error) when no such id exists, so the handler can return 404
// without a separate existence check. url is encrypted before storage, same
// as CreateFeed.
func (p *Pool) UpdateFeed(ctx context.Context, id int, feedURL, label string) (bool, error) {
	encURL, err := crypto.Encrypt(p.masterKey, feedURL)
	if err != nil {
		return false, fmt.Errorf("db: encrypt feed url: %w", err)
	}
	tag, err := p.Exec(ctx, `
		UPDATE news_feeds SET url = $1, label = $2 WHERE id = $3
	`, encURL, label, id)
	if err != nil {
		return false, fmt.Errorf("db: update feed %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteFeed removes the feed row. ON DELETE CASCADE in
// user_feed_subscriptions handles the child rows automatically. Returns
// found = false when no such id exists.
func (p *Pool) DeleteFeed(ctx context.Context, id int) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM news_feeds WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("db: delete feed %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListFeedsForUser returns every feed paired with whether userID has it
// enabled. A missing subscription row is treated as enabled = false (the
// default for newly added feeds, per the agreed spec: new feeds are opt-in).
func (p *Pool) ListFeedsForUser(ctx context.Context, userID string) ([]FeedWithSub, error) {
	rows, err := p.Query(ctx, `
		SELECT f.id, f.url, f.label, f.created_at,
		       COALESCE(s.enabled, false) AS enabled
		FROM   news_feeds f
		LEFT   JOIN user_feed_subscriptions s
		       ON s.feed_id = f.id AND s.user_id = $1
		ORDER  BY lower(f.label) ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list feeds for user: %w", err)
	}
	defer rows.Close()
	var out []FeedWithSub
	for rows.Next() {
		var f FeedWithSub
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt, &f.Enabled); err != nil {
			return nil, fmt.Errorf("db: scan feed with sub: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFeedSubscription upserts the user's enabled/disabled preference for a
// single feed. A feedID that does not exist causes a foreign-key violation
// (returned as an error); callers should surface this as 404.
func (p *Pool) SetFeedSubscription(ctx context.Context, userID string, feedID int, enabled bool) error {
	_, err := p.Exec(ctx, `
		INSERT INTO user_feed_subscriptions (user_id, feed_id, enabled)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, feed_id) DO UPDATE SET enabled = EXCLUDED.enabled
	`, userID, feedID, enabled)
	if err != nil {
		return fmt.Errorf("db: set feed subscription: %w", err)
	}
	return nil
}

// EnabledFeedsForUser returns the feed rows the user has explicitly enabled,
// used by the news aggregator to decide which feeds to fetch.
func (p *Pool) EnabledFeedsForUser(ctx context.Context, userID string) ([]FeedRow, error) {
	rows, err := p.Query(ctx, `
		SELECT f.id, f.url, f.label, f.created_at
		FROM   news_feeds f
		JOIN   user_feed_subscriptions s ON s.feed_id = f.id
		WHERE  s.user_id = $1 AND s.enabled = true
		ORDER  BY f.created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: enabled feeds for user: %w", err)
	}
	defer rows.Close()
	var out []FeedRow
	for rows.Next() {
		var f FeedRow
		if err := rows.Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan enabled feed: %w", err)
		}
		if f.URL, err = crypto.DecryptIfNotEmpty(p.masterKey, f.URL); err != nil {
			return nil, fmt.Errorf("db: decrypt feed %d url: %w", f.ID, err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// encryptionVersionKey is the core_settings key that records whether the
// one-time plaintext→encrypted storage migration has been completed for
// this instance. Absent = not yet run; "1" = done.
const encryptionVersionKey = "core_encryption_version"

// MigrateToEncryptedStorage is a one-time startup migration that encrypts
// any plaintext PII that existed in the database before the encrypt-
// everything feature landed. It is safe to call on every boot: the
// core_encryption_version flag in core_settings makes each step a no-op
// once it has run successfully. The flag is a numeric string so later steps
// (e.g. version "2" below) can be added without re-running earlier ones on
// instances that already completed them.
//
// Fields migrated at version 1:
//   - users.email, users.name
//   - core_settings: smtp_host, smtp_username, smtp_from_address,
//     oidc_issuer_url, oidc_client_id
//     (dns_challenge_provider was migrated here too until the DNS-challenge
//     feature was removed entirely - see migration 0005)
//
// Fields migrated at version 2:
//   - news_feeds.url (CreateFeed/UpdateFeed started encrypting new rows
//     directly; this backfills rows created before that change)
//
// The _enc variants (smtp_password_enc, oidc_client_secret_enc) were
// already encrypted before this feature landed and are left untouched.
func (p *Pool) MigrateToEncryptedStorage(ctx context.Context) error {
	v, exists, err := p.GetSetting(ctx, encryptionVersionKey)
	if err != nil {
		return fmt.Errorf("db: migration check: %w", err)
	}
	version := 0
	if exists {
		version, _ = strconv.Atoi(v)
	}
	if version >= 2 {
		return nil // already done
	}

	if version < 1 {
		if err := p.migrateEncryptionV1(ctx); err != nil {
			return err
		}
	}
	if version < 2 {
		if err := p.migrateEncryptionV2NewsFeeds(ctx); err != nil {
			return err
		}
	}

	if err := p.SetSetting(ctx, encryptionVersionKey, "2"); err != nil {
		return fmt.Errorf("db: migration set version flag: %w", err)
	}
	return nil
}

// migrateEncryptionV2NewsFeeds backfills news_feeds.url for rows written
// before CreateFeed/UpdateFeed started encrypting it. Detects already-
// encrypted rows by attempting a decrypt first: crypto.Encrypt's output is
// never valid as a bare http(s) URL, so a successful decrypt means "already
// migrated, skip" and a decrypt failure means "still plaintext, encrypt it".
func (p *Pool) migrateEncryptionV2NewsFeeds(ctx context.Context) error {
	rows, err := p.Query(ctx, `SELECT id, url FROM news_feeds`)
	if err != nil {
		return fmt.Errorf("db: migration list news_feeds: %w", err)
	}
	type feedPlain struct {
		id  int
		url string
	}
	var feeds []feedPlain
	for rows.Next() {
		var f feedPlain
		if err := rows.Scan(&f.id, &f.url); err != nil {
			rows.Close()
			return fmt.Errorf("db: migration scan news_feed: %w", err)
		}
		feeds = append(feeds, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: migration rows: %w", err)
	}

	for _, f := range feeds {
		if f.url == "" {
			continue
		}
		if _, err := crypto.Decrypt(p.masterKey, f.url); err == nil {
			continue // already encrypted, skip
		}
		enc, err := crypto.Encrypt(p.masterKey, f.url)
		if err != nil {
			return fmt.Errorf("db: migration encrypt news_feed %d url: %w", f.id, err)
		}
		if _, err := p.Exec(ctx, `UPDATE news_feeds SET url=$1 WHERE id=$2`, enc, f.id); err != nil {
			return fmt.Errorf("db: migration update news_feed %d: %w", f.id, err)
		}
	}
	return nil
}

// migrateEncryptionV1 is the original (pre-versioning) migration body,
// unchanged in behavior from before version tracking was introduced.
func (p *Pool) migrateEncryptionV1(ctx context.Context) error {
	// Migrate users table: read id/email/name, encrypt, write back.
	rows, err := p.Query(ctx, `SELECT id, email, name FROM users`)
	if err != nil {
		return fmt.Errorf("db: migration list users: %w", err)
	}
	type userPlain struct{ id, email, name string }
	var users []userPlain
	for rows.Next() {
		var u userPlain
		if err := rows.Scan(&u.id, &u.email, &u.name); err != nil {
			rows.Close()
			return fmt.Errorf("db: migration scan user: %w", err)
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: migration rows: %w", err)
	}

	for _, u := range users {
		encEmail, err := crypto.EncryptIfNotEmpty(p.masterKey, u.email)
		if err != nil {
			return fmt.Errorf("db: migration encrypt email for %q: %w", u.id, err)
		}
		encName, err := crypto.EncryptIfNotEmpty(p.masterKey, u.name)
		if err != nil {
			return fmt.Errorf("db: migration encrypt name for %q: %w", u.id, err)
		}
		if _, err := p.Exec(ctx, `UPDATE users SET email=$1, name=$2 WHERE id=$3`, encEmail, encName, u.id); err != nil {
			return fmt.Errorf("db: migration update user %q: %w", u.id, err)
		}
	}

	// Migrate core_settings: plaintext configuration fields.
	settingsToMigrate := []string{
		"smtp_host", "smtp_username", "smtp_from_address",
		"oidc_issuer_url", "oidc_client_id",
	}
	for _, key := range settingsToMigrate {
		val, exists, err := p.GetSetting(ctx, key)
		if err != nil {
			return fmt.Errorf("db: migration get setting %q: %w", key, err)
		}
		if !exists || val == "" {
			continue
		}
		enc, err := crypto.Encrypt(p.masterKey, val)
		if err != nil {
			return fmt.Errorf("db: migration encrypt setting %q: %w", key, err)
		}
		if err := p.SetSetting(ctx, key, enc); err != nil {
			return fmt.Errorf("db: migration set setting %q: %w", key, err)
		}
	}

	// Version flag is set by the MigrateToEncryptedStorage wrapper after all
	// applicable steps (this one and any later ones) have succeeded, not
	// here - see its doc comment.
	return nil
}

// SearchPrefs holds a user's web-search preferences.
type SearchPrefs struct {
	Safesearch int    `json:"safesearch"` // 0 = off, 1 = moderate, 2 = strict
	Language   string `json:"language"`   // "all", "de", "en", …
}

// GetSearchPrefs returns stored search preferences for userID, or defaults
// (safesearch=0, language="all") when no row exists yet.
func (p *Pool) GetSearchPrefs(ctx context.Context, userID string) (SearchPrefs, error) {
	var prefs SearchPrefs
	err := p.QueryRow(ctx, `
		SELECT safesearch, language
		FROM   user_search_preferences
		WHERE  user_id = $1
	`, userID).Scan(&prefs.Safesearch, &prefs.Language)
	if err != nil {
		return SearchPrefs{Safesearch: 0, Language: "all"}, nil
	}
	return prefs, nil
}

// SetSearchPrefs upserts the search preferences for userID.
func (p *Pool) SetSearchPrefs(ctx context.Context, userID string, prefs SearchPrefs) error {
	if prefs.Safesearch < 0 || prefs.Safesearch > 2 {
		prefs.Safesearch = 0
	}
	if prefs.Language == "" {
		prefs.Language = "all"
	}
	_, err := p.Exec(ctx, `
		INSERT INTO user_search_preferences (user_id, safesearch, language)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		  SET safesearch = EXCLUDED.safesearch,
		      language   = EXCLUDED.language
	`, userID, prefs.Safesearch, prefs.Language)
	return err
}

// ---- AI providers ----------------------------------------------------------

// EnsureAISchema creates the ai_providers and ai_user_keys tables if they do
// not exist yet. Called from EnsureCoreSchema after the users table, so the
// FK on ai_user_keys.user_id resolves.
//
// ai_providers holds both built-in providers (anthropic, openai, gemini,
// deepseek — type = their slug) and user-defined OpenAI-compatible endpoints
// (type = "openai_compat"). encrypted_admin_key is nullable: a provider row
// can exist without an admin key (user-only) and without a default_model for
// the built-in entries that expose model selection to callers.
//
// ai_user_keys stores per-user overrides: the user's own API key for a given
// provider, GCM-encrypted. A missing row means "fall back to admin key".
func (p *Pool) EnsureAISchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ai_providers (
			id                 TEXT        PRIMARY KEY,
			type               TEXT        NOT NULL,
			name               TEXT        NOT NULL,
			base_url           TEXT        NOT NULL DEFAULT '',
			encrypted_admin_key TEXT,
			default_model      TEXT        NOT NULL DEFAULT '',
			user_can_override  BOOLEAN     NOT NULL DEFAULT true,
			enabled            BOOLEAN     NOT NULL DEFAULT true,
			sort_order         INTEGER     NOT NULL DEFAULT 0,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure ai_providers: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ai_user_keys (
			user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider_id TEXT NOT NULL REFERENCES ai_providers(id) ON DELETE CASCADE,
			encrypted_key TEXT NOT NULL,
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (user_id, provider_id)
		)
	`); err != nil {
		return fmt.Errorf("db: ensure ai_user_keys: %w", err)
	}
	// Seed the four built-in providers so they always exist in the DB, even
	// before an admin adds any keys. Users can then add their own keys for any
	// built-in. ON CONFLICT DO NOTHING preserves any admin changes (keys,
	// enabled flag, model, etc.) made after the initial seed.
	if _, err := p.Exec(ctx, `
		INSERT INTO ai_providers (id, type, name, base_url, default_model, user_can_override, enabled, sort_order)
		VALUES
			('anthropic', 'anthropic', 'Anthropic (Claude)', '',         'claude-sonnet-4-5', true, true, 1),
			('openai',    'openai',    'OpenAI',             '',         'gpt-4o',            true, true, 2),
			('gemini',    'gemini',    'Google Gemini',      '',         'gemini-2.0-flash',  true, true, 3),
			('deepseek',  'deepseek',  'DeepSeek',           '',         'deepseek-chat',     true, true, 4)
		ON CONFLICT (id) DO NOTHING
	`); err != nil {
		return fmt.Errorf("db: seed built-in ai_providers: %w", err)
	}
	// Idempotent migration: add preferred_model to ai_user_keys if it was
	// created before this column existed.
	if _, err := p.Exec(ctx, `
		ALTER TABLE ai_user_keys ADD COLUMN IF NOT EXISTS preferred_model TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: migrate ai_user_keys preferred_model: %w", err)
	}
	// Idempotent migration: add preferred_provider_id to users so the last
	// selected AI provider is remembered cross-device.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_provider_id TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: migrate users preferred_provider_id: %w", err)
	}
	return nil
}

// GetPreferredProvider returns the provider ID the user last selected, or ""
// if none has been set.
func (p *Pool) GetPreferredProvider(ctx context.Context, userID string) (string, error) {
	var id string
	err := p.QueryRow(ctx,
		`SELECT preferred_provider_id FROM users WHERE id = $1`, userID,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: get preferred provider: %w", err)
	}
	return id, nil
}

// SetPreferredProvider persists the user's preferred AI provider selection.
// Passing an empty string clears the preference.
func (p *Pool) SetPreferredProvider(ctx context.Context, userID, providerID string) error {
	_, err := p.Exec(ctx,
		`UPDATE users SET preferred_provider_id = $2 WHERE id = $1`,
		userID, providerID,
	)
	if err != nil {
		return fmt.Errorf("db: set preferred provider: %w", err)
	}
	return nil
}

// AIProviderRow is one row from ai_providers. encrypted_admin_key is not
// exposed directly — callers use ResolveAIKey to get the decrypted key.
type AIProviderRow struct {
	ID              string
	Type            string
	Name            string
	BaseURL         string
	HasAdminKey     bool
	DefaultModel    string
	UserCanOverride bool
	Enabled         bool
	SortOrder       int
}

// ListAIProviders returns all provider rows ordered by sort_order, then name.
func (p *Pool) ListAIProviders(ctx context.Context) ([]AIProviderRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, type, name, base_url,
		       (encrypted_admin_key IS NOT NULL AND encrypted_admin_key != '') AS has_admin_key,
		       default_model, user_can_override, enabled, sort_order
		FROM ai_providers
		ORDER BY sort_order ASC, name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list ai_providers: %w", err)
	}
	defer rows.Close()
	var out []AIProviderRow
	for rows.Next() {
		var r AIProviderRow
		if err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.BaseURL, &r.HasAdminKey,
			&r.DefaultModel, &r.UserCanOverride, &r.Enabled, &r.SortOrder); err != nil {
			return nil, fmt.Errorf("db: scan ai_provider: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAIProvider returns a single provider row and whether it exists.
func (p *Pool) GetAIProvider(ctx context.Context, id string) (AIProviderRow, bool, error) {
	var r AIProviderRow
	err := p.QueryRow(ctx, `
		SELECT id, type, name, base_url,
		       (encrypted_admin_key IS NOT NULL AND encrypted_admin_key != '') AS has_admin_key,
		       default_model, user_can_override, enabled, sort_order
		FROM ai_providers WHERE id = $1
	`, id).Scan(&r.ID, &r.Type, &r.Name, &r.BaseURL, &r.HasAdminKey,
		&r.DefaultModel, &r.UserCanOverride, &r.Enabled, &r.SortOrder)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AIProviderRow{}, false, nil
		}
		return AIProviderRow{}, false, fmt.Errorf("db: get ai_provider %q: %w", id, err)
	}
	return r, true, nil
}

// UpsertAIProvider inserts or fully replaces a provider row. plainAdminKey
// may be empty ("") to leave the encrypted_admin_key column NULL (no admin key).
func (p *Pool) UpsertAIProvider(ctx context.Context, r AIProviderRow, plainAdminKey string) error {
	var encKey *string
	if plainAdminKey != "" {
		enc, err := crypto.Encrypt(p.masterKey, plainAdminKey)
		if err != nil {
			return fmt.Errorf("db: encrypt admin key for %q: %w", r.ID, err)
		}
		encKey = &enc
	}
	_, err := p.Exec(ctx, `
		INSERT INTO ai_providers
		  (id, type, name, base_url, encrypted_admin_key, default_model,
		   user_can_override, enabled, sort_order)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
		  type              = EXCLUDED.type,
		  name              = EXCLUDED.name,
		  base_url          = EXCLUDED.base_url,
		  encrypted_admin_key = COALESCE(EXCLUDED.encrypted_admin_key, ai_providers.encrypted_admin_key),
		  default_model     = EXCLUDED.default_model,
		  user_can_override = EXCLUDED.user_can_override,
		  enabled           = EXCLUDED.enabled,
		  sort_order        = EXCLUDED.sort_order
	`, r.ID, r.Type, r.Name, r.BaseURL, encKey, r.DefaultModel,
		r.UserCanOverride, r.Enabled, r.SortOrder)
	if err != nil {
		return fmt.Errorf("db: upsert ai_provider %q: %w", r.ID, err)
	}
	return nil
}

// ClearAIProviderAdminKey sets encrypted_admin_key = NULL for the given provider,
// used when an admin explicitly removes their key.
func (p *Pool) ClearAIProviderAdminKey(ctx context.Context, id string) error {
	_, err := p.Exec(ctx, `UPDATE ai_providers SET encrypted_admin_key = NULL WHERE id = $1`, id)
	return err
}

// GetAIProviderAdminKey returns the decrypted admin key for a provider.
// Returns ("", nil) if no key is set.
func (p *Pool) GetAIProviderAdminKey(ctx context.Context, providerID string) (string, error) {
	var enc *string
	err := p.QueryRow(ctx, `
		SELECT encrypted_admin_key FROM ai_providers WHERE id = $1
	`, providerID).Scan(&enc)
	if err != nil {
		return "", fmt.Errorf("db: get ai provider admin key: %w", err)
	}
	if enc == nil || *enc == "" {
		return "", nil
	}
	plain, err := crypto.Decrypt(p.masterKey, *enc)
	if err != nil {
		return "", fmt.Errorf("db: decrypt ai admin key: %w", err)
	}
	return plain, nil
}

// DeleteAIProvider removes the provider row. ON DELETE CASCADE in ai_user_keys
// removes all per-user keys for it automatically.
func (p *Pool) DeleteAIProvider(ctx context.Context, id string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM ai_providers WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("db: delete ai_provider %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ResolveAIKey returns the plaintext API key to use for (userID, providerID):
// the user's own key if present and allowed, otherwise the admin key, or ""
// if neither exists. A non-empty return value is always a decrypted plaintext.
func (p *Pool) ResolveAIKey(ctx context.Context, userID, providerID string) (string, error) {
	// Check user's own key first.
	var encUserKey string
	var userCanOverride bool
	err := p.QueryRow(ctx, `
		SELECT k.encrypted_key, pr.user_can_override
		FROM ai_user_keys k
		JOIN ai_providers pr ON pr.id = k.provider_id
		WHERE k.user_id = $1 AND k.provider_id = $2
	`, userID, providerID).Scan(&encUserKey, &userCanOverride)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("db: resolve ai key (user): %w", err)
	}
	if err == nil && userCanOverride && encUserKey != "" {
		plain, err := crypto.Decrypt(p.masterKey, encUserKey)
		if err != nil {
			return "", fmt.Errorf("db: decrypt user ai key: %w", err)
		}
		return plain, nil
	}

	// Fall back to admin key.
	var encAdminKey *string
	err = p.QueryRow(ctx, `
		SELECT encrypted_admin_key FROM ai_providers WHERE id = $1
	`, providerID).Scan(&encAdminKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("db: resolve ai key (admin): %w", err)
	}
	if encAdminKey == nil || *encAdminKey == "" {
		return "", nil
	}
	plain, err := crypto.Decrypt(p.masterKey, *encAdminKey)
	if err != nil {
		return "", fmt.Errorf("db: decrypt admin ai key: %w", err)
	}
	return plain, nil
}

// SetAIUserKey stores (or replaces) the user's own API key for a provider.
// preferred_model is preserved across key updates (only reset on delete).
func (p *Pool) SetAIUserKey(ctx context.Context, userID, providerID, plainKey string) error {
	enc, err := crypto.Encrypt(p.masterKey, plainKey)
	if err != nil {
		return fmt.Errorf("db: encrypt user ai key: %w", err)
	}
	_, err = p.Exec(ctx, `
		INSERT INTO ai_user_keys (user_id, provider_id, encrypted_key, preferred_model, updated_at)
		VALUES ($1, $2, $3, '', now())
		ON CONFLICT (user_id, provider_id) DO UPDATE
		  SET encrypted_key = EXCLUDED.encrypted_key,
		      updated_at    = now()
	`, userID, providerID, enc)
	if err != nil {
		return fmt.Errorf("db: set user ai key: %w", err)
	}
	return nil
}

// SetAIUserPreferredModel updates the preferred model for a user's own key.
// The key itself is not changed.
func (p *Pool) SetAIUserPreferredModel(ctx context.Context, userID, providerID, model string) error {
	tag, err := p.Exec(ctx, `
		UPDATE ai_user_keys SET preferred_model = $3, updated_at = now()
		WHERE user_id = $1 AND provider_id = $2
	`, userID, providerID, model)
	if err != nil {
		return fmt.Errorf("db: set user preferred model: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: no user key found for provider %q", providerID)
	}
	return nil
}

// GetAIUserDecryptedKey returns the decrypted key the user stored for a
// provider, and their preferred model. Returns found=false if no row exists.
func (p *Pool) GetAIUserDecryptedKey(ctx context.Context, userID, providerID string) (key, preferredModel string, found bool, err error) {
	var enc string
	var pref string
	scanErr := p.QueryRow(ctx, `
		SELECT encrypted_key, preferred_model FROM ai_user_keys
		WHERE user_id = $1 AND provider_id = $2
	`, userID, providerID).Scan(&enc, &pref)
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("db: get user ai key: %w", scanErr)
	}
	plain, err := crypto.Decrypt(p.masterKey, enc)
	if err != nil {
		return "", "", false, fmt.Errorf("db: decrypt user ai key: %w", err)
	}
	return plain, pref, true, nil
}

// DeleteAIUserKey removes a user's own key for a provider. After this the
// admin key (if any) becomes the fallback again.
func (p *Pool) DeleteAIUserKey(ctx context.Context, userID, providerID string) error {
	_, err := p.Exec(ctx, `
		DELETE FROM ai_user_keys WHERE user_id = $1 AND provider_id = $2
	`, userID, providerID)
	return err
}

// AIProviderWithUserKey combines a provider row with per-user key state.
type AIProviderWithUserKey struct {
	AIProviderRow
	HasUserKey     bool
	PreferredModel string // user's preferred model; empty = use provider default
}

func (p *Pool) ListAIProvidersForUser(ctx context.Context, userID string) ([]AIProviderWithUserKey, error) {
	rows, err := p.Query(ctx, `
		SELECT pr.id, pr.type, pr.name, pr.base_url,
		       (pr.encrypted_admin_key IS NOT NULL AND pr.encrypted_admin_key != '') AS has_admin_key,
		       pr.default_model, pr.user_can_override, pr.enabled, pr.sort_order,
		       (k.encrypted_key IS NOT NULL) AS has_user_key,
		       COALESCE(k.preferred_model, '') AS preferred_model
		FROM ai_providers pr
		LEFT JOIN ai_user_keys k ON k.provider_id = pr.id AND k.user_id = $1
		ORDER BY pr.sort_order ASC, pr.name ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list ai providers for user: %w", err)
	}
	defer rows.Close()
	var out []AIProviderWithUserKey
	for rows.Next() {
		var r AIProviderWithUserKey
		if err := rows.Scan(&r.ID, &r.Type, &r.Name, &r.BaseURL, &r.HasAdminKey,
			&r.DefaultModel, &r.UserCanOverride, &r.Enabled, &r.SortOrder,
			&r.HasUserKey, &r.PreferredModel); err != nil {
			return nil, fmt.Errorf("db: scan ai provider for user: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Quick links ------------------------------------------------------------

// AdminQuickLinkRow is one row from admin_quick_links (title/url/description
// already decrypted by the methods below).
type AdminQuickLinkRow struct {
	ID          string
	Title       string
	URL         string
	Icon        string
	Description string
	SortOrder   int
	CreatedBy   string
	CreatedAt   time.Time
}

// UserQuickLinkRow is one row from user_quick_links (title/url/description
// already decrypted).
type UserQuickLinkRow struct {
	ID          string
	UserID      string
	Title       string
	URL         string
	Icon        string
	Description string
	SortOrder   int
	CreatedAt   time.Time
}

// TileRef is one entry in a user's saved tile-order JSON array. Type
// distinguishes admin-managed tiles from the user's own tiles.
type TileRef struct {
	Type string `json:"type"` // "admin" | "user"
	ID   string `json:"id"`
}

// EnsureQuickLinksSchema creates the three quick-links tables if they do not
// exist yet. Called from EnsureCoreSchema after EnsureAISchema.
//
// admin_quick_links: global shortcuts an org-admin/super-admin creates.
// user_quick_links: personal shortcuts each user creates for themselves.
// user_tile_order: stores each user's custom tile ordering as a JSON array of
// TileRef values. A missing row means "use default order" (admin tiles first
// by sort_order, then user tiles by created_at).
func (p *Pool) EnsureQuickLinksSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS admin_quick_links (
			id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			title_enc   TEXT        NOT NULL,
			url_enc     TEXT        NOT NULL,
			icon        TEXT        NOT NULL DEFAULT '',
			desc_enc    TEXT        NOT NULL DEFAULT '',
			sort_order  INTEGER     NOT NULL DEFAULT 0,
			created_by  TEXT        NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure admin_quick_links: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_quick_links (
			id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			title_enc   TEXT        NOT NULL,
			url_enc     TEXT        NOT NULL,
			icon        TEXT        NOT NULL DEFAULT '',
			desc_enc    TEXT        NOT NULL DEFAULT '',
			sort_order  INTEGER     NOT NULL DEFAULT 0,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_quick_links: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_tile_order (
			user_id    TEXT        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			order_json TEXT        NOT NULL DEFAULT '[]',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure user_tile_order: %w", err)
	}
	return nil
}

// ListAdminQuickLinks returns all admin quick links ordered by sort_order,
// then created_at. title/url/description are returned decrypted.
func (p *Pool) ListAdminQuickLinks(ctx context.Context) ([]AdminQuickLinkRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, title_enc, url_enc, icon, desc_enc, sort_order, created_by, created_at
		FROM admin_quick_links
		ORDER BY sort_order ASC, created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list admin_quick_links: %w", err)
	}
	defer rows.Close()
	var out []AdminQuickLinkRow
	for rows.Next() {
		var r AdminQuickLinkRow
		if err := rows.Scan(&r.ID, &r.Title, &r.URL, &r.Icon, &r.Description,
			&r.SortOrder, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan admin_quick_link: %w", err)
		}
		var decErr error
		if r.Title, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Title); decErr != nil {
			return nil, fmt.Errorf("db: decrypt admin link title %q: %w", r.ID, decErr)
		}
		if r.URL, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.URL); decErr != nil {
			return nil, fmt.Errorf("db: decrypt admin link url %q: %w", r.ID, decErr)
		}
		if r.Description, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Description); decErr != nil {
			return nil, fmt.Errorf("db: decrypt admin link desc %q: %w", r.ID, decErr)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateAdminQuickLink inserts a new admin quick link. title/url/description
// are received as plaintext and stored encrypted. Returns the created row.
func (p *Pool) CreateAdminQuickLink(ctx context.Context, title, url, icon, description string, sortOrder int, createdBy string) (AdminQuickLinkRow, error) {
	encTitle, err := crypto.EncryptIfNotEmpty(p.masterKey, title)
	if err != nil {
		return AdminQuickLinkRow{}, fmt.Errorf("db: encrypt admin link title: %w", err)
	}
	encURL, err := crypto.EncryptIfNotEmpty(p.masterKey, url)
	if err != nil {
		return AdminQuickLinkRow{}, fmt.Errorf("db: encrypt admin link url: %w", err)
	}
	encDesc, err := crypto.EncryptIfNotEmpty(p.masterKey, description)
	if err != nil {
		return AdminQuickLinkRow{}, fmt.Errorf("db: encrypt admin link desc: %w", err)
	}
	var r AdminQuickLinkRow
	err = p.QueryRow(ctx, `
		INSERT INTO admin_quick_links (title_enc, url_enc, icon, desc_enc, sort_order, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`, encTitle, encURL, icon, encDesc, sortOrder, createdBy).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return AdminQuickLinkRow{}, fmt.Errorf("db: create admin_quick_link: %w", err)
	}
	r.Title = title
	r.URL = url
	r.Icon = icon
	r.Description = description
	r.SortOrder = sortOrder
	r.CreatedBy = createdBy
	return r, nil
}

// UpdateAdminQuickLink updates all mutable fields for the given id.
// Returns found=false when no such id exists.
func (p *Pool) UpdateAdminQuickLink(ctx context.Context, id, title, url, icon, description string, sortOrder int) (bool, error) {
	encTitle, err := crypto.EncryptIfNotEmpty(p.masterKey, title)
	if err != nil {
		return false, fmt.Errorf("db: encrypt admin link title: %w", err)
	}
	encURL, err := crypto.EncryptIfNotEmpty(p.masterKey, url)
	if err != nil {
		return false, fmt.Errorf("db: encrypt admin link url: %w", err)
	}
	encDesc, err := crypto.EncryptIfNotEmpty(p.masterKey, description)
	if err != nil {
		return false, fmt.Errorf("db: encrypt admin link desc: %w", err)
	}
	tag, err := p.Exec(ctx, `
		UPDATE admin_quick_links
		SET title_enc=$2, url_enc=$3, icon=$4, desc_enc=$5, sort_order=$6
		WHERE id=$1::uuid
	`, id, encTitle, encURL, icon, encDesc, sortOrder)
	if err != nil {
		return false, fmt.Errorf("db: update admin_quick_link %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeleteAdminQuickLink removes an admin quick link by id.
func (p *Pool) DeleteAdminQuickLink(ctx context.Context, id string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM admin_quick_links WHERE id = $1::uuid`, id)
	if err != nil {
		return false, fmt.Errorf("db: delete admin_quick_link %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListUserQuickLinks returns all personal quick links for userID, ordered by
// sort_order, then created_at. title/url/description are returned decrypted.
func (p *Pool) ListUserQuickLinks(ctx context.Context, userID string) ([]UserQuickLinkRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, user_id, title_enc, url_enc, icon, desc_enc, sort_order, created_at
		FROM user_quick_links
		WHERE user_id = $1
		ORDER BY sort_order ASC, created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list user_quick_links: %w", err)
	}
	defer rows.Close()
	var out []UserQuickLinkRow
	for rows.Next() {
		var r UserQuickLinkRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.Title, &r.URL, &r.Icon,
			&r.Description, &r.SortOrder, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan user_quick_link: %w", err)
		}
		var decErr error
		if r.Title, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Title); decErr != nil {
			return nil, fmt.Errorf("db: decrypt user link title %q: %w", r.ID, decErr)
		}
		if r.URL, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.URL); decErr != nil {
			return nil, fmt.Errorf("db: decrypt user link url %q: %w", r.ID, decErr)
		}
		if r.Description, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Description); decErr != nil {
			return nil, fmt.Errorf("db: decrypt user link desc %q: %w", r.ID, decErr)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateUserQuickLink inserts a new personal quick link. Returns the new UUID.
func (p *Pool) CreateUserQuickLink(ctx context.Context, userID, title, url, icon, description string) (string, error) {
	encTitle, err := crypto.EncryptIfNotEmpty(p.masterKey, title)
	if err != nil {
		return "", fmt.Errorf("db: encrypt user link title: %w", err)
	}
	encURL, err := crypto.EncryptIfNotEmpty(p.masterKey, url)
	if err != nil {
		return "", fmt.Errorf("db: encrypt user link url: %w", err)
	}
	encDesc, err := crypto.EncryptIfNotEmpty(p.masterKey, description)
	if err != nil {
		return "", fmt.Errorf("db: encrypt user link desc: %w", err)
	}
	var id string
	err = p.QueryRow(ctx, `
		INSERT INTO user_quick_links (user_id, title_enc, url_enc, icon, desc_enc)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, userID, encTitle, encURL, icon, encDesc).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: create user_quick_link: %w", err)
	}
	return id, nil
}

// DeleteUserQuickLink removes a personal quick link. The user_id guard
// ensures a user cannot delete another user's link by guessing a UUID.
func (p *Pool) DeleteUserQuickLink(ctx context.Context, userID, id string) (bool, error) {
	tag, err := p.Exec(ctx, `
		DELETE FROM user_quick_links WHERE id = $1::uuid AND user_id = $2
	`, id, userID)
	if err != nil {
		return false, fmt.Errorf("db: delete user_quick_link %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetUserTileOrder returns the stored TileRef slice for userID, or nil (not an
// error) when no custom order has been saved yet.
func (p *Pool) GetUserTileOrder(ctx context.Context, userID string) ([]TileRef, error) {
	var raw string
	err := p.QueryRow(ctx, `
		SELECT order_json FROM user_tile_order WHERE user_id = $1
	`, userID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get user tile order: %w", err)
	}
	var refs []TileRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return nil, fmt.Errorf("db: parse user tile order: %w", err)
	}
	return refs, nil
}

// SetUserTileOrder upserts the user's custom tile ordering.
func (p *Pool) SetUserTileOrder(ctx context.Context, userID string, refs []TileRef) error {
	data, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("db: marshal tile order: %w", err)
	}
	_, err = p.Exec(ctx, `
		INSERT INTO user_tile_order (user_id, order_json, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (user_id) DO UPDATE
		  SET order_json = EXCLUDED.order_json,
		      updated_at = now()
	`, userID, string(data))
	if err != nil {
		return fmt.Errorf("db: set user tile order: %w", err)
	}
	return nil
}

// ---- Module Store -----------------------------------------------------------

// EnsureModuleStoreSchema extends the installed_modules stub (created above in
// EnsureCoreSchema) with the full column set needed for the module lifecycle
// pipeline (spec section 4.3/4.9/4.10), and creates the module_registry table
// for the daily registry-sync cache (spec section 4.10).
//
// All ALTERs use ADD COLUMN IF NOT EXISTS so this is safe to run on every boot.
func (p *Pool) EnsureModuleStoreSchema(ctx context.Context) error {
	// ── installed_modules: extend the stub with new columns ──────────────────

	// source: official | community | direct
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules
		    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'direct'
		    CHECK (source IN ('official', 'community', 'direct'))
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.source: %w", err)
	}

	// release_url: exact URL the module.zip was downloaded from.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS release_url TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.release_url: %w", err)
	}

	// sha256: verified checksum at install/update time.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.sha256: %w", err)
	}

	// manifest: full manifest.yaml as JSONB for the detail endpoint.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.manifest: %w", err)
	}

	// pinned: when true, update suggestions are suppressed for this module.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.pinned: %w", err)
	}

	// cached_zip_path: old ZIP kept during an in-progress update for rollback.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS cached_zip_path TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.cached_zip_path: %w", err)
	}

	// available_version: set by the update-check when a newer version exists.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS available_version TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.available_version: %w", err)
	}

	// last_update_check: timestamp of the most recent update check.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS last_update_check TIMESTAMPTZ
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.last_update_check: %w", err)
	}

	// updated_at: bumped on every status change, update, pin toggle, etc.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.updated_at: %w", err)
	}

	// ── module_registry ───────────────────────────────────────────────────────

	// Local cache of official registry.json + modulab-community index.
	// No PII, no credentials → no GCM encryption needed (spec section 2.4).
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS module_registry (
		    name            TEXT        PRIMARY KEY,
		    source          TEXT        NOT NULL CHECK (source IN ('official', 'community')),
		    source_repo     TEXT        NOT NULL,
		    release_asset   TEXT        NOT NULL,
		    cosign_sig_url  TEXT,
		    category        TEXT        NOT NULL,
		    latest_version  TEXT,
		    manifest_cache  JSONB,
		    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry: %w", err)
	}

	// cosign_sig_url: added after the table's initial release. ADD COLUMN IF
	// NOT EXISTS so this is a no-op on fresh installs (already in the CREATE
	// TABLE above) and safely backfills existing installations on next boot.
	// Without this, store.Entry.CosignSigURL was silently dropped between
	// FetchOfficialRegistry and installer.go's Cosign check, so verification
	// was always skipped.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS cosign_sig_url TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.cosign_sig_url: %w", err)
	}

	// store.ListEntries (internal/store/registry.go) filters
	// "WHERE ($1 = '' OR source = $1) AND ($2 = '' OR category = $2)" for
	// the Module Store's source/category filter UI. In practice this table
	// stays small (a handful to a few dozen modules), so this index is more
	// about correctness than a real performance need at today's scale - but
	// free to keep, and correct if the registry ever grows past a trivial
	// size (e.g. once a larger community index exists).
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_module_registry_source_category ON module_registry (source, category)
	`); err != nil {
		return fmt.Errorf("db: ensure idx_module_registry_source_category: %w", err)
	}

	return nil
}

// ---- Installed Modules CRUD -------------------------------------------------

// ModuleStatus constants mirror the CHECK constraint on installed_modules.status.
const (
	ModuleStatusInstalling = "installing"
	ModuleStatusActive     = "active"
	ModuleStatusDegraded   = "degraded"
	ModuleStatusFailed     = "failed"
	ModuleStatusIsolated   = "isolated"
)

// InstalledModuleRow is a full row from installed_modules.
type InstalledModuleRow struct {
	Name             string     `json:"name"`
	Version          string     `json:"version"`
	Tier             int        `json:"tier"`
	Scope            string     `json:"scope"`
	Source           string     `json:"source"`
	ReleaseURL       string     `json:"release_url"`
	SHA256           string     `json:"sha256"`
	Manifest         json.RawMessage `json:"manifest,omitempty"` // raw JSONB — RawMessage serialises as-is, not base64
	Status           string     `json:"status"`
	Pinned           bool       `json:"pinned"`
	CachedZipPath    *string    `json:"cached_zip_path,omitempty"`
	AvailableVersion *string    `json:"available_version,omitempty"`
	LastUpdateCheck  *time.Time `json:"last_update_check,omitempty"`
	InstalledAt      time.Time  `json:"installed_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// InsertInstalledModule writes a new module row with status "installing".
// Called at the start of the install transaction so the UI can show progress
// via the modul.state_change SSE event before migrations finish.
func (p *Pool) InsertInstalledModule(ctx context.Context, name, version string, tier int, scope, source, releaseURL, sha256 string, manifest []byte) error {
	_, err := p.Exec(ctx, `
		INSERT INTO installed_modules
		    (name, version, tier, scope, source, release_url, sha256, manifest, status, installed_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'installing', now(), now())
	`, name, version, tier, scope, source, releaseURL, sha256, manifest)
	if err != nil {
		return fmt.Errorf("db: insert installed_module %q: %w", name, err)
	}
	return nil
}

// UpdateModuleStatus sets the status (and bumps updated_at) for the named module.
// Returns false when no such module exists.
func (p *Pool) UpdateModuleStatus(ctx context.Context, name, status string) (bool, error) {
	tag, err := p.Exec(ctx, `
		UPDATE installed_modules SET status = $2, updated_at = now() WHERE name = $1
	`, name, status)
	if err != nil {
		return false, fmt.Errorf("db: update module status %q → %q: %w", name, status, err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetInstalledModule returns the row for name, or (row{}, false, nil) if absent.
func (p *Pool) GetInstalledModule(ctx context.Context, name string) (InstalledModuleRow, bool, error) {
	var r InstalledModuleRow
	err := p.QueryRow(ctx, `
		SELECT name, version, tier, scope, source, release_url, sha256, manifest,
		       status, pinned, cached_zip_path, available_version, last_update_check,
		       installed_at, updated_at
		FROM installed_modules WHERE name = $1
	`, name).Scan(
		&r.Name, &r.Version, &r.Tier, &r.Scope, &r.Source, &r.ReleaseURL, &r.SHA256, &r.Manifest,
		&r.Status, &r.Pinned, &r.CachedZipPath, &r.AvailableVersion, &r.LastUpdateCheck,
		&r.InstalledAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return InstalledModuleRow{}, false, nil
		}
		return InstalledModuleRow{}, false, fmt.Errorf("db: get installed_module %q: %w", name, err)
	}
	return r, true, nil
}

// ListInstalledModules returns all installed module rows, ordered by name.
func (p *Pool) ListInstalledModules(ctx context.Context) ([]InstalledModuleRow, error) {
	rows, err := p.Query(ctx, `
		SELECT name, version, tier, scope, source, release_url, sha256, manifest,
		       status, pinned, cached_zip_path, available_version, last_update_check,
		       installed_at, updated_at
		FROM installed_modules ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list installed_modules: %w", err)
	}
	defer rows.Close()

	var out []InstalledModuleRow
	for rows.Next() {
		var r InstalledModuleRow
		if err := rows.Scan(
			&r.Name, &r.Version, &r.Tier, &r.Scope, &r.Source, &r.ReleaseURL, &r.SHA256, &r.Manifest,
			&r.Status, &r.Pinned, &r.CachedZipPath, &r.AvailableVersion, &r.LastUpdateCheck,
			&r.InstalledAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan installed_module: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteInstalledModule removes the module row. Schema/storage cleanup is
// handled separately by the uninstaller (internal/modules/uninstaller.go).
func (p *Pool) DeleteInstalledModule(ctx context.Context, name string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM installed_modules WHERE name = $1`, name)
	if err != nil {
		return false, fmt.Errorf("db: delete installed_module %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetModuleCachedZip stores the rollback ZIP path during an in-progress update.
func (p *Pool) SetModuleCachedZip(ctx context.Context, name, path string) error {
	_, err := p.Exec(ctx, `
		UPDATE installed_modules SET cached_zip_path = $2, updated_at = now() WHERE name = $1
	`, name, path)
	return err
}

// ClearModuleCachedZip removes the rollback ZIP path after a successful update.
func (p *Pool) ClearModuleCachedZip(ctx context.Context, name string) error {
	_, err := p.Exec(ctx, `
		UPDATE installed_modules SET cached_zip_path = NULL, updated_at = now() WHERE name = $1
	`, name)
	return err
}

// SetModuleAvailableVersion records that a newer version is available.
// Pass "" to clear after an update.
func (p *Pool) SetModuleAvailableVersion(ctx context.Context, name, version string) error {
	var v any
	if version != "" {
		v = version
	}
	_, err := p.Exec(ctx, `
		UPDATE installed_modules
		SET available_version = $2, last_update_check = now(), updated_at = now()
		WHERE name = $1
	`, name, v)
	return err
}

// SetModulePinned sets or clears the pinned flag for the named module.
func (p *Pool) SetModulePinned(ctx context.Context, name string, pinned bool) (bool, error) {
	tag, err := p.Exec(ctx, `
		UPDATE installed_modules SET pinned = $2, updated_at = now() WHERE name = $1
	`, name, pinned)
	if err != nil {
		return false, fmt.Errorf("db: set module pinned %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}
