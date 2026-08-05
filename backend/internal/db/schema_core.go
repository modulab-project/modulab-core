package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

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
			status TEXT NOT NULL DEFAULT 'installing' CHECK (status IN ('installing', 'active', 'degraded', 'failed', 'isolated')),
			installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules: %w", err)
	}
	// status had no CHECK constraint at all before this (unlike tier right
	// above it in the same table) despite the ModuleStatus* constants below
	// implying one always existed - CREATE TABLE IF NOT EXISTS above is a
	// no-op against any database that already has this table, so an
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

	// scope (per-location/cross-location) was part of an early multi-location
	// design that was dropped before v1 shipped - multi-location support is
	// not being built. DROP COLUMN IF EXISTS also removes the inline CHECK
	// constraint that was defined on it, and is a no-op on a fresh database
	// that never had the column (CREATE TABLE above already omits it).
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules DROP COLUMN IF EXISTS scope
	`); err != nil {
		return fmt.Errorf("db: drop installed_modules.scope: %w", err)
	}

	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL CHECK (role IN ('admin', 'user', 'pending')),
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
	// theme stores the user's light/dark/system preference (AppShell.tsx's
	// three-way toggle). This is now the only place it lives - the frontend
	// no longer mirrors it into localStorage, so every device reads the same
	// value. Plaintext for the same reason as ui_language: not PII. Empty
	// string means "no preference saved yet"; the client renders "light"
	// until a save happens.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure users.theme: %w", err)
	}
	// notify_new_login/notify_country_anomaly/notify_new_device/
	// notify_session_revoked_by_admin gate the four account-security emails
	// added alongside auth's country/device anomaly detection (see
	// session.go's checkSessionCountryAnomaly/checkSessionDeviceAnomaly and
	// handlers.go's CallbackHandler) - each defaults to true so existing
	// users keep getting every one of these mails exactly as before this
	// column existed, and can opt out per-category from their Profile page
	// instead of all-or-nothing. Deliberately four separate booleans, not one
	// bitmask/JSON blob: matches ui_language/theme's own one-column-per-
	// preference style just above, keeps each one individually indexable/
	// queryable, and a future fifth toggle is one more ADD COLUMN rather than
	// a migration of an opaque blob's shape. Not PII, same exemption as
	// ui_language/theme/locked - plain booleans, no GCM encryption needed.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_new_login BOOLEAN NOT NULL DEFAULT true
	`); err != nil {
		return fmt.Errorf("db: ensure users.notify_new_login: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_country_anomaly BOOLEAN NOT NULL DEFAULT true
	`); err != nil {
		return fmt.Errorf("db: ensure users.notify_country_anomaly: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_new_device BOOLEAN NOT NULL DEFAULT true
	`); err != nil {
		return fmt.Errorf("db: ensure users.notify_new_device: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_session_revoked_by_admin BOOLEAN NOT NULL DEFAULT true
	`); err != nil {
		return fmt.Errorf("db: ensure users.notify_session_revoked_by_admin: %w", err)
	}

	// Role model collapsed from four tiers to three on 2026-07-29: the
	// org-admin tier was removed entirely, and super-admin was renamed to
	// plain "admin" (single admin tier going forward). The pre-existing
	// CHECK constraint (from the original CREATE TABLE, still in force on
	// an upgraded database - CREATE TABLE IF NOT EXISTS above is a no-op
	// against it) only permits 'super-admin'/'org-admin'/'user'/'pending' -
	// it has never heard of 'admin' at all. So the constraint has to be
	// dropped *before* the backfill UPDATEs below, not after: backfilling
	// role='admin' while the old constraint is still in force fails with
	// "violates check constraint users_role_check" (23514), exactly the
	// bug this ordering fixes (found 2026-07-29, first deploy of this
	// migration). Only once every row has been rewritten to one of the two
	// remaining values does the tightened constraint get added back.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check
	`); err != nil {
		return fmt.Errorf("db: drop users_role_check: %w", err)
	}
	// org-admin accounts downgrade to plain 'user' (the operator's own
	// choice - see the migration plan discussion: existing org-admins are
	// being moved to the IdP's _user group by hand, not promoted to full
	// admin).
	if _, err := p.Exec(ctx, `
		UPDATE users SET role = 'user' WHERE role = 'org-admin'
	`); err != nil {
		return fmt.Errorf("db: migrate org-admin roles to user: %w", err)
	}
	if _, err := p.Exec(ctx, `
		UPDATE users SET role = 'admin' WHERE role = 'super-admin'
	`); err != nil {
		return fmt.Errorf("db: migrate super-admin roles to admin: %w", err)
	}
	// Idempotent add-back, same pattern as
	// installed_modules_source_check/module_registry_source_check below:
	// PostgreSQL has no ADD CONSTRAINT IF NOT EXISTS, so a constraint whose
	// definition changed has to be dropped and recreated on every boot
	// rather than only added once. The DROP above already makes this
	// idempotent across restarts (a later boot's DROP IF EXISTS is a no-op
	// once this ADD has already run).
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD CONSTRAINT users_role_check
		    CHECK (role IN ('admin', 'user', 'pending'))
	`); err != nil {
		return fmt.Errorf("db: ensure users_role_check: %w", err)
	}

	// HasAdmin/AdminCount/ListAdmins (users.go) all filter on role = 'admin',
	// and ListAdmins runs on every login's new-pending-user notification path
	// - without an index, every one of those was a sequential scan of the
	// whole users table (L-3, PERFORMANCE_AUDIT.md). A partial index (only
	// 'admin' rows) rather than a plain btree on the whole column: the only
	// queries filtering on role at all filter for exactly 'admin', so there
	// is no reason to also index the far larger 'user'/'pending' rows.
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_users_role_admin ON users (role) WHERE role = 'admin'
	`); err != nil {
		return fmt.Errorf("db: ensure idx_users_role_admin: %w", err)
	}

	if err := p.EnsureNewsSchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureAISchema(ctx); err != nil {
		return err
	}

	if err := p.EnsureSearchSchema(ctx); err != nil {
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

	// audit.ListActors filters/joins on actor_id and orders by id, and the
	// admin audit-log page's default (no event_type filter) view orders by
	// created_at - neither is covered by the event_type-led index above, so
	// both fall back to a full table scan without these.
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id_id ON audit_log (actor_id, id DESC)
	`); err != nil {
		return fmt.Errorf("db: ensure idx_audit_log_actor_id_id: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC)
	`); err != nil {
		return fmt.Errorf("db: ensure idx_audit_log_created_at: %w", err)
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
