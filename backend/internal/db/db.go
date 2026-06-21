// Package db wraps a Postgres connection pool (pgx) and provides the
// minimal key/value access Core needs for its own bootstrap state
// (core_settings), the users table populated by OIDC JIT provisioning
// (spec section 3.3), and module bookkeeping (installed_modules). Module
// schemas and per-module roles (spec section 4.3) are handled elsewhere,
// once the module installation pipeline lands.
package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps *pgxpool.Pool so Core-specific helper methods can be attached
// without polluting the pgx API surface everywhere it's used.
type Pool struct {
	*pgxpool.Pool
}

// Connect opens a pooled connection to Postgres and verifies it is reachable.
func Connect(ctx context.Context, dsn string) (*Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{pool}, nil
}

// EnsureCoreSchema creates Core's bootstrap tables if they do not exist yet.
// This mirrors migrations/0001_init_core_schema.up.sql and
// migrations/0002_add_users.up.sql, and lets a fresh Core instance boot
// without a separate migration step having been run first. Once a real
// golang-migrate runner is wired in, this becomes redundant and can be
// removed - tracked as a follow-up, not done here to keep this commit
// reviewable.
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
			status TEXT NOT NULL DEFAULT 'installing',
			installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules: %w", err)
	}

	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('super-admin', 'org-admin', 'user', 'pending')),
			approved BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure users: %w", err)
	}

	// users.approved was added after the table itself - CREATE TABLE IF NOT
	// EXISTS above is a no-op against an already-existing table from before
	// this column existed, so a separate idempotent ALTER is needed to pick
	// up the new column on an upgrade rather than just on a fresh database.
	if _, err := p.Exec(ctx, `
		ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN NOT NULL DEFAULT false
	`); err != nil {
		return fmt.Errorf("db: ensure users.approved: %w", err)
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

// UpsertUser inserts a new user row keyed by OIDC subject, or updates the
// existing one's email, role, and last_login_at if the subject was already
// known. Called once per successful OIDC login (spec section 3.3's JIT
// provisioning) - there is no separate "create account" step.
//
// approved is only ever written on the INSERT branch - deliberately absent
// from the ON CONFLICT ... DO UPDATE SET clause below, so a later login by
// an already-known user can never silently reset whatever an admin (or the
// bootstrap/wizard flow) previously set it to. Callers pass the value they
// want a brand-new row to start with; for an existing row it is ignored.
func (p *Pool) UpsertUser(ctx context.Context, subject, email, role string, approved bool) error {
	_, err := p.Exec(ctx, `
		INSERT INTO users (id, email, role, approved, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			role = EXCLUDED.role,
			last_login_at = now()
	`, subject, email, role, approved)
	if err != nil {
		return fmt.Errorf("db: upsert user %q: %w", subject, err)
	}
	return nil
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
