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
	"time"

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
			name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL CHECK (role IN ('super-admin', 'org-admin', 'user', 'pending')),
			approved BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure users: %w", err)
	}

	// approved and name were both added after the table itself - CREATE
	// TABLE IF NOT EXISTS above is a no-op against an already-existing
	// table from before either column existed, so separate idempotent
	// ALTERs are needed to pick them up on an upgrade rather than just on a
	// fresh database.
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
func (p *Pool) UpsertUser(ctx context.Context, subject, email, name, role string, approved bool) error {
	_, err := p.Exec(ctx, `
		INSERT INTO users (id, email, name, role, approved, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			role = EXCLUDED.role,
			last_login_at = now()
	`, subject, email, name, role, approved)
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

// PendingUser is one row from ListPendingUsers - the subset of the users
// table an admin needs to decide whether to approve someone. Role is
// included even though approval doesn't gate on it: it tells the admin
// which of the three configured OIDC groups this person is already
// correctly a member of (see handlers.go's CallbackHandler gate 1), which
// is exactly the context "should I approve them" needs.
type PendingUser struct {
	Subject   string
	Email     string
	Name      string
	Role      string
	CreatedAt time.Time
}

// ListPendingUsers returns every user row with approved = false, oldest
// first - the people CallbackHandler's gate 2 is currently holding at the
// /pending screen. Until now the only way to move someone out of this list
// was a manual "UPDATE users SET approved = true" - this is the read side
// of the admin UI that replaces that.
func (p *Pool) ListPendingUsers(ctx context.Context) ([]PendingUser, error) {
	rows, err := p.Query(ctx, `
		SELECT id, email, name, role, created_at
		FROM users
		WHERE approved = false
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list pending users: %w", err)
	}
	defer rows.Close()

	var out []PendingUser
	for rows.Next() {
		var u PendingUser
		if err := rows.Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan pending user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: list pending users: %w", err)
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
