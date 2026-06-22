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

	_, err = p.Exec(ctx, `
		INSERT INTO users (id, email, name, role, approved, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			role = EXCLUDED.role,
			last_login_at = now()
	`, subject, email, name, role, approved)
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
		SELECT id, email, name, role, approved, locked, created_at
		FROM users WHERE id = $1
	`, subject).Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRow{}, false, nil
		}
		return UserRow{}, false, fmt.Errorf("db: get user %q: %w", subject, err)
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
}

// ListUsers returns every user row, oldest first. Unlike the narrower
// ListPendingUsers this replaces, this includes already-approved and
// locked users too - the admin frontend derives a single status (Pending /
// Active / Locked) per row from Approved+Locked itself, rather than this
// method pre-filtering, so there is exactly one place an admin needs to
// look to manage anyone.
func (p *Pool) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, email, name, role, approved, locked, created_at
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
		if err := rows.Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: list users: %w", err)
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
