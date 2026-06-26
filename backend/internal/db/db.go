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

	if err := p.EnsureNewsSchema(ctx); err != nil {
		return err
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

// ListFeeds returns every feed row, oldest first. Used by the admin CRUD and
// by the news aggregator to look up feed URLs.
func (p *Pool) ListFeeds(ctx context.Context) ([]FeedRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, url, label, created_at FROM news_feeds ORDER BY created_at ASC
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
		out = append(out, f)
	}
	return out, rows.Err()
}

// CreateFeed inserts a new feed and returns the created row (with its
// server-assigned id and created_at).
func (p *Pool) CreateFeed(ctx context.Context, feedURL, label string) (FeedRow, error) {
	var f FeedRow
	err := p.QueryRow(ctx, `
		INSERT INTO news_feeds (url, label) VALUES ($1, $2)
		RETURNING id, url, label, created_at
	`, feedURL, label).Scan(&f.ID, &f.URL, &f.Label, &f.CreatedAt)
	if err != nil {
		return FeedRow{}, fmt.Errorf("db: create feed: %w", err)
	}
	return f, nil
}

// UpdateFeed sets url and label for the given feed id. Returns found = false
// (not an error) when no such id exists, so the handler can return 404
// without a separate existence check.
func (p *Pool) UpdateFeed(ctx context.Context, id int, feedURL, label string) (bool, error) {
	tag, err := p.Exec(ctx, `
		UPDATE news_feeds SET url = $1, label = $2 WHERE id = $3
	`, feedURL, label, id)
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
		ORDER  BY f.created_at ASC
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
// core_encryption_version flag in core_settings makes it a no-op once it
// has run successfully.
//
// Fields migrated here:
//   - users.email, users.name
//   - core_settings: smtp_host, smtp_username, smtp_from_address,
//     oidc_issuer_url, oidc_client_id, dns_challenge_provider
//
// The _enc variants (smtp_password_enc, oidc_client_secret_enc,
// dns_challenge_credentials_enc) were already encrypted before this
// feature landed and are left untouched.
func (p *Pool) MigrateToEncryptedStorage(ctx context.Context) error {
	v, exists, err := p.GetSetting(ctx, encryptionVersionKey)
	if err != nil {
		return fmt.Errorf("db: migration check: %w", err)
	}
	if exists && v == "1" {
		return nil // already done
	}

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
		"dns_challenge_provider",
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

	if err := p.SetSetting(ctx, encryptionVersionKey, "1"); err != nil {
		return fmt.Errorf("db: migration set version flag: %w", err)
	}
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
