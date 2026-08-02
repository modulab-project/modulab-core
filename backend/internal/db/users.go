package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

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
// used by the admin lock/delete handlers to decide whether the target is an
// admin before allowing an action that could otherwise strand the
// instance with zero admins.
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

// HasAdmin reports whether at least one user with role 'admin'
// exists. Used by setup.CompleteHandler to verify the wizard's step 6
// (spec section 6.5: "Admin binden") actually succeeded before
// allowing step 7 to invalidate the bootstrap token - a user merely
// attempting login is not enough, since spec section 3.3's Dynamic Prefix
// Hard Gate can still leave them as RolePending. Named HasSuperAdmin before
// 2026-07-29's role-model change (org-admin tier removed, super-admin
// renamed to plain "admin").
func (p *Pool) HasAdmin(ctx context.Context) (bool, error) {
	var exists bool
	err := p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE role = 'admin')`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("db: check admin existence: %w", err)
	}
	return exists, nil
}

// AdminCount returns how many user rows currently have role =
// 'admin', regardless of approved/locked state. Used by the admin
// lock/delete handlers' last-admin guard - unlike HasAdmin
// (a yes/no check used once during setup), this needs the actual count to
// tell "locking/deleting this one is fine, there are others" apart from
// "this is the only one left". Named SuperAdminCount before 2026-07-29's
// role-model change.
func (p *Pool) AdminCount(ctx context.Context) (int, error) {
	var count int
	err := p.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: count admins: %w", err)
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

// ListAdmins returns every user row with role admin, oldest first - used
// by CallbackHandler (handlers.go) to email every current admin when a
// brand-new pending signup needs review, alongside the "user.pending" SSE
// event (notify.AdminChannel) it already publishes: SSE only reaches
// whoever happens to be connected at that exact moment, mail still reaches
// everyone else afterwards.
func (p *Pool) ListAdmins(ctx context.Context) ([]UserRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, email, name, role, approved, locked, created_at
		FROM users
		WHERE role = 'admin'
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

// GetUserTheme returns the stored theme preference for userID ("light",
// "dark", "system"), or "" when no preference has been saved yet - callers
// treat "" as "keep whatever the client already has locally".
func (p *Pool) GetUserTheme(ctx context.Context, userID string) (string, error) {
	var theme string
	err := p.QueryRow(ctx, `SELECT theme FROM users WHERE id = $1`, userID).Scan(&theme)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("db: get theme for %q: %w", userID, err)
	}
	return theme, nil
}

// SetUserTheme persists the theme preference for userID. Only "light",
// "dark", and "system" are accepted (matching AppShell.tsx's Theme type);
// any other value is stored as "" (reset to default).
func (p *Pool) SetUserTheme(ctx context.Context, userID, theme string) error {
	if theme != "light" && theme != "dark" && theme != "system" {
		theme = ""
	}
	_, err := p.Exec(ctx, `UPDATE users SET theme = $1 WHERE id = $2`, theme, userID)
	if err != nil {
		return fmt.Errorf("db: set theme for %q: %w", userID, err)
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
	Theme       string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// GetUserExportRow returns the DSGVO export row for userID, decrypting PII.
func (p *Pool) GetUserExportRow(ctx context.Context, userID string) (UserExportRow, bool, error) {
	var u UserExportRow
	err := p.QueryRow(ctx, `
		SELECT id, email, name, role, approved, locked, ui_language, theme, created_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(&u.Subject, &u.Email, &u.Name, &u.Role, &u.Approved, &u.Locked,
		&u.UILanguage, &u.Theme, &u.CreatedAt, &u.LastLoginAt)
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
