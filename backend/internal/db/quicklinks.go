package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

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
// admin_quick_links: global shortcuts an admin creates.
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
