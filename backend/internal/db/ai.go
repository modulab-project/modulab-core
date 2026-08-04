package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// ---- AI providers ----------------------------------------------------------

// EnsureAISchema creates the ai_providers and ai_user_keys tables if they do
// not exist yet. Called from EnsureCoreSchema after the users table, so the
// FK on ai_user_keys.user_id resolves.
//
// ai_providers holds both built-in providers (anthropic, openai, gemini,
// deepseek, kimi, mistral, openrouter, requesty — type = their slug) and
// user-defined OpenAI-compatible endpoints
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
	// Seed the eight built-in providers so they always exist in the DB, even
	// before an admin adds any keys. Users can then add their own keys for any
	// built-in. ON CONFLICT DO NOTHING preserves any admin changes (keys,
	// enabled flag, model, etc.) made after the initial seed.
	//
	// default_model is left empty for providers whose vendor does not offer a
	// production-safe "always latest" alias (anthropic, openai, gemini,
	// deepseek, kimi, requesty) - model IDs there churn too often to keep
	// hardcoded, and a stale one silently breaks chat (see the deepseek-chat
	// retirement on 2026-07-24). requesty specifically routes by explicit
	// "provider/model" strings or an admin-defined fallback policy name
	// (e.g. "policy/sonnet-with-fallback") that only exists after the admin
	// sets it up in Requesty's own dashboard - nothing we could hardcode here
	// even if we wanted to. The admin picks a model on first setup via "load
	// models" (AdminListModelsHandler queries the provider's live model
	// list), and ChatHandler refuses to run with an empty model instead of
	// sending "" to the provider. mistral and openrouter DO have vendor-
	// guaranteed evergreen aliases (mistral-large-latest, openrouter/auto),
	// so those keep a preset.
	if _, err := p.Exec(ctx, `
		INSERT INTO ai_providers (id, type, name, base_url, default_model, user_can_override, enabled, sort_order)
		VALUES
			('anthropic',  'anthropic',  'Anthropic (Claude)',  '', '',                     true, true, 1),
			('openai',     'openai',     'OpenAI',               '', '',                     true, true, 2),
			('gemini',     'gemini',     'Google Gemini',        '', '',                     true, true, 3),
			('deepseek',   'deepseek',   'DeepSeek',             '', '',                     true, true, 4),
			('kimi',       'kimi',       'Kimi (Moonshot AI)',   '', '',                     true, true, 5),
			('mistral',    'mistral',    'Mistral AI',           '', 'mistral-large-latest', true, true, 6),
			('openrouter', 'openrouter', 'OpenRouter',           '', 'openrouter/auto',      true, true, 7),
			('requesty',   'requesty',   'Requesty',             '', '',                     true, true, 8)
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
