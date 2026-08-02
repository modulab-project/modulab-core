package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// SearchPrefs holds a user's web-search preferences.
type SearchPrefs struct {
	Safesearch int    `json:"safesearch"` // 0 = off, 1 = moderate, 2 = strict
	Language   string `json:"language"`   // "all", "de", "en", …
}

// GetSearchPrefs returns stored search preferences for userID, or defaults
// when no row exists yet: safesearch=2 ("strict") and language set to the
// user's already-configured ModuLab UI language (users.ui_language, via
// GetUserLanguage), falling back to "all" if that isn't set either.
// Defaults changed 2026-07-05 per user request - a fresh account should
// start with the stricter, less surprising SafeSearch level, and reuse a
// preference ModuLab already has instead of defaulting to every language.
func (p *Pool) GetSearchPrefs(ctx context.Context, userID string) (SearchPrefs, error) {
	var prefs SearchPrefs
	err := p.QueryRow(ctx, `
		SELECT safesearch, language
		FROM   user_search_preferences
		WHERE  user_id = $1
	`, userID).Scan(&prefs.Safesearch, &prefs.Language)
	if err != nil {
		lang := "all"
		if uiLang, langErr := p.GetUserLanguage(ctx, userID); langErr == nil && uiLang != "" {
			lang = uiLang
		}
		return SearchPrefs{Safesearch: 2, Language: lang}, nil
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

// ---- Search providers -------------------------------------------------------
//
// search_providers/search_user_keys mirror ai_providers/ai_user_keys (see
// "AI providers" below) on purpose: web search started as a single hardcoded
// SearXNG integration (base URL in core_settings), but now needs to support
// more than one backend (SearXNG, Serper.dev, and whatever gets added
// later) with the same admin-key/user-key override shape the AI providers
// already have. Reusing that exact shape means the search feature package
// (internal/search) can dispatch on provider "type" the same way internal/ai
// already does, instead of inventing a second config mechanism.
//
// base_url_enc is only meaningful for types that connect to an admin-chosen
// endpoint (SearXNG); encrypted_admin_key is only meaningful for types that
// authenticate via API key (Serper). Both are nullable so a single row
// shape covers either kind of provider without dead columns being
// mandatory. max_results/fetch_pages are SearXNG-specific tuning knobs
// (fetch_pages controls SearXNG's parallel-page fetch); Serper always does
// a single request per query, so fetch_pages is ignored for it, and
// max_results is reused as the "num" results cap Serper's API accepts.
func (p *Pool) EnsureSearchSchema(ctx context.Context) error {
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS search_providers (
			id                  TEXT        PRIMARY KEY,
			type                TEXT        NOT NULL,
			name                TEXT        NOT NULL,
			base_url_enc        TEXT,
			encrypted_admin_key TEXT,
			max_results         INTEGER     NOT NULL DEFAULT 25,
			fetch_pages         INTEGER     NOT NULL DEFAULT 1,
			user_can_override   BOOLEAN     NOT NULL DEFAULT true,
			enabled             BOOLEAN     NOT NULL DEFAULT true,
			sort_order          INTEGER     NOT NULL DEFAULT 0,
			created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure search_providers: %w", err)
	}
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS search_user_keys (
			user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider_id   TEXT NOT NULL REFERENCES search_providers(id) ON DELETE CASCADE,
			encrypted_key TEXT NOT NULL,
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (user_id, provider_id)
		)
	`); err != nil {
		return fmt.Errorf("db: ensure search_user_keys: %w", err)
	}
	return nil
}

// DefaultSearchProviderID is the id (and provider type) of the built-in
// SearXNG search provider row MigrateSearchProviders seeds below, and the
// fallback search.PrimaryProviderID returns when no primary is configured.
// Exported (2026-07-27) so every other reader of this same "searxng" value
// - search.go's PrimaryProviderID default and fetchFromProvider's type
// switch, plus cmd/core/main.go's healthz/systemInfoHandler
// GetSearchProviderBaseURL calls - shares one definition instead of each
// hardcoding its own "searxng" string literal. db is the right home for it
// (not search) since search already imports db, and db seeds the row in
// the first place; the reverse import would be a cycle.
const DefaultSearchProviderID = "searxng"

// MigrateSearchProviders performs the one-time move from the old
// single-provider SearXNG settings (searxng_url_enc, searxng_max_results,
// searxng_fetch_pages, searxng_search_timeout_seconds in core_settings) into
// the new search_providers table, and seeds a disabled "serper" row so it
// shows up in the admin UI ready to be configured. Idempotency is gated on
// whether the "searxng" row already exists — same style as searxng's old
// EnsureDefault, which this replaces.
//
// Called once at startup, after EnsureCoreSchema/MigrateToEncryptedStorage.
func (p *Pool) MigrateSearchProviders(ctx context.Context) error {
	_, found, err := p.GetSearchProvider(ctx, DefaultSearchProviderID)
	if err != nil {
		return fmt.Errorf("db: migrate search providers: check existing: %w", err)
	}
	if found {
		return nil // already migrated
	}

	const defaultSearXNGURL = "http://searxng:8080"
	baseURL := defaultSearXNGURL
	if enc, ok, err := p.GetSetting(ctx, "searxng_url_enc"); err == nil && ok && enc != "" {
		if plain, err := crypto.Decrypt(p.masterKey, enc); err == nil && plain != "" {
			baseURL = plain
		}
	}
	maxResults := legacySearchIntSetting(ctx, p, "searxng_max_results", 25)
	fetchPages := legacySearchIntSetting(ctx, p, "searxng_fetch_pages", 2)

	encBaseURL, err := crypto.Encrypt(p.masterKey, baseURL)
	if err != nil {
		return fmt.Errorf("db: migrate search providers: encrypt searxng base_url: %w", err)
	}
	if _, err := p.Exec(ctx, `
		INSERT INTO search_providers (id, type, name, base_url_enc, max_results, fetch_pages, user_can_override, enabled, sort_order)
		VALUES ($1, $1, 'SearXNG', $2, $3, $4, false, true, 1)
		ON CONFLICT (id) DO NOTHING
	`, DefaultSearchProviderID, encBaseURL, maxResults, fetchPages); err != nil {
		return fmt.Errorf("db: migrate search providers: seed searxng: %w", err)
	}
	// Serper has no admin key yet (nothing to migrate) - seeded disabled so
	// an admin has to deliberately turn it on after adding a key, mirroring
	// how a brand-new AI provider with no key is never auto-enabled either.
	if _, err := p.Exec(ctx, `
		INSERT INTO search_providers (id, type, name, max_results, user_can_override, enabled, sort_order)
		VALUES ('serper', 'serper', 'Serper.dev', 25, true, false, 2)
		ON CONFLICT (id) DO NOTHING
	`); err != nil {
		return fmt.Errorf("db: migrate search providers: seed serper: %w", err)
	}

	// Carry the old per-search timeout over under its new, provider-agnostic
	// name (see search.SearchTimeoutSeconds's doc comment for why one
	// timeout now covers every provider).
	if val, ok, _ := p.GetSetting(ctx, "searxng_search_timeout_seconds"); ok && val != "" {
		if err := p.SetSetting(ctx, "search_timeout_seconds", val); err != nil {
			log.Printf("db: migrate search providers: carry over search_timeout_seconds: %v", err)
		}
	}
	if _, ok, _ := p.GetSetting(ctx, "search_primary_provider_id"); !ok {
		if err := p.SetSetting(ctx, "search_primary_provider_id", DefaultSearchProviderID); err != nil {
			log.Printf("db: migrate search providers: set search_primary_provider_id: %v", err)
		}
	}

	// Clean up the legacy keys now that everything they held has a new home.
	// Best-effort: a leftover legacy key doesn't affect app behavior (nothing
	// reads searxng_url_enc/etc. any more), so a single delete failure here
	// logs and moves on rather than failing the whole migration.
	for _, key := range []string{
		"searxng_url_enc", "searxng_max_results", "searxng_fetch_pages", "searxng_search_timeout_seconds",
	} {
		if err := p.DeleteSetting(ctx, key); err != nil {
			log.Printf("db: migrate search providers: delete legacy setting %s: %v", key, err)
		}
	}
	return nil
}

// legacySearchIntSetting is a small helper for MigrateSearchProviders only -
// reads a plaintext integer core_settings value, returning def when absent
// or unparseable. Unexported and separate from EnsureAISchema/searxng's own
// int-setting readers since this one is only ever used during the one-time
// migration above, on keys that no longer exist afterwards.
func legacySearchIntSetting(ctx context.Context, p *Pool, key string, def int) int {
	val, ok, err := p.GetSetting(ctx, key)
	if err != nil || !ok || val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// SearchProviderRow is one row from search_providers. encrypted_admin_key is
// not exposed directly - callers use GetSearchProviderAdminKey /
// ResolveSearchKey to get the decrypted secret.
type SearchProviderRow struct {
	ID              string
	Type            string
	Name            string
	BaseURL         string
	HasAdminKey     bool
	MaxResults      int
	FetchPages      int
	UserCanOverride bool
	Enabled         bool
	SortOrder       int
}

const searchProviderSelectCols = `
	id, type, name,
	COALESCE(base_url_enc, '') AS base_url_enc,
	(encrypted_admin_key IS NOT NULL AND encrypted_admin_key != '') AS has_admin_key,
	max_results, fetch_pages, user_can_override, enabled, sort_order
`

func (p *Pool) scanSearchProviderRow(scan func(dest ...any) error) (SearchProviderRow, error) {
	var r SearchProviderRow
	var encBaseURL string
	if err := scan(&r.ID, &r.Type, &r.Name, &encBaseURL, &r.HasAdminKey,
		&r.MaxResults, &r.FetchPages, &r.UserCanOverride, &r.Enabled, &r.SortOrder); err != nil {
		return SearchProviderRow{}, err
	}
	var err error
	if r.BaseURL, err = crypto.DecryptIfNotEmpty(p.masterKey, encBaseURL); err != nil {
		return SearchProviderRow{}, fmt.Errorf("decrypt base_url for %q: %w", r.ID, err)
	}
	return r, nil
}

// ListSearchProviders returns all provider rows ordered by sort_order, then name.
func (p *Pool) ListSearchProviders(ctx context.Context) ([]SearchProviderRow, error) {
	rows, err := p.Query(ctx, `SELECT `+searchProviderSelectCols+`
		FROM search_providers ORDER BY sort_order ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("db: list search_providers: %w", err)
	}
	defer rows.Close()
	var out []SearchProviderRow
	for rows.Next() {
		r, err := p.scanSearchProviderRow(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("db: scan search_provider: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetSearchProvider returns a single provider row and whether it exists.
func (p *Pool) GetSearchProvider(ctx context.Context, id string) (SearchProviderRow, bool, error) {
	row := p.QueryRow(ctx, `SELECT `+searchProviderSelectCols+`
		FROM search_providers WHERE id = $1`, id)
	r, err := p.scanSearchProviderRow(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SearchProviderRow{}, false, nil
		}
		return SearchProviderRow{}, false, fmt.Errorf("db: get search_provider %q: %w", id, err)
	}
	return r, true, nil
}

// GetSearchProviderBaseURL returns the decrypted base_url for a provider
// (used by the SearXNG client and by /healthz's reachability check).
// Returns ("", false, nil) when unset OR when the provider has been
// disabled in /admin/system/search - a disabled provider (e.g. SearXNG
// removed from docker-compose but its old base_url row left behind) should
// not show up as an infrastructure check on the System Status page, since
// there is nothing left to reach on purpose.
func (p *Pool) GetSearchProviderBaseURL(ctx context.Context, id string) (string, bool, error) {
	row, found, err := p.GetSearchProvider(ctx, id)
	if err != nil || !found || row.BaseURL == "" || !row.Enabled {
		return "", false, err
	}
	return row.BaseURL, true, nil
}

// UpdateSearchProvider patches the admin-editable fields of a provider row.
// plainBaseURL/plainAdminKey passed as "" mean "leave unchanged" - same
// COALESCE-on-conflict convention as UpsertAIProvider. Providers themselves
// are pre-seeded (searxng, serper) rather than freely creatable, since each
// type needs matching Go code in internal/search to actually be usable -
// this only ever updates an existing row, never inserts one; it returns
// found=false if id doesn't exist.
func (p *Pool) UpdateSearchProvider(ctx context.Context, id string, plainBaseURL, plainAdminKey string, maxResults, fetchPages int, userCanOverride, enabled bool, sortOrder int) (bool, error) {
	var encBaseURL *string
	if plainBaseURL != "" {
		enc, err := crypto.Encrypt(p.masterKey, plainBaseURL)
		if err != nil {
			return false, fmt.Errorf("db: encrypt search provider base_url for %q: %w", id, err)
		}
		encBaseURL = &enc
	}
	var encAdminKey *string
	if plainAdminKey != "" {
		enc, err := crypto.Encrypt(p.masterKey, plainAdminKey)
		if err != nil {
			return false, fmt.Errorf("db: encrypt search provider admin key for %q: %w", id, err)
		}
		encAdminKey = &enc
	}
	tag, err := p.Exec(ctx, `
		UPDATE search_providers SET
		  base_url_enc        = COALESCE($2, base_url_enc),
		  encrypted_admin_key = COALESCE($3, encrypted_admin_key),
		  max_results         = $4,
		  fetch_pages         = $5,
		  user_can_override   = $6,
		  enabled             = $7,
		  sort_order           = $8
		WHERE id = $1
	`, id, encBaseURL, encAdminKey, maxResults, fetchPages, userCanOverride, enabled, sortOrder)
	if err != nil {
		return false, fmt.Errorf("db: update search_provider %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ClearSearchProviderAdminKey sets encrypted_admin_key = NULL, used when an
// admin explicitly removes their key (Serper) or wants to force per-user
// keys only.
func (p *Pool) ClearSearchProviderAdminKey(ctx context.Context, id string) error {
	_, err := p.Exec(ctx, `UPDATE search_providers SET encrypted_admin_key = NULL WHERE id = $1`, id)
	return err
}

// GetSearchProviderAdminKey returns the decrypted admin key for a provider.
// Returns ("", nil) if no key is set.
func (p *Pool) GetSearchProviderAdminKey(ctx context.Context, id string) (string, error) {
	var enc *string
	err := p.QueryRow(ctx, `SELECT encrypted_admin_key FROM search_providers WHERE id = $1`, id).Scan(&enc)
	if err != nil {
		return "", fmt.Errorf("db: get search provider admin key: %w", err)
	}
	if enc == nil || *enc == "" {
		return "", nil
	}
	plain, err := crypto.Decrypt(p.masterKey, *enc)
	if err != nil {
		return "", fmt.Errorf("db: decrypt search admin key: %w", err)
	}
	return plain, nil
}

// ResolveSearchKey returns the plaintext API key to use for (userID,
// providerID): the user's own key if present and allowed, otherwise the
// admin key, or "" if neither exists - identical resolution order to
// ResolveAIKey.
func (p *Pool) ResolveSearchKey(ctx context.Context, userID, providerID string) (string, error) {
	var encUserKey string
	var userCanOverride bool
	err := p.QueryRow(ctx, `
		SELECT k.encrypted_key, pr.user_can_override
		FROM search_user_keys k
		JOIN search_providers pr ON pr.id = k.provider_id
		WHERE k.user_id = $1 AND k.provider_id = $2
	`, userID, providerID).Scan(&encUserKey, &userCanOverride)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("db: resolve search key (user): %w", err)
	}
	if err == nil && userCanOverride && encUserKey != "" {
		plain, err := crypto.Decrypt(p.masterKey, encUserKey)
		if err != nil {
			return "", fmt.Errorf("db: decrypt user search key: %w", err)
		}
		return plain, nil
	}
	return p.GetSearchProviderAdminKey(ctx, providerID)
}

// SetSearchUserKey stores (or replaces) the user's own API key for a provider.
func (p *Pool) SetSearchUserKey(ctx context.Context, userID, providerID, plainKey string) error {
	enc, err := crypto.Encrypt(p.masterKey, plainKey)
	if err != nil {
		return fmt.Errorf("db: encrypt user search key: %w", err)
	}
	_, err = p.Exec(ctx, `
		INSERT INTO search_user_keys (user_id, provider_id, encrypted_key, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (user_id, provider_id) DO UPDATE
		  SET encrypted_key = EXCLUDED.encrypted_key,
		      updated_at    = now()
	`, userID, providerID, enc)
	if err != nil {
		return fmt.Errorf("db: set user search key: %w", err)
	}
	return nil
}

// DeleteSearchUserKey removes a user's own key for a provider. After this
// the admin key (if any) becomes the fallback again.
func (p *Pool) DeleteSearchUserKey(ctx context.Context, userID, providerID string) error {
	_, err := p.Exec(ctx, `
		DELETE FROM search_user_keys WHERE user_id = $1 AND provider_id = $2
	`, userID, providerID)
	return err
}

// SearchProviderWithUserKey combines a provider row with per-user key state,
// for the user-facing provider list (GET /v1/search/providers).
type SearchProviderWithUserKey struct {
	SearchProviderRow
	HasUserKey bool
}

// ListSearchProvidersForUser returns every provider paired with whether
// userID has their own key stored for it.
func (p *Pool) ListSearchProvidersForUser(ctx context.Context, userID string) ([]SearchProviderWithUserKey, error) {
	rows, err := p.Query(ctx, `
		SELECT pr.id, pr.type, pr.name,
		       COALESCE(pr.base_url_enc, ''),
		       (pr.encrypted_admin_key IS NOT NULL AND pr.encrypted_admin_key != ''),
		       pr.max_results, pr.fetch_pages, pr.user_can_override, pr.enabled, pr.sort_order,
		       (k.encrypted_key IS NOT NULL) AS has_user_key
		FROM search_providers pr
		LEFT JOIN search_user_keys k ON k.provider_id = pr.id AND k.user_id = $1
		ORDER BY pr.sort_order ASC, pr.name ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list search providers for user: %w", err)
	}
	defer rows.Close()
	var out []SearchProviderWithUserKey
	for rows.Next() {
		var r SearchProviderWithUserKey
		var encBaseURL string
		if err := rows.Scan(&r.ID, &r.Type, &r.Name, &encBaseURL, &r.HasAdminKey,
			&r.MaxResults, &r.FetchPages, &r.UserCanOverride, &r.Enabled, &r.SortOrder, &r.HasUserKey); err != nil {
			return nil, fmt.Errorf("db: scan search provider for user: %w", err)
		}
		if r.BaseURL, err = crypto.DecryptIfNotEmpty(p.masterKey, encBaseURL); err != nil {
			return nil, fmt.Errorf("db: decrypt base_url for %q: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
