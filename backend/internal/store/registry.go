// Package store manages the Modul-Store registry: discovery, caching and
// browsing of all known modules from the official (modulab-modules) and
// community (modulab-community) sources (spec section 4.10).
//
// The registry is a local DB cache (module_registry table) populated by the
// daily sync goroutine in sync.go. Browsing the store always reads from this
// cache, so it works offline with the last-known data. Installation itself
// (internal/modules) fetches the actual ZIP at install time.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

// Deps bundles what the store package needs from the outside world.
type Deps struct {
	Pool   *db.Pool
	Valkey *valkey.Client
}

// Entry is one row of the module_registry table, ready for the API response.
type Entry struct {
	Name         string `json:"name"`
	Source       string `json:"source"` // "official" | "community" | "custom"
	SourceRepo   string `json:"source_repo"`
	ReleaseAsset string `json:"release_asset"`
	// CosignSigURL is the URL of the Cosign signature file. Empty string means
	// no signature is available and Cosign verification should be skipped.
	CosignSigURL string `json:"cosign_sig_url,omitempty"`
	// CosignPubKey is the Cosign public key (PEM text) to verify this entry's
	// signature against. Only ever set for source="custom" - the admin
	// manually enters it when adding the custom source (see
	// db.CreateCustomSource; deliberately NOT auto-read from the repo itself,
	// to avoid trust-on-first-use - a repo compromise that swaps its key
	// can't silently take over verification). Empty for official/community,
	// which always verify against the embedded key in modules.VerifyCosign.
	CosignPubKey  string `json:"cosign_pubkey,omitempty"`
	Category      string `json:"category"`
	LatestVersion string `json:"latest_version,omitempty"`
	// Description is a map of language code → short blurb, taken from the
	// module's own manifest.yaml (same shape as manifest.yaml's display_name -
	// see Manifest.Description in installer.go). Official modules carry it in
	// registry.json (copied there at release time by build-module.sh);
	// community modules have it read directly since Core already fetches
	// their manifest.yaml during sync (see FetchCommunityRegistry in
	// github.go). The frontend resolves the right language with an
	// en-fallback lookup, mirroring how display_name is already resolved for
	// installed modules (AppShell.tsx).
	Description map[string]string `json:"description,omitempty"`
	// DisplayName is a map of language code → human-readable module name,
	// same shape/purpose as Description - falls back to Name in the
	// frontend when absent (see StorePage.tsx).
	DisplayName map[string]string `json:"display_name,omitempty"`
	// LogoURL is an absolute URL to the module's logo image, or empty when
	// the module ships none - the frontend falls back to the ModuLab mark
	// in that case. Built by build-module.sh for official modules (written
	// straight into registry.json) and by FetchCommunityRegistry for
	// community modules (github.go).
	LogoURL string `json:"logo_url,omitempty"`
	// BrowseURL is the "view on GitHub" link. For official modules this
	// points at the module's own subdirectory in the monorepo (SourceRepo
	// alone would only link to the repo root); for community modules it's
	// empty and the frontend falls back to SourceRepo, which already points
	// at the module's own dedicated repo.
	BrowseURL     string          `json:"browse_url,omitempty"`
	ManifestCache json.RawMessage `json:"manifest,omitempty"`
	SyncedAt      time.Time       `json:"synced_at"`
}

// UpsertEntry inserts or fully replaces a registry entry. Called by the sync
// goroutine (sync.go) after fetching fresh data from GitHub.
func UpsertEntry(ctx context.Context, pool *db.Pool, e Entry) error {
	manifest := []byte("{}")
	if len(e.ManifestCache) > 0 {
		manifest = e.ManifestCache
	}
	description := []byte("{}")
	if len(e.Description) > 0 {
		b, err := json.Marshal(e.Description)
		if err != nil {
			return fmt.Errorf("store: marshal description for %q: %w", e.Name, err)
		}
		description = b
	}
	displayName := []byte("{}")
	if len(e.DisplayName) > 0 {
		b, err := json.Marshal(e.DisplayName)
		if err != nil {
			return fmt.Errorf("store: marshal display_name for %q: %w", e.Name, err)
		}
		displayName = b
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO module_registry
		    (name, source, source_repo, release_asset, cosign_sig_url, cosign_pubkey, category, latest_version, description, display_name, logo_url, browse_url, manifest_cache, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
		ON CONFLICT (name) DO UPDATE SET
		    source         = EXCLUDED.source,
		    source_repo    = EXCLUDED.source_repo,
		    release_asset  = EXCLUDED.release_asset,
		    cosign_sig_url = EXCLUDED.cosign_sig_url,
		    cosign_pubkey  = EXCLUDED.cosign_pubkey,
		    category       = EXCLUDED.category,
		    latest_version = EXCLUDED.latest_version,
		    description    = EXCLUDED.description,
		    display_name   = EXCLUDED.display_name,
		    logo_url       = EXCLUDED.logo_url,
		    browse_url     = EXCLUDED.browse_url,
		    manifest_cache = EXCLUDED.manifest_cache,
		    synced_at      = now()
	`, e.Name, e.Source, e.SourceRepo, e.ReleaseAsset, nullableString(e.CosignSigURL), nullableString(e.CosignPubKey), e.Category,
		nullableString(e.LatestVersion), description, displayName, nullableString(e.LogoURL),
		nullableString(e.BrowseURL), manifest)
	if err != nil {
		return fmt.Errorf("store: upsert entry %q: %w", e.Name, err)
	}
	return nil
}

// ListEntries returns all registry entries, newest sync first.
// Optional filter: source ("official" | "community" | "" for all),
// category ("" for all).
func ListEntries(ctx context.Context, pool *db.Pool, source, category string) ([]Entry, error) {
	query := `
		SELECT name, source, source_repo, release_asset, COALESCE(cosign_sig_url, ''), COALESCE(cosign_pubkey, ''), category,
		       COALESCE(latest_version, ''), description, display_name, COALESCE(logo_url, ''),
		       COALESCE(browse_url, ''), manifest_cache, synced_at
		FROM module_registry
		WHERE ($1 = '' OR source = $1)
		  AND ($2 = '' OR category = $2)
		ORDER BY name ASC
	`
	rows, err := pool.Query(ctx, query, source, category)
	if err != nil {
		return nil, fmt.Errorf("store: list entries: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var manifest, description, displayName []byte
		if err := rows.Scan(&e.Name, &e.Source, &e.SourceRepo, &e.ReleaseAsset, &e.CosignSigURL, &e.CosignPubKey,
			&e.Category, &e.LatestVersion, &description, &displayName, &e.LogoURL, &e.BrowseURL,
			&manifest, &e.SyncedAt); err != nil {
			return nil, fmt.Errorf("store: scan entry: %w", err)
		}
		e.ManifestCache = json.RawMessage(manifest)
		if len(description) > 0 {
			if err := json.Unmarshal(description, &e.Description); err != nil {
				return nil, fmt.Errorf("store: unmarshal description for %q: %w", e.Name, err)
			}
		}
		if len(displayName) > 0 {
			if err := json.Unmarshal(displayName, &e.DisplayName); err != nil {
				return nil, fmt.Errorf("store: unmarshal display_name for %q: %w", e.Name, err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEntry returns a single registry entry by name.
// Returns (Entry{}, false, nil) when the name is not found.
func GetEntry(ctx context.Context, pool *db.Pool, name string) (Entry, bool, error) {
	var e Entry
	var manifest, description, displayName []byte
	err := pool.QueryRow(ctx, `
		SELECT name, source, source_repo, release_asset, COALESCE(cosign_sig_url, ''), COALESCE(cosign_pubkey, ''), category,
		       COALESCE(latest_version, ''), description, display_name, COALESCE(logo_url, ''),
		       COALESCE(browse_url, ''), manifest_cache, synced_at
		FROM module_registry
		WHERE name = $1
	`, name).Scan(&e.Name, &e.Source, &e.SourceRepo, &e.ReleaseAsset, &e.CosignSigURL, &e.CosignPubKey,
		&e.Category, &e.LatestVersion, &description, &displayName, &e.LogoURL, &e.BrowseURL,
		&manifest, &e.SyncedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Entry{}, false, nil
		}
		return Entry{}, false, fmt.Errorf("store: get entry %q: %w", name, err)
	}
	e.ManifestCache = json.RawMessage(manifest)
	if len(description) > 0 {
		if err := json.Unmarshal(description, &e.Description); err != nil {
			return Entry{}, false, fmt.Errorf("store: unmarshal description for %q: %w", name, err)
		}
	}
	if len(displayName) > 0 {
		if err := json.Unmarshal(displayName, &e.DisplayName); err != nil {
			return Entry{}, false, fmt.Errorf("store: unmarshal display_name for %q: %w", name, err)
		}
	}
	return e, true, nil
}

// LastSyncedAt returns when any entry was last synced, or the zero time if
// the registry is empty (never synced). Used by the /v1/store response to
// show the admin when the cache was last refreshed.
func LastSyncedAt(ctx context.Context, pool *db.Pool) (time.Time, error) {
	var t time.Time
	err := pool.QueryRow(ctx, `SELECT MAX(synced_at) FROM module_registry`).Scan(&t)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("store: last synced at: %w", err)
	}
	return t, nil
}

// DeleteEntriesBySourceRepo removes module_registry rows for a given
// source_repo (source='custom' only - official/community never call this),
// skipping any that are currently installed so their metadata stays
// available (same "keep if installed" rule as pruneStaleEntries in sync.go).
// Called right after an admin deletes a custom_sources row, so the Store list
// reflects the removal immediately instead of waiting for the next sync.
func DeleteEntriesBySourceRepo(ctx context.Context, pool *db.Pool, sourceRepo string) error {
	rows, err := pool.Query(ctx, `
		SELECT name FROM module_registry WHERE source = 'custom' AND source_repo = $1
	`, sourceRepo)
	if err != nil {
		return fmt.Errorf("store: list entries for source_repo %q: %w", sourceRepo, err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return fmt.Errorf("store: scan entry name: %w", err)
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		var installed bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM installed_modules WHERE name = $1)`, name,
		).Scan(&installed); err != nil {
			return fmt.Errorf("store: check installed %q: %w", name, err)
		}
		if installed {
			continue
		}
		if _, err := pool.Exec(ctx, `DELETE FROM module_registry WHERE name = $1`, name); err != nil {
			return fmt.Errorf("store: delete entry %q: %w", name, err)
		}
	}
	return nil
}

// nullableString returns nil when s is empty so Postgres stores NULL instead
// of an empty string in nullable TEXT columns (latest_version).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
