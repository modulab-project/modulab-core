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
	Source       string `json:"source"` // "official" | "community"
	SourceRepo   string `json:"source_repo"`
	ReleaseAsset string `json:"release_asset"`
	// CosignSigURL is the URL of the Cosign signature file. Empty string means
	// no signature is available and Cosign verification should be skipped.
	CosignSigURL  string          `json:"cosign_sig_url,omitempty"`
	Category      string          `json:"category"`
	LatestVersion string          `json:"latest_version,omitempty"`
	// Description is a map of language code → short blurb, taken from the
	// module's own manifest.yaml (same shape as manifest.yaml's display_name -
	// see Manifest.Description in installer.go). Official modules carry it in
	// registry.json (copied there at release time by build-module.sh);
	// community modules have it read directly since Core already fetches
	// their manifest.yaml during sync (see FetchCommunityRegistry in
	// github.go). The frontend resolves the right language with an
	// en-fallback lookup, mirroring how display_name is already resolved for
	// installed modules (AppShell.tsx).
	Description   map[string]string `json:"description,omitempty"`
	ManifestCache json.RawMessage   `json:"manifest,omitempty"`
	SyncedAt      time.Time         `json:"synced_at"`
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
	_, err := pool.Exec(ctx, `
		INSERT INTO module_registry
		    (name, source, source_repo, release_asset, cosign_sig_url, category, latest_version, description, manifest_cache, synced_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (name) DO UPDATE SET
		    source         = EXCLUDED.source,
		    source_repo    = EXCLUDED.source_repo,
		    release_asset  = EXCLUDED.release_asset,
		    cosign_sig_url = EXCLUDED.cosign_sig_url,
		    category       = EXCLUDED.category,
		    latest_version = EXCLUDED.latest_version,
		    description    = EXCLUDED.description,
		    manifest_cache = EXCLUDED.manifest_cache,
		    synced_at      = now()
	`, e.Name, e.Source, e.SourceRepo, e.ReleaseAsset, nullableString(e.CosignSigURL), e.Category,
		nullableString(e.LatestVersion), description, manifest)
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
		SELECT name, source, source_repo, release_asset, COALESCE(cosign_sig_url, ''), category,
		       COALESCE(latest_version, ''), description, manifest_cache, synced_at
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
		var manifest, description []byte
		if err := rows.Scan(&e.Name, &e.Source, &e.SourceRepo, &e.ReleaseAsset, &e.CosignSigURL,
			&e.Category, &e.LatestVersion, &description, &manifest, &e.SyncedAt); err != nil {
			return nil, fmt.Errorf("store: scan entry: %w", err)
		}
		e.ManifestCache = json.RawMessage(manifest)
		if len(description) > 0 {
			if err := json.Unmarshal(description, &e.Description); err != nil {
				return nil, fmt.Errorf("store: unmarshal description for %q: %w", e.Name, err)
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
	var manifest, description []byte
	err := pool.QueryRow(ctx, `
		SELECT name, source, source_repo, release_asset, COALESCE(cosign_sig_url, ''), category,
		       COALESCE(latest_version, ''), description, manifest_cache, synced_at
		FROM module_registry
		WHERE name = $1
	`, name).Scan(&e.Name, &e.Source, &e.SourceRepo, &e.ReleaseAsset, &e.CosignSigURL,
		&e.Category, &e.LatestVersion, &description, &manifest, &e.SyncedAt)
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

// nullableString returns nil when s is empty so Postgres stores NULL instead
// of an empty string in nullable TEXT columns (latest_version).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
