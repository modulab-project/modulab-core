// Package search is the web-search orchestration layer: it owns provider
// selection (primary + optional fallback), per-request timeouts, and
// dispatches to whichever provider-specific client actually talks HTTP
// (internal/searxng for SearXNG, serper.go in this package for Serper.dev).
//
// This replaces the old internal/searxng package's admin/user HTTP handlers
// and single-provider config (searxng_url_enc et al. in core_settings) -
// see db.MigrateSearchProviders for the one-time move of that data into the
// search_providers table. internal/searxng itself now only implements the
// low-level SearXNG protocol client (FetchResults, Ping) and no longer knows
// about ModuLab's config layer at all.
//
// Endpoints (spec section 6.4, search widget):
//
//	GET /v1/search/web?q=<query>             → []searxng.WebResult (any approved session)
//	GET  /v1/search/providers                → []UserProviderResponse (any approved session)
//	PUT  /v1/user/search/keys/{id}            → 204 (set own key for a provider)
//	DELETE /v1/user/search/keys/{id}          → 204 (remove own key)
//	GET|POST /v1/user/search-prefs            → SearchPrefs (safesearch/language)
//
//	GET  /v1/admin/search/providers           → []ProviderResponse (super-admin)
//	PATCH /v1/admin/search/providers/{id}     → ProviderResponse
//	DELETE /v1/admin/search/providers/{id}/key → 204 (clear admin key only)
//	GET|PATCH /v1/admin/search/settings       → SettingsResponse (primary/fallback/timeouts)
package search

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/searxng"
)

// ErrNotConfigured is returned by Fetch when no enabled search provider has
// a usable credential/URL at all (as opposed to one erroring at request
// time). SearchHandler maps this to 503, same status the old
// searxng-only handler used for "not configured".
var ErrNotConfigured = errors.New("search: no provider configured")

const (
	// defaultSearchTimeoutSeconds mirrors what the old
	// searxng_search_timeout_seconds default used to be, bumped slightly
	// (2s → 5s): now that this bound is shared across every provider type,
	// not just a fast hosted API like Serper but also a self-hosted SearXNG
	// instance on modest homelab hardware, 2s proved too tight in practice.
	// Existing installs keep whatever value they already had - this only
	// affects brand-new installs (see db.MigrateSearchProviders, which
	// copies a previously-configured value over verbatim).
	defaultSearchTimeoutSeconds = 5
	// defaultFallbackTimeoutSeconds bounds how long the *primary* provider
	// gets before Fetch gives up on it and tries the fallback, when one is
	// configured. Intentionally shorter than defaultSearchTimeoutSeconds so
	// a dead primary fails fast instead of making every search wait out the
	// full timeout before the fallback ever gets a turn.
	defaultFallbackTimeoutSeconds = 3

	settingKeyTimeout         = "search_timeout_seconds"
	settingKeyFallbackTimeout = "search_fallback_timeout_seconds"
	settingKeyPrimary         = "search_primary_provider_id"
	settingKeyFallback        = "search_fallback_provider_id"
)

func resolveIntSetting(ctx context.Context, pool *db.Pool, key string, def int) int {
	val, ok, err := pool.GetSetting(ctx, key)
	if err != nil || !ok || val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// SearchTimeoutSeconds reads the shared, provider-agnostic search timeout
// (core_settings "search_timeout_seconds"). Exported so adminapi.limits can
// surface it alongside every other operational timeout.
func SearchTimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	return resolveIntSetting(ctx, pool, settingKeyTimeout, defaultSearchTimeoutSeconds)
}

// FallbackTimeoutSeconds reads how long the primary provider gets before
// Fetch switches to the fallback provider (only relevant when a fallback is
// configured at all).
func FallbackTimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	return resolveIntSetting(ctx, pool, settingKeyFallbackTimeout, defaultFallbackTimeoutSeconds)
}

// PrimaryProviderID returns the configured primary provider id, defaulting
// to "searxng" (the only provider that existed before this feature).
func PrimaryProviderID(ctx context.Context, pool *db.Pool) string {
	id, ok, err := pool.GetSetting(ctx, settingKeyPrimary)
	if err != nil || !ok || id == "" {
		return "searxng"
	}
	return id
}

// FallbackProviderID returns the configured fallback provider id, or "" if
// none is set (fallback is optional - see FetchSettingsRequest.FallbackID).
func FallbackProviderID(ctx context.Context, pool *db.Pool) string {
	id, _, _ := pool.GetSetting(ctx, settingKeyFallback)
	return id
}

// Fetch resolves the primary (and, if configured, fallback) provider and
// returns results from whichever one succeeds first. userID is used to
// resolve a per-user key override for providers that allow it (Serper).
//
// Ordering/timeout rule (see FallbackTimeoutSeconds's doc comment): when a
// fallback is configured, the primary attempt is capped at
// FallbackTimeoutSeconds so a dead/slow primary doesn't eat the whole
// request budget before the fallback ever runs; the (last) attempt in the
// chain always gets the full SearchTimeoutSeconds.
func Fetch(ctx context.Context, pool *db.Pool, userID, query, category string, sp searxng.SearchParams) ([]searxng.WebResult, error) {
	primaryID := PrimaryProviderID(ctx, pool)
	fallbackID := FallbackProviderID(ctx, pool)

	ids := make([]string, 0, 2)
	if primaryID != "" {
		ids = append(ids, primaryID)
	}
	if fallbackID != "" && fallbackID != primaryID {
		ids = append(ids, fallbackID)
	}

	baseTimeout := SearchTimeoutSeconds(ctx, pool)
	cutoffTimeout := FallbackTimeoutSeconds(ctx, pool)

	var lastErr error
	attempted := false
	for i, id := range ids {
		row, found, err := pool.GetSearchProvider(ctx, id)
		if err != nil || !found || !row.Enabled {
			continue
		}
		timeout := baseTimeout
		if i < len(ids)-1 {
			timeout = cutoffTimeout
		}
		results, err := fetchFromProvider(ctx, pool, userID, row, query, category, timeout, sp)
		if err != nil {
			attempted = true
			lastErr = err
			continue
		}
		return results, nil
	}
	if !attempted {
		return nil, ErrNotConfigured
	}
	return nil, lastErr
}

// fetchFromProvider dispatches to the right protocol client based on the
// provider row's type. Adding a new provider type means adding a case here
// plus its own client file (see serper.go) - the DB schema, admin/user
// handlers, and Fetch's fallback logic above all stay generic.
func fetchFromProvider(ctx context.Context, pool *db.Pool, userID string, row db.SearchProviderRow, query, category string, timeoutSeconds int, sp searxng.SearchParams) ([]searxng.WebResult, error) {
	switch row.Type {
	case "searxng":
		if row.BaseURL == "" {
			return nil, fmt.Errorf("searxng: no base URL configured")
		}
		sp.Category = category
		return searxng.FetchResults(ctx, row.BaseURL, query, row.MaxResults, row.FetchPages, timeoutSeconds, sp)

	case "serper":
		key, err := pool.ResolveSearchKey(ctx, userID, row.ID)
		if err != nil {
			return nil, fmt.Errorf("serper: resolve key: %w", err)
		}
		if key == "" {
			return nil, fmt.Errorf("serper: no API key configured")
		}
		return fetchSerper(ctx, key, query, category, row.MaxResults, sp, timeoutSeconds)

	default:
		return nil, fmt.Errorf("search: unsupported provider type %q", row.Type)
	}
}
