package store

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// defaultSyncIntervalSeconds is SyncIntervalSeconds's fallback - mirrors the
// fixed 1h value this replaced.
const defaultSyncIntervalSeconds = 3600

// SyncIntervalSeconds reads the registry-sync interval (seconds) from
// core_settings ("store_sync_interval_seconds"), same pattern as
// modules.MaxUploadBodyBytes. Defaults to defaultSyncIntervalSeconds if
// unset. Exposed to callers outside this package (e.g. a future
// GET /v1/admin/system/info countdown) via SyncInterval below.
func SyncIntervalSeconds(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, "store_sync_interval_seconds")
	if err != nil || !ok || val == "" {
		return defaultSyncIntervalSeconds
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultSyncIntervalSeconds
	}
	return n
}

// SyncInterval is SyncIntervalSeconds as a time.Duration, for callers that
// want it pre-converted (e.g. an admin "next sync in X" countdown).
func SyncInterval(ctx context.Context, pool *db.Pool) time.Duration {
	return time.Duration(SyncIntervalSeconds(ctx, pool)) * time.Second
}

// onSynced is called after every sync attempt (manual or scheduled),
// regardless of whether it fully succeeded — a partial sync (one source
// failed) still persists whatever it did manage to fetch, and running a
// module-update check against that partial-but-fresher cache is harmless
// even in the worst case (it just won't find anything new for the module(s)
// whose source failed). May be nil, in which case it is simply not called;
// this package cannot depend on modules (it imports store, not the other way
// around), so the check itself lives there — see modules.RunUpdateCheckOnce.
type onSyncedFunc func(ctx context.Context)

// RunSync is the long-running background goroutine for registry synchronisation.
// It runs once immediately on startup, then again every SyncInterval (default
// 1h, admin-configurable via store_sync_interval_seconds). Designed to be
// started with `go store.RunSync(ctx, deps, onSynced)` from main.go, mirroring
// the same pattern as mail.RunWorker. Stopping ctx stops the goroutine cleanly.
//
// Uses a manually re-armed time.Timer instead of a time.Ticker: a Ticker's
// period is fixed at creation and Go's stdlib has no way to change it short
// of Reset, so re-reading the current interval fresh before each Reset (via
// SyncIntervalSeconds) is how an admin's change to the setting takes effect
// on the very next cycle instead of requiring a Core restart.
func RunSync(ctx context.Context, d Deps, onSynced onSyncedFunc) {
	// Run immediately on first start so the store is populated before any
	// admin opens the UI, rather than showing an empty list for up to the
	// full interval.
	runSync(ctx, d, onSynced)

	timer := time.NewTimer(SyncInterval(ctx, d.Pool))
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			runSync(ctx, d, onSynced)
			timer.Reset(SyncInterval(ctx, d.Pool))
		case <-ctx.Done():
			return
		}
	}
}

// TriggerSync performs a one-off manual sync. Called by POST /v1/store/sync.
// Returns an error summary if any source failed; partial results are still
// persisted so the cache reflects whatever was reachable. onSynced still
// runs even on a partial/full failure — see onSyncedFunc's doc comment.
func TriggerSync(ctx context.Context, d Deps, onSynced onSyncedFunc) error {
	customErrs, offErr, comErr := syncAll(ctx, d)
	if onSynced != nil {
		onSynced(ctx)
	}
	var parts []string
	if offErr != nil {
		parts = append(parts, fmt.Sprintf("official: %v", offErr))
	}
	if comErr != nil {
		parts = append(parts, fmt.Sprintf("community: %v", comErr))
	}
	for name, err := range customErrs {
		parts = append(parts, fmt.Sprintf("custom (%s): %v", name, err))
	}
	if len(parts) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}

// runSync is the internal sync driver. Errors are logged but never fatal —
// the hourly goroutine must keep running regardless of transient GitHub outages.
func runSync(ctx context.Context, d Deps, onSynced onSyncedFunc) {
	customErrs, offErr, comErr := syncAll(ctx, d)
	if offErr != nil {
		log.Printf("store: sync: official registry: %v", offErr)
	}
	if comErr != nil {
		log.Printf("store: sync: community registry: %v", comErr)
	}
	for name, err := range customErrs {
		log.Printf("store: sync: custom source %q: %v", name, err)
	}
	if offErr == nil && comErr == nil && len(customErrs) == 0 {
		log.Printf("store: sync: completed successfully")
	}
	if onSynced != nil {
		onSynced(ctx)
	}
}

// syncAll fetches and persists entries from every source: official,
// community, and every admin-added custom_sources row. Each source is
// independent: a failure on one does not prevent the others from being
// updated. After upserting, stale entries that no longer appear in any
// source are pruned from the DB so deleted modules don't linger in the store
// UI. customErrs maps a custom source's repo_url to its fetch error, for
// sources that failed - a nil/empty map means all custom sources synced fine.
func syncAll(ctx context.Context, d Deps) (customErrs map[string]error, offErr, comErr error) {
	seen := make(map[string]bool)

	// ── Official ────────────────────────────────────────────────────────────
	official, err := FetchOfficialRegistry(ctx, d.Pool)
	if err != nil {
		offErr = err
	} else {
		for _, e := range official {
			if err := UpsertEntry(ctx, d.Pool, e); err != nil {
				log.Printf("store: sync: upsert official %q: %v", e.Name, err)
			} else {
				seen[e.Name] = true
			}
		}
	}

	// ── Community ───────────────────────────────────────────────────────────
	community, err := FetchCommunityRegistry(ctx, d.Pool)
	if err != nil {
		comErr = err
	} else {
		for _, e := range community {
			// Community entries don't carry a version in the index — fetch it
			// from the GitHub Releases API so the store can show "v1.2.0".
			if e.LatestVersion == "" {
				version, err := FetchLatestRelease(ctx, d.Pool, e.SourceRepo, "")
				if err != nil {
					log.Printf("store: sync: latest release for %q: %v", e.Name, err)
				} else {
					e.LatestVersion = version
				}
			}
			if err := UpsertEntry(ctx, d.Pool, e); err != nil {
				log.Printf("store: sync: upsert community %q: %v", e.Name, err)
			} else {
				seen[e.Name] = true
			}
		}
	}

	// ── Custom (admin-added) ────────────────────────────────────────────────
	customSources, err := d.Pool.ListCustomSources(ctx)
	if err != nil {
		log.Printf("store: sync: list custom_sources: %v", err)
	}
	for _, cs := range customSources {
		// entries: 1 for a single-module repo, N for a monorepo (see
		// FetchCustomRepo's doc comment) - all share this source's repo_url
		// and pubkey.
		entries, err := FetchCustomRepo(ctx, d.Pool, cs.RepoURL, cs.PubKey, cs.Token)
		if err != nil {
			if customErrs == nil {
				customErrs = make(map[string]error)
			}
			customErrs[cs.RepoURL] = err
			continue
		}
		for _, entry := range entries {
			if err := UpsertEntry(ctx, d.Pool, entry); err != nil {
				log.Printf("store: sync: upsert custom %q: %v", entry.Name, err)
			} else {
				seen[entry.Name] = true
			}
		}
	}

	// ── Prune stale entries ─────────────────────────────────────────────────
	// Only prune when at least one source succeeded — if everything failed we
	// have no reliable "current" list and must not wipe the cache. "Succeeded"
	// for custom sources means at least one of them is in seen (an admin with
	// zero custom sources configured trivially satisfies this - there was
	// nothing to fail).
	anySucceeded := offErr == nil || comErr == nil || len(customErrs) < len(customSources)
	if anySucceeded {
		if err := pruneStaleEntries(ctx, d, seen); err != nil {
			log.Printf("store: sync: prune stale entries: %v", err)
		}
	}

	return customErrs, offErr, comErr
}

// pruneStaleEntries deletes registry rows whose names are not in the seen set.
// Modules that are currently installed are never deleted from the registry so
// their metadata (version, source_repo) remains available for the UI even if
// the upstream listing was temporarily unavailable.
func pruneStaleEntries(ctx context.Context, d Deps, seen map[string]bool) error {
	// Build a list of all registry names.
	rows, err := d.Pool.Query(ctx, `SELECT name FROM module_registry`)
	if err != nil {
		return fmt.Errorf("query names: %w", err)
	}
	var stale []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan name: %w", err)
		}
		if !seen[name] {
			stale = append(stale, name)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	for _, name := range stale {
		// Skip modules that are installed — keep their registry row intact.
		var installed bool
		if err := d.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM installed_modules WHERE name = $1)`, name,
		).Scan(&installed); err != nil {
			log.Printf("store: sync: prune check installed %q: %v", name, err)
			continue
		}
		if installed {
			log.Printf("store: sync: keeping stale registry entry %q (still installed)", name)
			continue
		}
		if _, err := d.Pool.Exec(ctx, `DELETE FROM module_registry WHERE name = $1`, name); err != nil {
			log.Printf("store: sync: delete stale entry %q: %v", name, err)
		} else {
			log.Printf("store: sync: pruned stale entry %q (no longer in registry)", name)
		}
	}
	return nil
}
