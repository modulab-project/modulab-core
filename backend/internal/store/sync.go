package store

import (
	"context"
	"fmt"
	"log"
	"time"
)

const syncInterval = 1 * time.Hour

// RunSync is the long-running background goroutine for registry synchronisation.
// It runs once immediately on startup, then again every hour. Designed to
// be started with `go store.RunSync(ctx, deps)` from main.go, mirroring the
// same pattern as mail.RunWorker. Stopping ctx stops the goroutine cleanly.
func RunSync(ctx context.Context, d Deps) {
	// Run immediately on first start so the store is populated before any
	// admin opens the UI, rather than showing an empty list for up to 1h.
	runSync(ctx, d)

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runSync(ctx, d)
		case <-ctx.Done():
			return
		}
	}
}

// TriggerSync performs a one-off manual sync. Called by POST /v1/store/sync.
// Returns an error summary if either source failed; partial results are still
// persisted so the cache reflects whatever was reachable.
func TriggerSync(ctx context.Context, d Deps) error {
	offErr, comErr := syncBoth(ctx, d)
	if offErr != nil && comErr != nil {
		return fmt.Errorf("official: %v; community: %v", offErr, comErr)
	}
	if offErr != nil {
		return fmt.Errorf("official registry sync failed: %w", offErr)
	}
	if comErr != nil {
		return fmt.Errorf("community registry sync failed: %w", comErr)
	}
	return nil
}

// runSync is the internal sync driver. Errors are logged but never fatal —
// the hourly goroutine must keep running regardless of transient GitHub outages.
func runSync(ctx context.Context, d Deps) {
	offErr, comErr := syncBoth(ctx, d)
	if offErr != nil {
		log.Printf("store: sync: official registry: %v", offErr)
	}
	if comErr != nil {
		log.Printf("store: sync: community registry: %v", comErr)
	}
	if offErr == nil && comErr == nil {
		log.Printf("store: sync: completed successfully")
	}
}

// syncBoth fetches and persists entries from both sources. Each source is
// independent: a failure on one does not prevent the other from being updated.
// After upserting, stale entries that no longer appear in either registry are
// pruned from the DB so deleted modules don't linger in the store UI.
func syncBoth(ctx context.Context, d Deps) (offErr, comErr error) {
	seen := make(map[string]bool)

	// ── Official ────────────────────────────────────────────────────────────
	official, err := FetchOfficialRegistry(ctx)
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
	community, err := FetchCommunityRegistry(ctx)
	if err != nil {
		comErr = err
	} else {
		for _, e := range community {
			// Community entries don't carry a version in the index — fetch it
			// from the GitHub Releases API so the store can show "v1.2.0".
			if e.LatestVersion == "" {
				version, err := FetchLatestRelease(ctx, e.SourceRepo)
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

	// ── Prune stale entries ─────────────────────────────────────────────────
	// Only prune when at least one source succeeded — if both failed we have
	// no reliable "current" list and must not wipe the cache.
	if offErr == nil || comErr == nil {
		if err := pruneStaleEntries(ctx, d, seen); err != nil {
			log.Printf("store: sync: prune stale entries: %v", err)
		}
	}

	return offErr, comErr
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
