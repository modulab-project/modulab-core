package modules

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	"github.com/modulab-project/modulab-core/backend/internal/store"
)

// UpdateInfo describes a single module that has an update available.
// Returned by CheckUpdates and serialised as the GET /v1/modules/updates response.
type UpdateInfo struct {
	Name             string    `json:"name"`
	InstalledVersion string    `json:"installed_version"`
	AvailableVersion string    `json:"available_version"`
	Source           string    `json:"source"`
	LastChecked      time.Time `json:"last_checked"`
}

// updateCheckInterval is how often RunUpdateChecks re-compares installed
// modules against the registry cache in the background. 15 minutes was
// chosen over store.syncInterval's 1h (the registry-listing sync — a
// different, slower-moving thing, see store/sync.go) because a fresh
// GitHub release should become visible in ModuLab reasonably quickly
// without the admin needing to know to click "check updates" — reported by
// the user 2026-07-04 ("dauert manchmal bis zu 15 min das ich es in
// ModuLab sehe", at a time when there was in fact no background check at
// all, only the manual button and the unrelated hourly registry sync).
const updateCheckInterval = 15 * time.Minute

// RunUpdateChecks is the long-running background goroutine that keeps
// installed_modules.available_version current without requiring an admin
// to click "check updates" or reload the page. Mirrors store.RunSync's
// shape exactly (run once immediately, then on a ticker, stop on ctx.Done).
//
// Before this existed, CheckUpdates only ever ran from the manual
// POST /v1/modules/updates handler — an admin publishing a new GitHub
// release for a module had no way to see it in ModuLab except clicking
// that button (or restarting Core), regardless of store.RunSync's hourly
// registry-listing sync having already picked up the new LatestVersion.
func RunUpdateChecks(ctx context.Context, d Deps, storeDeps store.Deps) {
	runUpdateCheck(ctx, d, storeDeps)

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runUpdateCheck(ctx, d, storeDeps)
		case <-ctx.Done():
			return
		}
	}
}

// runUpdateCheck runs one CheckUpdates pass and, if it found anything new,
// publishes a single "module.updates_available" event to notify.AdminChannel
// so every currently-connected admin session's SSE stream (auth/events.go)
// picks it up live — the same delivery path already used for "user.pending".
// A background pass that finds nothing new does not publish anything: there
// is no "still zero updates" event, matching user.pending's pattern of only
// ever announcing a change, not a steady state.
func runUpdateCheck(ctx context.Context, d Deps, storeDeps store.Deps) {
	updates, err := CheckUpdates(ctx, d, storeDeps)
	if err != nil {
		log.Printf("modules: background update check: %v", err)
		return
	}
	if len(updates) == 0 || d.Valkey == nil {
		return
	}
	ev := notify.Event{Type: "module.updates_available", Data: map[string]any{"count": len(updates)}}
	if err := notify.Publish(ctx, d.Valkey, notify.AdminChannel(), ev); err != nil {
		log.Printf("modules: background update check: publish event: %v", err)
	}
}

// CheckUpdates compares every installed module against the registry cache and
// records any newer version in installed_modules.available_version.
// Returns the list of modules that have an update waiting.
//
// Called from three places: the background RunUpdateChecks goroutine above,
// on demand via POST /v1/modules/updates (handlers.go, the manual "check
// updates" button), and nowhere else — despite an earlier version of this
// doc comment claiming store/sync.go's registry sync called it too; it never
// did (that goroutine only refreshes the registry listing's LatestVersion,
// a different cache this function reads from).
func CheckUpdates(ctx context.Context, d Deps, storeDeps store.Deps) ([]UpdateInfo, error) {
	installed, err := d.DB.ListInstalledModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("modules: check updates: list installed: %w", err)
	}

	var updates []UpdateInfo
	for _, row := range installed {
		if row.Status == db.ModuleStatusInstalling {
			continue // skip in-flight installs
		}

		// Look up the latest known version in the registry cache.
		entry, ok, err := store.GetEntry(ctx, storeDeps.Pool, row.Name)
		if err != nil {
			log.Printf("modules: check updates: lookup %q in registry: %v", row.Name, err)
			continue
		}
		if !ok || entry.LatestVersion == "" || entry.LatestVersion == row.Version {
			// No registry entry or already on latest → clear stale available_version.
			if row.AvailableVersion != nil && *row.AvailableVersion != "" {
				_ = d.DB.SetModuleAvailableVersion(ctx, row.Name, "")
			}
			continue
		}

		// New version available.
		if err := d.DB.SetModuleAvailableVersion(ctx, row.Name, entry.LatestVersion); err != nil {
			log.Printf("modules: check updates: set available_version %q: %v", row.Name, err)
		}

		updates = append(updates, UpdateInfo{
			Name:             row.Name,
			InstalledVersion: row.Version,
			AvailableVersion: entry.LatestVersion,
			Source:           row.Source,
			LastChecked:      time.Now(),
		})
		log.Printf("modules: update available for %q: %s → %s", row.Name, row.Version, entry.LatestVersion)
	}

	return updates, nil
}

// CircuitBreaker is a placeholder for the Tier 2/3 module circuit breaker
// (spec section 4.9). When a Deno worker crashes repeatedly, the circuit
// breaker transitions the module to ModuleStatusDegraded and prevents
// automatic restart until an operator intervenes.
//
// TODO(post-v1): implement crash counting + exponential back-off once the
// Deno worker IPC bus (internal/modules/deno.go) is in place.
type CircuitBreaker struct{}
