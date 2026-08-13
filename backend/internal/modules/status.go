package modules

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
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

// RunUpdateCheckOnce runs a single CheckUpdates pass and, if it found
// anything new, publishes a "module.updates_available" event to
// notify.AdminChannel so every currently-connected admin session's SSE
// stream (auth/events.go) picks it up live — the same delivery path already
// used for "user.pending". A pass that finds nothing new does not publish
// anything: there is no "still zero updates" event, matching user.pending's
// pattern of only ever announcing a change, not a steady state.
//
// Called from store.RunSync/store.TriggerSync (via the onStoreSynced
// closure in cmd/core/main.go) right after every registry sync completes -
// manual or the hourly background one. This used to run on its own separate
// 15-minute ticker too (RunUpdateChecks, removed 2026-07-05), but that was
// pure redundancy: the registry cache CheckUpdates compares against only
// ever changes when a sync runs, and a sync already triggers this
// immediately - a standalone timer in between could only ever re-check data
// it had already checked moments (or up to an hour) earlier. Relying solely
// on the sync trigger means one code path instead of two, and the System
// Info page now shows one merged "next check" countdown instead of two
// timers that always converged on the same event anyway.
//
// authDeps (added alongside auto_update support) is threaded through to
// RunAutoUpdates below, which needs it to write an audit_log entry for any
// module it updates in the background - the same auth.Deps every other
// module-lifecycle audit write already uses via logModuleAudit.
func RunUpdateCheckOnce(ctx context.Context, d Deps, storeDeps store.Deps, authDeps auth.Deps) {
	updates, err := CheckUpdates(ctx, d, storeDeps)
	if err != nil {
		log.Printf("modules: update check: %v", err)
		return
	}
	if len(updates) > 0 && d.Valkey != nil {
		ev := notify.Event{Type: "module.updates_available", Data: map[string]any{"count": len(updates)}}
		if err := notify.Publish(ctx, d.Valkey, notify.AdminChannel(), ev); err != nil {
			log.Printf("modules: update check: publish event: %v", err)
		}
	}

	// auto_update-flagged modules are applied right away, on the same cycle
	// the "update available" notification above would otherwise have merely
	// announced them - see RunAutoUpdates' doc comment (updater.go).
	RunAutoUpdates(ctx, d, storeDeps, authDeps, updates)
}

// CheckUpdates compares every installed module against the registry cache and
// records any newer version in installed_modules.available_version.
// Returns the list of modules that have an update waiting.
//
// Called from two places: RunUpdateCheckOnce above (itself triggered right
// after every registry sync) and on demand via POST /v1/modules/updates
// (handlers.go, the manual "check updates" button).
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

// Crash handling (spec section 4.9's circuit breaker) lives in
// WorkerPool.SetCrashHandler (deno.go), not as a separate type here: a
// worker that exits unexpectedly is marked ModuleStatusDegraded and reported
// via notify.AdminChannel, wired up once in main.go. There is deliberately
// no automatic restart-with-backoff — see SetCrashHandler's doc comment for
// why "detect and surface to an admin" was chosen over "detect and
// auto-respawn" for a homelab instance nobody is actively paging on.
