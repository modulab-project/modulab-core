package modules

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
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

// CheckUpdates compares every installed module against the registry cache and
// records any newer version in installed_modules.available_version.
// Returns the list of modules that have an update waiting.
//
// This is called both by the background store sync goroutine (store/sync.go)
// and on demand via POST /v1/modules/updates (see handlers.go).
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
