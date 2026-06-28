package modules

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// Uninstall removes the module from the system:
//  1. Guard: module must be installed and not pinned
//  2. Mark status "isolated" (stops serving traffic, pre-v1 stub)
//  3. Deno worker shutdown (post-v1 stub)
//  4. Delete module files from DataDir/{name}
//  5. Delete cached rollback ZIP if present
//  6. Remove DB row
//
// The module's own DB schema (if it has one) is intentionally left in place
// after uninstall, following the same convention as most plugin systems: data
// preservation on uninstall, explicit purge only on request. A future
// /v1/modules/{name}/purge endpoint will handle schema drops.
func Uninstall(ctx context.Context, d Deps, name string) error {
	// ── 1. Guard ──────────────────────────────────────────────────────────
	row, exists, err := d.DB.GetInstalledModule(ctx, name)
	if err != nil {
		return fmt.Errorf("modules: uninstall %q: lookup: %w", name, err)
	}
	if !exists {
		return fmt.Errorf("modules: uninstall %q: not installed", name)
	}
	if row.Pinned {
		return fmt.Errorf("modules: uninstall %q: module is pinned — unpin it first", name)
	}
	if row.Status == db.ModuleStatusInstalling {
		return fmt.Errorf("modules: uninstall %q: installation is still in progress", name)
	}

	// ── 2. Isolate (mark offline before touching files) ───────────────────
	if _, err := d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusIsolated); err != nil {
		return fmt.Errorf("modules: uninstall %q: mark isolated: %w", name, err)
	}

	// ── 3. Deno worker shutdown ───────────────────────────────────────────
	// TODO(post-v1): signal the Deno IPC bus to stop the worker for this module.

	// ── 4. Remove module files ────────────────────────────────────────────
	moduleDir := filepath.Join(d.DataDir, name)
	if err := os.RemoveAll(moduleDir); err != nil {
		// Failure here is logged but does not abort — we still want the DB
		// row gone so the module can be re-installed cleanly.
		log.Printf("modules: uninstall %q: warning: remove files %q: %v", name, moduleDir, err)
	} else {
		log.Printf("modules: uninstall %q: removed files from %s", name, moduleDir)
	}

	// ── 5. Delete cached rollback ZIP ─────────────────────────────────────
	if row.CachedZipPath != nil && *row.CachedZipPath != "" {
		if err := os.Remove(*row.CachedZipPath); err != nil && !os.IsNotExist(err) {
			log.Printf("modules: uninstall %q: warning: remove cached zip %q: %v",
				name, *row.CachedZipPath, err)
		}
	}

	// ── 6. Remove DB row ──────────────────────────────────────────────────
	if _, err := d.DB.DeleteInstalledModule(ctx, name); err != nil {
		return fmt.Errorf("modules: uninstall %q: delete db row: %w", name, err)
	}

	log.Printf("modules: uninstalled %q (was version %s, tier %d)", name, row.Version, row.Tier)
	return nil
}
