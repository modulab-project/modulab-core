package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/store"
)

// Update upgrades an installed module to the version recorded in the registry
// (entry.LatestVersion). If anything fails after the old ZIP is cached, it
// attempts an automatic rollback to the previous version.
//
// Steps:
//  1. Guard: module installed, not pinned, not already on latest version
//  2. Cache current module ZIP for rollback
//  3. Download new ZIP + SHA256 in parallel
//  4. Verify SHA-256
//  5. Cosign verification (same rules as Install)
//  6. Extract new ZIP
//  7. Parse and validate new manifest
//  8. Copy new files over old files (atomic dir swap via temp)
//  9. Run new module migrations (post-v1 stub)
//
// 10. Update DB row (version, sha256, manifest, status=active)
// 11. Delete cached rollback ZIP on success
func Update(ctx context.Context, d Deps, entry store.Entry) error {
	if entry.LatestVersion == "" {
		return fmt.Errorf("modules: update %q: no target version known", entry.Name)
	}

	// ── 1. Guard ──────────────────────────────────────────────────────────
	row, exists, err := d.DB.GetInstalledModule(ctx, entry.Name)
	if err != nil {
		return fmt.Errorf("modules: update %q: lookup: %w", entry.Name, err)
	}
	if !exists {
		return fmt.Errorf("modules: update %q: not installed", entry.Name)
	}
	if row.Pinned {
		return fmt.Errorf("modules: update %q: module is pinned", entry.Name)
	}
	if row.Version == entry.LatestVersion {
		return fmt.Errorf("modules: update %q: already on latest version %s", entry.Name, row.Version)
	}

	maxZIPBytes := MaxModuleZIPBytes(ctx, d.DB)

	// ── 2. Cache current ZIP for rollback ─────────────────────────────────
	cacheDir := filepath.Join(d.DataDir, ".rollback")
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return fmt.Errorf("modules: update %q: create rollback cache dir: %w", entry.Name, err)
	}
	// Resolved once, fresh from custom_sources - see
	// resolveCustomSourceCredential's doc comment (installer.go) for why this
	// is never carried on entry itself, and githubCredential's for why it is
	// bound to entry.SourceRepo rather than being a bare token.
	cred := resolveCustomSourceCredential(ctx, d.DB, entry.Source, entry.SourceRepo, entry.Name, "update")

	cachedZip := filepath.Join(cacheDir, entry.Name+"-"+row.Version+".zip")
	if err := cacheCurrentZIP(ctx, d.DB, row.ReleaseURL, cachedZip, maxZIPBytes, cred); err != nil {
		// Not fatal — we'll proceed without rollback capability and log a warning.
		log.Printf("modules: update %q: warning: could not cache rollback zip: %v", entry.Name, err)
		cachedZip = ""
	} else {
		if err := d.DB.SetModuleCachedZip(ctx, entry.Name, cachedZip); err != nil {
			log.Printf("modules: update %q: warning: set cached zip in db: %v", entry.Name, err)
		}
	}

	// ── 3. Download new ZIP + SHA256 in parallel ───────────────────────────
	// ReleaseAsset may be a full URL (official modules) or a bare filename.
	var zipURL string
	if strings.HasPrefix(entry.ReleaseAsset, "https://") || strings.HasPrefix(entry.ReleaseAsset, "http://") {
		zipURL = entry.ReleaseAsset
	} else {
		zipURL = entry.SourceRepo + "/releases/download/" + entry.LatestVersion + "/" + entry.ReleaseAsset
	}
	sha256URL := zipURL + ".sha256"
	sigURL := zipURL + ".sig"

	tmpDir, err := os.MkdirTemp("", "modulab-update-"+entry.Name+"-*")
	if err != nil {
		return fmt.Errorf("modules: update %q: create temp dir: %w", entry.Name, err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("modules: update %q: cleanup temp dir %s: %v", entry.Name, tmpDir, err)
		}
	}()

	zipPath := filepath.Join(tmpDir, "module.zip")
	sha256Path := filepath.Join(tmpDir, "module.zip.sha256")
	sigPath := filepath.Join(tmpDir, "module.zip.sig")

	type dlResult struct{ err error }
	zipCh := make(chan dlResult, 1)
	hashCh := make(chan dlResult, 1)

	installDownloadTimeout := time.Duration(InstallDownloadTimeoutSeconds(ctx, d.DB)) * time.Second
	dlCtx, dlCancel := context.WithTimeout(ctx, installDownloadTimeout)
	defer dlCancel()

	go func() { zipCh <- dlResult{downloadFile(dlCtx, zipURL, zipPath, maxZIPBytes, cred)} }()
	go func() { hashCh <- dlResult{downloadFile(dlCtx, sha256URL, sha256Path, maxSHA256FileBytes, cred)} }()

	if r := <-zipCh; r.err != nil {
		return fmt.Errorf("modules: update %q: download zip: %w", entry.Name, r.err)
	}
	if r := <-hashCh; r.err != nil {
		return fmt.Errorf("modules: update %q: download sha256: %w", entry.Name, r.err)
	}

	// ── 4. Verify SHA-256 ─────────────────────────────────────────────────
	expectedHex, err := readHexFile(sha256Path)
	if err != nil {
		return fmt.Errorf("modules: update %q: read sha256: %w", entry.Name, err)
	}
	gotHex, err := VerifySHA256(zipPath, expectedHex)
	if err != nil {
		return fmt.Errorf("modules: update %q: %w", entry.Name, err)
	}

	// ── 5. Cosign verification ─────────────────────────────────────────────
	// entry.CosignSigURL (official modules) points at a Sigstore bundle (JSON,
	// see build-module.sh / VerifyCosign doc comment), not a legacy raw signature.
	//
	// cosignVerified (added 2026-07-05, same as installer.go's install path)
	// is threaded through to updateInstalledModuleRecord below so the result
	// is actually persisted - previously it was computed here and then
	// discarded, same gap as the install path had.
	cosignVerified := false
	if entry.CosignSigURL != "" {
		if err := downloadFile(dlCtx, entry.CosignSigURL, sigPath, maxSigFileBytes, cred); err != nil {
			return fmt.Errorf("modules: update %q: download cosign bundle: %w", entry.Name, err)
		}
		ok, err := VerifyCosign(zipPath, sigPath, entry.CosignPubKey, d.CosignBin)
		if err != nil {
			return fmt.Errorf("modules: update %q: cosign verify: %w", entry.Name, err)
		}
		cosignVerified = ok
	} else if entry.Source != "official" {
		// Community/custom: best-effort with conventional .sig path.
		// entry.CosignPubKey is only set for source="custom" (admin-entered
		// key) - see installer.go's Install for the matching comment.
		if dlErr := downloadFile(dlCtx, sigURL, sigPath, maxSigFileBytes, cred); dlErr == nil {
			ok, err := VerifyCosign(zipPath, sigPath, entry.CosignPubKey, d.CosignBin)
			if err == nil {
				cosignVerified = ok
			} else {
				log.Printf("modules: update %q: cosign skipped: %v", entry.Name, err)
			}
		}
	} else {
		// Official module without cosign_sig_url: reject outright, same
		// reasoning as installer.go's Install - every official module has
		// carried a real cosign_sig_url since all three were re-released
		// with signing (confirmed 2026-07-12), so a missing one now means an
		// unsigned rollback or a tampered registry, not "not yet signed".
		return fmt.Errorf("modules: update %q: official module has no cosign_sig_url in registry - refusing to update to an unsigned official release", entry.Name)
	}

	// ── 6. Extract new ZIP ────────────────────────────────────────────────
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractZIP(zipPath, extractDir, maxZIPBytes); err != nil {
		return fmt.Errorf("modules: update %q: extract zip: %w", entry.Name, err)
	}

	// ── 7. Parse and validate new manifest ───────────────────────────────
	mf, err := parseManifest(filepath.Join(extractDir, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("modules: update %q: %w", entry.Name, err)
	}
	if mf.Name != entry.Name {
		return fmt.Errorf("modules: update %q: manifest name mismatch (got %q)", entry.Name, mf.Name)
	}
	// Same tier/handler/jobs/egress cross-validation as a first install (see
	// validateManifestTier's doc comment) - an update used to skip this
	// entirely, so a manifest could change tier (or add egress_allowlist to
	// a tier-2 module, etc.) with no check at all (found 2026-07-16).
	if err := validateManifestTier(mf); err != nil {
		return fmt.Errorf("modules: update %q: %w", entry.Name, err)
	}

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: update %q: marshal manifest: %w", entry.Name, err)
	}

	// ── 8. Swap module files (temp dir → DataDir/{name}) ──────────────────
	destDir := filepath.Join(d.DataDir, entry.Name)
	// Write new files to a sibling temp dir, then rename atomically.
	newDir := destDir + ".new-" + entry.LatestVersion
	if err := os.MkdirAll(newDir, 0o750); err != nil {
		return d.rollback(ctx, entry.Name, cachedZip,
			fmt.Errorf("create new dir: %w", err))
	}
	if err := copyDir(extractDir, newDir); err != nil {
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update %q: cleanup %s after failed copy: %v", entry.Name, newDir, rmErr)
		}
		return d.rollback(ctx, entry.Name, cachedZip,
			fmt.Errorf("copy new files: %w", err))
	}
	oldDir := destDir + ".old-" + row.Version
	if err := os.Rename(destDir, oldDir); err != nil {
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update %q: cleanup %s after failed rename: %v", entry.Name, newDir, rmErr)
		}
		return d.rollback(ctx, entry.Name, cachedZip,
			fmt.Errorf("move old dir: %w", err))
	}
	if err := os.Rename(newDir, destDir); err != nil {
		// Try to restore old dir before rolling back. If this restore
		// itself fails, the module is left with neither destDir nor oldDir
		// in place — worth logging loudly since it needs manual recovery,
		// not just silent fall-through into rollback (which would then also
		// fail, since destDir wouldn't exist for copyDir to write into).
		if restoreErr := os.Rename(oldDir, destDir); restoreErr != nil {
			log.Printf("modules: update %q: CRITICAL: could not restore %s after failed activation, module directory may be missing: %v", entry.Name, oldDir, restoreErr)
		}
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update %q: cleanup %s after failed rename: %v", entry.Name, newDir, rmErr)
		}
		return d.rollback(ctx, entry.Name, cachedZip,
			fmt.Errorf("move new dir: %w", err))
	}
	// User-uploaded content (router.go's saveUploadedFile writes to
	// {DataDir}/{name}/storage/uploads/) lives inside the same directory as
	// the module's own code, but the freshly extracted zip above never
	// contains a "storage" directory - it's created lazily on first upload.
	// Without this step, the RemoveAll(oldDir) below would silently delete
	// every image/file a user has ever uploaded to this module on every
	// single update. Move it back into the new destDir before the old
	// directory is discarded.
	oldStorageDir := filepath.Join(oldDir, "storage")
	if _, err := os.Stat(oldStorageDir); err == nil {
		newStorageDir := filepath.Join(destDir, "storage")
		if err := os.Rename(oldStorageDir, newStorageDir); err != nil {
			log.Printf("modules: update %q: could not preserve storage dir (uploaded files may be lost): %v", entry.Name, err)
		}
	}
	// Best-effort cleanup of superseded files. Logged (not just swallowed)
	// because a failure here leaves a "{name}.old-{version}" directory
	// permanently and invisibly orphaned in DataDir — nothing else in the
	// codebase ever revisits or reports on stray .old-* directories, so a
	// silent failure here was effectively unrecoverable without someone
	// noticing extra disk usage and investigating by hand.
	if err := os.RemoveAll(oldDir); err != nil {
		log.Printf("modules: update %q: could not remove superseded dir %s: %v", entry.Name, oldDir, err)
	}

	// ── 9. Module migrations ──────────────────────────────────────────────
	newMigrationsDir := filepath.Join(extractDir, "migrations")
	if err := runModuleUpdateMigrations(ctx, d, entry.Name, newMigrationsDir); err != nil {
		return d.rollback(ctx, entry.Name, cachedZip,
			fmt.Errorf("migrations: %w", err))
	}

	// ── 9b. Tier 1: cross-check crud against the migrated table ───────────
	// Same reasoning as Install's step 10b - an update can change crud.fields
	// and/or ship new migrations; catch a mismatch here rather than at the
	// first API call after the update. See docs/tier1-crud-plan.md.
	if mf.Tier == 1 {
		if err := validateCrudTable(ctx, d, entry.Name, mf.Crud); err != nil {
			return d.rollback(ctx, entry.Name, cachedZip, err)
		}
	}

	// ── 10. Update DB row ─────────────────────────────────────────────────
	if err := d.updateInstalledModuleRecord(ctx, entry.Name, mf.Version, mf.Tier, gotHex, zipURL, manifestJSON, cosignVerified, entry.LogoURL); err != nil {
		return fmt.Errorf("modules: update %q: db update: %w", entry.Name, err)
	}
	if _, err := d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusActive); err != nil {
		return fmt.Errorf("modules: update %q: mark active: %w", entry.Name, err)
	}
	// Clear available_version now that we're on the latest. Logged (not
	// just swallowed): a failure here leaves the UI showing a permanent,
	// misleading "update available" badge for a module that is already on
	// the latest version, with nothing in the logs to explain why to
	// whoever investigates the mismatch later.
	if err := d.DB.SetModuleAvailableVersion(ctx, entry.Name, ""); err != nil {
		log.Printf("modules: update %q: could not clear available_version: %v", entry.Name, err)
	}

	// ── 11. Remove rollback cache ─────────────────────────────────────────
	if cachedZip != "" {
		if err := os.Remove(cachedZip); err != nil && !os.IsNotExist(err) {
			log.Printf("modules: update %q: warning: remove rollback zip: %v", entry.Name, err)
		}
		// Same reasoning as SetModuleAvailableVersion above: a failure here
		// is invisible otherwise, and leaves the DB pointing at a rollback
		// zip that Remove just deleted from disk — a future rollback
		// attempt for this module would fail confusingly instead of
		// cleanly reporting "no rollback available".
		if err := d.DB.ClearModuleCachedZip(ctx, entry.Name); err != nil {
			log.Printf("modules: update %q: could not clear cached zip reference: %v", entry.Name, err)
		}
	}

	log.Printf("modules: updated %q %s → %s", entry.Name, row.Version, mf.Version)
	return nil
}

// UpdateManual upgrades an already-installed module using a freshly
// uploaded ZIP file (as opposed to Update, which downloads the new version
// from a registry entry's URLs). zipPath is a file already on disk — same
// convention as InstallManual (installer.go), ownership stays with the
// caller.
//
// Mirrors Update from "extract new ZIP" onward, but:
//   - No rollback-cache step. Update's step 2 re-downloads the *currently
//     installed* version from row.ReleaseURL to snapshot it before
//     overwriting — a manually installed module has release_url == ""
//     (nothing to re-download), so there is nothing to snapshot. A failed
//     UpdateManual therefore has no automatic rollback: d.rollback below is
//     still called for consistency (same failure-path logging/status
//     handling as Update), but always with cachedZip == "", so it can only
//     mark the module "failed", never actually restore the previous code.
//   - No SHA256/Cosign verification, same reasoning as InstallManual.
//   - source stays "manual" — an update via re-upload doesn't change how
//     the module was originally obtained.
func UpdateManual(ctx context.Context, d Deps, zipPath string) error {
	// The uploaded ZIP's manifest.yaml is the only way to know which module
	// this even is — read it before touching the DB.
	peekDir, err := os.MkdirTemp("", "modulab-update-manual-peek-*")
	if err != nil {
		return fmt.Errorf("modules: update manual: create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(peekDir); err != nil {
			log.Printf("modules: update manual: cleanup peek dir %s: %v", peekDir, err)
		}
	}()
	maxZIPBytes := MaxModuleZIPBytes(ctx, d.DB)
	if err := extractZIP(zipPath, peekDir, maxZIPBytes); err != nil {
		return fmt.Errorf("modules: update manual: extract zip: %w", err)
	}
	mf, err := parseManifest(filepath.Join(peekDir, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("modules: update manual: %w", err)
	}

	// ── Guard: installed, not pinned ───────────────────────────────────────
	row, exists, err := d.DB.GetInstalledModule(ctx, mf.Name)
	if err != nil {
		return fmt.Errorf("modules: update manual %q: lookup: %w", mf.Name, err)
	}
	if !exists {
		return fmt.Errorf("modules: update manual %q: not installed", mf.Name)
	}
	if row.Pinned {
		return fmt.Errorf("modules: update manual %q: module is pinned", mf.Name)
	}

	if err := validateManifestTier(mf); err != nil {
		return fmt.Errorf("modules: update manual %q: %w", mf.Name, err)
	}

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: update manual %q: marshal manifest: %w", mf.Name, err)
	}

	gotHex, err := hashSHA256File(zipPath)
	if err != nil {
		return fmt.Errorf("modules: update manual %q: hash zip: %w", mf.Name, err)
	}

	// extractDir reuses peekDir's already-extracted content rather than
	// re-extracting — peekDir was only ever read from (manifest parse), not
	// written into by anything else, so it's still exactly what copyDir
	// needs below.
	extractDir := peekDir

	// ── Swap module files (extractDir → DataDir/{name}) ───────────────────
	// Identical atomic dir-swap as Update's step 8 — see that function's
	// comments for why the rename-twice dance and storage-dir preservation
	// exist.
	destDir := filepath.Join(d.DataDir, mf.Name)
	newDir := destDir + ".new-" + mf.Version
	if err := os.MkdirAll(newDir, 0o750); err != nil {
		return d.rollback(ctx, mf.Name, "", fmt.Errorf("create new dir: %w", err))
	}
	if err := copyDir(extractDir, newDir); err != nil {
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update manual %q: cleanup %s after failed copy: %v", mf.Name, newDir, rmErr)
		}
		return d.rollback(ctx, mf.Name, "", fmt.Errorf("copy new files: %w", err))
	}
	oldDir := destDir + ".old-" + row.Version
	if err := os.Rename(destDir, oldDir); err != nil {
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update manual %q: cleanup %s after failed rename: %v", mf.Name, newDir, rmErr)
		}
		return d.rollback(ctx, mf.Name, "", fmt.Errorf("move old dir: %w", err))
	}
	if err := os.Rename(newDir, destDir); err != nil {
		if restoreErr := os.Rename(oldDir, destDir); restoreErr != nil {
			log.Printf("modules: update manual %q: CRITICAL: could not restore %s after failed activation, module directory may be missing: %v", mf.Name, oldDir, restoreErr)
		}
		if rmErr := os.RemoveAll(newDir); rmErr != nil {
			log.Printf("modules: update manual %q: cleanup %s after failed rename: %v", mf.Name, newDir, rmErr)
		}
		return d.rollback(ctx, mf.Name, "", fmt.Errorf("move new dir: %w", err))
	}
	oldStorageDir := filepath.Join(oldDir, "storage")
	if _, err := os.Stat(oldStorageDir); err == nil {
		newStorageDir := filepath.Join(destDir, "storage")
		if err := os.Rename(oldStorageDir, newStorageDir); err != nil {
			log.Printf("modules: update manual %q: could not preserve storage dir (uploaded files may be lost): %v", mf.Name, err)
		}
	}
	if err := os.RemoveAll(oldDir); err != nil {
		log.Printf("modules: update manual %q: could not remove superseded dir %s: %v", mf.Name, oldDir, err)
	}

	// ── Module migrations ───────────────────────────────────────────────────
	newMigrationsDir := filepath.Join(extractDir, "migrations")
	if err := runModuleUpdateMigrations(ctx, d, mf.Name, newMigrationsDir); err != nil {
		return d.rollback(ctx, mf.Name, "", fmt.Errorf("migrations: %w", err))
	}

	if mf.Tier == 1 {
		if err := validateCrudTable(ctx, d, mf.Name, mf.Crud); err != nil {
			return d.rollback(ctx, mf.Name, "", err)
		}
	}

	// ── Update DB row ───────────────────────────────────────────────────────
	// source stays "manual" — updateInstalledModuleRecord doesn't touch the
	// source column at all (see its own doc comment), so nothing extra is
	// needed here to keep it from flipping to something else.
	if err := d.updateInstalledModuleRecord(ctx, mf.Name, mf.Version, mf.Tier, gotHex, "", manifestJSON, false, ""); err != nil {
		return fmt.Errorf("modules: update manual %q: db update: %w", mf.Name, err)
	}
	if _, err := d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusActive); err != nil {
		return fmt.Errorf("modules: update manual %q: mark active: %w", mf.Name, err)
	}
	if err := d.DB.SetModuleAvailableVersion(ctx, mf.Name, ""); err != nil {
		log.Printf("modules: update manual %q: could not clear available_version: %v", mf.Name, err)
	}

	log.Printf("modules: updated %q %s → %s manually (unverified)", mf.Name, row.Version, mf.Version)
	return nil
}

// rollback attempts to restore a module to its previous state using the cached
// ZIP, then returns a wrapped error combining the original failure with any
// rollback error.
func (d Deps) rollback(ctx context.Context, name, cachedZip string, origErr error) error {
	if cachedZip == "" {
		_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: update %q failed (no rollback available): %w", name, origErr)
	}

	log.Printf("modules: update %q: rolling back due to: %v", name, origErr)
	_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusDegraded)

	destDir := filepath.Join(d.DataDir, name)
	tmpDir, err := os.MkdirTemp("", "modulab-rollback-"+name+"-*")
	if err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: update %q failed; rollback also failed (tempdir): %w | orig: %v",
			name, err, origErr)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("modules: update %q: rollback: cleanup temp dir %s: %v", name, tmpDir, err)
		}
	}()

	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractZIP(cachedZip, extractDir, MaxModuleZIPBytes(ctx, d.DB)); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: update %q failed; rollback extract failed: %w | orig: %v",
			name, err, origErr)
	}
	if err := copyDir(extractDir, destDir); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: update %q failed; rollback copy failed: %w | orig: %v",
			name, err, origErr)
	}

	_, _ = d.DB.UpdateModuleStatus(ctx, name, db.ModuleStatusActive)
	log.Printf("modules: update %q: rollback successful", name)
	return fmt.Errorf("modules: update %q failed (rolled back): %w", name, origErr)
}

// cacheCurrentZIP re-downloads the currently installed module ZIP and saves it
// to path. Used as a rollback snapshot before an update begins. maxBytes is
// the caller-resolved max_module_zip_bytes value (see MaxModuleZIPBytes).
// cred is the same repo-bound custom-source credential resolved once by the
// caller (Update) - releaseURL comes from installed_modules.release_url,
// itself derived from a registry entry, so it gets the same per-URL check
// every other download does (see githubCredential in installer.go).
func cacheCurrentZIP(ctx context.Context, pool *db.Pool, releaseURL, path string, maxBytes int64, cred githubCredential) error {
	installDownloadTimeout := time.Duration(InstallDownloadTimeoutSeconds(ctx, pool)) * time.Second
	dlCtx, cancel := context.WithTimeout(ctx, installDownloadTimeout)
	defer cancel()
	return downloadFile(dlCtx, releaseURL, path, maxBytes, cred)
}

// updateInstalledModuleRecord patches the version, tier, sha256, release_url,
// manifest, cosign_verified, and logo_url columns on the installed_modules
// row. There is no single DB helper for this combination, so we exec the
// UPDATE directly. cosignVerified is this update's own Cosign result (added
// 2026-07-05) - overwrites whatever was recorded for the previous version,
// since a signature check is only ever meaningful for the version it was
// actually run against. logoURL is re-synced from the registry on every
// update (not just at first install) so a module that gains, changes, or
// loses a logo after install picks that up on its next update.
//
// tier (added 2026-07-16) must be written here for the same reason: every
// tier-gating check in the codebase (worker restart in handlers.go, the job
// scheduler in jobs.go, the boot-time worker-restore loop in main.go, the
// frontend's TierBadge) reads the standalone tier column, not manifest.tier.
// Before this, a manifest that changed tier during an update left the column
// permanently frozen at the tier from first install - Update() validates the
// new tier via validateManifestTier above, so it is safe to persist here.
func (d Deps) updateInstalledModuleRecord(ctx context.Context, name, version string, tier int, sha256, releaseURL string, manifest []byte, cosignVerified bool, logoURL string) error {
	var logoURLArg any
	if logoURL != "" {
		logoURLArg = logoURL
	}
	_, err := d.DB.Exec(ctx, `
		UPDATE installed_modules
		SET version         = $2,
		    tier            = $3,
		    sha256          = $4,
		    release_url     = $5,
		    manifest        = $6,
		    cosign_verified = $7,
		    logo_url        = $8,
		    updated_at      = $9
		WHERE name = $1
	`, name, version, tier, sha256, releaseURL, manifest, cosignVerified, logoURLArg, time.Now())
	if err != nil {
		return fmt.Errorf("db: update installed_module record %q: %w", name, err)
	}
	return nil
}
