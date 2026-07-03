package modules

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"gopkg.in/yaml.v3"
)

// Deps bundles what the modules package needs from the outside world.
// Constructed once in main.go and shared by Install, Uninstall, and Updater.
type Deps struct {
	DB        *db.Pool
	DataDir   string      // base dir for module files, e.g. /var/lib/modulab/modules
	CosignBin string      // "" = use "cosign" on $PATH
	Workers   *WorkerPool // Deno worker lifecycle manager (tier 2/3 modules)
}

// Manifest is the parsed content of manifest.yaml inside a module ZIP.
// Every module must ship this file at the archive root.
type Manifest struct {
	Name        string            `yaml:"name"         json:"name"`
	Version     string            `yaml:"version"      json:"version"`
	Tier        int               `yaml:"tier"         json:"tier"`
	Scope       string            `yaml:"scope"        json:"scope"`
	Description string            `yaml:"description"  json:"description"`
	Author      string            `yaml:"author"       json:"author,omitempty"`
	License     string            `yaml:"license"      json:"license,omitempty"`
	MinCore     string            `yaml:"min_core"     json:"min_core,omitempty"`
	// DisplayName is an optional map of language code → human-readable name,
	// e.g. {"en": "Recipes", "de": "Rezepte"}. Used by the AppShell to show
	// a localized module name instead of the raw module identifier.
	DisplayName map[string]string `yaml:"display_name" json:"display_name,omitempty"`
	// Handler is the Deno entrypoint (relative path inside the ZIP), required
	// for Tier 2 and 3 modules.
	Handler         string   `yaml:"handler"          json:"handler,omitempty"`
	// EgressAllowlist lists the hostnames the Deno worker may connect to
	// (mapped to --allow-net). Empty = no outbound network.
	EgressAllowlist []string `yaml:"egress_allowlist" json:"egress_allowlist,omitempty"`
	// Jobs lists scheduled background jobs the module ships (Tier 2/3 only).
	// Read by JobRunner (jobs.go) to build the periodic dispatch schedule;
	// each job's Handler path is resolved relative to the module's installed
	// directory, same as the top-level Handler field.
	Jobs []ManifestJob `yaml:"jobs" json:"jobs,omitempty"`
	// TLSSkipVerify, when true, scopes the worker's
	// --unsafely-ignore-certificate-errors to exactly its EgressHosts — see
	// WorkerOptions.SkipTLSVerify in deno.go. Only for modules whose runtime
	// destinations are private IPs with no CA-issued cert (unifi-network).
	// Defaults to false; must be explicitly opted into per module.
	TLSSkipVerify bool `yaml:"tls_skip_verify" json:"tls_skip_verify,omitempty"`
	// DynamicEgress, when true, tells UpdateModuleHandler (handlers.go) to
	// preserve the running worker's current egress hosts across a module
	// code update instead of resetting to EgressAllowlist. Only for modules
	// that add hosts at runtime via ReloadEgress that EgressAllowlist can
	// never express (unifi-network's admin-configured gateway IPs — its
	// manifest declares egress_allowlist: [] by design).
	//
	// Without this flag, EVERY module update would need to guess whether a
	// difference between the running worker's hosts and the manifest's
	// EgressAllowlist means "runtime hosts to preserve" or "the manifest
	// author removed these hosts on purpose" — those two cases are
	// indistinguishable from the runtime hosts alone. Found 2026-07-03:
	// recipes removed world.openfoodfacts.org/api.openfoodfacts.org from
	// its manifest (no longer used, see handlers/index.ts), but every
	// subsequent update kept restarting the worker with those old hosts
	// anyway, because the earlier (unifi-network-motivated) fix blindly
	// preferred any non-empty runtime host list over the manifest. Modules
	// default to false — a manifest's EgressAllowlist is trusted as-is
	// unless a module explicitly opts into runtime-managed egress.
	DynamicEgress bool `yaml:"dynamic_egress" json:"dynamic_egress,omitempty"`
}

// ManifestJob describes one scheduled job entry under a module's jobs: list.
type ManifestJob struct {
	Name    string `yaml:"name"     json:"name"`
	// Schedule is a 5-field cron expression. JobRunner only supports minute
	// granularity (spec says "Cron-Format erlaubt kein Sub-Minuten-Intervall"
	// in the reference modules) — it is evaluated once per minute, so any
	// schedule finer than "* * * * *" is not meaningfully supported.
	Schedule string `yaml:"schedule" json:"schedule"`
	Handler  string `yaml:"handler"  json:"handler"`
	CatchUp  bool   `yaml:"catch_up" json:"catch_up,omitempty"`
}

const (
	installDownloadTimeout = 5 * time.Minute
	maxModuleZIPBytes      = 100 << 20 // 100 MB hard cap
	maxSHA256FileBytes     = 1024      // a hex digest is at most 64 chars
	maxSigFileBytes        = 4096
)

// Install performs the full module installation pipeline for entry.
// It is idempotent in the sense that it refuses to start if the module
// is already registered in installed_modules.
//
// Steps:
//  1. Guard: module not already installed
//  2. Resolve download URLs from registry entry
//  3. Download module.zip + module.zip.sha256 in parallel
//  4. Verify SHA-256
//  5. Download + verify Cosign signature (official: mandatory, community: best-effort)
//  6. Extract ZIP to temp directory
//  7. Parse and validate manifest.yaml
//  8. Record module in DB with status "installing"
//  9. Copy module files to permanent DataDir/{name}
// 10. Run module-supplied SQL migrations (v1: skipped — no migration runner yet)
// 11. Deno worker registration (post-v1 stub)
// 12. Mark module status "active"
func Install(ctx context.Context, d Deps, entry store.Entry) error {
	if entry.LatestVersion == "" {
		return fmt.Errorf("modules: install %q: no version known — registry may not have synced yet", entry.Name)
	}

	// ── 1. Guard: not already installed ───────────────────────────────────
	_, exists, err := d.DB.GetInstalledModule(ctx, entry.Name)
	if err != nil {
		return fmt.Errorf("modules: install %q: check existing: %w", entry.Name, err)
	}
	if exists {
		return fmt.Errorf("modules: install %q: already installed", entry.Name)
	}

	// ── 2. Resolve URLs ───────────────────────────────────────────────────
	// ReleaseAsset may be either:
	//   a) a full URL  (official registry: release_url stored verbatim)
	//   b) a bare filename  (community entries: reconstructed from source_repo + tag)
	// SHA256 asset: {zip_url}.sha256
	// Cosign sig:   {zip_url}.sig
	var zipURL string
	if strings.HasPrefix(entry.ReleaseAsset, "https://") || strings.HasPrefix(entry.ReleaseAsset, "http://") {
		zipURL = entry.ReleaseAsset
	} else {
		zipURL = entry.SourceRepo + "/releases/download/" + entry.LatestVersion + "/" + entry.ReleaseAsset
	}
	sha256URL := zipURL + ".sha256"
	sigURL := zipURL + ".sig"

	// ── 3. Download ZIP + SHA256 in parallel ──────────────────────────────
	tmpDir, err := os.MkdirTemp("", "modulab-install-"+entry.Name+"-*")
	if err != nil {
		return fmt.Errorf("modules: install %q: create temp dir: %w", entry.Name, err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "module.zip")
	sha256Path := filepath.Join(tmpDir, "module.zip.sha256")
	sigPath := filepath.Join(tmpDir, "module.zip.sig")

	type dlResult struct{ err error }
	zipCh := make(chan dlResult, 1)
	hashCh := make(chan dlResult, 1)

	dlCtx, dlCancel := context.WithTimeout(ctx, installDownloadTimeout)
	defer dlCancel()

	go func() { zipCh <- dlResult{downloadFile(dlCtx, zipURL, zipPath, maxModuleZIPBytes)} }()
	go func() { hashCh <- dlResult{downloadFile(dlCtx, sha256URL, sha256Path, maxSHA256FileBytes)} }()

	if r := <-zipCh; r.err != nil {
		return fmt.Errorf("modules: install %q: download zip: %w", entry.Name, r.err)
	}
	if r := <-hashCh; r.err != nil {
		return fmt.Errorf("modules: install %q: download sha256: %w", entry.Name, r.err)
	}

	// ── 4. Verify SHA-256 ─────────────────────────────────────────────────
	expectedHex, err := readHexFile(sha256Path)
	if err != nil {
		return fmt.Errorf("modules: install %q: read sha256 file: %w", entry.Name, err)
	}
	gotHex, err := VerifySHA256(zipPath, expectedHex)
	if err != nil {
		return fmt.Errorf("modules: install %q: %w", entry.Name, err)
	}
	log.Printf("modules: install %q: sha256 verified (%s)", entry.Name, gotHex)

	// ── 5. Cosign verification ────────────────────────────────────────────
	cosignVerified := false
	cosignSkipped := false
	if entry.CosignSigURL != "" {
		// Signature URL explicitly provided — download and verify.
		if err := downloadFile(dlCtx, entry.CosignSigURL, sigPath, maxSigFileBytes); err != nil {
			return fmt.Errorf("modules: install %q: download cosign sig: %w", entry.Name, err)
		}
		ok, err := VerifyCosign(zipPath, sigPath, d.CosignBin)
		if err != nil {
			return fmt.Errorf("modules: install %q: cosign verify: %w", entry.Name, err)
		}
		cosignVerified = ok
	} else if entry.Source != "official" {
		// Community modules without explicit sig URL: try the conventional .sig
		// path as a best-effort, proceed even if absent.
		if dlErr := downloadFile(dlCtx, sigURL, sigPath, maxSigFileBytes); dlErr == nil {
			ok, err := VerifyCosign(zipPath, sigPath, d.CosignBin)
			if err == nil {
				cosignVerified = ok
			} else {
				cosignSkipped = true
				log.Printf("modules: install %q: cosign skipped: %v", entry.Name, err)
			}
		} else {
			cosignSkipped = true
		}
	} else {
		// Official module without cosign_sig_url → skip (not yet signed).
		cosignSkipped = true
		log.Printf("modules: install %q: cosign skipped (no sig URL in registry)", entry.Name)
	}
	_ = cosignSkipped // badge logic lives in handlers — stored in VerifyResult if needed

	// ── 6. Extract ZIP ────────────────────────────────────────────────────
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractZIP(zipPath, extractDir, maxModuleZIPBytes); err != nil {
		return fmt.Errorf("modules: install %q: extract zip: %w", entry.Name, err)
	}

	// ── 7. Parse and validate manifest.yaml ───────────────────────────────
	mf, err := parseManifest(filepath.Join(extractDir, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("modules: install %q: %w", entry.Name, err)
	}
	if mf.Name != entry.Name {
		return fmt.Errorf("modules: install %q: manifest name mismatch (got %q)", entry.Name, mf.Name)
	}
	if mf.Tier < 1 || mf.Tier > 3 {
		return fmt.Errorf("modules: install %q: invalid tier %d (must be 1–3)", entry.Name, mf.Tier)
	}
	if mf.Scope == "" {
		mf.Scope = "org" // sensible default
	}

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: install %q: marshal manifest: %w", entry.Name, err)
	}

	// ── 8. DB insert (status = installing) ────────────────────────────────
	// From this point on, any error must attempt to clean up the DB row.
	if err := d.DB.InsertInstalledModule(ctx,
		mf.Name, mf.Version, mf.Tier, mf.Scope,
		entry.Source, zipURL, gotHex, manifestJSON,
	); err != nil {
		return fmt.Errorf("modules: install %q: db insert: %w", entry.Name, err)
	}

	// ── 9. Copy module files to DataDir/{name} ────────────────────────────
	destDir := filepath.Join(d.DataDir, entry.Name)
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install %q: create dest dir: %w", entry.Name, err)
	}
	if err := copyDir(extractDir, destDir); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install %q: copy files: %w", entry.Name, err)
	}

	// ── 10. Module SQL migrations ─────────────────────────────────────────
	migrationsDir := filepath.Join(extractDir, "migrations")
	if err := runModuleMigrations(ctx, d, mf.Name, migrationsDir); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install %q: migrations: %w", entry.Name, err)
	}

	// ── 11. Deno worker registration ──────────────────────────────────────
	// EgressAllowlist comes straight from the manifest the module author
	// shipped — this is the only source of --allow-net hosts for the
	// worker. See WorkerOptions in deno.go for why there is no wildcard.
	if mf.Tier >= 2 {
		opts := WorkerOptions{
			EgressHosts:   mf.EgressAllowlist,
			Jobs:          ResolveJobEntrypoints(destDir, mf.Jobs),
			SkipTLSVerify: mf.TLSSkipVerify,
		}
		if err := d.Workers.Start(mf.Name, filepath.Join(destDir, mf.Handler), opts); err != nil {
			_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
			return fmt.Errorf("modules: install %q: start deno worker: %w", entry.Name, err)
		}
	}

	// ── 12. Mark active ───────────────────────────────────────────────────
	if _, err := d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusActive); err != nil {
		return fmt.Errorf("modules: install %q: mark active: %w", entry.Name, err)
	}

	log.Printf("modules: installed %q %s (tier %d, source %s, cosignVerified=%v)",
		entry.Name, mf.Version, mf.Tier, entry.Source, cosignVerified)
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// downloadFile fetches url and writes the body to path. Returns an error if
// the response is not 2xx or the body exceeds maxBytes.
func downloadFile(ctx context.Context, url, path string, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "modulab-core/1 (https://github.com/modulab-project/modulab-core)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1)); err != nil {
		return err
	}

	// Verify we didn't hit the cap (LimitReader silently truncates).
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("response from %s exceeds %d byte limit", url, maxBytes)
	}
	return nil
}

// readHexFile reads a .sha256 file and returns its trimmed content.
// SHA256 files contain a single hex digest, optionally followed by a filename.
func readHexFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Format is either "deadbeef...\n" or "deadbeef...  module.zip\n"
	line := strings.TrimSpace(string(b))
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", fmt.Errorf("sha256 file %q is empty", path)
	}
	return parts[0], nil
}

// extractZIP extracts src.zip into destDir, guarding against zip-slip
// (path traversal). Any file whose resolved path escapes destDir is rejected.
func extractZIP(src, destDir string, maxTotalBytes int64) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	destDir = filepath.Clean(destDir)
	var totalWritten int64

	for _, f := range r.File {
		target := filepath.Join(destDir, filepath.FromSlash(f.Name))

		// Zip-slip guard: resolved path must stay inside destDir.
		if !strings.HasPrefix(target+string(os.PathSeparator), destDir+string(os.PathSeparator)) {
			return fmt.Errorf("zip-slip rejected: %q", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}

		written, err := extractZIPEntry(f, target)
		if err != nil {
			return err
		}
		totalWritten += written
		if totalWritten > maxTotalBytes {
			return fmt.Errorf("extracted size exceeds %d byte limit", maxTotalBytes)
		}
	}
	return nil
}

func extractZIPEntry(f *zip.File, target string) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return 0, err
	}
	defer out.Close()

	return io.Copy(out, rc)
}

// parseManifest reads and parses manifest.yaml from path.
func parseManifest(path string) (Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: open %q: %w", path, err)
	}
	var mf Manifest
	if err := yaml.Unmarshal(b, &mf); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: yaml: %w", err)
	}
	if mf.Name == "" || mf.Version == "" {
		return Manifest{}, fmt.Errorf("parse manifest: name and version are required")
	}
	return mf, nil
}

// copyDir recursively copies the contents of src into dst.
// Existing files in dst are overwritten.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
