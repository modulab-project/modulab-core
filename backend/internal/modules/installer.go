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
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"gopkg.in/yaml.v3"
)

// Deps bundles what the modules package needs from the outside world.
// Constructed once in main.go and shared by Install, Uninstall, and Updater.
type Deps struct {
	DB        *db.Pool
	DataDir   string      // base dir for module files, e.g. /var/lib/modulab/modules
	CosignBin string      // "" = use "cosign" on $PATH
	Workers   *WorkerPool // Deno worker lifecycle manager (tier 2/3 modules)
	// Valkey is used by RunUpdateCheckOnce (status.go) to publish a
	// notify.AdminChannel() event when an update check (run right after
	// every registry sync) finds a newer version for an installed module,
	// so connected admin sessions see it via SSE (GET /v1/events) without
	// needing to reopen the notifications panel or reload the page.
	// Nil-safe: CheckUpdates itself does not require it (only
	// RunUpdateCheckOnce publishes), so existing callers that construct
	// Deps without it (if any) keep working.
	Valkey *valkey.Client
}

// Manifest is the parsed content of manifest.yaml inside a module ZIP.
// Every module must ship this file at the archive root.
type Manifest struct {
	Name    string `yaml:"name"         json:"name"`
	Version string `yaml:"version"      json:"version"`
	Tier    int    `yaml:"tier"         json:"tier"`
	Scope   string `yaml:"scope"        json:"scope"`
	// Description is a map of language code → short blurb, e.g.
	// {"en": "...", "de": "..."} - same shape as DisplayName below, so the
	// frontend resolves it with the identical lng-with-"en"-fallback lookup
	// (see AppShell.tsx's activeModules render and StorePage.tsx).
	Description map[string]string `yaml:"description"  json:"description,omitempty"`
	Author      string            `yaml:"author"       json:"author,omitempty"`
	License     string            `yaml:"license"      json:"license,omitempty"`
	MinCore     string            `yaml:"min_core"     json:"min_core,omitempty"`
	// DisplayName is an optional map of language code → human-readable name,
	// e.g. {"en": "Recipes", "de": "Rezepte"}. Used by the AppShell to show
	// a localized module name instead of the raw module identifier.
	DisplayName map[string]string `yaml:"display_name" json:"display_name,omitempty"`
	// Logo is the filename of an optional logo image shipped at the module's
	// own repo root (e.g. "logo.png"). The Module Store resolves it to an
	// absolute raw.githubusercontent.com URL (see store.Entry.LogoURL /
	// github.go) rather than Core hosting the image itself - same
	// no-own-asset-hosting principle as release_url/cosign_sig_url.
	Logo string `yaml:"logo" json:"logo,omitempty"`
	// Handler is the Deno entrypoint (relative path inside the ZIP), required
	// for Tier 2 and 3 modules.
	Handler string `yaml:"handler"          json:"handler,omitempty"`
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
	// EgressHostsHandler is the relative path (same convention as Handler) to
	// a .ts module whose default export is () => Promise<string[]> — the
	// module's own computation of its current runtime egress hosts (e.g.
	// unifi-network's computeEgressHosts(), reading configured gateway IPs
	// out of its own DB schema).
	//
	// Only meaningful when DynamicEgress is true. Solves a gap DynamicEgress
	// alone didn't cover: DynamicEgress preserves a RUNNING worker's egress
	// across a code update by asking the worker itself (see
	// WorkerPool.CurrentModuleEgressHosts), but there is no running worker to
	// ask right after Core's own process starts (container restart, not a
	// module update) — main.go's startup-restore loop was still resetting
	// unifi-network to egress_allowlist: [] on every Core restart, silently
	// making all configured gateways unreachable until an admin happened to
	// re-save one (found 2026-07-03, one day after DynamicEgress shipped).
	// When set, Core dispatches this handler as a one-off job (see
	// WorkerPool.QueryEgressHosts in deno.go) immediately after starting the
	// worker with an empty/manifest-only egress grant, then reloads the
	// worker with whatever hosts it returns — computed fresh from the
	// module's own DB state every time, so it can never go stale the way a
	// Core-side cache of "last known hosts" could.
	EgressHostsHandler string `yaml:"egress_hosts_handler" json:"egress_hosts_handler,omitempty"`
}

// ManifestJob describes one scheduled job entry under a module's jobs: list.
type ManifestJob struct {
	Name string `yaml:"name"     json:"name"`
	// Schedule is a 5-field cron expression. JobRunner only supports minute
	// granularity (spec says "Cron-Format erlaubt kein Sub-Minuten-Intervall"
	// in the reference modules) — it is evaluated once per minute, so any
	// schedule finer than "* * * * *" is not meaningfully supported.
	Schedule string `yaml:"schedule" json:"schedule"`
	Handler  string `yaml:"handler"  json:"handler"`
	CatchUp  bool   `yaml:"catch_up" json:"catch_up,omitempty"`
}

const (
	// defaultInstallDownloadTimeoutSeconds is
	// InstallDownloadTimeoutSeconds's fallback - mirrors the fixed 5min
	// value this replaced.
	defaultInstallDownloadTimeoutSeconds = 300
	// defaultMaxModuleZIPBytes is the fallback used when the
	// max_module_zip_bytes setting (see MaxModuleZIPBytes) has never been
	// set.
	defaultMaxModuleZIPBytes = 100 << 20 // 100 MB
	// maxSHA256FileBytes/maxSigFileBytes are not admin-configurable on
	// purpose: they bound a hex digest (always 64 chars) and a cosign
	// signature bundle respectively — fixed by the file formats involved,
	// not an operational choice anyone would plausibly need to tune.
	maxSHA256FileBytes = 1024
	maxSigFileBytes    = 4096
)

// InstallDownloadTimeoutSeconds reads the module install/update ZIP download
// timeout (seconds) from core_settings ("modules_install_download_timeout_seconds").
// Defaults to defaultInstallDownloadTimeoutSeconds if unset. Companion
// setting to MaxModuleZIPBytes: a larger admin-configured ZIP cap can also
// need a longer download window on a slow connection.
func InstallDownloadTimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, "modules_install_download_timeout_seconds")
	if err != nil || !ok || val == "" {
		return defaultInstallDownloadTimeoutSeconds
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultInstallDownloadTimeoutSeconds
	}
	return n
}

// MaxModuleZIPBytes reads the module-install ZIP size cap from
// core_settings ("max_module_zip_bytes"). Defaults to
// defaultMaxModuleZIPBytes (100 MB) if unset; 0 means unlimited, the same
// convention max_body_bytes/MaxUploadBodyBytes use. See
// adminapi.AdminLimitsHandler for where this is admin-editable.
func MaxModuleZIPBytes(ctx context.Context, pool *db.Pool) int64 {
	val, ok, err := pool.GetSetting(ctx, "max_module_zip_bytes")
	if err != nil || !ok || val == "" {
		return defaultMaxModuleZIPBytes
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n < 0 {
		return defaultMaxModuleZIPBytes
	}
	return n
}

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
//
// 10. Run module-supplied SQL migrations (v1: skipped — no migration runner yet)
// 11. Deno worker registration (post-v1 stub)
// 12. Mark module status "active"
func Install(ctx context.Context, d Deps, entry store.Entry) error {
	if entry.LatestVersion == "" {
		return fmt.Errorf("modules: install %q: no version known — registry may not have synced yet", entry.Name)
	}
	maxZIPBytes := MaxModuleZIPBytes(ctx, d.DB)

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
	// SHA256 asset:      {zip_url}.sha256
	// Cosign bundle:     {zip_url}.sig  (legacy convention path for community
	//                    best-effort verification; official modules always use
	//                    entry.CosignSigURL, which points at the new
	//                    <zip>.cosign.bundle asset — see build-module.sh)
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
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("modules: install %q: cleanup temp dir %s: %v", entry.Name, tmpDir, err)
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

	go func() { zipCh <- dlResult{downloadFile(dlCtx, zipURL, zipPath, maxZIPBytes)} }()
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
	// VerifyCosign expects a Sigstore bundle (JSON, `cosign sign-blob --bundle`),
	// not a legacy raw signature. entry.CosignSigURL (official modules) always
	// points at a real bundle. The community best-effort `.sig` convention path
	// below may still be a legacy raw signature from an older tool — that's
	// fine, VerifyCosign returning an error there just falls through to
	// cosignSkipped, same as if no sig existed at all.
	cosignVerified := false
	cosignSkipped := false
	if entry.CosignSigURL != "" {
		// Bundle URL explicitly provided — download and verify.
		if err := downloadFile(dlCtx, entry.CosignSigURL, sigPath, maxSigFileBytes); err != nil {
			return fmt.Errorf("modules: install %q: download cosign bundle: %w", entry.Name, err)
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
		// Official module without cosign_sig_url: reject outright, not a
		// best-effort skip. Every official module in registry.json has
		// carried a real cosign_sig_url since all three (my-places, recipes,
		// unifi-network) were re-released with signing - confirmed 2026-07-12
		// - so a registry entry missing one now is either a rollback to an
		// unsigned release or a tampered/spoofed registry, not the expected
		// "not yet signed" case this branch used to allow through.
		return fmt.Errorf("modules: install %q: official module has no cosign_sig_url in registry - refusing to install an unsigned official release", entry.Name)
	}
	// cosignVerified is persisted below (step 8, InsertInstalledModule) so
	// System Info can show a signature badge - previously computed here and
	// then discarded. cosignSkipped itself isn't persisted (it's implied by
	// cosignVerified == false); kept as a local variable only for its log
	// lines above.
	_ = cosignSkipped

	// ── 6. Extract ZIP ────────────────────────────────────────────────────
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractZIP(zipPath, extractDir, maxZIPBytes); err != nil {
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
	if err := validateManifestTier(mf); err != nil {
		return fmt.Errorf("modules: install %q: %w", entry.Name, err)
	}
	if mf.Scope == "" {
		// "cross-location" (not "org") - must match installed_modules'
		// CHECK (scope IN ('per-location', 'cross-location')) in db.go, or
		// every install with an unset scope fails at the DB insert below.
		// Broadest fallback for a module that doesn't declare a scope.
		mf.Scope = "cross-location"
	}

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: install %q: marshal manifest: %w", entry.Name, err)
	}

	// ── 8. DB insert (status = installing) ────────────────────────────────
	// From this point on, any error must attempt to clean up the DB row.
	if err := d.DB.InsertInstalledModule(ctx,
		mf.Name, mf.Version, mf.Tier, mf.Scope,
		entry.Source, zipURL, gotHex, manifestJSON, cosignVerified, entry.LogoURL,
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
			Jobs:          ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
			SkipTLSVerify: mf.TLSSkipVerify,
		}
		if err := d.Workers.Start(mf.Name, filepath.Join(destDir, mf.Handler), opts); err != nil {
			_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
			return fmt.Errorf("modules: install %q: start deno worker: %w", entry.Name, err)
		}
		// A fresh install has no prior runtime egress state to preserve (no
		// gateways configured yet for unifi-network, etc.) — but if the
		// module declares EgressHostsHandler, ask it anyway rather than
		// special-casing "just installed": harmless (returns an empty list
		// when nothing is configured yet) and keeps this path identical to
		// the update/startup ones, one less place to get out of sync.
		if mf.DynamicEgress && mf.EgressHostsHandler != "" {
			if hosts, ok := d.Workers.QueryEgressHosts(ctx, mf.Name); ok {
				if err := d.Workers.ReloadEgress(mf.Name, hosts); err != nil {
					log.Printf("modules: install %q: initial egress hosts reload failed: %v", entry.Name, err)
				}
			}
		}
	}

	// ── 12. Mark active ───────────────────────────────────────────────────
	if _, err := d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusActive); err != nil {
		// The Deno worker (started in step 11, tier >= 2 only) is already
		// running at this point but the module never reaches an "active"
		// row — without this, a failure here left the worker orphaned:
		// running, consuming resources, reachable by nothing (the proxy
		// route requires status "active"), and with no code path left to
		// stop it short of a full Core restart. Mirrors uninstaller.go's
		// Workers.Stop call for the symmetric teardown case.
		if mf.Tier >= 2 {
			if stopErr := d.Workers.Stop(mf.Name); stopErr != nil {
				log.Printf("modules: install %q: stop orphaned worker after failed activate: %v", entry.Name, stopErr)
			}
		}
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("modules: downloadFile: close response body for %s: %v", url, err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("modules: downloadFile: close %s: %v", path, err)
		}
	}()

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
	defer func() {
		if err := r.Close(); err != nil {
			log.Printf("modules: extractZIP: close %s: %v", src, err)
		}
	}()

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
	defer func() {
		if err := rc.Close(); err != nil {
			log.Printf("modules: extractZIPEntry: close zip entry %s: %v", f.Name, err)
		}
	}()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("modules: extractZIPEntry: close %s: %v", target, err)
		}
	}()

	return io.Copy(out, rc)
}

// validateManifestTier cross-checks mf.Tier against the fields that actually
// imply Tier 2/3 capability. Shared by Install and Update so a tier-changing
// module update is held to the exact same rules as a first install - before
// this existed, Update skipped tier validation entirely (found 2026-07-16).
//
// Rules, per Pflichtenheft §4.1:
//   - Tier 1 (config-driven, no worker): must not declare handler/jobs/
//     egress_allowlist - those are Tier 2/3-only concepts.
//   - Tier 2/3 (has a Deno worker): must declare a handler, or Workers.Start
//     would be called with an empty entrypoint path.
//   - Tier 2 (no egress per spec): must not declare egress_allowlist - only
//     Tier 3 ("TypeScript + Egress") is allowed outbound network access.
//   - tls_skip_verify is only meaningful alongside a non-empty
//     egress_allowlist; true with no egress hosts is almost certainly an
//     author mistake and is rejected rather than silently ignored.
func validateManifestTier(mf Manifest) error {
	if mf.Tier < 1 || mf.Tier > 3 {
		return fmt.Errorf("invalid tier %d (must be 1–3)", mf.Tier)
	}
	if mf.Tier == 1 && (mf.Handler != "" || len(mf.Jobs) > 0 || len(mf.EgressAllowlist) > 0) {
		return fmt.Errorf("tier 1 must not declare handler/jobs/egress_allowlist")
	}
	if mf.Tier >= 2 && mf.Handler == "" {
		return fmt.Errorf("tier %d requires a handler", mf.Tier)
	}
	if mf.Tier == 2 && len(mf.EgressAllowlist) > 0 {
		return fmt.Errorf("tier 2 must not declare egress_allowlist (use tier 3)")
	}
	if mf.TLSSkipVerify && len(mf.EgressAllowlist) == 0 {
		return fmt.Errorf("tls_skip_verify requires a non-empty egress_allowlist")
	}
	return nil
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
	defer func() {
		if err := in.Close(); err != nil {
			log.Printf("modules: copyFile: close %s: %v", src, err)
		}
	}()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("modules: copyFile: close %s: %v", dst, err)
		}
	}()

	_, err = io.Copy(out, in)
	return err
}
