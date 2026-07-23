package modules

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// PIIKey is MODULAB_MODULE_PII_KEY (config.Config.ModulePIIKey), the same
	// raw key already shared with every Tier 2/3 Deno worker (see
	// WorkerPool.piiKey in deno.go). The Tier 1 generic CRUD handler
	// (crud.go) uses it directly via crypto.Encrypt/Decrypt for
	// crud.fields[].encrypted columns - no per-module derivation, see
	// docs/tier1-crud-plan.md for why that's unnecessary (crypto.Encrypt
	// already uses a random nonce per call). May be empty if unset, same as
	// WorkerPool.piiKey - encrypted fields simply cannot be used until it's
	// configured.
	PIIKey string
}

// Manifest is the parsed content of manifest.yaml inside a module ZIP.
// Every module must ship this file at the archive root.
type Manifest struct {
	Name    string `yaml:"name"         json:"name"`
	Version string `yaml:"version"      json:"version"`
	Tier    int    `yaml:"tier"         json:"tier"`
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
	// Crud is Tier 1 only: the config-driven CRUD definition Core generates
	// a REST API (and fallback UI) from — see crud.go. Required for Tier 1,
	// forbidden for Tier 2/3 (validateManifestTier enforces both).
	Crud *ManifestCrud `yaml:"crud" json:"crud,omitempty"`
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

// ManifestCrud is a Tier 1 module's config-driven CRUD definition.
type ManifestCrud struct {
	// Table is the table name within the module's own module_{name} schema.
	// Must satisfy safeIdentRe (see moduleIdentifiers) since it is
	// interpolated into SQL identifiers - validated by validateCrudTable at
	// install/update time, not here.
	Table string `yaml:"table" json:"table"`
	// Fields are the author-declared, user-facing columns. Core also manages
	// a fixed set of implicit columns not listed here - id, created_at,
	// updated_at, and (when OwnerScoped) created_by - see crud.go's
	// implicitCrudColumns.
	Fields []ManifestCrudField `yaml:"fields" json:"fields"`
	// OwnerScoped, when true, restricts every row to the user who created
	// it: list/get/update/delete all filter or reject on created_by =
	// the caller's own user ID, with no exception - not even for admins.
	// When false (default), every user with access to the module can read
	// and write every row (shared data).
	OwnerScoped bool `yaml:"owner_scoped" json:"owner_scoped,omitempty"`
}

// ManifestCrudField is one field of a Tier 1 module's crud.fields list.
type ManifestCrudField struct {
	Name string `yaml:"name" json:"name"`
	// Type is one of the crudFieldTypes below (see crud.go) - validated by
	// validateCrudTable against the real column type at install/update time.
	Type string `yaml:"type" json:"type"`
	// Required marks the field mandatory on create - enforced by the
	// generic CRUD handler (crud.go), not by a DB NOT NULL constraint alone,
	// so a missing field gets a clear 400 instead of a raw SQL error.
	Required bool `yaml:"required" json:"required,omitempty"`
	// Encrypted, when true, stores this field's value AES-256-GCM encrypted
	// at rest (crypto.Encrypt, MODULAB_MODULE_PII_KEY) and transparently
	// decrypts it on read. Cannot be filtered/searched server-side - see
	// crud.go's doc comment.
	Encrypted bool `yaml:"encrypted" json:"encrypted,omitempty"`
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
// 10. Run module-supplied SQL migrations
// 11. Deno worker registration and start
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

	// A private custom source needs its GitHub PAT on every download below.
	// Resolved fresh from custom_sources here rather than carried on entry -
	// module_registry (what entry is cached from) never stores credentials,
	// see db.CustomSourceRow's doc comment. "" for official/community and for
	// a custom source added without a token (public repo) - downloadFile
	// treats an empty token as "no Authorization header", same as before this
	// existed.
	token := resolveCustomSourceToken(ctx, d.DB, entry.Source, entry.SourceRepo, entry.Name, "install")

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

	go func() { zipCh <- dlResult{downloadFile(dlCtx, zipURL, zipPath, maxZIPBytes, token)} }()
	go func() { hashCh <- dlResult{downloadFile(dlCtx, sha256URL, sha256Path, maxSHA256FileBytes, token)} }()

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
		if err := downloadFile(dlCtx, entry.CosignSigURL, sigPath, maxSigFileBytes, token); err != nil {
			return fmt.Errorf("modules: install %q: download cosign bundle: %w", entry.Name, err)
		}
		ok, err := VerifyCosign(zipPath, sigPath, entry.CosignPubKey, d.CosignBin)
		if err != nil {
			return fmt.Errorf("modules: install %q: cosign verify: %w", entry.Name, err)
		}
		cosignVerified = ok
	} else if entry.Source != "official" {
		// Community/custom modules without explicit sig URL: try the
		// conventional .sig path as a best-effort, proceed even if absent.
		// entry.CosignPubKey is only ever non-empty for source="custom" (the
		// admin-entered key for that repo); empty for community, which falls
		// back to the embedded official key inside VerifyCosign and - as
		// expected - will not verify against it, ending up cosignSkipped.
		if dlErr := downloadFile(dlCtx, sigURL, sigPath, maxSigFileBytes, token); dlErr == nil {
			ok, err := VerifyCosign(zipPath, sigPath, entry.CosignPubKey, d.CosignBin)
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

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: install %q: marshal manifest: %w", entry.Name, err)
	}

	// ── 8. DB insert (status = installing) ────────────────────────────────
	// From this point on, any error must attempt to clean up the DB row.
	if err := d.DB.InsertInstalledModule(ctx,
		mf.Name, mf.Version, mf.Tier,
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

	// ── 10b. Tier 1: cross-check crud against the migrated table ──────────
	// Must run after migrations (10) so the table actually exists, and
	// before marking active (12) so a mismatch between crud.fields and the
	// author's own migrations/*.sql blocks the install with a clear error
	// instead of surfacing as an opaque SQL error on the first API call.
	// See docs/tier1-crud-plan.md.
	if mf.Tier == 1 {
		if err := validateCrudTable(ctx, d, mf.Name, mf.Crud); err != nil {
			_, _ = d.DB.UpdateModuleStatus(ctx, entry.Name, db.ModuleStatusFailed)
			return fmt.Errorf("modules: install %q: %w", entry.Name, err)
		}
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

// InstallManual installs a module from a locally uploaded ZIP file (as
// opposed to Install, which downloads one from a registry entry's URLs).
// zipPath is a file already on disk (the HTTP handler writes the uploaded
// multipart body there before calling this) — ownership of that file stays
// with the caller, InstallManual only reads it.
//
// Mirrors Install from step 6 onward (extract → parse manifest → validate
// tier → DB insert → copy files → migrations → Deno worker), but skips
// everything download/signature-related:
//   - No registry entry, so no zipURL/sha256URL/sigURL to resolve.
//   - No Cosign verification — there is no signature to check for a file
//     that never went through the official/community/custom release
//     pipeline. cosign_verified is persisted as false, and the source is
//     recorded as "manual" so the Store UI shows an "unverified" badge
//     instead of silently implying the same trust level as a signed source.
//   - sha256 is still computed (VerifySHA256 with expectedHex == the just-
//     computed hash, i.e. always "matches") purely so the column is
//     populated for System Info / audit purposes, not as a security check.
func InstallManual(ctx context.Context, d Deps, zipPath string) error {
	maxZIPBytes := MaxModuleZIPBytes(ctx, d.DB)

	// ── Extract ZIP to a scratch dir so we can read manifest.yaml before
	// touching the DB or any installed_modules row ────────────────────────
	tmpDir, err := os.MkdirTemp("", "modulab-install-manual-*")
	if err != nil {
		return fmt.Errorf("modules: install manual: create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("modules: install manual: cleanup temp dir %s: %v", tmpDir, err)
		}
	}()

	extractDir := filepath.Join(tmpDir, "extracted")
	if err := extractZIP(zipPath, extractDir, maxZIPBytes); err != nil {
		return fmt.Errorf("modules: install manual: extract zip: %w", err)
	}

	mf, err := parseManifest(filepath.Join(extractDir, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("modules: install manual: %w", err)
	}
	if err := validateManifestTier(mf); err != nil {
		return fmt.Errorf("modules: install manual %q: %w", mf.Name, err)
	}

	// ── Guard: not already installed (mirrors Install's step 1, moved here
	// since the module name is only known once the manifest is parsed) ────
	_, exists, err := d.DB.GetInstalledModule(ctx, mf.Name)
	if err != nil {
		return fmt.Errorf("modules: install manual %q: check existing: %w", mf.Name, err)
	}
	if exists {
		return fmt.Errorf("modules: install manual %q: already installed", mf.Name)
	}

	// sha256 is computed for record-keeping only (System Info / audit) —
	// there is no separate .sha256 sidecar file to verify a manual upload
	// against, so this is plain hashing, not VerifySHA256's mismatch check.
	gotHex, err := hashSHA256File(zipPath)
	if err != nil {
		return fmt.Errorf("modules: install manual %q: hash zip: %w", mf.Name, err)
	}

	manifestJSON, err := json.Marshal(mf)
	if err != nil {
		return fmt.Errorf("modules: install manual %q: marshal manifest: %w", mf.Name, err)
	}

	// ── DB insert (status = installing) ────────────────────────────────────
	if err := d.DB.InsertInstalledModule(ctx,
		mf.Name, mf.Version, mf.Tier,
		"manual", "", gotHex, manifestJSON, false, "",
	); err != nil {
		return fmt.Errorf("modules: install manual %q: db insert: %w", mf.Name, err)
	}

	// ── Copy module files to DataDir/{name} ────────────────────────────────
	destDir := filepath.Join(d.DataDir, mf.Name)
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install manual %q: create dest dir: %w", mf.Name, err)
	}
	if err := copyDir(extractDir, destDir); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install manual %q: copy files: %w", mf.Name, err)
	}

	// ── Module SQL migrations ──────────────────────────────────────────────
	migrationsDir := filepath.Join(extractDir, "migrations")
	if err := runModuleMigrations(ctx, d, mf.Name, migrationsDir); err != nil {
		_, _ = d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusFailed)
		return fmt.Errorf("modules: install manual %q: migrations: %w", mf.Name, err)
	}

	// ── Tier 1: cross-check crud against the migrated table ────────────────
	if mf.Tier == 1 {
		if err := validateCrudTable(ctx, d, mf.Name, mf.Crud); err != nil {
			_, _ = d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusFailed)
			return fmt.Errorf("modules: install manual %q: %w", mf.Name, err)
		}
	}

	// ── Deno worker registration ────────────────────────────────────────────
	if mf.Tier >= 2 {
		opts := WorkerOptions{
			EgressHosts:   mf.EgressAllowlist,
			Jobs:          ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
			SkipTLSVerify: mf.TLSSkipVerify,
		}
		if err := d.Workers.Start(mf.Name, filepath.Join(destDir, mf.Handler), opts); err != nil {
			_, _ = d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusFailed)
			return fmt.Errorf("modules: install manual %q: start deno worker: %w", mf.Name, err)
		}
		if mf.DynamicEgress && mf.EgressHostsHandler != "" {
			if hosts, ok := d.Workers.QueryEgressHosts(ctx, mf.Name); ok {
				if err := d.Workers.ReloadEgress(mf.Name, hosts); err != nil {
					log.Printf("modules: install manual %q: initial egress hosts reload failed: %v", mf.Name, err)
				}
			}
		}
	}

	// ── Mark active ─────────────────────────────────────────────────────────
	if _, err := d.DB.UpdateModuleStatus(ctx, mf.Name, db.ModuleStatusActive); err != nil {
		if mf.Tier >= 2 {
			if stopErr := d.Workers.Stop(mf.Name); stopErr != nil {
				log.Printf("modules: install manual %q: stop orphaned worker after failed activate: %v", mf.Name, stopErr)
			}
		}
		return fmt.Errorf("modules: install manual %q: mark active: %w", mf.Name, err)
	}

	log.Printf("modules: installed %q %s manually (tier %d, unverified)", mf.Name, mf.Version, mf.Tier)
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// resolveCustomSourceToken looks up the GitHub PAT for a private custom
// source, or "" for anything else (official, community, or a custom source
// added without a token). Errors are logged and swallowed, not returned -
// worst case a private repo's download 404s downstream with a clear error,
// same failure mode as a token that was simply never configured; this must
// never abort an install/update over a lookup hiccup.
func resolveCustomSourceToken(ctx context.Context, pool *db.Pool, source, sourceRepo, name, action string) string {
	if source != "custom" {
		return ""
	}
	row, found, err := pool.GetCustomSourceByRepoURL(ctx, sourceRepo)
	if err != nil {
		log.Printf("modules: %s %q: resolve custom source token: %v", action, name, err)
		return ""
	}
	if !found {
		return ""
	}
	return row.Token
}

// githubReleaseDownloadPrefix marks a URL as GitHub's plain
// "releases/download" scheme (as opposed to an already-resolved
// api.github.com asset URL, or some third-party host a future source type
// might use) - see resolveGithubAssetURL's doc comment for why that
// distinction matters.
const githubReleaseDownloadPrefix = "https://github.com/"

// resolveGithubAssetURL turns a plain
// "https://github.com/OWNER/REPO/releases/download/TAG/FILE" URL into the
// api.github.com asset-id URL GitHub actually honors a PAT Authorization
// header on for a PRIVATE repo.
//
// Found 2026-07-18 installing the first real private custom-source module:
// the plain releases/download URL is meant for an
// unauthenticated browser redirect flow. Sending it a Bearer token does not
// authenticate a private repo's request - GitHub returns 404 regardless of
// the token, indistinguishable from "the asset genuinely doesn't exist".
// This never surfaced before because official/community sources are always
// public repos, where the plain URL works with no auth at all. The
// documented API path for a private repo's release asset is: GET
// /repos/{owner}/{repo}/releases/tags/{tag} to find the asset's own "url"
// field (already an api.github.com/.../releases/assets/{id} URL), then GET
// that URL with Accept: application/octet-stream - which is what
// downloadFile does once this function hands it the resolved URL.
func resolveGithubAssetURL(ctx context.Context, rawURL, token string) (string, error) {
	rest := strings.TrimPrefix(rawURL, githubReleaseDownloadPrefix)
	parts := strings.SplitN(rest, "/releases/download/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("not a releases/download URL: %s", rawURL)
	}
	ownerRepo := parts[0]
	tagAndFile := strings.SplitN(parts[1], "/", 2)
	if len(tagAndFile) != 2 {
		return "", fmt.Errorf("could not split tag/filename out of: %s", rawURL)
	}
	tag, filename := tagAndFile[0], tagAndFile[1]

	apiURL := "https://api.github.com/repos/" + ownerRepo + "/releases/tags/" + tag
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "modulab-core/1 (https://github.com/modulab-project/modulab-core)")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("modules: resolveGithubAssetURL: close response body: %v", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d resolving release %q for %s", resp.StatusCode, tag, ownerRepo)
	}

	var release struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode release %q: %w", tag, err)
	}
	for _, a := range release.Assets {
		if a.Name == filename {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("asset %q not found in release %q", filename, tag)
}

// downloadFile fetches url and writes the body to path. Returns an error if
// the response is not 2xx or the body exceeds maxBytes. token is an optional
// GitHub PAT (see resolveCustomSourceToken) - sent as an Authorization
// header when non-empty, so a private custom source's release assets
// resolve instead of 404ing exactly like the public-source case.
//
// When token is set and url is a plain github.com releases/download URL,
// resolves it to the api.github.com asset URL first (resolveGithubAssetURL)
// - required for private repos, harmless to redo for a public one, so this
// isn't conditioned on the repo actually being private.
func downloadFile(ctx context.Context, url, path string, maxBytes int64, token string) error {
	acceptOctetStream := false
	if token != "" && strings.HasPrefix(url, githubReleaseDownloadPrefix) && strings.Contains(url, "/releases/download/") {
		resolved, err := resolveGithubAssetURL(ctx, url, token)
		if err != nil {
			return fmt.Errorf("resolve private release asset: %w", err)
		}
		url = resolved
		acceptOctetStream = true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "modulab-core/1 (https://github.com/modulab-project/modulab-core)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if acceptOctetStream {
		req.Header.Set("Accept", "application/octet-stream")
	}

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

// hashSHA256File computes the hex-encoded SHA-256 digest of path, with no
// comparison against an expected value — used by InstallManual/UpdateManual
// to populate the sha256 column for a manual upload, where there is no
// separate .sha256 sidecar file to check against (see VerifySHA256 in
// verifier.go for the download-and-verify counterpart used by every other
// source).
func hashSHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash sha256: open %q: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("modules: hashSHA256File: close %s: %v", path, err)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash sha256: hash %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
//   - tls_skip_verify is only meaningful alongside hosts the worker will
//     actually contact - either a non-empty egress_allowlist, or
//     dynamic_egress + egress_hosts_handler for modules that compute their
//     egress hosts at runtime (unifi-network). true with neither source of
//     hosts is almost certainly an author mistake and is rejected rather
//     than silently ignored.
//   - Tier 1 must declare a crud block (table + at least one field), or the
//     module installs with no functionality and no clear error explaining
//     why - see docs/tier1-crud-plan.md.
func validateManifestTier(mf Manifest) error {
	if mf.Tier < 1 || mf.Tier > 3 {
		return fmt.Errorf("invalid tier %d (must be 1–3)", mf.Tier)
	}
	if mf.Tier == 1 && (mf.Handler != "" || len(mf.Jobs) > 0 || len(mf.EgressAllowlist) > 0) {
		return fmt.Errorf("tier 1 must not declare handler/jobs/egress_allowlist")
	}
	if mf.Tier == 1 && (mf.Crud == nil || mf.Crud.Table == "" || len(mf.Crud.Fields) == 0) {
		return fmt.Errorf("tier 1 requires a crud block with a table and at least one field")
	}
	if mf.Tier == 1 {
		if err := validateCrudFields(mf.Crud); err != nil {
			return err
		}
	}
	if mf.Tier >= 2 && mf.Crud != nil {
		return fmt.Errorf("tier %d must not declare crud (tier 1 only)", mf.Tier)
	}
	if mf.Tier >= 2 && mf.Handler == "" {
		return fmt.Errorf("tier %d requires a handler", mf.Tier)
	}
	if mf.Tier == 2 && len(mf.EgressAllowlist) > 0 {
		return fmt.Errorf("tier 2 must not declare egress_allowlist (use tier 3)")
	}
	// tls_skip_verify is scoped to whatever hosts the worker actually gets
	// --allow-net for - that's normally EgressAllowlist, but a module can
	// opt into dynamic_egress + egress_hosts_handler instead (unifi-network)
	// to compute its egress hosts at runtime from its own DB rather than a
	// static manifest list. Both are valid sources of "hosts this worker
	// will contact"; only reject tls_skip_verify when NEITHER is present,
	// since that combination has no hosts to scope it to at all.
	if mf.TLSSkipVerify && len(mf.EgressAllowlist) == 0 && (!mf.DynamicEgress || mf.EgressHostsHandler == "") {
		return fmt.Errorf("tls_skip_verify requires a non-empty egress_allowlist or dynamic_egress with an egress_hosts_handler")
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
