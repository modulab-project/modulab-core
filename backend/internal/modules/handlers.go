package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
)

// logModuleAudit writes one audit_log entry for a module lifecycle action.
// Mirrors auth/admin.go's logAudit (same "resolve master key, log-and-swallow
// on failure" shape) - duplicated rather than shared because it lives in a
// different package and depends on auth.Deps only for MasterKeyEnv/Pool, not
// anything modules-specific. A failed audit write must never turn a
// successful install/uninstall/update/pin into a 500 the admin has to retry;
// the module action has already happened by the time this is called.
func logModuleAudit(ctx context.Context, authDeps auth.Deps, p audit.LogParams) {
	masterKey, err := setup.ResolveMasterKey(ctx, authDeps.Pool, authDeps.MasterKeyEnv)
	if err != nil {
		log.Printf("modules: audit: failed to resolve master key for %s: %v", p.EventType, err)
		return
	}
	if err := audit.Log(ctx, authDeps.Pool, masterKey, p); err != nil {
		log.Printf("modules: audit: failed to write %s: %v", p.EventType, err)
	}
}

// ── GET /v1/modules ───────────────────────────────────────────────────────────

// ListInstalledHandler returns all installed modules. Requires an active session
// (any approved user — the installed module list is visible to all).
func ListInstalledHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}

		rows, err := d.DB.ListInstalledModules(r.Context())
		if err != nil {
			http.Error(w, "failed to list modules", http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []db.InstalledModuleRow{}
		}
		writeModuleJSON(w, http.StatusOK, rows)
	}
}

// ── GET /v1/modules/updates ───────────────────────────────────────────────────

// CheckUpdatesHandler triggers an immediate update check against the registry
// cache and returns the list of modules with newer versions available.
// Requires admin.
func CheckUpdatesHandler(d Deps, storeDeps store.Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
			return
		}

		updates, err := CheckUpdates(r.Context(), d, storeDeps)
		if err != nil {
			http.Error(w, "update check failed", http.StatusInternalServerError)
			return
		}
		if updates == nil {
			updates = []UpdateInfo{}
		}
		writeModuleJSON(w, http.StatusOK, map[string]any{
			"updates": updates,
			"count":   len(updates),
		})
	}
}

// ── GET /v1/modules/{name} ────────────────────────────────────────────────────

// GetInstalledHandler returns a single installed module by name.
// Requires any active session, OR a module-scoped token minted for exactly
// this module (see auth.RequireSessionOrModuleToken - a module's own
// ModuleInfoView "info" tab calls this route with only its module token).
func GetInstalledHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		if _, ok := auth.RequireSessionOrModuleToken(authDeps, name, w, r); !ok {
			return
		}

		row, found, err := d.DB.GetInstalledModule(r.Context(), name)
		if err != nil {
			http.Error(w, "failed to read module", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}

		writeModuleJSON(w, http.StatusOK, row)
	}
}

// ── GET /v1/modules/{name}/egress-hosts ───────────────────────────────────────

// GetModuleEgressHostsHandler returns the module's CURRENTLY RUNNING worker's
// actual egress hosts — as opposed to GetInstalledHandler's row.Manifest,
// which only has the static egress_allowlist from the manifest at last
// install/update.
//
// This distinction matters for modules like unifi-network whose real network
// access is entirely runtime-configured (admin-entered gateway IPs) and
// whose manifest deliberately declares egress_allowlist: [] — the info card
// (ModuleInfoView in each module's own UI) was showing "no network access"
// even with gateways configured and working, because it only ever read the
// static manifest value. Reported by the user 2026-07-04 ("Info Netzzugriff
// (Core) kein Netzzugriff" despite configured gateways).
//
// Falls back to an empty list (not an error) if no worker is currently
// running for the module (Tier 0/1 module with no worker at all, or a
// worker that failed to start) — the info card already renders that the
// same way as "static allowlist is empty".
func GetModuleEgressHostsHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		if _, ok := auth.RequireSessionOrModuleToken(authDeps, name, w, r); !ok {
			return
		}

		hosts, ok := d.Workers.CurrentModuleEgressHosts(name)
		if !ok {
			hosts = []string{}
		}
		writeModuleJSON(w, http.StatusOK, map[string]any{"egress_hosts": hosts})
	}
}

// ── POST /v1/modules/install ──────────────────────────────────────────────────

// InstallHandler installs a module from the registry.
// Body: {"name": "module-name"}
// Requires admin.
//
// Note: Install runs synchronously. For large modules (approaching the 100 MB
// cap) this can take several seconds. The client should show a loading state.
// A non-blocking job queue (with SSE progress) is planned post-v1.
func InstallHandler(d Deps, storeDeps store.Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "request body must be JSON with a non-empty \"name\" field", http.StatusBadRequest)
			return
		}

		entry, found, err := store.GetEntry(r.Context(), storeDeps.Pool, body.Name)
		if err != nil {
			http.Error(w, "registry lookup failed", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not found in registry", http.StatusNotFound)
			return
		}

		if err := Install(r.Context(), d, entry); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		row, _, _ := d.DB.GetInstalledModule(r.Context(), body.Name)

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleInstalled,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   body.Name,
			Details:    fmt.Sprintf(`{"version":%q,"tier":%d,"source":%q}`, row.Version, row.Tier, entry.Source),
		})

		writeModuleJSON(w, http.StatusCreated, row)
	}
}

// ── POST /v1/modules/install-manual ───────────────────────────────────────────

// InstallManualHandler installs (or, if already installed, updates) a module
// from a manually uploaded ZIP file — no registry entry, no download, no
// Cosign signature (see InstallManual/UpdateManual's doc comments,
// installer.go/updater.go). Multipart body, field "file".
//
// Whether this ends up calling InstallManual or UpdateManual is decided
// AFTER peeking the uploaded ZIP's manifest.yaml for its module name (the
// request itself carries no name — the ZIP is the only source of truth for
// which module this is), not by any query param the client would have to
// get right.
//
// Requires admin, same as InstallHandler/UpdateModuleHandler.
func InstallManualHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		maxZIPBytes := MaxModuleZIPBytes(r.Context(), d.DB)
		// Reject oversized uploads before reading any body bytes — same
		// Content-Length pre-check reasoning as router.go's file-upload path
		// (avoids a bare 502 from a reverse proxy on a body that trips
		// MaxBytesReader mid-stream instead of failing cleanly upfront).
		if maxZIPBytes > 0 && r.ContentLength > maxZIPBytes {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
		parseMemory := maxZIPBytes
		if maxZIPBytes <= 0 {
			parseMemory = unlimitedUploadParseMemory
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, maxZIPBytes)
		}
		if err := r.ParseMultipartForm(parseMemory); err != nil {
			http.Error(w, "parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing \"file\" field", http.StatusBadRequest)
			return
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("modules: install-manual: close uploaded file: %v", err)
			}
		}()

		tmpFile, err := os.CreateTemp("", "modulab-manual-upload-*.zip")
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		tmpPath := tmpFile.Name()
		defer func() {
			if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
				log.Printf("modules: install-manual: cleanup uploaded zip %s: %v", tmpPath, err)
			}
		}()

		if _, err := io.Copy(tmpFile, file); err != nil {
			_ = tmpFile.Close()
			http.Error(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := tmpFile.Close(); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		// Peek the manifest to learn the module name and whether it's
		// already installed — this is what decides Install vs. Update, not
		// anything the client sent.
		name, alreadyInstalled, oldVersion, err := peekManualUploadModule(r.Context(), d, tmpPath, maxZIPBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		if alreadyInstalled {
			if err := UpdateManual(r.Context(), d, tmpPath); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			row, _, _ := d.DB.GetInstalledModule(r.Context(), name)
			logModuleAudit(r.Context(), authDeps, audit.LogParams{
				EventType:  audit.EventModuleUpdated,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				TargetID:   name,
				Details:    fmt.Sprintf(`{"from_version":%q,"to_version":%q,"source":"manual"}`, oldVersion, row.Version),
			})
			writeModuleJSON(w, http.StatusOK, row)
			return
		}

		if err := InstallManual(r.Context(), d, tmpPath); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		row, _, _ := d.DB.GetInstalledModule(r.Context(), name)
		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleInstalled,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
			Details:    fmt.Sprintf(`{"version":%q,"tier":%d,"source":"manual"}`, row.Version, row.Tier),
		})
		writeModuleJSON(w, http.StatusCreated, row)
	}
}

// peekManualUploadModule extracts just manifest.yaml from the uploaded ZIP
// (into a throwaway temp dir, separate from InstallManual/UpdateManual's own
// extraction) to learn the module name before deciding which of the two to
// call. Returns the name, whether installed_modules already has a row for
// it, and that row's current version (for the audit "from_version" field —
// zero value if not installed).
func peekManualUploadModule(ctx context.Context, d Deps, zipPath string, maxZIPBytes int64) (name string, installed bool, currentVersion string, err error) {
	peekDir, err := os.MkdirTemp("", "modulab-manual-upload-peek-*")
	if err != nil {
		return "", false, "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(peekDir); rmErr != nil {
			log.Printf("modules: install-manual: cleanup peek dir %s: %v", peekDir, rmErr)
		}
	}()

	if err := extractZIP(zipPath, peekDir, maxZIPBytes); err != nil {
		return "", false, "", fmt.Errorf("extract zip: %w", err)
	}
	mf, err := parseManifest(filepath.Join(peekDir, "manifest.yaml"))
	if err != nil {
		return "", false, "", err
	}

	row, found, err := d.DB.GetInstalledModule(ctx, mf.Name)
	if err != nil {
		return "", false, "", fmt.Errorf("check existing: %w", err)
	}
	if found {
		return mf.Name, true, row.Version, nil
	}
	return mf.Name, false, "", nil
}

// ── DELETE /v1/modules/{name} ─────────────────────────────────────────────────

// UninstallHandler removes an installed module.
// Requires admin.
func UninstallHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		// Read the row before Uninstall deletes it, so the audit entry below
		// can still record what version/tier was actually removed.
		row, _, _ := d.DB.GetInstalledModule(r.Context(), name)

		if err := Uninstall(r.Context(), d, name); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleUninstalled,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
			Details:    fmt.Sprintf(`{"version":%q,"tier":%d}`, row.Version, row.Tier),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

// ── POST /v1/modules/{name}/update ───────────────────────────────────────────

// UpdateModuleHandler triggers an immediate update of an installed module.
// The module must have an available_version set (run CheckUpdates first, or
// rely on the daily sync). Requires admin.
func UpdateModuleHandler(d Deps, storeDeps store.Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		entry, found, err := store.GetEntry(r.Context(), storeDeps.Pool, name)
		if err != nil {
			http.Error(w, "registry lookup failed", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not found in registry", http.StatusNotFound)
			return
		}

		// Capture the pre-update version for the audit entry below - Update
		// overwrites installed_modules.version in place.
		oldRow, _, _ := d.DB.GetInstalledModule(r.Context(), name)
		oldVersion := oldRow.Version

		if err := Update(r.Context(), d, entry); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Capture the currently-running worker's actual (runtime-discovered)
		// egress hosts BEFORE stopping it — see CurrentModuleEgressHosts doc
		// comment in deno.go. Only actually used below if the NEW manifest
		// declares dynamic_egress: true (see Manifest.DynamicEgress doc
		// comment for why this must be an explicit opt-in, not a guess based
		// on "the old worker had hosts the new manifest doesn't").
		runtimeEgressHosts, hadRuntimeHosts := d.Workers.CurrentModuleEgressHosts(name)

		// Restart the Deno worker so it picks up the new handler code.
		//
		// row is re-fetched AFTER Update() returns, so row.Tier now reflects
		// the NEW manifest's tier (Update's updateInstalledModuleRecord
		// persists it - see that function's doc comment; before 2026-07-16 it
		// didn't, so a tier-changing update left this gate checking the
		// stale pre-update tier forever). Stop() above always runs
		// unconditionally, so a tier>=2 → tier==1 downgrade correctly ends
		// up with no worker restarted below; a tier==1 → tier>=2 upgrade
		// correctly starts one where none ran before.
		_ = d.Workers.Stop(name)
		row, _, _ := d.DB.GetInstalledModule(r.Context(), name)
		if row.Tier >= 2 {
			var mf struct {
				Handler            string        `json:"handler"`
				EgressAllowlist    []string      `json:"egress_allowlist"`
				Jobs               []ManifestJob `json:"jobs"`
				TLSSkipVerify      bool          `json:"tls_skip_verify"`
				DynamicEgress      bool          `json:"dynamic_egress"`
				EgressHostsHandler string        `json:"egress_hosts_handler"`
				DynamicEgressAllow []string      `json:"dynamic_egress_allow"`
			}
			if row.Manifest != nil {
				_ = json.Unmarshal(row.Manifest, &mf)
			}
			if mf.Handler != "" {
				destDir := filepath.Join(d.DataDir, name)
				entrypoint := filepath.Join(destDir, mf.Handler)
				egressHosts := mf.EgressAllowlist
				if mf.DynamicEgress && hadRuntimeHosts && len(runtimeEgressHosts) > 0 {
					// Runtime hosts carried over from the worker we just
					// stopped were checked against the OLD manifest's policy
					// when they were granted. This is a module *update*, so
					// the policy may have just changed - re-check them
					// against the version being installed rather than
					// grandfathering them in, otherwise tightening
					// dynamic_egress_allow would have no effect until the
					// next reload happened to come along.
					egressHosts = carryOverRuntimeEgress(name, runtimeEgressHosts, mf.DynamicEgressAllow, "update")
				}
				opts := WorkerOptions{
					EgressHosts:    egressHosts,
					Jobs:           ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
					SkipTLSVerify:  mf.TLSSkipVerify,
					EgressPolicy:   mf.DynamicEgressAllow,
					DBRolePassword: moduleDBRolePassword(r.Context(), d, name),
					PIIMigrated:    modulePIIMigrated(r.Context(), d, name),
				}
				if err := d.Workers.Start(name, entrypoint, opts); err != nil {
					log.Printf("modules: update %q: restart worker: %v", name, err)
				} else if mf.DynamicEgress && mf.EgressHostsHandler != "" {
					// The just-started worker is a fresher source of truth
					// than whatever we captured before stopping it above
					// (the update may itself have changed how hosts are
					// computed) — ask it directly and reload once more.
					if hosts, ok := d.Workers.QueryEgressHosts(r.Context(), name); ok {
						if err := d.Workers.ReloadEgress(name, hosts); err != nil {
							log.Printf("modules: update %q: egress hosts reload failed: %v", name, err)
						}
					}
				}
			}
		}

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleUpdated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
			Details:    fmt.Sprintf(`{"from_version":%q,"to_version":%q}`, oldVersion, row.Version),
		})

		writeModuleJSON(w, http.StatusOK, row)
	}
}

// ── POST /v1/modules/{name}/pin ───────────────────────────────────────────────

// PinHandler pins a module, preventing automatic updates and uninstallation.
// Requires admin.
func PinHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		found, err := d.DB.SetModulePinned(r.Context(), name, true)
		if err != nil {
			http.Error(w, "failed to pin module", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModulePinned,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
		})

		writeModuleJSON(w, http.StatusOK, map[string]any{"name": name, "pinned": true})
	}
}

// ── DELETE /v1/modules/{name}/pin ─────────────────────────────────────────────

// UnpinHandler removes the pin from a module.
// Requires admin.
func UnpinHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		found, err := d.DB.SetModulePinned(r.Context(), name, false)
		if err != nil {
			http.Error(w, "failed to unpin module", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleUnpinned,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
		})

		writeModuleJSON(w, http.StatusOK, map[string]any{"name": name, "pinned": false})
	}
}

// ── POST /v1/modules/{name}/restart ───────────────────────────────────────────

// RestartModuleHandler restarts a Tier 2/3 module's Deno worker from its
// currently-installed manifest, without touching version/source/registry at
// all. Requires admin.
//
// Exists specifically for the "degraded" recovery gap: WorkerPool's crash
// handler (deno.go's SetCrashHandler) deliberately never auto-restarts a
// crashed worker, and the boot-time restart loop (main.go) only restarts
// modules whose status is already "active" - a module that crashed once
// stays "degraded" forever otherwise, with no way back to "active" short of
// an actual version update (UpdateModuleHandler above, which requires
// available_version to be set - not the case for a module already on the
// latest release). Before this handler existed, the only recovery path for
// "degraded, no update available" was a manual UPDATE installed_modules SET
// status = 'active' in psql (hit in practice 2026-07-04, after the Deno 2.9
// upgrade's unix-socket --allow-net change - see WorkerPool.Start's doc
// comment - crashed my-places/recipes/unifi-network and left them stuck).
func RestartModuleHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		row, found, err := d.DB.GetInstalledModule(r.Context(), name)
		if err != nil {
			http.Error(w, "failed to look up module", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}
		if row.Tier < 2 {
			// Tier 1 modules have no Deno worker to restart at all.
			http.Error(w, "module has no worker to restart", http.StatusBadRequest)
			return
		}

		// Same runtime-egress-preservation dance as UpdateModuleHandler above
		// (see CurrentModuleEgressHosts's doc comment in deno.go): a plain
		// Stop/Start would otherwise silently drop hosts a dynamic_egress
		// module discovered at runtime (e.g. unifi-network's configured
		// gateway IPs) back down to just the manifest's static allowlist.
		runtimeEgressHosts, hadRuntimeHosts := d.Workers.CurrentModuleEgressHosts(name)

		_ = d.Workers.Stop(name)

		var mf struct {
			Handler            string        `json:"handler"`
			EgressAllowlist    []string      `json:"egress_allowlist"`
			Jobs               []ManifestJob `json:"jobs"`
			TLSSkipVerify      bool          `json:"tls_skip_verify"`
			DynamicEgress      bool          `json:"dynamic_egress"`
			EgressHostsHandler string        `json:"egress_hosts_handler"`
			DynamicEgressAllow []string      `json:"dynamic_egress_allow"`
		}
		if row.Manifest != nil {
			_ = json.Unmarshal(row.Manifest, &mf)
		}
		if mf.Handler == "" {
			http.Error(w, "module manifest has no handler", http.StatusUnprocessableEntity)
			return
		}

		destDir := filepath.Join(d.DataDir, name)
		entrypoint := filepath.Join(destDir, mf.Handler)
		egressHosts := mf.EgressAllowlist
		if mf.DynamicEgress && hadRuntimeHosts && len(runtimeEgressHosts) > 0 {
			// Same re-check as the update path above - see its comment. A
			// plain restart is not expected to change the policy, but it is
			// also the operation an admin reaches for after editing one, so
			// silently reapplying unchecked hosts here would be the obvious
			// way for the update-path check to be worked around.
			egressHosts = carryOverRuntimeEgress(name, runtimeEgressHosts, mf.DynamicEgressAllow, "restart")
		}
		opts := WorkerOptions{
			EgressHosts:    egressHosts,
			Jobs:           ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
			SkipTLSVerify:  mf.TLSSkipVerify,
			EgressPolicy:   mf.DynamicEgressAllow,
			DBRolePassword: moduleDBRolePassword(r.Context(), d, name),
			PIIMigrated:    modulePIIMigrated(r.Context(), d, name),
		}
		if err := d.Workers.Start(name, entrypoint, opts); err != nil {
			http.Error(w, fmt.Sprintf("failed to restart worker: %v", err), http.StatusInternalServerError)
			return
		}
		if mf.DynamicEgress && mf.EgressHostsHandler != "" {
			if hosts, ok := d.Workers.QueryEgressHosts(r.Context(), name); ok {
				if err := d.Workers.ReloadEgress(name, hosts); err != nil {
					log.Printf("modules: restart %q: egress hosts reload failed: %v", name, err)
				}
			}
		}

		if _, err := d.DB.UpdateModuleStatus(r.Context(), name, db.ModuleStatusActive); err != nil {
			log.Printf("modules: restart %q: set status active: %v", name, err)
		}
		row, _, _ = d.DB.GetInstalledModule(r.Context(), name)

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModuleRestarted,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
		})

		writeModuleJSON(w, http.StatusOK, row)
	}
}

// ── POST /v1/admin/modules/{name}/migrate-pii-key ─────────────────────────────

// MigratePIIKeyHandler triggers a Tier 2/3 module's own migrate-pii-key
// handler (see docs/Modul-DB-Sandbox_Plan_2026-08-02.md Part B) and, on
// success, marks installed_modules.pii_migrated_at so the next worker
// (re)start stops granting MODULAB_MODULE_PII_LEGACY_KEY (deno.go's
// buildWorker checks opts.PIIMigrated). This is the one PII-bearing action
// gated by adminReauthOnly (wired in main.go) rather than plain
// RequireAdminSession: it is a one-time, hard-to-undo action - once the
// legacy key stops being granted, any row the module's handler failed to
// re-encrypt becomes unreadable - the same bar as revoking a session or
// changing SMTP/OIDC config.
//
// The module side of the contract (its own POST /admin/migrate-pii-key
// route) is expected to check auth.roles for "admin" itself, same as every
// other module route - Core does not special-case that here, it just
// forwards the already-verified admin session as WorkerAuth like the normal
// module proxy (router.go) does.
func MigratePIIKeyHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		row, found, err := d.DB.GetInstalledModule(r.Context(), name)
		if err != nil {
			http.Error(w, "failed to look up module", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}
		if row.Tier < 2 {
			// Tier 1 modules have no Deno worker and never received the
			// shared PII key in the first place (crud.go uses d.PIIKey
			// directly, undifferentiated per module - see installer.go's
			// Deps.PIIKey doc comment).
			http.Error(w, "module has no PII key to migrate", http.StatusBadRequest)
			return
		}
		if row.Status != "active" {
			http.Error(w, fmt.Sprintf("module is %s", row.Status), http.StatusServiceUnavailable)
			return
		}

		migrated, err := d.DB.IsModulePIIMigrated(r.Context(), name)
		if err != nil {
			http.Error(w, "failed to check migration status", http.StatusInternalServerError)
			return
		}
		if migrated {
			http.Error(w, "module already migrated", http.StatusConflict)
			return
		}

		workerAuth := WorkerAuth{
			UserID:    sess.UserID,
			UserEmail: sess.Email,
			UserName:  sess.Name,
			Roles:     []string{sess.Role},
			Scopes:    []string{},
		}

		resp, err := d.Workers.Dispatch(r.Context(), name, WorkerRequest{
			Method: "POST",
			Path:   "/admin/migrate-pii-key",
			Auth:   workerAuth,
		})
		if err != nil {
			log.Printf("modules: migrate-pii-key %q: dispatch error: %v", name, err)
			if err == ErrWorkerNotFound {
				http.Error(w, "module worker not running", http.StatusServiceUnavailable)
			} else {
				http.Error(w, "module error: "+err.Error(), http.StatusBadGateway)
			}
			return
		}
		if resp.Status < 200 || resp.Status >= 300 {
			// Forward the module handler's own error body/status as-is -
			// same reasoning as the generic proxy (router.go): the module
			// knows best why its own migration failed (e.g. a row it
			// couldn't decrypt under the legacy key), Core just relays it.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.Status)
			_, _ = w.Write(resp.Body)
			return
		}

		if err := d.DB.SetModulePIIMigrated(r.Context(), name); err != nil {
			log.Printf("modules: migrate-pii-key %q: mark migrated: %v", name, err)
			http.Error(w, "module re-encrypted its data but Core failed to record the migration - do not retry, contact support", http.StatusInternalServerError)
			return
		}

		logModuleAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventModulePIIKeyMigrated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   name,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Body)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// writeModuleJSON serialises v as JSON and writes it to w.
// Duplicated from store/handlers.go to keep packages independent.
func writeModuleJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		httperr.Internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		log.Printf("modules: write response: %v", err)
	}
}
