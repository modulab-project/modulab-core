package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
// Requires org-admin or super-admin.
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
// Requires org-admin or super-admin.
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

// ── DELETE /v1/modules/{name} ─────────────────────────────────────────────────

// UninstallHandler removes an installed module.
// Requires org-admin or super-admin.
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
// rely on the daily sync). Requires org-admin or super-admin.
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
			}
			if row.Manifest != nil {
				_ = json.Unmarshal(row.Manifest, &mf)
			}
			if mf.Handler != "" {
				destDir := filepath.Join(d.DataDir, name)
				entrypoint := filepath.Join(destDir, mf.Handler)
				egressHosts := mf.EgressAllowlist
				if mf.DynamicEgress && hadRuntimeHosts && len(runtimeEgressHosts) > 0 {
					egressHosts = runtimeEgressHosts
				}
				opts := WorkerOptions{
					EgressHosts:   egressHosts,
					Jobs:          ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
					SkipTLSVerify: mf.TLSSkipVerify,
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
// Requires org-admin or super-admin.
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
// Requires org-admin or super-admin.
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
// all. Requires org-admin or super-admin.
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
			egressHosts = runtimeEgressHosts
		}
		opts := WorkerOptions{
			EgressHosts:   egressHosts,
			Jobs:          ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
			SkipTLSVerify: mf.TLSSkipVerify,
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
