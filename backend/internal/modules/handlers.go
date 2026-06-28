package modules

import (
	"encoding/json"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/store"
)

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
// Requires any active session.
func GetInstalledHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
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
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
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
		writeModuleJSON(w, http.StatusCreated, row)
	}
}

// ── DELETE /v1/modules/{name} ─────────────────────────────────────────────────

// UninstallHandler removes an installed module.
// Requires org-admin or super-admin.
func UninstallHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		if err := Uninstall(r.Context(), d, name); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ── POST /v1/modules/{name}/update ───────────────────────────────────────────

// UpdateModuleHandler triggers an immediate update of an installed module.
// The module must have an available_version set (run CheckUpdates first, or
// rely on the daily sync). Requires org-admin or super-admin.
func UpdateModuleHandler(d Deps, storeDeps store.Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
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

		if err := Update(r.Context(), d, entry); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		row, _, _ := d.DB.GetInstalledModule(r.Context(), name)
		writeModuleJSON(w, http.StatusOK, row)
	}
}

// ── POST /v1/modules/{name}/pin ───────────────────────────────────────────────

// PinHandler pins a module, preventing automatic updates and uninstallation.
// Requires org-admin or super-admin.
func PinHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
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

		writeModuleJSON(w, http.StatusOK, map[string]any{"name": name, "pinned": true})
	}
}

// ── DELETE /v1/modules/{name}/pin ─────────────────────────────────────────────

// UnpinHandler removes the pin from a module.
// Requires org-admin or super-admin.
func UnpinHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
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

		writeModuleJSON(w, http.StatusOK, map[string]any{"name": name, "pinned": false})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// writeModuleJSON serialises v as JSON and writes it to w.
// Duplicated from store/handlers.go to keep packages independent.
func writeModuleJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

