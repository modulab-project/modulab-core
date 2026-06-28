package store

import (
	"encoding/json"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
)

// ── GET /v1/store ─────────────────────────────────────────────────────────────

// ListResponse is what GET /v1/store returns.
type ListResponse struct {
	Entries    []Entry `json:"entries"`
	TotalCount int     `json:"total_count"`
	// LastSyncedAt is the RFC3339 timestamp of the most recent registry sync,
	// or null when the registry has never been synced.
	LastSyncedAt *string `json:"last_synced_at"`
}

// ListHandler serves GET /v1/store. Reads from the local DB cache so it works
// even when GitHub is unreachable. Requires any active (approved) session.
//
// Query parameters:
//
//	source   — "official" | "community" (default: all)
//	category — e.g. "productivity" (default: all)
func ListHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}

		source := r.URL.Query().Get("source")
		category := r.URL.Query().Get("category")

		entries, err := ListEntries(r.Context(), d.Pool, source, category)
		if err != nil {
			http.Error(w, "failed to read registry", http.StatusInternalServerError)
			return
		}

		lastSync, err := LastSyncedAt(r.Context(), d.Pool)
		if err != nil {
			http.Error(w, "failed to read registry", http.StatusInternalServerError)
			return
		}

		resp := ListResponse{
			Entries:    entries,
			TotalCount: len(entries),
		}
		if !lastSync.IsZero() {
			s := lastSync.UTC().Format("2006-01-02T15:04:05Z07:00")
			resp.LastSyncedAt = &s
		}
		if resp.Entries == nil {
			resp.Entries = []Entry{}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// ── GET /v1/store/{name} ──────────────────────────────────────────────────────

// DetailHandler serves GET /v1/store/{name}. Returns a single registry entry
// from the DB cache. Requires any active session.
func DetailHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}

		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		entry, found, err := GetEntry(r.Context(), d.Pool, name)
		if err != nil {
			http.Error(w, "failed to read registry", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "module not found in registry", http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, entry)
	}
}

// ── POST /v1/store/sync ───────────────────────────────────────────────────────

// SyncHandler serves POST /v1/store/sync. Triggers an immediate registry sync
// and waits for it to complete before responding. Requires org-admin or
// super-admin role.
func SyncHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
			return
		}

		if err := TriggerSync(r.Context(), d); err != nil {
			// Partial sync: still a 200 so the UI can show what was refreshed,
			// but include the error detail so the admin can investigate.
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}
