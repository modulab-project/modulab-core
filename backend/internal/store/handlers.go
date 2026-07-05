package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// logStoreAudit writes one audit_log entry for a store admin action. Mirrors
// logAudit/logModuleAudit/logFeedAudit/logQuickLinkAudit in the other
// packages (same "resolve master key, log-and-swallow on failure" shape).
func logStoreAudit(ctx context.Context, authDeps auth.Deps, p audit.LogParams) {
	masterKey, err := setup.ResolveMasterKey(ctx, authDeps.Pool, authDeps.MasterKeyEnv)
	if err != nil {
		log.Printf("store: audit: failed to resolve master key for %s: %v", p.EventType, err)
		return
	}
	if err := audit.Log(ctx, authDeps.Pool, masterKey, p); err != nil {
		log.Printf("store: audit: failed to write %s: %v", p.EventType, err)
	}
}

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
// super-admin role. onSynced (may be nil) is forwarded to TriggerSync — see
// onSyncedFunc's doc comment; main.go wires it to modules.RunUpdateCheckOnce
// so a manual sync also surfaces any newly-available module update right
// away instead of waiting for the next background tick.
func SyncHandler(d Deps, authDeps auth.Deps, onSynced onSyncedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		if err := TriggerSync(r.Context(), d, onSynced); err != nil {
			logStoreAudit(r.Context(), authDeps, audit.LogParams{
				EventType:  audit.EventStoreSyncTriggered,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error()),
			})
			// Partial sync: still a 200 so the UI can show what was refreshed,
			// but include the error detail so the admin can investigate.
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}

		logStoreAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventStoreSyncTriggered,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details:    `{"ok":true}`,
		})
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
	if _, err := w.Write(data); err != nil {
		log.Printf("store: write response: %v", err)
	}
}
