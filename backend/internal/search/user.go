package search

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// UserProviderResponse is the JSON shape returned to non-admin callers by
// GET /v1/search/providers. Shows whether a key/URL is available (admin or
// user) without exposing any secret material - same shape as
// ai.UserProviderResponse.
type UserProviderResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Available   bool   `json:"available"`
	HasUserKey  bool   `json:"has_user_key"`
	HasAdminKey bool   `json:"has_admin_key"`
	CanOverride bool   `json:"can_override"`
}

// UserProvidersHandler handles GET /v1/search/providers. Used by the
// frontend to decide, e.g., whether to show a "your own Serper key" field
// on the search preferences page.
func UserProvidersHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		rows, err := deps.Pool.ListSearchProvidersForUser(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := make([]UserProviderResponse, 0, len(rows))
		for _, row := range rows {
			available := (row.HasAdminKey || row.BaseURL != "") || (row.HasUserKey && row.UserCanOverride)
			out = append(out, UserProviderResponse{
				ID:          row.ID,
				Name:        row.Name,
				Type:        row.Type,
				Enabled:     row.Enabled,
				Available:   available,
				HasUserKey:  row.HasUserKey,
				HasAdminKey: row.HasAdminKey,
				CanOverride: row.UserCanOverride,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

type setKeyRequest struct {
	Key string `json:"key"`
}

// UserSetKeyHandler handles PUT /v1/user/search/keys/{id}.
func UserSetKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		if providerID == "" {
			http.Error(w, "missing provider id", http.StatusBadRequest)
			return
		}
		prov, found, err := deps.Pool.GetSearchProvider(r.Context(), providerID)
		if err != nil || !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		if !prov.UserCanOverride {
			http.Error(w, "this provider does not allow user keys", http.StatusForbidden)
			return
		}
		var req setKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			http.Error(w, "key is required", http.StatusBadRequest)
			return
		}
		if err := deps.Pool.SetSearchUserKey(r.Context(), sess.UserID, providerID, req.Key); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		// Best-effort audit; the key value itself never appears here, only
		// which provider_id was touched - same treatment as
		// ai.UserSetKeyHandler.
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventSearchUserKeySet,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, providerID),
			}); err != nil {
				log.Printf("search: audit set user key for provider %q: %v", providerID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserDeleteKeyHandler handles DELETE /v1/user/search/keys/{id}.
func UserDeleteKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		if err := deps.Pool.DeleteSearchUserKey(r.Context(), sess.UserID, providerID); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventSearchUserKeyDeleted,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, providerID),
			}); err != nil {
				log.Printf("search: audit delete user key for provider %q: %v", providerID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
