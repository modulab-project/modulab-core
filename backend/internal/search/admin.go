package search

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// ProviderResponse is the JSON shape returned to admin callers by
// GET /v1/admin/search/providers.
type ProviderResponse struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	BaseURL         string `json:"base_url,omitempty"`
	HasAdminKey     bool   `json:"has_admin_key"`
	MaxResults      int    `json:"max_results"`
	FetchPages      int    `json:"fetch_pages"`
	UserCanOverride bool   `json:"user_can_override"`
	Enabled         bool   `json:"enabled"`
	SortOrder       int    `json:"sort_order"`
}

func rowToProviderResponse(r db.SearchProviderRow) ProviderResponse {
	return ProviderResponse{
		ID:              r.ID,
		Type:            r.Type,
		Name:            r.Name,
		BaseURL:         r.BaseURL,
		HasAdminKey:     r.HasAdminKey,
		MaxResults:      r.MaxResults,
		FetchPages:      r.FetchPages,
		UserCanOverride: r.UserCanOverride,
		Enabled:         r.Enabled,
		SortOrder:       r.SortOrder,
	}
}

// patchProviderRequest is the body of PATCH /v1/admin/search/providers/{id}.
// Providers are pre-seeded (searxng, serper) - this only updates an
// existing row, it never creates one (see UpdateSearchProvider's doc
// comment for why).
type patchProviderRequest struct {
	BaseURL         *string `json:"base_url"`
	AdminKey        *string `json:"admin_key"`
	MaxResults      *int    `json:"max_results"`
	FetchPages      *int    `json:"fetch_pages"`
	UserCanOverride *bool   `json:"user_can_override"`
	Enabled         *bool   `json:"enabled"`
	SortOrder       *int    `json:"sort_order"`
}

// AdminListProvidersHandler handles GET /v1/admin/search/providers.
func AdminListProvidersHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rows, err := deps.Pool.ListSearchProviders(r.Context())
		if err != nil {
			log.Printf("search: list providers: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := make([]ProviderResponse, len(rows))
		for i, row := range rows {
			out[i] = rowToProviderResponse(row)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// AdminPatchProviderHandler handles PATCH /v1/admin/search/providers/{id}.
func AdminPatchProviderHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		existing, found, err := deps.Pool.GetSearchProvider(r.Context(), id)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		var req patchProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		baseURL := ""
		if req.BaseURL != nil {
			baseURL = *req.BaseURL
		}
		adminKey := ""
		if req.AdminKey != nil {
			adminKey = *req.AdminKey
		}
		maxResults := existing.MaxResults
		if req.MaxResults != nil {
			maxResults = *req.MaxResults
		}
		if maxResults < 1 {
			maxResults = 1
		}
		if maxResults > 100 {
			maxResults = 100
		}
		fetchPages := existing.FetchPages
		if req.FetchPages != nil {
			fetchPages = *req.FetchPages
		}
		if fetchPages < 1 {
			fetchPages = 1
		}
		if fetchPages > 5 {
			fetchPages = 5
		}
		userCanOverride := existing.UserCanOverride
		if req.UserCanOverride != nil {
			userCanOverride = *req.UserCanOverride
		}
		enabled := existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		sortOrder := existing.SortOrder
		if req.SortOrder != nil {
			sortOrder = *req.SortOrder
		}

		if _, err := deps.Pool.UpdateSearchProvider(r.Context(), id, baseURL, adminKey, maxResults, fetchPages, userCanOverride, enabled, sortOrder); err != nil {
			log.Printf("search: update provider %q: %v", id, err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Best-effort audit; a failed write must not block the response.
		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigSearchProvider,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q,"enabled":%v}`, id, enabled),
			}); err != nil {
				log.Printf("search: audit patch provider %q: %v", id, err)
			}
		}

		updated, _, _ := deps.Pool.GetSearchProvider(r.Context(), id)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rowToProviderResponse(updated))
	}
}

// AdminClearProviderKeyHandler handles
// DELETE /v1/admin/search/providers/{id}/key. Removes the admin key without
// touching the rest of the provider row.
func AdminClearProviderKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		if err := deps.Pool.ClearSearchProviderAdminKey(r.Context(), id); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigSearchKeyCleared,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, id),
			}); err != nil {
				log.Printf("search: audit clear key for provider %q: %v", id, err)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// SettingsResponse is the JSON shape of GET/PATCH /v1/admin/search/settings.
type SettingsResponse struct {
	PrimaryProviderID      string `json:"primary_provider_id"`
	FallbackProviderID     string `json:"fallback_provider_id"`
	TimeoutSeconds         int    `json:"timeout_seconds"`
	FallbackTimeoutSeconds int    `json:"fallback_timeout_seconds"`
}

func currentSettings(r *http.Request, pool *db.Pool) SettingsResponse {
	ctx := r.Context()
	return SettingsResponse{
		PrimaryProviderID:      PrimaryProviderID(ctx, pool),
		FallbackProviderID:     FallbackProviderID(ctx, pool),
		TimeoutSeconds:         SearchTimeoutSeconds(ctx, pool),
		FallbackTimeoutSeconds: FallbackTimeoutSeconds(ctx, pool),
	}
}

// AdminSettingsHandler handles GET and PATCH /v1/admin/search/settings:
// which provider is primary, which (if any) is the fallback, and the two
// shared timeouts (see search.go's SearchTimeoutSeconds/
// FallbackTimeoutSeconds doc comments).
func AdminSettingsHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(currentSettings(r, deps.Pool))

		case http.MethodPatch:
			var body SettingsResponse
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if body.PrimaryProviderID == "" {
				http.Error(w, "primary_provider_id is required", http.StatusBadRequest)
				return
			}
			if _, found, err := deps.Pool.GetSearchProvider(r.Context(), body.PrimaryProviderID); err != nil || !found {
				http.Error(w, "primary_provider_id does not exist", http.StatusBadRequest)
				return
			}
			if body.FallbackProviderID != "" {
				if _, found, err := deps.Pool.GetSearchProvider(r.Context(), body.FallbackProviderID); err != nil || !found {
					http.Error(w, "fallback_provider_id does not exist", http.StatusBadRequest)
					return
				}
			}
			if body.TimeoutSeconds <= 0 {
				body.TimeoutSeconds = defaultSearchTimeoutSeconds
			}
			if body.FallbackTimeoutSeconds <= 0 {
				body.FallbackTimeoutSeconds = defaultFallbackTimeoutSeconds
			}

			ctx := r.Context()
			if err := deps.Pool.SetSetting(ctx, settingKeyPrimary, body.PrimaryProviderID); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			if body.FallbackProviderID == "" {
				_ = deps.Pool.DeleteSetting(ctx, settingKeyFallback)
			} else if err := deps.Pool.SetSetting(ctx, settingKeyFallback, body.FallbackProviderID); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			if err := deps.Pool.SetSetting(ctx, settingKeyTimeout, fmt.Sprintf("%d", body.TimeoutSeconds)); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			if err := deps.Pool.SetSetting(ctx, settingKeyFallbackTimeout, fmt.Sprintf("%d", body.FallbackTimeoutSeconds)); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}

			sess, _ := auth.SessionFromContext(ctx)
			if masterKey, err := setup.ResolveMasterKey(ctx, deps.Pool, deps.MasterKeyEnv); err == nil {
				detailsJSON, _ := json.Marshal(body)
				if err := audit.Log(ctx, deps.Pool, masterKey, audit.LogParams{
					EventType:  audit.EventConfigSearchSettings,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					Details:    string(detailsJSON),
				}); err != nil {
					log.Printf("search: audit settings update: %v", err)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(currentSettings(r, deps.Pool))

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
