package search

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/searxng"
)

// SearchHandler returns the HTTP handler for GET /v1/search/web?q=<query>.
// Unchanged response shape from the old searxng.SearchHandler
// ([]searxng.WebResult) - only the provider resolution behind it changed.
func SearchHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			http.Error(w, "q is required", http.StatusBadRequest)
			return
		}

		// Load user search prefs for safesearch + language defaults.
		prefs, err := deps.Pool.GetSearchPrefs(r.Context(), sess.UserID)
		if err != nil {
			// Non-fatal: fall back to the same defaults GetSearchPrefs itself
			// uses for a user with no saved row.
			prefs = db.SearchPrefs{Safesearch: 2, Language: "all"}
		}

		category := r.URL.Query().Get("category")
		if category == "" {
			category = "general"
		}

		timeRange := r.URL.Query().Get("time_range")
		switch timeRange {
		case "day", "week", "month", "year":
			// valid
		default:
			timeRange = ""
		}

		sp := searxng.SearchParams{
			Category:   category,
			Safesearch: prefs.Safesearch,
			Language:   prefs.Language,
			TimeRange:  timeRange,
		}

		results, err := Fetch(r.Context(), deps.Pool, sess.UserID, q, category, sp)
		if err != nil {
			if errors.Is(err, ErrNotConfigured) {
				http.Error(w, "web search not configured", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "search upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// SearchPrefsHandler returns the HTTP handler for GET and POST
// /v1/user/search-prefs. Moved verbatim from the old searxng package - this
// endpoint (safesearch/language) is unrelated to which provider answers a
// query, so its behavior is unchanged.
func SearchPrefsHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}

		switch r.Method {
		case http.MethodGet:
			prefs, err := deps.Pool.GetSearchPrefs(r.Context(), sess.UserID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(prefs)

		case http.MethodPost:
			current, err := deps.Pool.GetSearchPrefs(r.Context(), sess.UserID)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			var patch db.SearchPrefs
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if patch.Language != "" {
				current.Language = patch.Language
			}
			current.Safesearch = patch.Safesearch

			if err := deps.Pool.SetSearchPrefs(r.Context(), sess.UserID, current); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(current)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
