// Package searxng implements the web-search proxy (GET /v1/search/web) and
// the super-admin configuration endpoints (GET|POST|DELETE /v1/admin/searxng)
// for ModuLab's SearXNG integration (spec section 6.4, search widget).
//
// Configuration lives in core_settings:
//   - "searxng_url_enc"      — GCM-encrypted base URL (spec 2.4 URL tier)
//   - "searxng_max_results"  — plaintext integer, max results forwarded
//   - "searxng_fetch_pages"  — plaintext integer, pages fetched in parallel
//
// Both integer settings are purely technical values (no PII) and are
// therefore stored as plaintext, matching the same classify/encrypt logic
// used for SMTP port and encryption-mode fields.
//
// Admin endpoints (super-admin only, same tier as SMTP):
//
//	GET  /v1/admin/searxng/status    → SearXNGStatus
//	POST /v1/admin/searxng/configure → body SearXNGConfigRequest → SearXNGStatus
//	DELETE /v1/admin/searxng         → 204
//
// Search endpoint (any approved session):
//
//	GET /v1/search/web?q=<query>     → []WebResult
package searxng

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	settingKeyURL        = "searxng_url_enc"
	settingKeyMaxResults = "searxng_max_results"
	settingKeyFetchPages = "searxng_fetch_pages"

	// searchTimeout is the hard cap for a SearXNG round-trip. Both pages
	// are fetched in parallel so the wall-clock cost is one round-trip.
	searchTimeout = 2 * time.Second

	// Defaults used when no value has been saved to core_settings yet.
	defaultMaxResults = 25
	defaultFetchPages = 2

	// Hard limits to prevent accidental DoS of the SearXNG instance.
	limitMaxResults = 100
	limitFetchPages = 5
)

// SearXNGStatus is the JSON body of GET /v1/admin/searxng/status.
type SearXNGStatus struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url,omitempty"`
	MaxResults int    `json:"max_results"`
	FetchPages int    `json:"fetch_pages"`
}

// SearXNGConfigRequest is the body of POST /v1/admin/searxng/configure.
type SearXNGConfigRequest struct {
	URL        string `json:"url"`
	MaxResults int    `json:"max_results"`
	FetchPages int    `json:"fetch_pages"`
}

// IsConfigured returns true when a SearXNG URL has been saved to
// core_settings. Used by /healthz to decide whether to show a reachability
// row for SearXNG at all.
func IsConfigured(ctx context.Context, pool *db.Pool, masterKey string) (bool, error) {
	_, ok, err := resolveURL(ctx, pool, masterKey)
	return ok, err
}

// ResolveURLPublic is the exported counterpart of resolveURL, used by
// main.go's /healthz handler to retrieve the base URL for Ping.
func ResolveURLPublic(ctx context.Context, pool *db.Pool, masterKey string) (string, bool, error) {
	return resolveURL(ctx, pool, masterKey)
}

// Ping performs a lightweight GET against the SearXNG base URL and returns
// true if the instance responds with any non-5xx status within 1 second.
// Intended only for /healthz — not a full search round-trip.
func Ping(ctx context.Context, baseURL string) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "ModuLab-Core/1.0 (https://modulab.app)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

// WebResult is one entry in GET /v1/search/web's response array.
// Thumbnail and ImgSrc are only populated for category=images results.
type WebResult struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Snippet   string `json:"snippet"`
	Thumbnail string `json:"thumbnail,omitempty"`
	ImgSrc    string `json:"img_src,omitempty"`
}

// resolveURL reads the encrypted SearXNG URL from core_settings.
// Returns ("", false, nil) when not configured.
func resolveURL(ctx context.Context, pool *db.Pool, masterKey string) (string, bool, error) {
	enc, ok, err := pool.GetSetting(ctx, settingKeyURL)
	if err != nil {
		return "", false, err
	}
	if !ok || enc == "" {
		return "", false, nil
	}
	plain, err := crypto.Decrypt(masterKey, enc)
	if err != nil {
		return "", false, fmt.Errorf("searxng: decrypt url: %w", err)
	}
	return plain, true, nil
}

// resolveInt reads an integer setting from core_settings, returning
// defaultVal when the key is absent or unparseable.
func resolveInt(ctx context.Context, pool *db.Pool, key string, defaultVal int) int {
	raw, ok, err := pool.GetSetting(ctx, key)
	if err != nil || !ok || raw == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
}

// resolveConfig reads all three settings in one go.
func resolveConfig(ctx context.Context, pool *db.Pool, masterKey string) (rawURL string, configured bool, maxResults int, fetchPages int, err error) {
	rawURL, configured, err = resolveURL(ctx, pool, masterKey)
	if err != nil {
		return
	}
	maxResults = resolveInt(ctx, pool, settingKeyMaxResults, defaultMaxResults)
	fetchPages = resolveInt(ctx, pool, settingKeyFetchPages, defaultFetchPages)
	return
}

// clamp ensures v is within [min, max].
func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// StatusHandler returns the HTTP handler for GET /v1/admin/searxng/status.
func StatusHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rawURL, ok, maxResults, fetchPages, err := resolveConfig(r.Context(), pool, masterKey)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SearXNGStatus{
			Configured: ok,
			URL:        rawURL,
			MaxResults: maxResults,
			FetchPages: fetchPages,
		})
	}
}

// ConfigureHandler returns the HTTP handler for POST /v1/admin/searxng/configure.
func ConfigureHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req SearXNGConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		rawURL := strings.TrimRight(strings.TrimSpace(req.URL), "/")
		if rawURL == "" {
			http.Error(w, "url is required", http.StatusBadRequest)
			return
		}
		if _, err := url.ParseRequestURI(rawURL); err != nil {
			http.Error(w, "url is not a valid URL", http.StatusBadRequest)
			return
		}

		// Apply defaults when the caller sends zero values.
		maxResults := req.MaxResults
		if maxResults <= 0 {
			maxResults = defaultMaxResults
		}
		fetchPages := req.FetchPages
		if fetchPages <= 0 {
			fetchPages = defaultFetchPages
		}
		maxResults = clamp(maxResults, 1, limitMaxResults)
		fetchPages = clamp(fetchPages, 1, limitFetchPages)

		enc, err := crypto.Encrypt(masterKey, rawURL)
		if err != nil {
			http.Error(w, "encrypt error", http.StatusInternalServerError)
			return
		}
		ctx := r.Context()
		if err := pool.SetSetting(ctx, settingKeyURL, enc); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, settingKeyMaxResults, strconv.Itoa(maxResults)); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, settingKeyFetchPages, strconv.Itoa(fetchPages)); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SearXNGStatus{
			Configured: true,
			URL:        rawURL,
			MaxResults: maxResults,
			FetchPages: fetchPages,
		})
	}
}

// DeleteHandler returns the HTTP handler for DELETE /v1/admin/searxng.
func DeleteHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		for _, key := range []string{settingKeyURL, settingKeyMaxResults, settingKeyFetchPages} {
			if err := pool.DeleteSetting(ctx, key); err != nil {
				http.Error(w, "database error", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SearchPrefsHandler returns the HTTP handler for GET and POST /v1/user/search-prefs.
// GET returns the current prefs; POST accepts a partial or full JSON body and saves it.
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
			// Decode only the fields present in the body so a partial update
			// (e.g. just changing safesearch) works without overwriting language.
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
			// Merge: zero value means "not provided" — keep existing.
			if patch.Language != "" {
				current.Language = patch.Language
			}
			// safesearch 0 is a valid value (off), so we can always accept it.
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

// SearchHandler returns the HTTP handler for GET /v1/search/web?q=<query>.
func SearchHandler(deps auth.Deps, masterKey string) http.HandlerFunc {
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

		baseURL, configured, maxResults, fetchPages, err := resolveConfig(r.Context(), deps.Pool, masterKey)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !configured {
			http.Error(w, "web search not configured", http.StatusServiceUnavailable)
			return
		}

		// Load user search prefs for safesearch + language defaults.
		prefs, err := deps.Pool.GetSearchPrefs(r.Context(), sess.UserID)
		if err != nil {
			// Non-fatal: fall back to defaults.
			prefs = db.SearchPrefs{Safesearch: 0, Language: "all"}
		}

		// Query params can override stored prefs for this request.
		category := r.URL.Query().Get("category")
		if category == "" {
			category = "general"
		}

		// Validate time_range against the set SearXNG accepts.
		timeRange := r.URL.Query().Get("time_range")
		switch timeRange {
		case "day", "week", "month", "year":
			// valid
		default:
			timeRange = ""
		}

		sp := searchParams{
			category:   category,
			safesearch: prefs.Safesearch,
			language:   prefs.Language,
			timeRange:  timeRange,
		}

		results, err := fetchResults(r.Context(), baseURL, q, maxResults, fetchPages, sp)
		if err != nil {
			http.Error(w, "search upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// searxngResponse is the minimal shape of SearXNG's format=json output.
type searxngResponse struct {
	Results []struct {
		Title     string `json:"title"`
		URL       string `json:"url"`
		Content   string `json:"content"`
		Thumbnail string `json:"thumbnail"`
		ImgSrc    string `json:"img_src"`
	} `json:"results"`
}

// searchParams holds the per-request parameters forwarded to SearXNG.
type searchParams struct {
	category   string // "general" or "images"
	safesearch int    // 0, 1, or 2
	language   string // "all", "de", "en", …
	timeRange  string // "", "day", "week", "month", "year"
}

// fetchPage fetches one SearXNG result page (1-indexed pageno).
func fetchPage(ctx context.Context, baseURL, query string, pageno int, sp searchParams) ([]WebResult, error) {
	category := sp.category
	if category == "" {
		category = "general"
	}
	params := url.Values{
		"q":          {query},
		"format":     {"json"},
		"pageno":     {strconv.Itoa(pageno)},
		"categories": {category},
		"safesearch": {strconv.Itoa(sp.safesearch)},
		"language":   {sp.language},
	}
	if sp.timeRange != "" {
		params.Set("time_range", sp.timeRange)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/search?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ModuLab-Core/1.0 (https://modulab.app)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("searxng returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap
	if err != nil {
		return nil, err
	}
	var raw searxngResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	out := make([]WebResult, 0, len(raw.Results))
	for _, r := range raw.Results {
		out = append(out, WebResult{
			Title:     r.Title,
			URL:       r.URL,
			Snippet:   r.Content,
			Thumbnail: r.Thumbnail,
			ImgSrc:    r.ImgSrc,
		})
	}
	return out, nil
}

// fetchResults fetches up to fetchPages pages in parallel, merges them,
// deduplicates by URL, and returns up to maxResults entries.
// Page 1 results always appear first so ranking is preserved.
func fetchResults(ctx context.Context, baseURL, query string, maxResults, fetchPages int, sp searchParams) ([]WebResult, error) {
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()

	type pageResult struct {
		page    int
		results []WebResult
		err     error
	}

	ch := make(chan pageResult, fetchPages)
	var wg sync.WaitGroup
	for p := 1; p <= fetchPages; p++ {
		wg.Add(1)
		go func(pageno int) {
			defer wg.Done()
			res, err := fetchPage(ctx, baseURL, query, pageno, sp)
			ch <- pageResult{page: pageno, results: res, err: err}
		}(p)
	}
	go func() { wg.Wait(); close(ch) }()

	byPage := make(map[int][]WebResult, fetchPages)
	var firstErr error
	for pr := range ch {
		if pr.err != nil {
			if firstErr == nil {
				firstErr = pr.err
			}
			continue
		}
		byPage[pr.page] = pr.results
	}
	if len(byPage) == 0 && firstErr != nil {
		return nil, firstErr
	}

	seen := make(map[string]struct{})
	out := make([]WebResult, 0, maxResults)
	for p := 1; p <= fetchPages; p++ {
		for _, r := range byPage[p] {
			if len(out) >= maxResults {
				break
			}
			if _, dup := seen[r.URL]; dup {
				continue
			}
			seen[r.URL] = struct{}{}
			out = append(out, r)
		}
		if len(out) >= maxResults {
			break
		}
	}
	return out, nil
}
