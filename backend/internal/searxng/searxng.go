// Package searxng implements the web-search proxy (GET /v1/search/web) and
// the super-admin configuration endpoints (GET|POST|DELETE /v1/admin/searxng)
// for ModuLab's SearXNG integration (spec section 6.4, search widget).
//
// SearXNG is a self-hosted, privacy-respecting meta-search engine. This
// package acts as a thin authenticated proxy so:
//   - The frontend never talks to SearXNG directly (no CORS dance).
//   - The SearXNG URL stays server-side and is never exposed to clients.
//   - A 2-second per-request timeout prevents a slow SearXNG instance from
//     blocking the home-page load.
//
// Configuration lives in core_settings under the key "searxng_url_enc"
// (GCM-encrypted, following spec section 2.4's encrypt-everything policy for
// URLs/endpoints). When unconfigured, GET /v1/search/web returns HTTP 503 so
// the frontend can silently hide the web-search section.
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
	"strings"
	"sync"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	settingKeyURL = "searxng_url_enc"

	// searchTimeout is the hard cap for a SearXNG round-trip. A slow
	// instance must not block the home-page load for longer than this.
	// Both pages are fetched in parallel so the wall-clock cost is one
	// round-trip, not two.
	searchTimeout = 2 * time.Second

	// fetchPages is how many SearXNG result pages we request in parallel.
	// Each page typically yields ~10 results; after deduplication by URL
	// the combined set usually reaches 15–25 unique entries.
	fetchPages = 2

	// maxResults caps the final list forwarded to the frontend.
	maxResults = 25
)

// SearXNGStatus is the JSON body of GET /v1/admin/searxng/status.
// The URL is returned in plaintext (decrypted) so the admin UI can show
// the current value - it is never sensitive the way a password is.
type SearXNGStatus struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url,omitempty"`
}

// SearXNGConfigRequest is the body of POST /v1/admin/searxng/configure.
type SearXNGConfigRequest struct {
	URL string `json:"url"`
}

// WebResult is one entry in GET /v1/search/web's response array.
// Matches the fields SearXNG returns in format=json that the frontend
// actually uses; the rest of SearXNG's payload is discarded.
type WebResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

// resolveURL reads the encrypted SearXNG URL from core_settings and
// decrypts it. Returns ("", false, nil) when not configured.
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

// StatusHandler returns the HTTP handler for GET /v1/admin/searxng/status.
// Super-admin only (enforced by RequireSuperAdminMiddleware in main.go).
func StatusHandler(pool *db.Pool, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rawURL, ok, err := resolveURL(r.Context(), pool, masterKey)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SearXNGStatus{
			Configured: ok,
			URL:        rawURL,
		})
	}
}

// ConfigureHandler returns the HTTP handler for POST /v1/admin/searxng/configure.
// Super-admin only (enforced by RequireSuperAdminMiddleware in main.go).
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
		// Basic URL sanity check.
		if _, err := url.ParseRequestURI(rawURL); err != nil {
			http.Error(w, "url is not a valid URL", http.StatusBadRequest)
			return
		}
		enc, err := crypto.Encrypt(masterKey, rawURL)
		if err != nil {
			http.Error(w, "encrypt error", http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(r.Context(), settingKeyURL, enc); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SearXNGStatus{Configured: true, URL: rawURL})
	}
}

// DeleteHandler returns the HTTP handler for DELETE /v1/admin/searxng.
// Super-admin only (enforced by RequireSuperAdminMiddleware in main.go).
func DeleteHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := pool.DeleteSetting(r.Context(), settingKeyURL); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SearchHandler returns the HTTP handler for GET /v1/search/web?q=<query>.
// Requires any approved session (Bearer token). When SearXNG is not
// configured, returns HTTP 503 so the frontend can silently hide the
// web-search section.
func SearchHandler(deps auth.Deps, masterKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Auth: any approved, non-locked session.
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sess, ok, err := auth.ValidateSession(r.Context(), deps.Valkey, token)
		if err != nil || !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if sess.Role == "pending" || sess.Locked {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			http.Error(w, "q is required", http.StatusBadRequest)
			return
		}

		baseURL, configured, err := resolveURL(r.Context(), deps.Pool, masterKey)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !configured {
			// 503 = SearXNG not configured. The frontend interprets this as
			// "hide the web-search results section silently".
			http.Error(w, "web search not configured", http.StatusServiceUnavailable)
			return
		}

		results, err := fetchResults(r.Context(), baseURL, q)
		if err != nil {
			http.Error(w, "search upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// searxngResponse is the minimal shape of SearXNG's format=json output.
// Only the fields we actually use are mapped; the rest is ignored.
type searxngResponse struct {
	Results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Content string `json:"content"`
	} `json:"results"`
}

// fetchPage fetches a single SearXNG result page (1-indexed pageno).
func fetchPage(ctx context.Context, baseURL, query string, pageno int) ([]WebResult, error) {
	params := url.Values{
		"q":      {query},
		"format": {"json"},
		"pageno": {fmt.Sprintf("%d", pageno)},
	}
	reqURL := baseURL + "/search?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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

	body, err := io.ReadAll(resp.Body)
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
			Title:   r.Title,
			URL:     r.URL,
			Snippet: r.Content,
		})
	}
	return out, nil
}

// fetchResults fetches fetchPages pages from SearXNG in parallel, merges
// them, deduplicates by URL, and returns up to maxResults entries. Page 1
// results always appear first so ranking is preserved.
func fetchResults(ctx context.Context, baseURL, query string) ([]WebResult, error) {
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
			results, err := fetchPage(ctx, baseURL, query, pageno)
			ch <- pageResult{page: pageno, results: results, err: err}
		}(p)
	}

	// Close channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect results keyed by page number to preserve page-1-first order.
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

	// If page 1 failed entirely, surface the error. If only page 2 failed
	// we still return page 1's results rather than an error.
	if len(byPage) == 0 && firstErr != nil {
		return nil, firstErr
	}

	// Merge pages in order, deduplicate by URL.
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
