// Package searxng is a thin HTTP client for a SearXNG instance's
// format=json search API. It has no knowledge of ModuLab's admin/user
// config layer (core_settings, search_providers, etc.) — that orchestration
// (which provider is active, key/URL resolution, fallback) lives in
// internal/search, which calls FetchResults with a resolved base URL. This
// split keeps the client trivially reusable/testable and mirrors how
// internal/ai keeps its actual HTTP clients (streamAnthropic,
// streamOpenAICompat) separate from the provider-table bookkeeping.
package searxng

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// searxClient is used for every request to an admin-configured SearXNG base
// URL.
//
// Bugfix (2026-07-05, later same day): this previously went through
// netguard.SafeHTTPClient, the same SSRF guard used for news feeds and AI
// providers. That broke SearXNG outright: unlike those two, which are meant
// to reach arbitrary *public* endpoints chosen by an admin, SearXNG's
// base_url is expected to point at a private, Docker-internal address by
// design (defaultURL is "http://searxng:8080", itself a private IP on the
// Docker bridge network) - netguard's allowlist rejects exactly that.
// Restricting outbound requests here would also add no real security value:
// only a super-admin can change this URL, and a super-admin already has
// full control of the Docker host (docker-compose.yml, the socket, etc.),
// so there is no privilege boundary for netguard to enforce in the first
// place - just a plain client with a sane timeout.
//
// Timeout: 0 - the client-level Timeout was in practice almost never the
// thing that actually fired: FetchResults already wraps every call in a
// shorter context.WithTimeout (the caller-supplied timeoutSeconds), so a
// client-level cap would just sit dormant behind it.
var searxClient = &http.Client{Timeout: 0}

// Ping performs a lightweight GET against a SearXNG base URL and returns
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
	resp, err := searxClient.Do(req)
	if err != nil {
		return false
	}
	if err := resp.Body.Close(); err != nil {
		log.Printf("searxng: ping: close response body: %v", err)
	}
	return resp.StatusCode < 500
}

// WebResult is one search result. Thumbnail and ImgSrc are only populated
// for category=images results. Shared across every provider internal/search
// dispatches to (SearXNG, Serper, ...) so callers never need to know which
// backend answered a given query.
type WebResult struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Snippet   string `json:"snippet"`
	Thumbnail string `json:"thumbnail,omitempty"`
	ImgSrc    string `json:"img_src,omitempty"`
}

// SearchParams holds the per-request parameters forwarded to a search
// provider. Exported so internal/search can build one without needing its
// own parallel type.
type SearchParams struct {
	Category   string // "general" or "images"
	Safesearch int    // 0, 1, or 2
	Language   string // "all", "de", "en", …
	TimeRange  string // "", "day", "week", "month", "year"
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

// fetchPage fetches one SearXNG result page (1-indexed pageno).
func fetchPage(ctx context.Context, baseURL, query string, pageno int, sp SearchParams) ([]WebResult, error) {
	category := sp.Category
	if category == "" {
		category = "general"
	}
	params := url.Values{
		"q":          {query},
		"format":     {"json"},
		"pageno":     {strconv.Itoa(pageno)},
		"categories": {category},
		"safesearch": {strconv.Itoa(sp.Safesearch)},
		"language":   {sp.Language},
	}
	if sp.TimeRange != "" {
		params.Set("time_range", sp.TimeRange)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/search?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ModuLab-Core/1.0 (https://modulab.app)")

	resp, err := searxClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("searxng: search: close response body: %v", err)
		}
	}()

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

// FetchResults fetches up to fetchPages pages in parallel, merges them,
// deduplicates by URL, and returns up to maxResults entries. Page 1 results
// always appear first so ranking is preserved. timeoutSeconds is the hard
// cap for the whole round-trip, resolved by the caller (internal/search).
func FetchResults(ctx context.Context, baseURL, query string, maxResults, fetchPages, timeoutSeconds int, sp SearchParams) ([]WebResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	if fetchPages < 1 {
		fetchPages = 1
	}

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
