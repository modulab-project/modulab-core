// Package news implements the news-feed feature: admin CRUD for a global
// pool of RSS/Atom feed URLs, per-user subscription toggles, and a
// /v1/news aggregator that fetches each enabled feed in parallel and
// returns a unified list of articles sorted by publish date.
//
// All three user-facing endpoints are protected by a valid, non-pending
// session (requireActiveSession). The admin CRUD endpoints additionally
// require org-admin or super-admin role (requireAdminSession), matching
// the role model used elsewhere in the backend (auth/admin.go).
//
// Valkey is used as a per-feed article cache (key "news:feed:{id}",
// 15-minute TTL). The cache is invalidated on admin update or delete so
// stale articles do not survive URL changes.
package news

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const (
	feedCacheTTL  = 15 * time.Minute
	cacheKeyPfx   = "news:feed:"
	maxArticles   = 100
	fetchTimeout  = 10 * time.Second
	httpUserAgent = "ModuLab-Core/1.0 (https://modulab.app)"
)

// ---- Response types ---------------------------------------------------------

// Article is one normalized news entry returned by GET /v1/news.
type Article struct {
	Title       string    `json:"title"`
	URL         string    `json:"url"`
	Source      string    `json:"source"`
	PublishedAt time.Time `json:"published_at"`
	ImageURL    string    `json:"image_url,omitempty"`
}

// FeedResponse is one entry returned by GET /v1/feeds and the admin list.
type FeedResponse struct {
	ID        int       `json:"id"`
	URL       string    `json:"url"`
	Label     string    `json:"label"`
	Enabled   *bool     `json:"enabled,omitempty"` // only set on user-facing /v1/feeds
	CreatedAt time.Time `json:"created_at"`
}

// ---- RSS/Atom XML structs ---------------------------------------------------

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title string    `xml:"title"`
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title        string       `xml:"title"`
	Link         string       `xml:"link"`
	PubDate      string       `xml:"pubDate"`
	Enclosure    rssEnclosure `xml:"enclosure"`
	MediaContent []mediaCont  `xml:"http://search.yahoo.com/mrss/ content"`
}

type rssEnclosure struct {
	URL  string `xml:"url,attr"`
	Type string `xml:"type,attr"`
}

type mediaCont struct {
	URL    string `xml:"url,attr"`
	Medium string `xml:"medium,attr"`
}

type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string      `xml:"title"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
}

// ---- Feed parsing -----------------------------------------------------------

// detectFormat peeks at the root XML element to decide whether the body is
// RSS 2.0 ("rss") or Atom 1.0 ("feed"). Returns "" for anything else.
func detectFormat(body []byte) string {
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

var dateFormats = []string{
	time.RFC1123Z,
	time.RFC1123,
	time.RFC3339,
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700",
	"2 Jan 2006 15:04:05 MST",
	"2006-01-02T15:04:05Z",
	"2006-01-02",
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, f := range dateFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseRSS(label string, body []byte) ([]Article, error) {
	var feed rssFeed
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	// Deliberately NOT setting d.AutoClose = xml.HTMLAutoClose here:
	// in HTML, <link> is a void element, so the HTMLAutoClose list would
	// treat <link>https://...</link> as an empty self-closing tag and drop
	// the URL. RSS uses <link> as a normal element with text content.
	d.Entity = xml.HTMLEntity
	if err := d.Decode(&feed); err != nil {
		return nil, fmt.Errorf("rss decode: %w", err)
	}
	var out []Article
	for _, item := range feed.Channel.Items {
		title := strings.TrimSpace(item.Title)
		link := strings.TrimSpace(item.Link)
		if title == "" || link == "" {
			continue
		}
		a := Article{
			Title:       title,
			URL:         link,
			Source:      label,
			PublishedAt: parseDate(item.PubDate),
		}
		// Prefer media:content image, fall back to enclosure.
		for _, mc := range item.MediaContent {
			if mc.Medium == "image" && mc.URL != "" {
				a.ImageURL = mc.URL
				break
			}
		}
		if a.ImageURL == "" && strings.HasPrefix(item.Enclosure.Type, "image/") {
			a.ImageURL = item.Enclosure.URL
		}
		out = append(out, a)
	}
	return out, nil
}

func parseAtom(label string, body []byte) ([]Article, error) {
	var feed atomFeed
	d := xml.NewDecoder(bytes.NewReader(body))
	d.Strict = false
	if err := d.Decode(&feed); err != nil {
		return nil, fmt.Errorf("atom decode: %w", err)
	}
	var out []Article
	for _, entry := range feed.Entries {
		title := strings.TrimSpace(entry.Title)
		if title == "" {
			continue
		}
		// Pick the "alternate" link (or first link if none is labelled).
		var link string
		for _, l := range entry.Links {
			if l.Rel == "alternate" || l.Rel == "" {
				link = l.Href
				break
			}
		}
		if link == "" && len(entry.Links) > 0 {
			link = entry.Links[0].Href
		}
		if link == "" {
			continue
		}
		pub := entry.Published
		if pub == "" {
			pub = entry.Updated
		}
		out = append(out, Article{
			Title:       title,
			URL:         link,
			Source:      label,
			PublishedAt: parseDate(pub),
		})
	}
	return out, nil
}

func parseFeed(label string, body []byte) ([]Article, error) {
	switch detectFormat(body) {
	case "rss":
		return parseRSS(label, body)
	case "feed":
		return parseAtom(label, body)
	default:
		return nil, fmt.Errorf("unrecognized feed format")
	}
}

// ---- Fetch + cache ----------------------------------------------------------

func cacheKey(feedID int) string {
	return fmt.Sprintf("%s%d", cacheKeyPfx, feedID)
}

// valkeyCache is the minimal Valkey interface news needs - same client that
// weather.go uses, accepted by pointer but accessed via this interface so the
// package does not need to import the concrete valkey package directly.
// In practice the caller always passes *valkey.Client.
type valkeyCache interface {
	Get(ctx context.Context, key string) (string, bool, error)
	SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// fetchFeed downloads feedURL and returns parsed articles labelled with label.
func fetchFeed(ctx context.Context, feedURL, label string) ([]Article, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB cap
	if err != nil {
		return nil, err
	}
	return parseFeed(label, body)
}

// cachedFeed serves from Valkey when available; otherwise fetches, parses,
// and stores under cacheKey(feedID) with a 15-minute TTL.
func cachedFeed(ctx context.Context, vk valkeyCache, feedID int, feedURL, label string) ([]Article, error) {
	key := cacheKey(feedID)
	if cached, ok, err := vk.Get(ctx, key); err == nil && ok {
		var arts []Article
		if err := json.Unmarshal([]byte(cached), &arts); err == nil {
			return arts, nil
		}
	}
	arts, err := fetchFeed(ctx, feedURL, label)
	if err != nil {
		return nil, err
	}
	// Only cache non-empty results: caching nil/[] would lock the feed into
	// an empty state for the full TTL if the first fetch happened to return
	// nothing (e.g. due to a transient parse error or an upstream glitch).
	if len(arts) > 0 {
		if data, err := json.Marshal(arts); err == nil {
			_ = vk.SetWithTTL(ctx, key, string(data), feedCacheTTL)
		}
	}
	return arts, nil
}

// ---- Auth helpers (replicated from auth package to avoid coupling) ----------

func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func requireActiveDeps(d auth.Deps, w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return auth.Session{}, false
	}
	sess, ok, err := auth.ValidateSession(r.Context(), d.Valkey, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return auth.Session{}, false
	}
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return auth.Session{}, false
	}
	if sess.Role == auth.RolePending {
		http.Error(w, "forbidden", http.StatusForbidden)
		return auth.Session{}, false
	}
	return sess, true
}

func requireAdminDeps(d auth.Deps, w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	sess, ok := requireActiveDeps(d, w, r)
	if !ok {
		return auth.Session{}, false
	}
	if sess.Role != auth.RoleOrgAdmin && sess.Role != auth.RoleSuperAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return auth.Session{}, false
	}
	return sess, true
}

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

// ---- Admin handlers ---------------------------------------------------------

// AdminListHandler is GET /v1/admin/feeds.
func AdminListHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminDeps(d, w, r); !ok {
			return
		}
		feeds, err := d.Pool.ListFeeds(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := make([]FeedResponse, 0, len(feeds))
		for _, f := range feeds {
			resp = append(resp, FeedResponse{
				ID:        f.ID,
				URL:       f.URL,
				Label:     f.Label,
				CreatedAt: f.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// AdminCreateHandler is POST /v1/admin/feeds.
// Body: {"url": "...", "label": "..."}
func AdminCreateHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminDeps(d, w, r); !ok {
			return
		}
		var body struct {
			URL   string `json:"url"`
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.URL = strings.TrimSpace(body.URL)
		body.Label = strings.TrimSpace(body.Label)
		if body.URL == "" || body.Label == "" {
			http.Error(w, "url and label are required", http.StatusBadRequest)
			return
		}
		feed, err := d.Pool.CreateFeed(r.Context(), body.URL, body.Label)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, FeedResponse{
			ID:        feed.ID,
			URL:       feed.URL,
			Label:     feed.Label,
			CreatedAt: feed.CreatedAt,
		})
	}
}

// AdminUpdateHandler is PATCH /v1/admin/feeds/{id}.
// Body: {"url": "...", "label": "..."} — both fields required.
func AdminUpdateHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminDeps(d, w, r); !ok {
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			http.Error(w, "invalid feed id", http.StatusBadRequest)
			return
		}
		var body struct {
			URL   string `json:"url"`
			Label string `json:"label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.URL = strings.TrimSpace(body.URL)
		body.Label = strings.TrimSpace(body.Label)
		if body.URL == "" || body.Label == "" {
			http.Error(w, "url and label are required", http.StatusBadRequest)
			return
		}
		found, err := d.Pool.UpdateFeed(r.Context(), id, body.URL, body.Label)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "no such feed", http.StatusNotFound)
			return
		}
		// Invalidate the cached articles for this feed so a URL change
		// takes effect immediately rather than waiting for TTL expiry.
		_ = d.Valkey.Del(r.Context(), cacheKey(id))
		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminDeleteHandler is DELETE /v1/admin/feeds/{id}.
func AdminDeleteHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminDeps(d, w, r); !ok {
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			http.Error(w, "invalid feed id", http.StatusBadRequest)
			return
		}
		found, err := d.Pool.DeleteFeed(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "no such feed", http.StatusNotFound)
			return
		}
		// Best-effort cache invalidation - the feed row is already gone.
		_ = d.Valkey.Del(r.Context(), cacheKey(id))
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- User handlers ----------------------------------------------------------

// FeedsHandler is GET /v1/feeds: all feeds with the calling user's
// subscription state (enabled = true/false per feed).
func FeedsHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireActiveDeps(d, w, r)
		if !ok {
			return
		}
		feeds, err := d.Pool.ListFeedsForUser(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := make([]FeedResponse, 0, len(feeds))
		for _, f := range feeds {
			enabled := f.Enabled
			resp = append(resp, FeedResponse{
				ID:        f.ID,
				URL:       f.URL,
				Label:     f.Label,
				Enabled:   &enabled,
				CreatedAt: f.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// SubscriptionHandler is PATCH /v1/feeds/{id}/subscription.
// Body: {"enabled": true|false}
func SubscriptionHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireActiveDeps(d, w, r)
		if !ok {
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			http.Error(w, "invalid feed id", http.StatusBadRequest)
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := d.Pool.SetFeedSubscription(r.Context(), sess.UserID, id, body.Enabled); err != nil {
			// A foreign-key violation means the feed id does not exist.
			if strings.Contains(err.Error(), "violates foreign key") {
				http.Error(w, "no such feed", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// NewsHandler is GET /v1/news: aggregates articles from the calling user's
// enabled feeds, fetching each in parallel and serving from Valkey cache
// where possible. Returns up to maxArticles items sorted newest-first.
func NewsHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireActiveDeps(d, w, r)
		if !ok {
			return
		}

		feeds, err := d.Pool.EnabledFeedsForUser(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(feeds) == 0 {
			writeJSON(w, http.StatusOK, []Article{})
			return
		}

		// Fetch all enabled feeds in parallel. Errors for individual feeds
		// are logged and skipped rather than failing the whole response -
		// a single unreachable upstream should not blank out the entire panel.
		type result struct {
			arts []Article
			err  error
		}
		results := make([]result, len(feeds))
		var wg sync.WaitGroup
		for i, feed := range feeds {
			wg.Add(1)
			go func(i int, f db.FeedRow) {
				defer wg.Done()
				arts, err := cachedFeed(r.Context(), d.Valkey, f.ID, f.URL, f.Label)
				results[i] = result{arts: arts, err: err}
			}(i, feed)
		}
		wg.Wait()

		var all []Article
		for i, res := range results {
			if res.err != nil {
				log.Printf("news: feed %d (%s): %v", feeds[i].ID, feeds[i].URL, res.err)
				continue
			}
			all = append(all, res.arts...)
		}

		// Sort newest first, cap at maxArticles.
		sort.Slice(all, func(i, j int) bool {
			return all[i].PublishedAt.After(all[j].PublishedAt)
		})
		if len(all) > maxArticles {
			all = all[:maxArticles]
		}
		// Ensure the response is always a JSON array, never null.
		if all == nil {
			all = []Article{}
		}
		writeJSON(w, http.StatusOK, all)
	}
}

// PrefsHandler serves GET and PATCH /v1/news/preferences.
//
//   GET  → returns the calling user's NewsPrefs (defaults if none stored yet).
//   PATCH → accepts a partial body; only provided fields are updated.
func PrefsHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := requireActiveDeps(d, w, r)
		if !ok {
			return
		}

		if r.Method == http.MethodGet {
			prefs, err := d.Pool.GetNewsPrefs(r.Context(), sess.UserID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, prefs)
			return
		}

		// PATCH: read current prefs first, then merge the body.
		current, err := d.Pool.GetNewsPrefs(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Use pointer fields so we can detect which keys the caller sent.
		var body struct {
			HomeArticleCount *int  `json:"home_article_count"`
			ShowImages       *bool `json:"show_images"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.HomeArticleCount != nil {
			current.HomeArticleCount = *body.HomeArticleCount
		}
		if body.ShowImages != nil {
			current.ShowImages = *body.ShowImages
		}
		if err := d.Pool.SetNewsPrefs(r.Context(), sess.UserID, current); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, current)
	}
}
