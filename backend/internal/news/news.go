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
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/netguard"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// logFeedAudit writes one audit_log entry for a feed admin action. Mirrors
// auth/admin.go's logAudit and modules/handlers.go's logModuleAudit (same
// "resolve master key, log-and-swallow on failure" shape) - a failed audit
// write must never turn a successful feed create/update/delete into a 500
// the admin has to retry.
func logFeedAudit(ctx context.Context, d auth.Deps, p audit.LogParams) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		log.Printf("news: audit: failed to resolve master key for %s: %v", p.EventType, err)
		return
	}
	if err := audit.Log(ctx, d.Pool, masterKey, p); err != nil {
		log.Printf("news: audit: failed to write %s: %v", p.EventType, err)
	}
}

const (
	feedCacheTTL   = 15 * time.Minute
	cacheKeyPfx    = "news:feed:"
	maxArticles    = 100
	httpUserAgent  = "ModuLab-Core/1.0 (https://modulab.app)"
	maxConcurrency = 10 // parallel feed reachability checks

	// defaultFetchTimeoutSeconds is FetchTimeoutSeconds's fallback - mirrors
	// the fixed 10s value this replaced.
	defaultFetchTimeoutSeconds = 10
)

// safeFeedClient fetches admin-configured feed URLs through netguard's
// dial-time IP allowlist (see that package's doc comment) rather than
// http.DefaultClient - a feed URL is arbitrary input from an admin, and
// without this an admin account could point Core at an internal service
// or the cloud metadata endpoint and read the response back as "articles".
//
// Timeout: 0 - previously a fixed fetchTimeout const. The actual bound is
// now the admin-configurable news_fetch_timeout_seconds setting (see
// FetchTimeoutSeconds), applied per-call as a context deadline in fetchFeed
// instead of baked into the client at package-init time - some RSS/Atom
// feeds are slow or flaky enough that the old fixed 10s caused spurious
// "unreachable" reports for feeds that just needed a bit longer.
var safeFeedClient = netguard.SafeHTTPClient(0)

// FetchTimeoutSeconds reads the feed-fetch HTTP timeout (seconds) from
// core_settings ("news_fetch_timeout_seconds"). Defaults to
// defaultFetchTimeoutSeconds if unset.
func FetchTimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, "news_fetch_timeout_seconds")
	if err != nil || !ok || val == "" {
		return defaultFetchTimeoutSeconds
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultFetchTimeoutSeconds
	}
	return n
}

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
func fetchFeed(ctx context.Context, pool *db.Pool, feedURL, label string) ([]Article, error) {
	timeout := time.Duration(FetchTimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml, */*")

	resp, err := safeFeedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("news: close response body: %v", err)
		}
	}()

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
func cachedFeed(ctx context.Context, vk valkeyCache, pool *db.Pool, feedID int, feedURL, label string) ([]Article, error) {
	key := cacheKey(feedID)
	if cached, ok, err := vk.Get(ctx, key); err == nil && ok {
		var arts []Article
		if err := json.Unmarshal([]byte(cached), &arts); err == nil {
			return arts, nil
		}
	}
	arts, err := fetchFeed(ctx, pool, feedURL, label)
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

// ---- Local helpers ----------------------------------------------------------

// isHTTPURL returns true when raw is a syntactically valid http or https URL.
// Blocks javascript:, data:, and any other non-http scheme that could be used
// as a stored XSS vector when the frontend renders URLs as anchor hrefs.
func isHTTPURL(raw string) bool {
	u, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		log.Printf("news: write response: %v", err)
	}
}

// ---- OPML import ------------------------------------------------------------

// opmlBody is the minimal OPML 2.0 structure we need to parse.
// OPML organises feeds in <outline> elements; the feed URL is in the
// xmlUrl attribute and a human-readable name is in text or title.
type opmlBody struct {
	XMLName  xml.Name      `xml:"opml"`
	Outlines []opmlOutline `xml:"body>outline"`
}

type opmlOutline struct {
	Text     string        `xml:"text,attr"`
	Title    string        `xml:"title,attr"`
	XMLURL   string        `xml:"xmlUrl,attr"`
	Children []opmlOutline `xml:"outline"`
}

// flattenOPML collects all leaf outlines (those with an xmlUrl attribute)
// recursively so folder-grouped feeds are handled the same as flat ones.
func flattenOPML(outlines []opmlOutline) []opmlOutline {
	var flat []opmlOutline
	for _, o := range outlines {
		if o.XMLURL != "" {
			flat = append(flat, o)
		}
		flat = append(flat, flattenOPML(o.Children)...)
	}
	return flat
}

// OPMLEntry is one feed parsed from an OPML file, returned by
// POST /v1/admin/feeds/opml-parse before any import happens.
type OPMLEntry struct {
	URL   string `json:"url"`
	Label string `json:"label"`
	// AlreadyExists is true when this feed URL is already in the global pool.
	AlreadyExists bool `json:"already_exists"`
	// Reachable is false when the feed URL could not be fetched or parsed
	// during the parse step. The frontend uses this to pre-deselect and
	// disable unreachable feeds in the selection modal.
	Reachable bool `json:"reachable"`
	// ReachError is a short human-readable reason when Reachable is false.
	ReachError string `json:"reach_error,omitempty"`
}

// defaultMaxOPMLUploadBytes is the fallback OPML import size cap used when
// the max_opml_upload_bytes setting (see MaxOPMLUploadBytes) has never been
// set.
const defaultMaxOPMLUploadBytes = 2 << 20 // 2 MB

// MaxOPMLUploadBytes reads the OPML-import upload size cap from
// core_settings ("max_opml_upload_bytes"). Used to be a hardcoded constant
// with no admin control — the same class of problem max_body_bytes'
// interaction with module uploads turned out to have (see
// modules.MaxUploadBodyBytes's doc comment): a hardcoded per-handler limit
// silently capped at whatever value happened to be smaller. Defaults to
// defaultMaxOPMLUploadBytes (2 MB) if unset; 0 means unlimited, same
// convention as the other size settings. See adminapi.AdminLimitsHandler
// for where this is admin-editable.
func MaxOPMLUploadBytes(ctx context.Context, pool *db.Pool) int64 {
	val, ok, err := pool.GetSetting(ctx, "max_opml_upload_bytes")
	if err != nil || !ok || val == "" {
		return defaultMaxOPMLUploadBytes
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n < 0 {
		return defaultMaxOPMLUploadBytes
	}
	return n
}

// AdminParseOPMLHandler is POST /v1/admin/feeds/opml-parse.
// Accepts a multipart/form-data upload with a field named "file" containing
// an OPML document. Returns the list of feeds found in the file — including
// whether each is already in the global pool and whether it is reachable —
// without inserting anything. Reachability is checked in parallel (up to 10
// concurrent fetches) so large OPML files resolve quickly without overwhelming
// the network. The caller (admin UI) shows a selection step and then calls
// POST /v1/admin/feeds/import with the chosen feeds.
func AdminParseOPMLHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(d, w, r); !ok {
			return
		}
		maxUploadSize := MaxOPMLUploadBytes(r.Context(), d.Pool)
		// Reject oversized uploads before reading any body bytes rather than
		// letting ParseMultipartForm's internal limit trip mid-stream - see
		// maxBodyMiddleware's doc comment (cmd/core/main.go) for why that
		// matters (an abrupt connection close looks like a 502 to any proxy
		// in front of Core, not a clean error).
		if maxUploadSize > 0 && r.ContentLength > maxUploadSize {
			http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
		parseMemory := maxUploadSize
		if parseMemory <= 0 {
			parseMemory = defaultMaxOPMLUploadBytes * 16 // generous bound for the "unlimited" case
		}
		if err := r.ParseMultipartForm(parseMemory); err != nil {
			http.Error(w, "file too large or invalid form", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing file field", http.StatusBadRequest)
			return
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("news: close uploaded file: %v", err)
			}
		}()

		readLimit := maxUploadSize
		if readLimit <= 0 {
			readLimit = parseMemory
		}
		body, err := io.ReadAll(io.LimitReader(file, readLimit))
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		var doc opmlBody
		dec := xml.NewDecoder(bytes.NewReader(body))
		dec.Strict = false
		if err := dec.Decode(&doc); err != nil {
			http.Error(w, "invalid OPML: "+err.Error(), http.StatusBadRequest)
			return
		}

		leaves := flattenOPML(doc.Outlines)
		if len(leaves) == 0 {
			http.Error(w, "no feed entries found in OPML", http.StatusBadRequest)
			return
		}

		existing, _ := d.Pool.ListFeeds(r.Context())
		existingURLs := make(map[string]bool, len(existing))
		for _, f := range existing {
			existingURLs[strings.ToLower(strings.TrimSpace(f.URL))] = true
		}

		// Build the candidate list first (filter invalid URLs).
		type candidate struct {
			idx   int
			entry OPMLEntry
		}
		candidates := make([]candidate, 0, len(leaves))
		entries := make([]OPMLEntry, 0, len(leaves))
		for _, o := range leaves {
			feedURL := strings.TrimSpace(o.XMLURL)
			if feedURL == "" || !isHTTPURL(feedURL) {
				continue
			}
			label := strings.TrimSpace(o.Text)
			if label == "" {
				label = strings.TrimSpace(o.Title)
			}
			if label == "" {
				label = feedURL
			}
			e := OPMLEntry{
				URL:           feedURL,
				Label:         label,
				AlreadyExists: existingURLs[strings.ToLower(feedURL)],
			}
			candidates = append(candidates, candidate{idx: len(entries), entry: e})
			entries = append(entries, e)
		}

		// Check reachability in parallel, bounded by maxConcurrency.
		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup
		for _, c := range candidates {
			wg.Add(1)
			go func(idx int, feedURL, label string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				_, fetchErr := fetchFeed(r.Context(), d.Pool, feedURL, label)
				if fetchErr != nil {
					entries[idx].Reachable = false
					entries[idx].ReachError = fetchErr.Error()
				} else {
					entries[idx].Reachable = true
				}
			}(c.idx, c.entry.URL, c.entry.Label)
		}
		wg.Wait()

		writeJSON(w, http.StatusOK, entries)
	}
}

// ImportResult is one entry in the JSON array returned by POST /v1/admin/feeds/import.
type ImportResult struct {
	URL     string `json:"url"`
	Label   string `json:"label"`
	Skipped bool   `json:"skipped"` // true if feed already existed
	Error   string `json:"error,omitempty"`
}

// ImportRequest is the body of POST /v1/admin/feeds/import when called with
// a JSON body (selection-based import). The caller sends the list of feeds
// the user selected from the OPML parse step.
type ImportRequest struct {
	Feeds []OPMLEntry `json:"feeds"`
}

// AdminImportHandler is POST /v1/admin/feeds/import.
// Accepts a JSON body {"feeds": [{url, label}, ...]} — the selection the
// admin made after the parse step (AdminParseOPMLHandler). Inserts each
// valid feed URL, skipping any already present.
func AdminImportHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}

		var req ImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Feeds) == 0 {
			http.Error(w, "feeds list is empty", http.StatusBadRequest)
			return
		}

		// Fetch existing feed URLs once to skip duplicates without relying on
		// DB unique-constraint errors for flow control.
		existing, _ := d.Pool.ListFeeds(r.Context())
		existingURLs := make(map[string]bool, len(existing))
		for _, f := range existing {
			existingURLs[strings.ToLower(strings.TrimSpace(f.URL))] = true
		}

		results := make([]ImportResult, 0, len(req.Feeds))
		for _, entry := range req.Feeds {
			feedURL := strings.TrimSpace(entry.URL)
			label := strings.TrimSpace(entry.Label)
			if label == "" {
				label = feedURL
			}
			if !isHTTPURL(feedURL) {
				results = append(results, ImportResult{URL: feedURL, Label: label, Error: "invalid URL"})
				continue
			}
			if existingURLs[strings.ToLower(feedURL)] {
				results = append(results, ImportResult{URL: feedURL, Label: label, Skipped: true})
				continue
			}
			if _, err := d.Pool.CreateFeed(r.Context(), feedURL, label); err != nil {
				results = append(results, ImportResult{URL: feedURL, Label: label, Error: err.Error()})
				continue
			}
			existingURLs[strings.ToLower(feedURL)] = true
			results = append(results, ImportResult{URL: feedURL, Label: label})
		}

		// One summary entry per import batch rather than one per feed - an
		// OPML import can bring in dozens of feeds at once, and per-feed
		// entries would drown out everything else in the audit log for a
		// single admin action.
		created, skipped, failed := 0, 0, 0
		for _, res := range results {
			switch {
			case res.Error != "":
				failed++
			case res.Skipped:
				skipped++
			default:
				created++
			}
		}
		logFeedAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventFeedCreated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details:    fmt.Sprintf(`{"import":true,"created":%d,"skipped":%d,"failed":%d}`, created, skipped, failed),
		})

		writeJSON(w, http.StatusOK, results)
	}
}

// ---- Feed check -------------------------------------------------------------

// CheckResult is the JSON body returned by POST /v1/admin/feeds/check.
type CheckResult struct {
	Reachable    bool   `json:"reachable"`
	ArticleCount int    `json:"article_count"`
	HasImages    bool   `json:"has_images"`
	Error        string `json:"error,omitempty"`
}

// AdminCheckHandler is POST /v1/admin/feeds/check.
// Body: {"url": "..."}
// Fetches the feed URL, parses it, and reports reachability + image support.
// Does not write to the database — purely diagnostic.
func AdminCheckHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(d, w, r); !ok {
			return
		}
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.URL = strings.TrimSpace(body.URL)
		if !isHTTPURL(body.URL) {
			writeJSON(w, http.StatusOK, CheckResult{Reachable: false, Error: "url must be a valid http or https URL"})
			return
		}

		arts, err := fetchFeed(r.Context(), d.Pool, body.URL, "check")
		if err != nil {
			writeJSON(w, http.StatusOK, CheckResult{Reachable: false, Error: err.Error()})
			return
		}

		hasImages := false
		for _, a := range arts {
			if a.ImageURL != "" {
				hasImages = true
				break
			}
		}
		writeJSON(w, http.StatusOK, CheckResult{
			Reachable:    true,
			ArticleCount: len(arts),
			HasImages:    hasImages,
		})
	}
}

// ---- Admin handlers ---------------------------------------------------------

// AdminListHandler is GET /v1/admin/feeds.
func AdminListHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(d, w, r); !ok {
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
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
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
		if !isHTTPURL(body.URL) {
			http.Error(w, "url must be a valid http or https URL", http.StatusBadRequest)
			return
		}
		feed, err := d.Pool.CreateFeed(r.Context(), body.URL, body.Label)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logFeedAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventFeedCreated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   strconv.Itoa(feed.ID),
			Details:    fmt.Sprintf(`{"label":%q,"url":%q}`, feed.Label, feed.URL),
		})
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
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
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
		if !isHTTPURL(body.URL) {
			http.Error(w, "url must be a valid http or https URL", http.StatusBadRequest)
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
		logFeedAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventFeedUpdated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   strconv.Itoa(id),
			Details:    fmt.Sprintf(`{"label":%q,"url":%q}`, body.Label, body.URL),
		})
		// Invalidate the cached articles for this feed so a URL change
		// takes effect immediately rather than waiting for TTL expiry.
		_ = d.Valkey.Del(r.Context(), cacheKey(id))
		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminDeleteHandler is DELETE /v1/admin/feeds/{id}.
func AdminDeleteHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			http.Error(w, "invalid feed id", http.StatusBadRequest)
			return
		}
		// Capture label/URL before deleting - DeleteFeed only returns
		// found/error, and the audit entry below is more useful with the
		// feed's identity than a bare numeric id. Best-effort: if this
		// lookup fails for some reason, the delete still proceeds and the
		// audit entry just falls back to the id alone.
		var label, feedURL string
		if feeds, err := d.Pool.ListFeeds(r.Context()); err == nil {
			for _, f := range feeds {
				if f.ID == id {
					label, feedURL = f.Label, f.URL
					break
				}
			}
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
		logFeedAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventFeedDeleted,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   strconv.Itoa(id),
			Details:    fmt.Sprintf(`{"label":%q,"url":%q}`, label, feedURL),
		})
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
		sess, ok := auth.RequireActiveSession(d, w, r)
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
		sess, ok := auth.RequireActiveSession(d, w, r)
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
		sess, ok := auth.RequireActiveSession(d, w, r)
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
				arts, err := cachedFeed(r.Context(), d.Valkey, d.Pool, f.ID, f.URL, f.Label)
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

		// Read admin-configured cap; fall back to compile-time default.
		cap := maxArticles
		if v, ok, _ := d.Pool.GetSetting(r.Context(), "news_max_articles"); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cap = n
			}
		}

		// Sort newest first, cap at the configured limit.
		sort.Slice(all, func(i, j int) bool {
			return all[i].PublishedAt.After(all[j].PublishedAt)
		})
		if len(all) > cap {
			all = all[:cap]
		}
		// Ensure the response is always a JSON array, never null.
		if all == nil {
			all = []Article{}
		}
		writeJSON(w, http.StatusOK, all)
	}
}

// newsSettingsDefaults returns the global news settings from core_settings,
// applying defaults when a key is absent.
func newsSettingsDefaults(ctx context.Context, pool interface {
	GetSetting(context.Context, string) (string, bool, error)
}) (maxArt, homeCount int, showImages bool) {
	maxArt, homeCount, showImages = 100, 5, true

	if v, ok, _ := pool.GetSetting(ctx, "news_max_articles"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxArt = n
		}
	}
	if v, ok, _ := pool.GetSetting(ctx, "news_home_count"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			homeCount = n
		}
	}
	if v, ok, _ := pool.GetSetting(ctx, "news_show_images"); ok {
		showImages = v != "false"
	}
	return
}

// NewsConfigHandler is GET /v1/news/config.
// Returns the admin-configured display settings relevant to regular users:
// how many articles to show on the home page and whether to show images.
func NewsConfigHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(d, w, r); !ok {
			return
		}
		_, homeCount, showImages := newsSettingsDefaults(r.Context(), d.Pool)
		writeJSON(w, http.StatusOK, map[string]any{
			"home_count":  homeCount,
			"show_images": showImages,
		})
	}
}

// AdminNewsSettingsHandler serves GET and PATCH /v1/admin/news/settings.
// Requires org-admin or super-admin role.
//
//	GET  → returns current settings (with defaults for unset keys).
//	PATCH → partial update; only provided fields are changed.
func AdminNewsSettingsHandler(d auth.Deps) http.HandlerFunc {
	type settings struct {
		MaxArticles *int  `json:"max_articles"`
		HomeCount   *int  `json:"home_count"`
		ShowImages  *bool `json:"show_images"`
	}

	readCurrent := func(ctx context.Context) settings {
		maxArt, homeCount, showImages := newsSettingsDefaults(ctx, d.Pool)
		return settings{
			MaxArticles: &maxArt,
			HomeCount:   &homeCount,
			ShowImages:  &showImages,
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}

		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, readCurrent(r.Context()))
			return
		}

		// PATCH: decode partial body, merge with current, persist changed keys.
		var body settings
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// Only the fields actually present in this PATCH, same convention
		// smtpDiff (cmd/core/main.go) uses for its audit entry - so the log
		// shows what changed, not the full settings blob on every save.
		changed := map[string]any{}

		if body.MaxArticles != nil {
			v := *body.MaxArticles
			if v < 1 {
				v = 1
			}
			if v > 1000 {
				v = 1000
			}
			if err := d.Pool.SetSetting(r.Context(), "news_max_articles", strconv.Itoa(v)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			changed["max_articles"] = v
		}
		if body.HomeCount != nil {
			v := *body.HomeCount
			if v < 1 {
				v = 1
			}
			if v > 50 {
				v = 50
			}
			if err := d.Pool.SetSetting(r.Context(), "news_home_count", strconv.Itoa(v)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			changed["home_count"] = v
		}
		if body.ShowImages != nil {
			val := "true"
			if !*body.ShowImages {
				val = "false"
			}
			if err := d.Pool.SetSetting(r.Context(), "news_show_images", val); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			changed["show_images"] = *body.ShowImages
		}

		// Best-effort, same tradeoff as every other audit.Log call in this
		// package: the settings write(s) above already succeeded - a failed
		// audit write must not turn it into an error. Skipped entirely for
		// an empty PATCH (no recognized fields present).
		if len(changed) > 0 {
			if details, err := json.Marshal(changed); err == nil {
				logFeedAudit(r.Context(), d, audit.LogParams{
					EventType:  audit.EventNewsSettings,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					Details:    string(details),
				})
			}
		}

		writeJSON(w, http.StatusOK, readCurrent(r.Context()))
	}
}

// ---- Feed catalog -----------------------------------------------------------

const (
	catalogURL      = "https://raw.githubusercontent.com/yavuz/news-feed-list-of-countries/master/database/news-feed-list-of-countries.json"
	catalogCacheKey = "news:catalog"
	catalogCacheTTL = 24 * time.Hour
)

type catalogPublication struct {
	Name    string           `json:"publication_name"`
	Website string           `json:"publication_website_uri"`
	Feeds   []catalogFeedURI `json:"publication_rss_feed_uris"`
}

type catalogFeedURI struct {
	URI           string `json:"uri"`
	BotProtection bool   `json:"bot_protection"`
	Category      string `json:"category,omitempty"`
}

// catalogCountries maps each supported language code to the ISO 3166-1 Alpha-3
// country codes included in the catalog fetch.
var catalogCountries = map[string][]string{
	"DE": {"DEU", "AUT", "CHE"},
	"EN": {"GBR", "USA", "AUS", "CAN", "IRL", "NZL"},
	"ES": {"ESP", "MEX", "ARG", "COL", "CHL", "PER", "VEN"},
	"FR": {"FRA", "BEL", "CHE"},
	"NL": {"NLD", "BEL"},
}

// catalogLanguages is the ordered list of supported language codes for the catalog.
var catalogLanguages = []string{"DE", "EN", "ES", "FR", "NL"}

// AdminCatalogHandler is GET /v1/admin/feeds/catalog.
//
// Without query params: returns {"languages": ["DE","EN","ES","FR","NL"]}.
// With ?lang=DE: fetches the GitHub catalog (cached 24 h), filters to the
// countries for that language, checks reachability in parallel (same semaphore
// approach as AdminParseOPMLHandler), and returns []OPMLEntry with Reachable
// and AlreadyExists both populated.
func AdminCatalogHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(d, w, r); !ok {
			return
		}

		lang := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("lang")))

		// No lang param → return language list.
		if lang == "" {
			writeJSON(w, http.StatusOK, map[string][]string{"languages": catalogLanguages})
			return
		}

		// Validate lang.
		countryCodes, ok := catalogCountries[lang]
		if !ok {
			http.Error(w, "unsupported language: "+lang, http.StatusBadRequest)
			return
		}

		// 1. Fetch raw catalog JSON — try Valkey cache first.
		rawJSON, err := catalogFetchRaw(r.Context(), d)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// 2. Parse catalog.
		var catalog map[string][]catalogPublication
		if err := json.Unmarshal([]byte(rawJSON), &catalog); err != nil {
			http.Error(w, "failed to parse catalog: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 3. Load existing DB feeds for AlreadyExists check.
		existingFeeds, dbErr := d.Pool.ListFeeds(r.Context())
		if dbErr != nil {
			http.Error(w, dbErr.Error(), http.StatusInternalServerError)
			return
		}
		existingURLs := make(map[string]bool, len(existingFeeds))
		for _, f := range existingFeeds {
			existingURLs[strings.ToLower(f.URL)] = true
		}

		// 4. Collect entries for the requested language (deduplicated by URL).
		targetSet := make(map[string]bool, len(countryCodes))
		for _, c := range countryCodes {
			targetSet[c] = true
		}
		seen := make(map[string]bool)
		var entries []OPMLEntry
		for countryCode, pubs := range catalog {
			if !targetSet[countryCode] {
				continue
			}
			for _, pub := range pubs {
				for _, feed := range pub.Feeds {
					if feed.BotProtection {
						continue
					}
					feedURL := strings.TrimSpace(feed.URI)
					if !isHTTPURL(feedURL) {
						continue
					}
					lower := strings.ToLower(feedURL)
					if seen[lower] {
						continue
					}
					seen[lower] = true

					label := pub.Name
					if feed.Category != "" {
						label = pub.Name + " – " + feed.Category
					}
					entries = append(entries, OPMLEntry{
						URL:           feedURL,
						Label:         label,
						AlreadyExists: existingURLs[lower],
					})
				}
			}
		}

		// 5. Check reachability in parallel (max 10 concurrent).
		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup
		for i := range entries {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				_, fetchErr := fetchFeed(r.Context(), d.Pool, entries[idx].URL, entries[idx].Label)
				if fetchErr != nil {
					entries[idx].Reachable = false
					entries[idx].ReachError = fetchErr.Error()
				} else {
					entries[idx].Reachable = true
				}
			}(i)
		}
		wg.Wait()

		writeJSON(w, http.StatusOK, entries)
	}
}

// catalogFetchRaw returns the raw GitHub catalog JSON, using Valkey as a 24 h cache.
func catalogFetchRaw(ctx context.Context, d auth.Deps) (string, error) {
	cached, hit, err := d.Valkey.Get(ctx, catalogCacheKey)
	if err == nil && hit {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build catalog request: %w", err)
	}
	req.Header.Set("User-Agent", httpUserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch catalog: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("news: close catalog response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("catalog returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read catalog: %w", err)
	}
	raw := string(body)
	if cacheErr := d.Valkey.SetWithTTL(ctx, catalogCacheKey, raw, catalogCacheTTL); cacheErr != nil {
		log.Printf("news: catalog cache write failed: %v", cacheErr)
	}
	return raw, nil
}
