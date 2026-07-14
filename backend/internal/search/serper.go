package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/netguard"
	"github.com/modulab-project/modulab-core/backend/internal/searxng"
)

// serperBaseURL is Serper.dev's fixed API host. Unlike SearXNG's base_url
// (always a private/admin-chosen address), this is a public third-party
// endpoint reached with an admin- or user-supplied API key, so it goes
// through netguard's SSRF guard like the AI providers' custom base_urls do
// (see ai.go's safeProviderClient doc comment for the rationale).
const serperBaseURL = "https://google.serper.dev"

var serperClient = netguard.SafeHTTPClient(0)

// serperOrganicResult is one entry in Serper's POST /search "organic" array.
type serperOrganicResult struct {
	Title   string `json:"title"`
	Link    string `json:"link"`
	Snippet string `json:"snippet"`
}

type serperSearchResponse struct {
	Organic []serperOrganicResult `json:"organic"`
}

// serperImageResult is one entry in Serper's POST /images "images" array.
type serperImageResult struct {
	Title        string `json:"title"`
	ImageURL     string `json:"imageUrl"`
	Link         string `json:"link"`
	ThumbnailURL string `json:"thumbnailUrl"`
}

type serperImagesResponse struct {
	Images []serperImageResult `json:"images"`
}

// serperTimeRangeCode maps our "day"/"week"/"month"/"year" time_range values
// to Google's tbs=qdr:X date-restrict codes, which Serper passes through
// verbatim.
var serperTimeRangeCode = map[string]string{
	"day": "d", "week": "w", "month": "m", "year": "y",
}

// fetchSerper calls Serper.dev's /search or /images endpoint (chosen by
// category) and maps the response onto the shared searxng.WebResult shape,
// so SearchHandler never needs to know which provider actually answered.
//
// Known gap: Serper has no documented SafeSearch parameter equivalent to
// SearXNG's, so sp.Safesearch is intentionally not sent - a user's
// safesearch preference has no effect when Serper serves the request. This
// is a Serper API limitation, not something fixable on ModuLab's side.
func fetchSerper(ctx context.Context, apiKey, query, category string, maxResults int, sp searxng.SearchParams, timeoutSeconds int) ([]searxng.WebResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	endpoint := serperBaseURL + "/search"
	if category == "images" {
		endpoint = serperBaseURL + "/images"
	}

	body := map[string]any{"q": query}
	if maxResults > 0 {
		body["num"] = maxResults
	}
	if sp.Language != "" && sp.Language != "all" {
		body["hl"] = sp.Language
	}
	if code, ok := serperTimeRangeCode[sp.TimeRange]; ok {
		body["tbs"] = "qdr:" + code
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", apiKey)

	resp, err := serperClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("serper: request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("search: serper: close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("serper returned HTTP %d: %s", resp.StatusCode, b)
	}

	limited := io.LimitReader(resp.Body, 2<<20) // 2 MB cap, same as searxng.FetchResults

	if category == "images" {
		var parsed serperImagesResponse
		if err := json.NewDecoder(limited).Decode(&parsed); err != nil {
			return nil, fmt.Errorf("serper: parse images response: %w", err)
		}
		out := make([]searxng.WebResult, 0, len(parsed.Images))
		for _, im := range parsed.Images {
			if maxResults > 0 && len(out) >= maxResults {
				break
			}
			out = append(out, searxng.WebResult{
				Title:     im.Title,
				URL:       im.Link,
				Thumbnail: im.ThumbnailURL,
				ImgSrc:    im.ImageURL,
			})
		}
		return out, nil
	}

	var parsed serperSearchResponse
	if err := json.NewDecoder(limited).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("serper: parse response: %w", err)
	}
	out := make([]searxng.WebResult, 0, len(parsed.Organic))
	for _, r := range parsed.Organic {
		if maxResults > 0 && len(out) >= maxResults {
			break
		}
		out = append(out, searxng.WebResult{Title: r.Title, URL: r.Link, Snippet: r.Snippet})
	}
	return out, nil
}
