package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// officialRegistryURL is the raw GitHub URL for the official registry.json
	// in the modulab-modules monorepo. No API token needed for public repos.
	officialRegistryURL = "https://raw.githubusercontent.com/modulab-project/modulab-modules/main/registry.json"

	// communityIndexURL is the GitHub Contents API URL that lists all .json
	// files in the modulab-community/modules/ directory. Returns a JSON array
	// of file objects, each with a "download_url" field we can fetch directly.
	communityIndexURL = "https://api.github.com/repos/modulab-project/modulab-community/contents/modules"

	githubAPITimeout = 15 * time.Second
)

// officialEntry is the shape of one element in the official registry.json.
type officialEntry struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ReleaseURL   string `json:"release_url"`
	SHA256       string `json:"sha256"`
	CosignSigURL string `json:"cosign_sig_url"`
	Category     string `json:"category"`
}

// communityIndexItem is one file object returned by the GitHub Contents API
// for the modulab-community/modules/ directory listing.
type communityIndexItem struct {
	Name        string `json:"name"`        // e.g. "unifi-radius.json"
	DownloadURL string `json:"download_url"` // raw file URL
}

// communityEntry is the shape of one modulab-community modules/*.json file.
type communityEntry struct {
	Name         string `json:"name"`
	SourceRepo   string `json:"source_repo"`
	ReleaseAsset string `json:"release_asset"`
	Category     string `json:"category"`
}

// githubRelease is the subset of fields the GitHub Releases API returns that
// we care about when checking for the latest version of a community module.
type githubRelease struct {
	TagName string `json:"tag_name"` // e.g. "unifi-radius-v1.2.0"
}

// FetchOfficialRegistry downloads and parses the official registry.json.
// Returns an empty slice (not an error) when the file exists but is empty,
// so a not-yet-populated monorepo doesn't prevent Core from starting.
func FetchOfficialRegistry(ctx context.Context) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, githubAPITimeout)
	defer cancel()

	data, err := httpGet(ctx, officialRegistryURL)
	if err != nil {
		return nil, fmt.Errorf("store: fetch official registry: %w", err)
	}

	var raw []officialEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("store: parse official registry: %w", err)
	}

	out := make([]Entry, 0, len(raw))
	for _, r := range raw {
		// Derive the source_repo from the release_url so we don't need a
		// separate field: trim everything from /releases/ onwards.
		sourceRepo := officialSourceRepo(r.ReleaseURL)
		out = append(out, Entry{
			Name:       r.Name,
			Source:     "official",
			SourceRepo: sourceRepo,
			// Store the full release_url as ReleaseAsset so the installer can
			// use it verbatim. The tag in the URL may differ from LatestVersion
			// (e.g. tag "recipes-v0.1.0" vs version "0.1.0").
			ReleaseAsset:  r.ReleaseURL,
			CosignSigURL:  r.CosignSigURL,
			Category:      r.Category,
			LatestVersion: r.Version,
		})
	}
	return out, nil
}

// FetchCommunityRegistry downloads the modulab-community index (one JSON file
// per module in modules/) and returns all valid entries. Files that cannot be
// fetched or parsed are logged and skipped, not fatal.
func FetchCommunityRegistry(ctx context.Context) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, githubAPITimeout)
	defer cancel()

	data, err := httpGet(ctx, communityIndexURL)
	if err != nil {
		return nil, fmt.Errorf("store: fetch community index: %w", err)
	}

	var items []communityIndexItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("store: parse community index: %w", err)
	}

	var out []Entry
	for _, item := range items {
		if !strings.HasSuffix(item.Name, ".json") {
			continue
		}
		entryData, err := httpGet(ctx, item.DownloadURL)
		if err != nil {
			// Best-effort: skip unreadable entries, don't abort the whole sync.
			continue
		}
		var e communityEntry
		if err := json.Unmarshal(entryData, &e); err != nil {
			continue
		}
		if e.Name == "" || e.SourceRepo == "" || e.ReleaseAsset == "" {
			continue // malformed entry
		}
		out = append(out, Entry{
			Name:         e.Name,
			Source:       "community",
			SourceRepo:   e.SourceRepo,
			ReleaseAsset: e.ReleaseAsset,
			Category:     e.Category,
		})
	}
	return out, nil
}

// FetchLatestRelease calls the GitHub Releases API for sourceRepo and returns
// the tag name of the latest release, or ("", nil) when the repo has no
// releases yet. Used by the daily update-check for community modules.
func FetchLatestRelease(ctx context.Context, sourceRepo string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, githubAPITimeout)
	defer cancel()

	// Convert https://github.com/owner/repo → owner/repo for the API path.
	repoPath := strings.TrimPrefix(sourceRepo, "https://github.com/")
	repoPath = strings.TrimSuffix(repoPath, "/")
	if repoPath == "" {
		return "", fmt.Errorf("store: invalid source_repo %q", sourceRepo)
	}

	url := "https://api.github.com/repos/" + repoPath + "/releases/latest"
	data, err := httpGet(ctx, url)
	if err != nil {
		// 404 = no releases yet → not an error, just no version known.
		return "", nil
	}

	var rel githubRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return "", fmt.Errorf("store: parse latest release for %q: %w", sourceRepo, err)
	}
	return rel.TagName, nil
}

// httpGet performs a GET request and returns the body. Returns an error for
// any non-2xx status. Uses the standard http.DefaultClient with the provided
// context for timeout control.
func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Identify ourselves so GitHub doesn't rate-limit us as a generic client.
	req.Header.Set("User-Agent", "modulab-core/1 (https://github.com/modulab-project/modulab-core)")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s", url)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// officialSourceRepo extracts the repo base URL from a release_url.
// "https://github.com/modulab-project/modulab-modules/releases/download/..."
// → "https://github.com/modulab-project/modulab-modules"
func officialSourceRepo(releaseURL string) string {
	if idx := strings.Index(releaseURL, "/releases/"); idx != -1 {
		return releaseURL[:idx]
	}
	return releaseURL
}

// assetFromURL extracts the filename from the last path segment of a URL.
// "https://github.com/.../releases/download/tag/rezepte.zip" → "rezepte.zip"
func assetFromURL(releaseURL string) string {
	parts := strings.Split(releaseURL, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
