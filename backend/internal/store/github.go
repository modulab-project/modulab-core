package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// officialRegistryURL is the raw GitHub URL for the official registry.json
	// in the modulab-modules monorepo. No API token needed for public repos.
	officialRegistryURL = "https://raw.githubusercontent.com/modulab-project/modulab-modules/main/registry.json"

	// communityRepoRootURL is the GitHub Contents API URL for the root of
	// modulab-community. Per that repo's own README/CONTRIBUTING, one
	// subdirectory per module lives directly at repo root (no "modules/"
	// wrapper directory) - each containing a single manifest.yaml, the same
	// format every module already ships in its own module.zip.
	communityRepoRootURL = "https://api.github.com/repos/modulab-project/modulab-community/contents/"

	// communityManifestRawURLFmt fetches a given module directory's
	// manifest.yaml directly from the main branch, given the directory name.
	communityManifestRawURLFmt = "https://raw.githubusercontent.com/modulab-project/modulab-community/main/%s/manifest.yaml"

	githubAPITimeout = 15 * time.Second
)

// communityExcludedDirs are root-level directories in modulab-community that
// are never real module entries: "example-module" is the CONTRIBUTING.md
// template (its manifest.yaml has placeholder source_repo/release_url
// values), and any dot-prefixed directory (".github" etc.) is repo tooling.
var communityExcludedDirs = map[string]bool{
	"example-module": true,
}

// officialEntry is the shape of one element in the official registry.json.
type officialEntry struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ReleaseURL   string `json:"release_url"`
	SHA256       string `json:"sha256"`
	CosignSigURL string `json:"cosign_sig_url"`
	Category     string `json:"category"`
	// Description is a map of language code → short blurb (same shape as
	// manifest.yaml's display_name, see installer.go's Manifest.Description).
	// Optional - older registry.json entries (released before build-module.sh
	// started writing this field) simply omit it, so this must stay nil
	// rather than fail to parse.
	Description map[string]string `json:"description"`
}

// communityRepoItem is one entry returned by the GitHub Contents API for the
// modulab-community repo root listing. Type is "dir" for module directories
// or "file" for root-level files like README.md.
type communityRepoItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// communityManifest is the subset of a modulab-community module directory's
// manifest.yaml this package needs. It is the same manifest.yaml format every
// module already ships in its own module.zip, plus three fields CONTRIBUTING.md
// requires specifically for the discovery entry: source_repo, manifest_path
// (where manifest.yaml lives within the module's own repo - not used for
// sync itself, only by human reviewers), and release_url.
type communityManifest struct {
	Version     string            `yaml:"version"`
	Category    string            `yaml:"category"`
	SourceRepo  string            `yaml:"source_repo"`
	ReleaseURL  string            `yaml:"release_url"`
	Description map[string]string `yaml:"description"`
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

	// Append a Unix timestamp to bypass raw.githubusercontent.com's CDN cache,
	// which can serve stale content for up to 5 minutes after a file is updated.
	cacheBust := officialRegistryURL + "?_=" + strconv.FormatInt(time.Now().Unix(), 10)
	data, err := httpGet(ctx, cacheBust)
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
			Description:   r.Description,
		})
	}
	return out, nil
}

// FetchCommunityRegistry downloads the modulab-community index: one
// subdirectory per module at the repo root, each containing a manifest.yaml
// (see communityManifest and CONTRIBUTING.md in that repo). Directories that
// cannot be fetched or parsed are logged and skipped, not fatal - one broken
// community submission must not take down the whole sync.
func FetchCommunityRegistry(ctx context.Context) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, githubAPITimeout)
	defer cancel()

	data, err := httpGet(ctx, communityRepoRootURL)
	if err != nil {
		return nil, fmt.Errorf("store: fetch community index: %w", err)
	}

	var items []communityRepoItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("store: parse community index: %w", err)
	}

	var out []Entry
	for _, item := range items {
		if item.Type != "dir" || strings.HasPrefix(item.Name, ".") || communityExcludedDirs[item.Name] {
			continue
		}

		manifestURL := fmt.Sprintf(communityManifestRawURLFmt, item.Name)
		manifestData, err := httpGet(ctx, manifestURL)
		if err != nil {
			// Best-effort: skip unreadable entries, don't abort the whole sync.
			log.Printf("store: community: fetch manifest for %q: %v", item.Name, err)
			continue
		}
		var m communityManifest
		if err := yaml.Unmarshal(manifestData, &m); err != nil {
			log.Printf("store: community: parse manifest for %q: %v", item.Name, err)
			continue
		}
		if m.SourceRepo == "" || m.ReleaseURL == "" {
			log.Printf("store: community: %q missing source_repo or release_url, skipping", item.Name)
			continue // malformed entry
		}
		out = append(out, Entry{
			// The directory name is already the short module name (README:
			// "named after the module's name field with the modulab-mod-
			// prefix removed"), so it's used directly rather than the
			// manifest's own (prefixed) name field.
			Name:          item.Name,
			Source:        "community",
			SourceRepo:    m.SourceRepo,
			ReleaseAsset:  m.ReleaseURL,
			Category:      m.Category,
			LatestVersion: m.Version,
			Description:   m.Description,
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("store: close response body for %s: %v", url, err)
		}
	}()

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
