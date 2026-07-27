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

	"github.com/modulab-project/modulab-core/backend/internal/db"
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

	// communityFileRawURLFmt builds a raw URL for an arbitrary file inside a
	// module directory, given the directory name and the file's relative
	// path (e.g. manifest.yaml's own "logo" field). %[1]s = directory, %[2]s = path.
	communityFileRawURLFmt = "https://raw.githubusercontent.com/modulab-project/modulab-community/main/%[1]s/%[2]s"

	// defaultGithubAPITimeoutSeconds is GithubAPITimeoutSeconds's fallback -
	// mirrors the fixed 15s value this replaced.
	defaultGithubAPITimeoutSeconds = 15
)

// SettingKeyGithubAPITimeoutSeconds names the core_settings key
// GithubAPITimeoutSeconds below reads. Exported so adminapi.
// AdminLimitsHandler's PATCH handler writes through this instead of a
// second, independently-hardcoded string literal - found 2026-07-27 as the
// same "two copies, one of which can drift" pattern as the
// __Host-modulab_session cookie-name bug.
const SettingKeyGithubAPITimeoutSeconds = "store_github_api_timeout_seconds"

// GithubAPITimeoutSeconds reads the GitHub API/raw-content fetch timeout
// (seconds) from core_settings ("store_github_api_timeout_seconds"), same
// pattern as modules.MaxUploadBodyBytes. Defaults to
// defaultGithubAPITimeoutSeconds if unset.
func GithubAPITimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, SettingKeyGithubAPITimeoutSeconds)
	if err != nil || !ok || val == "" {
		return defaultGithubAPITimeoutSeconds
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultGithubAPITimeoutSeconds
	}
	return n
}

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
	// DisplayName is a map of language code → human-readable module name
	// (same shape/source as manifest.yaml's own display_name field - see
	// installer.go's Manifest.DisplayName). Falls back to Name in the
	// frontend when absent.
	DisplayName map[string]string `json:"display_name"`
	// LogoURL is a full, already-absolute URL - build-module.sh computes it
	// at release time from manifest.yaml's "logo" field (a filename), since
	// Core never fetches an official module's manifest.yaml directly. Empty
	// when the module ships no logo; the frontend falls back to the ModuLab
	// mark in that case.
	LogoURL string `json:"logo_url"`
	// BrowseURL points at the module's own subdirectory in the modulab-modules
	// monorepo (e.g. ".../tree/main/my-place"), computed by build-module.sh
	// from the actual release directory name. Needed because Name and the
	// on-disk directory can differ (e.g. entry name "my-places" vs directory
	// "my-place") - SourceRepo alone would only link to the repo root.
	BrowseURL string `json:"browse_url"`
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
	DisplayName map[string]string `yaml:"display_name"`
	// Logo is a filename relative to the module's directory in
	// modulab-community (e.g. "logo.png"), resolved to an absolute raw URL
	// below via communityFileRawURLFmt.
	Logo string `yaml:"logo"`
}

// githubRelease is the subset of fields the GitHub Releases API returns that
// we care about when checking for the latest version of a community module.
type githubRelease struct {
	TagName string `json:"tag_name"` // e.g. "unifi-radius-v1.2.0"
}

// FetchOfficialRegistry downloads and parses the official registry.json.
// Returns an empty slice (not an error) when the file exists but is empty,
// so a not-yet-populated monorepo doesn't prevent Core from starting.
func FetchOfficialRegistry(ctx context.Context, pool *db.Pool) ([]Entry, error) {
	timeout := time.Duration(GithubAPITimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Append a Unix timestamp to bypass raw.githubusercontent.com's CDN cache,
	// which can serve stale content for up to 5 minutes after a file is updated.
	cacheBust := officialRegistryURL + "?_=" + strconv.FormatInt(time.Now().Unix(), 10)
	data, err := httpGet(ctx, cacheBust, "")
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
			DisplayName:   r.DisplayName,
			LogoURL:       r.LogoURL,
			BrowseURL:     r.BrowseURL,
		})
	}
	return out, nil
}

// FetchCommunityRegistry downloads the modulab-community index: one
// subdirectory per module at the repo root, each containing a manifest.yaml
// (see communityManifest and CONTRIBUTING.md in that repo). Directories that
// cannot be fetched or parsed are logged and skipped, not fatal - one broken
// community submission must not take down the whole sync.
func FetchCommunityRegistry(ctx context.Context, pool *db.Pool) ([]Entry, error) {
	timeout := time.Duration(GithubAPITimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	data, err := httpGet(ctx, communityRepoRootURL, "")
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
		manifestData, err := httpGet(ctx, manifestURL, "")
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
		logoURL := ""
		if m.Logo != "" {
			logoURL = fmt.Sprintf(communityFileRawURLFmt, item.Name, m.Logo)
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
			DisplayName:   m.DisplayName,
			LogoURL:       logoURL,
			// No BrowseURL: community modules live at the root of their own
			// dedicated repo (SourceRepo), not a monorepo subdirectory, so
			// SourceRepo itself is already the correct "view on GitHub" link.
		})
	}
	return out, nil
}

// customModuleReleaseAsset is the fixed asset filename every custom-source
// module's GitHub Release must attach, mirroring the "bare filename,
// reconstructed from source_repo + tag" convention installer.go's Install/
// Update already support (previously unused in practice - official and
// community entries both happen to carry a full ReleaseAsset URL instead).
// Documented convention for custom-source module authors: tag the release
// with the version (e.g. "v1.2.0") and attach module.zip (+ optionally
// module.zip.sha256 and module.zip.sig, same as every other module).
const customModuleReleaseAsset = "module.zip"

// customManifestBranches are the branch names tried, in order, when fetching
// a custom source repo's manifest.yaml - unlike modulab-community (a fixed,
// known-main-branch monorepo), an arbitrary third-party repo may default to
// either.
var customManifestBranches = []string{"main", "master"}

// customContentsRootURLFmt is the GitHub Contents API URL for a repo's root
// listing (%s = "owner/repo") - used to detect a monorepo layout (see
// fetchCustomMonorepo) the same way FetchCommunityRegistry lists
// modulab-community's own root.
const customContentsRootURLFmt = "https://api.github.com/repos/%s/contents/"

// customManifest is the subset of a custom source repo's own manifest.yaml
// (the same file the module ships inside its own module.zip - see
// modules.Manifest) this package needs for the store listing. Unlike
// communityManifest, it carries the module's own Name (a custom source has
// no curated index to take it from) and none of the community-only indexing
// fields (source_repo/release_url) - a custom source's release is located
// purely by convention (source_repo + tag + customModuleReleaseAsset).
type customManifest struct {
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Category    string            `yaml:"category"`
	Description map[string]string `yaml:"description"`
	DisplayName map[string]string `yaml:"display_name"`
	Logo        string            `yaml:"logo"`
}

// FetchCustomRepo fetches a single admin-added custom module source and
// returns every module it contains. Two layouts are supported, tried in
// order:
//
//  1. Single module: manifest.yaml directly at the repo root (trying main,
//     then master). The whole repo is one module, releases are tagged
//     however the author likes, and FetchLatestRelease's normal
//     .../releases/latest call resolves the version - unchanged from the
//     original single-module-only behavior.
//  2. Monorepo: no manifest.yaml at the root, so the repo root is listed via
//     the GitHub Contents API and every subdirectory containing its own
//     manifest.yaml becomes a separate Entry - same layout modulab-community
//     itself uses (see FetchCommunityRegistry). Because all modules in this
//     case share one release list, each module's releases must be tagged
//     "<subdirectory>-v..." to disambiguate (mirrors the official
//     modulab-modules monorepo's own "recipes-v0.1.0" convention - see
//     installer.go's zipURL comment) - resolved by
//     FetchLatestReleaseForPrefix instead of the plain "latest release" call.
//
// pubKeyPEM is passed through unchanged onto every resulting Entry's
// CosignPubKey - it comes from custom_sources.pubkey (admin-entered at
// add-time, see db.CreateCustomSource), never fetched from the repo itself,
// and applies to every module in the repo alike (one key per source, not
// per module). token is an optional GitHub PAT for a private repo (see
// db.CustomSourceRow.Token) - pass "" for a public one; NOT put onto the
// returned Entries (module_registry, which Entry maps to, is never expected
// to hold credentials - see its "no PII, no credentials" table comment in
// db.go). Install/Update re-resolve the token fresh from custom_sources via
// db.Pool.GetCustomSourceByRepoURL instead of reading it off the Entry.
//
// Returns an error only when neither layout produced anything installable -
// callers (store.syncAll) log and skip the whole source on error rather than
// aborting the sync, same as FetchCommunityRegistry's per-directory errors;
// a single bad subdirectory within an otherwise-valid monorepo is instead
// just skipped (see fetchCustomMonorepo).
func FetchCustomRepo(ctx context.Context, pool *db.Pool, repoURL, pubKeyPEM, token string) ([]Entry, error) {
	timeout := time.Duration(GithubAPITimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	repoPath := strings.TrimSuffix(strings.TrimPrefix(repoURL, "https://github.com/"), "/")
	if repoPath == "" || strings.Contains(repoPath, "://") {
		return nil, fmt.Errorf("store: custom source: invalid repo url %q", repoURL)
	}

	// ── 1. Single module: manifest.yaml at the repo root ──────────────────
	m, rootErr := fetchCustomManifestAt(ctx, repoPath, "", token)
	if rootErr == nil {
		version, verr := FetchLatestRelease(ctx, pool, repoURL, token)
		if verr != nil {
			return nil, fmt.Errorf("store: custom source: latest release for %q: %w", repoURL, verr)
		}
		return []Entry{buildCustomEntry(m, repoURL, customModuleReleaseAsset, version, pubKeyPEM)}, nil
	}

	// ── 2. Monorepo: no root manifest.yaml, scan subdirectories ───────────
	entries, scanErr := fetchCustomMonorepo(ctx, pool, repoURL, repoPath, pubKeyPEM, token)
	if scanErr != nil {
		return nil, fmt.Errorf("store: custom source: no manifest.yaml at repo root (%v) and monorepo scan failed for %q: %w", rootErr, repoURL, scanErr)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("store: custom source: no manifest.yaml found at repo root or in any subdirectory for %q (root: %v)", repoURL, rootErr)
	}
	return entries, nil
}

// fetchCustomManifestAt fetches and parses manifest.yaml at subPath within
// repoPath ("owner/repo"), trying every branch in customManifestBranches.
// subPath "" means the repo root (single-module layout); a subdirectory name
// means the monorepo layout (see FetchCustomRepo). Resolves Logo to an
// absolute raw.githubusercontent.com URL on the branch that worked. Returns
// an error if no branch has the file, or if it parses but is missing
// name/version - both are treated identically by callers (skip this
// path/module, don't abort the whole source).
func fetchCustomManifestAt(ctx context.Context, repoPath, subPath, token string) (customManifest, error) {
	manifestRelPath := "manifest.yaml"
	if subPath != "" {
		manifestRelPath = subPath + "/manifest.yaml"
	}

	var m customManifest
	var fetchErr error
	for _, branch := range customManifestBranches {
		manifestURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repoPath, branch, manifestRelPath)
		data, err := httpGet(ctx, manifestURL, token)
		if err != nil {
			fetchErr = err
			continue
		}
		if err := yaml.Unmarshal(data, &m); err != nil {
			return customManifest{}, fmt.Errorf("parse %q: %w", manifestRelPath, err)
		}
		if m.Name == "" || m.Version == "" {
			return customManifest{}, fmt.Errorf("%q missing name or version", manifestRelPath)
		}
		if m.Logo != "" {
			logoRelPath := m.Logo
			if subPath != "" {
				logoRelPath = subPath + "/" + m.Logo
			}
			m.Logo = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repoPath, branch, logoRelPath)
		}
		return m, nil
	}
	return customManifest{}, fmt.Errorf("fetch %q: %w", manifestRelPath, fetchErr)
}

// fetchCustomRegistryJSON tries to fetch and parse a registry.json at the
// root of a custom source repo, trying every branch in
// customManifestBranches. Same on-the-wire shape as the official registry.json
// (officialEntry) - reused as-is rather than duplicated, since a
// build-module.sh-style release script for a private monorepo can write
// exactly this shape with no extra work.
//
// Returns (nil, nil) - not an error - when no branch has the file, or it
// parses as an empty array: both mean "this custom source doesn't maintain
// its own registry.json", the normal case for a source added before this
// existed, or one that only ever holds a single module and never bothered.
// Callers fall back to the module.zip-by-convention scan in that case.
func fetchCustomRegistryJSON(ctx context.Context, repoPath, token string) ([]officialEntry, error) {
	var lastErr error
	for _, branch := range customManifestBranches {
		url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/registry.json", repoPath, branch)
		data, err := httpGet(ctx, url, token)
		if err != nil {
			lastErr = err
			continue
		}
		var raw []officialEntry
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse registry.json on branch %q: %w", branch, err)
		}
		return raw, nil
	}
	if lastErr != nil {
		// Every branch 404ed (or similar) - not a real error, just "no
		// registry.json here". A genuine transport/auth failure would look
		// identical over this API, but the manifest-scan fallback below
		// re-hits the same repo/token immediately after and will surface a
		// clearer error itself if something's actually wrong (bad token,
		// repo doesn't exist, etc.) rather than this function guessing.
		return nil, nil
	}
	return nil, nil
}

// fetchCustomMonorepo lists repoPath's root via the GitHub Contents API and
// treats every subdirectory with its own manifest.yaml as a separate module,
// same layout modulab-community itself uses (FetchCommunityRegistry). A
// subdirectory without a valid manifest.yaml is silently skipped - it might
// just be docs/, .github/, a shared lib, or similar, not every directory in
// a repo is a module. Each module's version comes from
// FetchLatestReleaseForPrefix, not FetchLatestRelease, since all modules in
// a monorepo share one release list - see FetchCustomRepo's doc comment for
// the "<subdirectory>-v..." tag convention this requires.
//
// Before any of that: tries fetchCustomRegistryJSON first. A repo that
// maintains its own registry.json (a build-module.sh-style release script
// can write one) gets its Entries built directly from
// it - explicit release_url/cosign_sig_url per module, exactly like official/
// community sources - instead of Core guessing a fixed "module.zip" asset
// name per release. This was a real gap found 2026-07-18: a private monorepo
// with several modules had no way to give each release its own readable,
// versioned asset filename, only the single hardcoded "module.zip" - fine
// for a single-module custom source, awkward for a monorepo of several. The
// module.zip-by-convention scan remains the fallback for sources without a
// registry.json, so existing custom sources keep working unchanged.
func fetchCustomMonorepo(ctx context.Context, pool *db.Pool, repoURL, repoPath, pubKeyPEM, token string) ([]Entry, error) {
	if raw, err := fetchCustomRegistryJSON(ctx, repoPath, token); err != nil {
		log.Printf("store: custom source: %q: registry.json found but failed to parse, falling back to module.zip convention: %v", repoURL, err)
	} else if len(raw) > 0 {
		out := make([]Entry, 0, len(raw))
		for _, r := range raw {
			out = append(out, Entry{
				Name:          r.Name,
				Source:        "custom",
				SourceRepo:    officialSourceRepo(r.ReleaseURL),
				ReleaseAsset:  r.ReleaseURL,
				CosignSigURL:  r.CosignSigURL,
				CosignPubKey:  pubKeyPEM,
				Category:      r.Category,
				LatestVersion: r.Version,
				Description:   r.Description,
				DisplayName:   r.DisplayName,
				LogoURL:       r.LogoURL,
				BrowseURL:     r.BrowseURL,
			})
		}
		return out, nil
	}

	rootURL := fmt.Sprintf(customContentsRootURLFmt, repoPath)
	data, err := httpGet(ctx, rootURL, token)
	if err != nil {
		return nil, fmt.Errorf("list repo root: %w", err)
	}
	var items []communityRepoItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse repo root listing: %w", err)
	}

	var out []Entry
	for _, item := range items {
		if item.Type != "dir" || strings.HasPrefix(item.Name, ".") {
			continue
		}
		m, err := fetchCustomManifestAt(ctx, repoPath, item.Name, token)
		if err != nil {
			// Not a module directory - skip silently, see doc comment above.
			continue
		}
		version, err := FetchLatestReleaseForPrefix(ctx, pool, repoURL, item.Name, token)
		if err != nil {
			log.Printf("store: custom source: %q: latest release for %q: %v", repoURL, item.Name, err)
			continue
		}
		out = append(out, buildCustomEntry(m, repoURL, customModuleReleaseAsset, version, pubKeyPEM))
	}
	return out, nil
}

// buildCustomEntry assembles a store.Entry for a custom-source module from
// its parsed manifest.yaml, shared by both the single-module and monorepo
// paths in FetchCustomRepo.
func buildCustomEntry(m customManifest, repoURL, releaseAsset, version, pubKeyPEM string) Entry {
	return Entry{
		Name:          m.Name,
		Source:        "custom",
		SourceRepo:    repoURL,
		ReleaseAsset:  releaseAsset,
		Category:      m.Category,
		LatestVersion: version,
		Description:   m.Description,
		DisplayName:   m.DisplayName,
		LogoURL:       m.Logo,
		CosignPubKey:  pubKeyPEM,
	}
}

// FetchLatestRelease calls the GitHub Releases API for sourceRepo and returns
// the tag name of the latest release, or ("", nil) when the repo has no
// releases yet. Used by the daily update-check for community modules and by
// FetchCustomRepo for custom sources. token is an optional GitHub PAT
// (fine-grained or classic) for a private repo - pass "" for a public one
// (official/community, or a custom source added without a token).
func FetchLatestRelease(ctx context.Context, pool *db.Pool, sourceRepo, token string) (string, error) {
	timeout := time.Duration(GithubAPITimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert https://github.com/owner/repo → owner/repo for the API path.
	repoPath := strings.TrimPrefix(sourceRepo, "https://github.com/")
	repoPath = strings.TrimSuffix(repoPath, "/")
	if repoPath == "" {
		return "", fmt.Errorf("store: invalid source_repo %q", sourceRepo)
	}

	url := "https://api.github.com/repos/" + repoPath + "/releases/latest"
	data, err := httpGet(ctx, url, token)
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

// FetchLatestReleaseForPrefix calls the GitHub Releases *list* API (not
// /releases/latest) and returns the newest release whose tag starts with
// "<prefix>-", or ("", nil) if none match. Used for a custom monorepo (see
// FetchCustomRepo/fetchCustomMonorepo) where multiple modules share one
// release list and disambiguate by tagging their releases
// "<module-subdirectory>-v1.2.0" - the same convention the official
// modulab-modules monorepo already uses for its own releases (e.g.
// "recipes-v0.1.0", see installer.go's zipURL comment). Only the first page
// (GitHub's default: 30 releases, newest first) is considered - more than
// that between two syncs of the same monorepo is not a case worth paginating
// for at this project's scale.
func FetchLatestReleaseForPrefix(ctx context.Context, pool *db.Pool, sourceRepo, prefix, token string) (string, error) {
	timeout := time.Duration(GithubAPITimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	repoPath := strings.TrimPrefix(sourceRepo, "https://github.com/")
	repoPath = strings.TrimSuffix(repoPath, "/")
	if repoPath == "" {
		return "", fmt.Errorf("store: invalid source_repo %q", sourceRepo)
	}

	url := "https://api.github.com/repos/" + repoPath + "/releases"
	data, err := httpGet(ctx, url, token)
	if err != nil {
		// No releases at all, or repo/API unreachable - not an error, just
		// nothing installable for this module yet.
		return "", nil
	}

	var rels []githubRelease
	if err := json.Unmarshal(data, &rels); err != nil {
		return "", fmt.Errorf("store: parse releases for %q: %w", sourceRepo, err)
	}

	want := prefix + "-"
	for _, r := range rels {
		if strings.HasPrefix(r.TagName, want) {
			return r.TagName, nil
		}
	}
	return "", nil
}

// httpGet performs a GET request and returns the body. Returns an error for
// any non-2xx status. Uses the standard http.DefaultClient with the provided
// context for timeout control. token is an optional GitHub PAT - when
// non-empty, sent as an Authorization header so private repos (custom
// sources only - official/community are always public) resolve instead of
// 404ing. GitHub accepts this same header on both api.github.com and
// raw.githubusercontent.com.
func httpGet(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Identify ourselves so GitHub doesn't rate-limit us as a generic client.
	req.Header.Set("User-Agent", "modulab-core/1 (https://github.com/modulab-project/modulab-core)")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

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
