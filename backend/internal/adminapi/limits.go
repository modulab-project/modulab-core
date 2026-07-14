// AdminLimitsHandler and its supporting types live in this file rather than
// handlers.go because they group a genuinely different concern: every other
// handler in this package edits a single, named subsystem's configuration
// (OIDC, group prefix). This one is a catch-all for cross-cutting
// operational limits — request/upload body size caps, per-IP rate limit
// ceilings, and the Deno worker connection pool size — that used to be
// hardcoded Go constants scattered across several packages, each requiring
// a code change and redeploy to tune.
//
// That became a real problem, not a hypothetical one: modules.saveUploadedFile
// had its own 20 MB upload cap, but Core's separate, unrelated max_body_bytes
// setting (originally added only for AI chat request bodies, default 1 MB,
// exposed only via PATCH /v1/admin/ai/settings) wrapped every request's body
// - including module uploads - *before* the module-specific limit ever got a
// chance to apply. Whichever limit was smaller always won, so every module
// photo upload over ~1 MB failed with a connection-reset 502 that looked
// like a proxy/infra problem (Cloudflare, Nginx Proxy Manager, and Pangolin
// were all suspected and individually tuned first) rather than the actual
// cause: two independently-configured limits nested inside each other with
// no visibility into either from the same place. See maxBodyMiddleware's
// doc comment (cmd/core/main.go) for the fix, and
// modules.MaxUploadBodyBytes's doc comment for the module-upload side.
//
// This handler exists so every limit in that same class - upload caps,
// rate limits, pool sizes - lives behind one endpoint and one admin UI
// page, instead of being rediscovered one incident at a time.
package adminapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/modulab-project/modulab-core/backend/internal/ai"
	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/modules"
	"github.com/modulab-project/modulab-core/backend/internal/news"
	"github.com/modulab-project/modulab-core/backend/internal/search"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"github.com/modulab-project/modulab-core/backend/internal/weather"
)

// The default* constants below intentionally mirror the unexported
// defaultAuthRateLimitMax/defaultAIChatRateLimitMax/defaultGlobalRateLimitMax
// constants in cmd/core/main.go: a Go "main" package cannot be imported by
// any other package, so both the fallback values and the read logic
// (readRateLimitInt below) are declared once more here rather than shared.
// The two places are kept in sync by both reading and writing the exact
// same core_settings keys (named in the GetSetting/SetSetting calls below)
// - if you change a default here, change the matching one in main.go too,
// and vice versa.
const (
	defaultAuthRateLimitMax   = 20
	defaultAIChatRateLimitMax = 30
	defaultGlobalRateLimitMax = 600
)

// LimitsSettings is the shape of GET/PATCH /v1/admin/system/limits.
//
// Configurable settings:
//   - max_body_bytes: request body size cap in bytes applied to every
//     non-upload route (0 = unlimited, default 1 MB). Moved here from
//     PATCH /v1/admin/ai/settings, which never had anything to do with AI
//     specifically - see this file's package doc comment.
//   - max_upload_body_bytes: module file-upload size cap in bytes (spot
//     photos, recipe images, etc. — anything proxied through
//     ModuleProxyHandler's multipart handling). 0 = unlimited, default 20 MB.
//   - max_module_zip_bytes: module install/update ZIP download size cap in
//     bytes. 0 = unlimited, default 100 MB.
//   - max_opml_upload_bytes: admin OPML feed-import upload size cap in
//     bytes. 0 = unlimited, default 2 MB.
//   - auth_rate_limit_max: requests per minute a single IP may make to
//     /v1/auth/login or /v1/auth/callback. Must be > 0, default 20.
//   - ai_chat_ip_rate_limit_max: requests per minute a single IP may make
//     to POST /v1/ai/chat (a coarse backstop on top of the existing
//     per-user chat_rpm_limit on the AI settings page). Must be > 0,
//     default 30.
//   - global_rate_limit_max: requests per minute a single identity (user
//     if authenticated, else IP) may make across every route except
//     /healthz. Must be > 0, default 600.
//   - deno_conn_pool_size: how many concurrent requests Core keeps in
//     flight to a single module's Deno worker (see modules.ConnPoolSize's
//     doc comment for why one slow request used to block every other
//     request to that module). Must be >= 1, default 4. Unlike every other
//     field here, this one only takes effect the next time each module's
//     worker (re)starts — a running worker's connection pool is sized once,
//     at creation.
//   - geo_timeout_ms: how long (in milliseconds) the browser's
//     navigator.geolocation.getCurrentPosition() call is allowed to run
//     before giving up (see weather.GeoTimeoutMS and Home.tsx's geolocation
//     effect). Must be > 0, default 5000. A Wi-Fi-based location fix
//     (enableHighAccuracy: false) can take longer than the default on some
//     corporate networks - this used to be a hardcoded frontend constant.
//   - ai_provider_timeout_seconds: HTTP timeout for fetchModels calls to an
//     admin-configured AI provider's base_url (see ai.ProviderTimeoutSeconds).
//     Must be > 0, default 30. Local/self-hosted model backends (Ollama etc.)
//     can need longer than 30s on modest hardware.
//   - search_timeout_seconds: hard cap for a web-search provider round-trip,
//     shared across every configured provider (see
//     search.SearchTimeoutSeconds). Must be > 0, default 5. A self-hosted
//     SearXNG instance querying several search-engine backends can need
//     longer than a fast hosted API like Serper on modest hardware.
//   - search_fallback_timeout_seconds: how long the primary search provider
//     gets before ModuLab gives up on it and tries the configured fallback
//     provider (see search.FallbackTimeoutSeconds). Must be > 0, default 3.
//     Only relevant when a fallback provider is actually configured
//     (GET/PATCH /v1/admin/search/settings).
//   - news_fetch_timeout_seconds: HTTP timeout per RSS/Atom feed fetch (see
//     news.FetchTimeoutSeconds). Must be > 0, default 10. Slow or flaky
//     feeds otherwise get reported as "unreachable" prematurely.
//   - store_sync_interval_seconds: how often the module registry
//     (official + community) is re-synced from GitHub in the background
//     (see store.SyncIntervalSeconds). Must be > 0, default 3600 (1h).
//   - store_github_api_timeout_seconds: HTTP timeout for GitHub
//     API/raw-content fetches during a registry sync (see
//     store.GithubAPITimeoutSeconds). Must be > 0, default 15.
//   - modules_install_download_timeout_seconds: timeout for downloading a
//     module's ZIP + checksum during install/update (see
//     modules.InstallDownloadTimeoutSeconds). Must be > 0, default 300 (5min).
//     Companion setting to max_module_zip_bytes - a larger ZIP cap can also
//     need a longer download window on a slow connection.
//   - chat_rpm_limit: POST /v1/ai/chat requests per user per minute (see
//     ai.ChatRPMLimit). 0 = unlimited, default 60. Moved here from its own
//     PATCH /v1/admin/ai/settings endpoint (ai.AdminSettingsHandler, now
//     removed) - that handler only ever exposed this one field, and it sat
//     right next to its IP-based sibling, ai_chat_ip_rate_limit_max, on two
//     different admin pages. Unlike every other rate limit/pool/timeout
//     field above, 0 is a valid "unlimited" value here, same as the byte
//     caps - not a config mistake to reject.
//
// Every field except deno_conn_pool_size takes effect immediately, on the
// next request, with no restart required. store_sync_interval_seconds is a
// partial exception: a change takes effect on the *next* sync cycle rather
// than instantly, since the background goroutine is already sleeping until
// then (see store.RunSync's doc comment).
type LimitsSettings struct {
	MaxBodyBytes                      int64 `json:"max_body_bytes"`
	MaxUploadBodyBytes                int64 `json:"max_upload_body_bytes"`
	MaxModuleZIPBytes                 int64 `json:"max_module_zip_bytes"`
	MaxOPMLUploadBytes                int64 `json:"max_opml_upload_bytes"`
	AuthRateLimitMax                  int64 `json:"auth_rate_limit_max"`
	AIChatIPRateLimitMax              int64 `json:"ai_chat_ip_rate_limit_max"`
	GlobalRateLimitMax                int64 `json:"global_rate_limit_max"`
	DenoConnPoolSize                  int   `json:"deno_conn_pool_size"`
	GeoTimeoutMS                      int   `json:"geo_timeout_ms"`
	AIProviderTimeoutSeconds          int   `json:"ai_provider_timeout_seconds"`
	SearchTimeoutSeconds              int   `json:"search_timeout_seconds"`
	SearchFallbackTimeoutSeconds      int   `json:"search_fallback_timeout_seconds"`
	NewsFetchTimeoutSeconds           int   `json:"news_fetch_timeout_seconds"`
	StoreSyncIntervalSeconds          int   `json:"store_sync_interval_seconds"`
	StoreGithubAPITimeoutSeconds      int   `json:"store_github_api_timeout_seconds"`
	ModulesInstallDownloadTimeoutSecs int   `json:"modules_install_download_timeout_seconds"`
	ChatRPMLimit                      int   `json:"chat_rpm_limit"`
}

// readRateLimitInt is a copy of main.go's readRateLimitSetting (see this
// file's doc comment for why it can't just be imported instead). 0 or an
// unparseable value falls back to def — a rate limit of 0 would trip on
// literally the first request of every window, which is never a sensible
// admin intent, so it's treated as "not configured" rather than as a real
// value, same as main.go's version.
func readRateLimitInt(pool *db.Pool, r *http.Request, key string, def int64) int64 {
	val, ok, err := pool.GetSetting(r.Context(), key)
	if err != nil || !ok || val == "" {
		return def
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// currentLimitsSettings resolves every field in LimitsSettings from
// core_settings, via each owning package's exported reader (ai.MaxBodyBytes,
// modules.MaxUploadBodyBytes, etc.) so this handler and the middleware/
// handlers that actually enforce these limits can never disagree about
// what "current" means.
func currentLimitsSettings(r *http.Request, pool *db.Pool) LimitsSettings {
	ctx := r.Context()
	return LimitsSettings{
		MaxBodyBytes:         ai.MaxBodyBytes(ctx, pool),
		MaxUploadBodyBytes:   modules.MaxUploadBodyBytes(ctx, pool),
		MaxModuleZIPBytes:    modules.MaxModuleZIPBytes(ctx, pool),
		MaxOPMLUploadBytes:   news.MaxOPMLUploadBytes(ctx, pool),
		AuthRateLimitMax:     readRateLimitInt(pool, r, "auth_rate_limit_max", defaultAuthRateLimitMax),
		AIChatIPRateLimitMax: readRateLimitInt(pool, r, "ai_chat_ip_rate_limit_max", defaultAIChatRateLimitMax),
		GlobalRateLimitMax:   readRateLimitInt(pool, r, "global_rate_limit_max", defaultGlobalRateLimitMax),
		DenoConnPoolSize:     modules.ConnPoolSize(ctx, pool),
		GeoTimeoutMS:         weather.GeoTimeoutMS(ctx, pool),

		AIProviderTimeoutSeconds:          ai.ProviderTimeoutSeconds(ctx, pool),
		SearchTimeoutSeconds:              search.SearchTimeoutSeconds(ctx, pool),
		SearchFallbackTimeoutSeconds:      search.FallbackTimeoutSeconds(ctx, pool),
		NewsFetchTimeoutSeconds:           news.FetchTimeoutSeconds(ctx, pool),
		StoreSyncIntervalSeconds:          store.SyncIntervalSeconds(ctx, pool),
		StoreGithubAPITimeoutSeconds:      store.GithubAPITimeoutSeconds(ctx, pool),
		ModulesInstallDownloadTimeoutSecs: modules.InstallDownloadTimeoutSeconds(ctx, pool),
		ChatRPMLimit:                      ai.ChatRPMLimit(ctx, pool),
	}
}

// AdminLimitsHandler handles GET and PATCH /v1/admin/system/limits.
// Auth is enforced by the superAdminOnly middleware in main.go, same as
// every other handler in this package.
func AdminLimitsHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, currentLimitsSettings(r, pool))

		case http.MethodPatch:
			var body LimitsSettings
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}

			// Byte-size caps and chat_rpm_limit: 0 means unlimited, negative
			// is invalid. chat_rpm_limit isn't a byte size, but shares the
			// same "0 = unlimited" semantics (see this file's doc comment),
			// unlike every rate limit/pool/timeout in the loop below.
			for _, f := range []struct {
				name string
				val  int64
			}{
				{"max_body_bytes", body.MaxBodyBytes},
				{"max_upload_body_bytes", body.MaxUploadBodyBytes},
				{"max_module_zip_bytes", body.MaxModuleZIPBytes},
				{"max_opml_upload_bytes", body.MaxOPMLUploadBytes},
				{"chat_rpm_limit", int64(body.ChatRPMLimit)},
			} {
				if f.val < 0 {
					http.Error(w, f.name+" must be >= 0 (0 = unlimited)", http.StatusBadRequest)
					return
				}
			}
			// Rate limits and pool size: unlike the byte caps above, 0
			// isn't a meaningful "unlimited" here (a rate limit of 0 would
			// trip on every single request; a pool of 0 would make every
			// module request block forever) - require a real positive value.
			for _, f := range []struct {
				name string
				val  int64
			}{
				{"auth_rate_limit_max", body.AuthRateLimitMax},
				{"ai_chat_ip_rate_limit_max", body.AIChatIPRateLimitMax},
				{"global_rate_limit_max", body.GlobalRateLimitMax},
				{"deno_conn_pool_size", int64(body.DenoConnPoolSize)},
				{"geo_timeout_ms", int64(body.GeoTimeoutMS)},
				{"ai_provider_timeout_seconds", int64(body.AIProviderTimeoutSeconds)},
				{"search_timeout_seconds", int64(body.SearchTimeoutSeconds)},
				{"search_fallback_timeout_seconds", int64(body.SearchFallbackTimeoutSeconds)},
				{"news_fetch_timeout_seconds", int64(body.NewsFetchTimeoutSeconds)},
				{"store_sync_interval_seconds", int64(body.StoreSyncIntervalSeconds)},
				{"store_github_api_timeout_seconds", int64(body.StoreGithubAPITimeoutSeconds)},
				{"modules_install_download_timeout_seconds", int64(body.ModulesInstallDownloadTimeoutSecs)},
			} {
				if f.val <= 0 {
					http.Error(w, f.name+" must be > 0", http.StatusBadRequest)
					return
				}
			}

			settings := map[string]string{
				"max_body_bytes":                           strconv.FormatInt(body.MaxBodyBytes, 10),
				"max_upload_body_bytes":                    strconv.FormatInt(body.MaxUploadBodyBytes, 10),
				"max_module_zip_bytes":                     strconv.FormatInt(body.MaxModuleZIPBytes, 10),
				"max_opml_upload_bytes":                    strconv.FormatInt(body.MaxOPMLUploadBytes, 10),
				"auth_rate_limit_max":                      strconv.FormatInt(body.AuthRateLimitMax, 10),
				"ai_chat_ip_rate_limit_max":                strconv.FormatInt(body.AIChatIPRateLimitMax, 10),
				"global_rate_limit_max":                    strconv.FormatInt(body.GlobalRateLimitMax, 10),
				"deno_conn_pool_size":                      strconv.Itoa(body.DenoConnPoolSize),
				"geo_timeout_ms":                           strconv.Itoa(body.GeoTimeoutMS),
				"ai_provider_timeout_seconds":              strconv.Itoa(body.AIProviderTimeoutSeconds),
				"search_timeout_seconds":                   strconv.Itoa(body.SearchTimeoutSeconds),
				"search_fallback_timeout_seconds":          strconv.Itoa(body.SearchFallbackTimeoutSeconds),
				"news_fetch_timeout_seconds":               strconv.Itoa(body.NewsFetchTimeoutSeconds),
				"store_sync_interval_seconds":              strconv.Itoa(body.StoreSyncIntervalSeconds),
				"store_github_api_timeout_seconds":         strconv.Itoa(body.StoreGithubAPITimeoutSeconds),
				"modules_install_download_timeout_seconds": strconv.Itoa(body.ModulesInstallDownloadTimeoutSecs),
				"ai_chat_rpm_limit":                        strconv.Itoa(body.ChatRPMLimit),
			}
			for key, val := range settings {
				if err := pool.SetSetting(ctx, key, val); err != nil {
					http.Error(w, "database error", http.StatusInternalServerError)
					return
				}
			}

			// Best-effort audit; a failed write must not block the response.
			// Every value here is DoS/availability-relevant (that's the
			// entire reason this endpoint exists), same reasoning as
			// max_body_bytes's own audit entry had before it moved here.
			sess, _ := auth.SessionFromContext(ctx)
			if masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv); err == nil {
				detailsJSON, _ := json.Marshal(body)
				if err := audit.Log(ctx, pool, masterKey, audit.LogParams{
					EventType:  audit.EventConfigSystemLimits,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					Details:    string(detailsJSON),
				}); err != nil {
					log.Printf("adminapi: audit limits update: %v", err)
				}
			}

			writeJSON(w, http.StatusOK, body)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
