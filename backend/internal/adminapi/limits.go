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
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/modulab-project/modulab-core/backend/internal/ai"
	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/coreupdate"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/modules"
	"github.com/modulab-project/modulab-core/backend/internal/news"
	"github.com/modulab-project/modulab-core/backend/internal/search"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"github.com/modulab-project/modulab-core/backend/internal/weather"
)

// DefaultAuthRateLimitMax/DefaultAIChatRateLimitMax/DefaultGlobalRateLimitMax
// are the fallbacks used when the matching core_settings key has never been
// set - see AuthRateLimitMax/AIChatIPRateLimitMax/GlobalRateLimitMax below.
// Exported (2026-07-27, alongside SettingKeyAuthRateLimitMax etc.) so
// cmd/core/main.go's authRateLimitMax/aiChatRateLimitMax/globalRateLimitMax
// - the actual rate-limit-middleware maxFn callbacks, which this package
// cannot itself provide since main wires up rateLimitMiddleware - can
// delegate to AuthRateLimitMax/AIChatIPRateLimitMax/GlobalRateLimitMax below
// instead of each keeping its own copy of the default and the
// "auth_rate_limit_max"/etc. key string. Before this export, those were two
// independently-hardcoded copies kept in sync only by a doc-comment
// admonition ("if you change a default here, change the matching one in
// main.go too") - the same drift risk as the __Host-modulab_session cookie
// name bug, just not yet actually triggered.
const (
	DefaultAuthRateLimitMax   = 20
	DefaultAIChatRateLimitMax = 30
	DefaultGlobalRateLimitMax = 600
)

// SettingKeyAuthRateLimitMax/SettingKeyAIChatIPRateLimitMax/
// SettingKeyGlobalRateLimitMax name the core_settings keys AuthRateLimitMax/
// AIChatIPRateLimitMax/GlobalRateLimitMax below read, and are also what this
// file's own PATCH validation/write logic keys off of - one definition each,
// not a literal repeated at every call site.
const (
	SettingKeyAuthRateLimitMax     = "auth_rate_limit_max"
	SettingKeyAIChatIPRateLimitMax = "ai_chat_ip_rate_limit_max"
	SettingKeyGlobalRateLimitMax   = "global_rate_limit_max"
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
//   - core_update_check_weekdays: comma-separated time.Weekday integers
//     (0=Sunday..6=Saturday) naming which days of the week
//     coreupdate.RunScheduler checks GitHub for a newer modulab-core
//     release. Must parse via coreupdate.ParseWeekdays (at least one valid
//     0-6 entry). Default "0,1,2,3,4,5,6" (every day).
//   - core_update_check_time: "HH:MM" (24h) time of day the check above
//     runs, on each selected weekday. Must parse via coreupdate.ParseTime.
//     Default "03:00".
//   - system_timezone: read-only here (added 2026-08-12) - the IANA zone
//     name core_update_check_time above is actually evaluated against (see
//     coreupdate.RunScheduler and setup.SystemTimezoneLocation). Surfaced
//     on GET so this page can show "03:00 (Europe/Berlin)" next to the
//     field without a second request to admin/system/general, but it is
//     NOT settable through PATCH /v1/admin/system/limits - it belongs to
//     admin/system/general (AdminGeneralHandler), the same page GeoIP's own
//     check-time field defers to for the identical reason.
//
// Every field except deno_conn_pool_size takes effect immediately, on the
// next request, with no restart required. store_sync_interval_seconds is a
// partial exception: a change takes effect on the *next* sync cycle rather
// than instantly, since the background goroutine is already sleeping until
// then (see store.RunSync's doc comment). core_update_check_weekdays/_time
// share that same "next tick" semantics with coreupdate.RunScheduler's
// minute-granularity ticker.
type LimitsSettings struct {
	MaxBodyBytes                      int64  `json:"max_body_bytes"`
	MaxUploadBodyBytes                int64  `json:"max_upload_body_bytes"`
	MaxModuleZIPBytes                 int64  `json:"max_module_zip_bytes"`
	MaxOPMLUploadBytes                int64  `json:"max_opml_upload_bytes"`
	AuthRateLimitMax                  int64  `json:"auth_rate_limit_max"`
	AIChatIPRateLimitMax              int64  `json:"ai_chat_ip_rate_limit_max"`
	GlobalRateLimitMax                int64  `json:"global_rate_limit_max"`
	DenoConnPoolSize                  int    `json:"deno_conn_pool_size"`
	GeoTimeoutMS                      int    `json:"geo_timeout_ms"`
	AIProviderTimeoutSeconds          int    `json:"ai_provider_timeout_seconds"`
	SearchTimeoutSeconds              int    `json:"search_timeout_seconds"`
	SearchFallbackTimeoutSeconds      int    `json:"search_fallback_timeout_seconds"`
	NewsFetchTimeoutSeconds           int    `json:"news_fetch_timeout_seconds"`
	StoreSyncIntervalSeconds          int    `json:"store_sync_interval_seconds"`
	StoreGithubAPITimeoutSeconds      int    `json:"store_github_api_timeout_seconds"`
	ModulesInstallDownloadTimeoutSecs int    `json:"modules_install_download_timeout_seconds"`
	ChatRPMLimit                      int    `json:"chat_rpm_limit"`
	CoreUpdateCheckWeekdays           string `json:"core_update_check_weekdays"`
	CoreUpdateCheckTime               string `json:"core_update_check_time"`
	// SystemTimezone is read-only - see this struct's doc comment above.
	SystemTimezone string `json:"system_timezone"`
}

// readRateLimitInt is the shared GetSetting/parse/fallback logic behind
// AuthRateLimitMax/AIChatIPRateLimitMax/GlobalRateLimitMax below. 0 or an
// unparseable value falls back to def — a rate limit of 0 would trip on
// literally the first request of every window, which is never a sensible
// admin intent, so it's treated as "not configured" rather than as a real
// value.
func readRateLimitInt(ctx context.Context, pool *db.Pool, key string, def int64) int64 {
	val, ok, err := pool.GetSetting(ctx, key)
	if err != nil || !ok || val == "" {
		return def
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// AuthRateLimitMax reads the configured auth-endpoint (login/callback/
// logout) rate limit ceiling from core_settings. Exported so
// cmd/core/main.go's authRateLimitMax can delegate here instead of keeping
// its own copy of SettingKeyAuthRateLimitMax/DefaultAuthRateLimitMax.
func AuthRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return readRateLimitInt(ctx, pool, SettingKeyAuthRateLimitMax, DefaultAuthRateLimitMax)
}

// AIChatIPRateLimitMax reads the configured AI-chat per-IP rate limit
// ceiling from core_settings. Exported so cmd/core/main.go's
// aiChatRateLimitMax can delegate here instead of keeping its own copy of
// SettingKeyAIChatIPRateLimitMax/DefaultAIChatRateLimitMax.
func AIChatIPRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return readRateLimitInt(ctx, pool, SettingKeyAIChatIPRateLimitMax, DefaultAIChatRateLimitMax)
}

// GlobalRateLimitMax reads the configured global (all-routes-except-
// /healthz) rate limit ceiling from core_settings. Exported so
// cmd/core/main.go's globalRateLimitMax can delegate here instead of
// keeping its own copy of SettingKeyGlobalRateLimitMax/
// DefaultGlobalRateLimitMax.
func GlobalRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return readRateLimitInt(ctx, pool, SettingKeyGlobalRateLimitMax, DefaultGlobalRateLimitMax)
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
		AuthRateLimitMax:     AuthRateLimitMax(ctx, pool),
		AIChatIPRateLimitMax: AIChatIPRateLimitMax(ctx, pool),
		GlobalRateLimitMax:   GlobalRateLimitMax(ctx, pool),
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
		CoreUpdateCheckWeekdays:           coreupdate.CheckWeekdaysRaw(ctx, pool),
		CoreUpdateCheckTime:               coreupdate.CheckTimeRaw(ctx, pool),
		SystemTimezone:                    setup.SystemTimezoneRaw(ctx, pool),
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
			httperr.JSON(w, http.StatusOK, currentLimitsSettings(r, pool))

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
			// core_update_check_weekdays/_time: string-shaped, validated via
			// their own parsers rather than the numeric loops above -
			// coreupdate owns the actual format (see its doc comments), this
			// handler just rejects anything it can't parse rather than
			// storing a value the scheduler would silently fall back away
			// from later.
			if _, err := coreupdate.ParseWeekdays(body.CoreUpdateCheckWeekdays); err != nil {
				http.Error(w, "core_update_check_weekdays: "+err.Error(), http.StatusBadRequest)
				return
			}
			if _, _, err := coreupdate.ParseTime(body.CoreUpdateCheckTime); err != nil {
				http.Error(w, "core_update_check_time: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Every key below is the owning package's exported
			// SettingKey* constant, not a literal - see this file's
			// doc comment history (2026-07-27): these used to be
			// hardcoded a second time here, independently of the
			// identical literal inside each package's own reader
			// (ai.MaxBodyBytes, modules.ConnPoolSize, etc.), the same
			// "two copies, one of which can drift" shape as the
			// __Host-modulab_session cookie-name bug.
			settings := map[string]string{
				ai.SettingKeyMaxBodyBytes:                       strconv.FormatInt(body.MaxBodyBytes, 10),
				modules.SettingKeyMaxUploadBodyBytes:            strconv.FormatInt(body.MaxUploadBodyBytes, 10),
				modules.SettingKeyMaxModuleZIPBytes:             strconv.FormatInt(body.MaxModuleZIPBytes, 10),
				news.SettingKeyMaxOPMLUploadBytes:               strconv.FormatInt(body.MaxOPMLUploadBytes, 10),
				SettingKeyAuthRateLimitMax:                      strconv.FormatInt(body.AuthRateLimitMax, 10),
				SettingKeyAIChatIPRateLimitMax:                  strconv.FormatInt(body.AIChatIPRateLimitMax, 10),
				SettingKeyGlobalRateLimitMax:                    strconv.FormatInt(body.GlobalRateLimitMax, 10),
				modules.SettingKeyConnPoolSize:                  strconv.Itoa(body.DenoConnPoolSize),
				weather.SettingKeyGeoTimeoutMS:                  strconv.Itoa(body.GeoTimeoutMS),
				ai.SettingKeyProviderTimeoutSeconds:             strconv.Itoa(body.AIProviderTimeoutSeconds),
				search.SettingKeyTimeout:                        strconv.Itoa(body.SearchTimeoutSeconds),
				search.SettingKeyFallbackTimeout:                strconv.Itoa(body.SearchFallbackTimeoutSeconds),
				news.SettingKeyFetchTimeoutSeconds:              strconv.Itoa(body.NewsFetchTimeoutSeconds),
				store.SettingKeySyncIntervalSeconds:             strconv.Itoa(body.StoreSyncIntervalSeconds),
				store.SettingKeyGithubAPITimeoutSeconds:         strconv.Itoa(body.StoreGithubAPITimeoutSeconds),
				modules.SettingKeyInstallDownloadTimeoutSeconds: strconv.Itoa(body.ModulesInstallDownloadTimeoutSecs),
				ai.SettingKeyChatRPMLimit:                       strconv.Itoa(body.ChatRPMLimit),
				coreupdate.SettingKeyCheckWeekdays:              body.CoreUpdateCheckWeekdays,
				coreupdate.SettingKeyCheckTime:                  body.CoreUpdateCheckTime,
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

			// system_timezone is read-only on this endpoint (see
			// LimitsSettings's doc comment) - always echo back the actual
			// stored value rather than whatever the client's body happened
			// to carry, so a PATCH can never appear to have silently
			// changed it.
			body.SystemTimezone = setup.SystemTimezoneRaw(ctx, pool)
			httperr.JSON(w, http.StatusOK, body)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
