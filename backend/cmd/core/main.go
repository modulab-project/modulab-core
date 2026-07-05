// Command core is the entry point for the modulab-core backend.
//
// This commit adds three more admin-only endpoints (internal/auth/admin.go)
// alongside the existing approve: GET /v1/admin/users now lists every
// user (not just pending ones), and POST .../lock, POST .../unlock, and
// DELETE /v1/admin/users/{id} let an org-admin/super-admin revoke or
// forget someone entirely - previously to revoke access at all
// short of deleting the row had no API path whatsoever. The Deno
// subprocess supervisor (spec section 4.7) is still unimplemented - that
// lands later, as part of the module-pipeline phase of the project
// roadmap.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/adminapi"
	"github.com/modulab-project/modulab-core/backend/internal/ai"
	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/bootstrap"
	"github.com/modulab-project/modulab-core/backend/internal/config"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/modules"
	"github.com/modulab-project/modulab-core/backend/internal/news"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	ntpcheck "github.com/modulab-project/modulab-core/backend/internal/ntp"
	"github.com/modulab-project/modulab-core/backend/internal/quicklinks"
	"github.com/modulab-project/modulab-core/backend/internal/searxng"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
	"github.com/modulab-project/modulab-core/backend/internal/tlscheck"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"github.com/modulab-project/modulab-core/backend/internal/version"
	"github.com/modulab-project/modulab-core/backend/internal/weather"
)

type healthStatus struct {
	Status            string `json:"status"`
	Version           string `json:"version"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	PostgresUp        bool   `json:"postgres_reachable"`
	ValkeyUp          bool   `json:"valkey_reachable"`
	MasterKeySetUp    bool   `json:"master_key_present"`
	SetupCompleted    bool   `json:"setup_completed"`
	SearXNGConfigured bool   `json:"searxng_configured"`
	// SearXNGUp is nil when SearXNG is not configured (omitted from JSON).
	// When configured it reflects whether the last ping succeeded.
	SearXNGUp *bool `json:"searxng_reachable,omitempty"`
	// NTPDriftOK is nil when the NTP check could not be performed (e.g. no
	// outbound UDP on port 123). When non-nil, true means the system clock
	// is within 30 s of pool.ntp.org; false means it is dangerously off and
	// TLS / JWT / audit-log timestamps may be wrong.
	NTPDriftOK *bool `json:"ntp_drift_ok,omitempty"`
	// ModulesActive/ModulesDegraded/ModulesFailed summarise
	// installed_modules.status across every installed module, so an admin
	// glancing at the System Status panel can see "1 of 3 modules is
	// degraded" without opening the Modules admin page separately. Degraded
	// is the status WorkerPool.SetCrashHandler (modules/deno.go) writes when
	// a Tier 2/3 Deno worker exits unexpectedly - before this field existed,
	// that crash was only visible via an SSE toast at the moment it happened
	// or by manually checking /admin/modules afterward.
	ModulesActive   int `json:"modules_active"`
	ModulesDegraded int `json:"modules_degraded"`
	ModulesFailed   int `json:"modules_failed"`
}

func main() {
	// Captured before anything else so /healthz's uptime_seconds reflects
	// the process's actual age, not just the time since the last dependency
	// finished connecting.
	startTime := time.Now()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("ModuLab Core %s — %s", version.Version, version.ProjectURL)

	// Generates the token now, but does not yet decide whether to print it -
	// that depends on whether the database already has a fully completed
	// wizard from a previous run, which we cannot know until after we
	// connect below. See the bootstrapMgr.LogToken / Complete call further
	// down for the actual decision.
	bootstrapMgr, err := bootstrap.New()
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	// ctx is cancelled the moment the process receives SIGTERM/SIGINT (e.g.
	// `docker stop`, systemd, or Ctrl-C in a dev shell). Every long-lived
	// background loop below (store.RunSync, mail.RunWorker, jobRunner)
	// already takes this ctx and returns once it is cancelled, so tying it
	// to the shutdown signal here is what makes them stop on their own
	// during a graceful shutdown - no separate per-goroutine stop signal
	// needed for those.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	pool, err := db.Connect(ctx, dsn, cfg.MasterKey)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()
	log.Printf("db: connected to postgres at %s:%s/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)

	if err := pool.EnsureCoreSchema(ctx); err != nil {
		log.Fatalf("db: %v", err)
	}

	// One-time migration: encrypt any plaintext PII/configuration that
	// existed before the encrypt-everything feature landed. No-op if already
	// run (guarded by core_encryption_version in core_settings).
	if err := pool.MigrateToEncryptedStorage(ctx); err != nil {
		log.Fatalf("db: encryption migration: %v", err)
	}

	valkeyClient := valkey.New(net.JoinHostPort(cfg.ValkeyHost, cfg.ValkeyPort), cfg.ValkeyPassword)
	defer func() {
		if err := valkeyClient.Close(); err != nil {
			log.Printf("valkey: close: %v", err)
		}
	}()

	// Checked once, actively, at boot - unlike /healthz's lazy per-request
	// check below, this gives the operator immediate feedback in the log
	// without having to curl anything. A failure here is not fatal: Valkey
	// is not required for the Setup Wizard, only for session storage (spec
	// section 3.2), which has no callers yet - go-redis will simply retry
	// on the next call.
	if err := valkeyClient.Ping(ctx); err != nil {
		log.Printf("valkey: WARNING - not reachable at %s:%s yet (rechecked on every /healthz request): %v", cfg.ValkeyHost, cfg.ValkeyPort, err)
	} else {
		log.Printf("valkey: reachable at %s:%s", cfg.ValkeyHost, cfg.ValkeyPort)
	}

	// Pre-seed the SearXNG URL so Docker deployments work out of the box.
	// EnsureDefault is a no-op when a URL is already configured.
	if err := searxng.EnsureDefault(ctx, pool, cfg.MasterKey); err != nil {
		log.Printf("searxng: could not seed default URL: %v", err)
	}

	// No master-key check here anymore: MODULAB_MASTER_KEY is mandatory and
	// already validated by config.Load above, so by this point it is
	// guaranteed present - see validateMasterKey in config.go and
	// wizard.go's doc comments for why the old DB-fallback check that used
	// to live here was removed.
	oidcConfigured, err := setup.OIDCConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: oidc check failed: %v", err)
	}
	groupPrefixConfigured, err := setup.GroupPrefixConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: group prefix check failed: %v", err)
	}
	log.Printf("setup wizard progress: oidc=%t group-prefix=%t", oidcConfigured, groupPrefixConfigured)

	// This is the decision bootstrapMgr.New()'s comment above refers to: a
	// completed wizard from a previous run means the bootstrap-token gate
	// should already be disabled, and printing a fresh "FIRST-TIME SETUP
	// REQUIRED" token would actively mislead an operator who finished setup
	// long ago. An incomplete wizard means we still need that token, so we
	// print it now and only now - this is the latest point at which the log
	// can still scroll, before any HTTP routes start serving traffic.
	wizardDone, err := setup.WizardComplete(ctx, pool)
	if err != nil {
		log.Printf("setup: completion check failed: %v", err)
	}
	if wizardDone {
		bootstrapMgr.Complete()
		log.Printf("setup: wizard already completed in a previous run - bootstrap-token gate stays disabled, no new token issued")
	} else {
		bootstrapMgr.LogToken()
	}

	mux := http.NewServeMux()

	// /healthz is intentionally exempt from the bootstrap-token gate: it is
	// meant for unauthenticated monitoring (e.g. Docker healthchecks,
	// Traefik) and never reveals anything more sensitive than booleans, plus
	// the build version - which the frontend's footer also reads from here
	// rather than duplicating the version string on the client side.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// master_key_present is now always true while Core is running at
		// all: MODULAB_MASTER_KEY has no database fallback anymore and
		// config.Load already refused to start Core without it. Kept as a
		// field (rather than removed) so existing /healthz consumers don't
		// break, and because "always true" is itself useful confirmation
		// that this build's startup validation actually ran.
		status := healthStatus{
			Status:         "ok",
			Version:        version.Version,
			UptimeSeconds:  int64(time.Since(startTime).Seconds()),
			PostgresUp:     pool.Ping(r.Context()) == nil,
			ValkeyUp:       valkeyClient.Ping(r.Context()) == nil,
			MasterKeySetUp: cfg.MasterKey != "",
			SetupCompleted: bootstrapMgr.Completed(),
		}
		// SearXNG is optional: only check reachability when a URL is saved.
		// resolveURL is a fast DB lookup; the Ping adds ~1 RTT on the internal
		// network (same order of magnitude as the Postgres/Valkey checks).
		if configured, err := searxng.IsConfigured(r.Context(), pool, cfg.MasterKey); err == nil {
			status.SearXNGConfigured = configured
			if configured {
				if rawURL, _, err := searxng.ResolveURLPublic(r.Context(), pool, cfg.MasterKey); err == nil {
					up := searxng.Ping(r.Context(), rawURL)
					status.SearXNGUp = &up
				}
			}
		}
		// NTP drift check: best-effort, 3 s timeout. If pool.ntp.org is not
		// reachable (firewalled UDP 123), NTPDriftOK stays nil — callers treat
		// nil as "unknown", not "bad". The 3-second deadline is the only extra
		// latency /healthz adds beyond the SearXNG ping above.
		if ok, err := ntpcheck.DriftOK(30 * time.Second); err == nil {
			status.NTPDriftOK = &ok
		}
		// Module worker health summary - best-effort, same as the checks
		// above: a failed lookup here must not break /healthz itself, it
		// just leaves the counts at zero (indistinguishable from "no
		// modules installed", which is an acceptable ambiguity for a
		// monitoring endpoint that already treats most fields as
		// best-effort).
		if installed, err := pool.ListInstalledModules(r.Context()); err == nil {
			for _, m := range installed {
				switch m.Status {
				case db.ModuleStatusActive:
					status.ModulesActive++
				case db.ModuleStatusDegraded:
					status.ModulesDegraded++
				case db.ModuleStatusFailed:
					status.ModulesFailed++
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	// Every Setup Wizard route below is wrapped in bootstrapMgr.Middleware:
	// per spec section 6.5, the entire wizard API is locked until the
	// correct bootstrap token (printed above, once, at startup) is supplied
	// via the X-ModuLab-Bootstrap-Token header.
	mux.Handle("/v1/setup/status", bootstrapMgr.Middleware(setup.StatusHandler(pool)))
	mux.Handle("/v1/setup/init", bootstrapMgr.Middleware(setup.InitHandler(pool)))

	mux.Handle("/v1/setup/oidc/status", bootstrapMgr.Middleware(setup.OIDCStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("/v1/setup/oidc/configure", bootstrapMgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The OIDC step needs the master key to encrypt the client secret.
		// ResolveMasterKey only ever returns cfg.MasterKey now (no database
		// fallback), so this can't actually fail in practice - it's called
		// per-request rather than once at startup purely to keep this
		// handler's shape consistent with the group-prefix step below.
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		setup.OIDCConfigureHandler(pool, masterKey)(w, r)
	})))

	mux.Handle("/v1/setup/group-prefix/status", bootstrapMgr.Middleware(setup.GroupPrefixStatusHandler(pool)))
	mux.Handle("/v1/setup/group-prefix/configure", bootstrapMgr.Middleware(setup.GroupPrefixConfigureHandler(pool)))

	// Wizard step 7 (spec section 6.5): only flips bootstrapMgr's gate once
	// every prior step's persisted state actually checks out - see
	// setup.CompleteHandler / missingSteps for what "actually checks out"
	// means, in particular for step 6 (a bound Super-Admin, not just an
	// attempted login).
	mux.Handle("/v1/setup/complete", bootstrapMgr.Middleware(setup.CompleteHandler(pool, bootstrapMgr, cfg.MasterKey)))

	// The actual end-user login flow (spec section 6.5 wizard step 6 /
	// section 3.3) - deliberately NOT wrapped in bootstrapMgr.Middleware,
	// since that gate is for the operator-only Setup Wizard API, not for
	// end users authenticating against their own IdP account. All
	// configuration (OIDC provider, group prefix, master key for
	// decrypting the client secret) is re-resolved on every request inside
	// these handlers, so changes made through the Setup Wizard take effect
	// without a Core restart.
	authDeps := auth.Deps{
		Pool:            pool,
		Valkey:          valkeyClient,
		MasterKeyEnv:    cfg.MasterKey,
		PublicBaseURL:   cfg.PublicBaseURL,
		FrontendBaseURL: cfg.FrontendBaseURL,
	}
	// Rate-limited: unauthenticated endpoints reachable by anyone who can
	// reach Core at all. login redirects to the IdP (creates an
	// oauthstate: key in Valkey per call — unbounded calls let someone
	// flood that keyspace) and callback completes the OIDC exchange (an
	// upstream-directed request whose volume this instance controls).
	// authRateLimitMiddleware fails open on a Valkey hiccup rather than
	// locking everyone out because of a cache blip — see its doc comment.
	mux.HandleFunc("/v1/auth/login", authRateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, "login", auth.LoginHandler(authDeps)))
	mux.HandleFunc("/v1/auth/callback", authRateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, "callback", auth.CallbackHandler(authDeps)))
	mux.HandleFunc("/v1/auth/me", auth.MeHandler(authDeps))
	// Method-specific pattern alongside the bare "/v1/auth/me" above - Go's
	// ServeMux treats the two as non-conflicting (the method-specific one
	// is more specific and wins for DELETE requests; GET/etc. still reach
	// MeHandler). Self-service account deletion: the counterpart to
	// /v1/admin/users/{id} below, but for the caller's own account, which
	// that admin-only route explicitly refuses to touch.
	mux.HandleFunc("DELETE /v1/auth/me", auth.DeleteSelfHandler(authDeps))
	// DSGVO data-portability export (GDPR Article 20): returns all personal
	// data stored for the calling user as a JSON attachment.
	mux.HandleFunc("GET /v1/auth/me/export", auth.ExportSelfHandler(authDeps))
	mux.HandleFunc("/v1/auth/logout", auth.LogoutHandler(authDeps))
	// UI language preference: GET returns {"ui_language":"en|de|"}, PATCH updates.
	mux.HandleFunc("/v1/user/preferences", auth.UserPrefsHandler(authDeps))

	// Spec section 3.5's real-time notification stream (internal/notify):
	// authenticates its own bearer token from a query parameter rather
	// than the Authorization header every other route uses, since the
	// browser's EventSource API cannot set custom request headers - see
	// auth.EventsHandler's doc comment. Not wrapped in requireAdmin or any
	// other middleware here: EventsHandler does its own session validation
	// and subscribes to admin-only channels only for sessions whose role
	// warrants it, the same self-contained shape as /v1/auth/me above.
	mux.HandleFunc("GET /v1/events", auth.EventsHandler(authDeps))

	// Admin-only user management (internal/auth/admin.go): every handler
	// here gates on role itself (requireAdmin), so no extra middleware
	// wrapper is needed, same as the /v1/auth/... routes above. {id} is the
	// target user's OIDC subject - Go 1.22+'s ServeMux wildcard syntax,
	// read back inside each handler via r.PathValue("id").
	mux.HandleFunc("GET /v1/admin/users", auth.UsersHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/users/{id}/approve", auth.ApproveUserHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/users/{id}/lock", auth.LockUserHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/users/{id}/unlock", auth.UnlockUserHandler(authDeps))
	mux.HandleFunc("DELETE /v1/admin/users/{id}", auth.DeleteUserHandler(authDeps))

	// SMTP configuration (spec section 3.5's Mail-Queue) lives in the
	// ongoing Admin Panel, not the Setup Wizard - see setup/smtp.go's doc
	// comment for why this is deliberately NOT wrapped in
	// bootstrapMgr.Middleware the way OIDC below is.
	// Super-admin only (auth.RequireSuperAdminMiddleware), same level as
	// OIDC configuration. The configure handler resolves the master key
	// per-request, same reasoning as the OIDC configure handler above: it
	// can't actually fail in practice (no DB fallback left to resolve),
	// kept this shape purely for consistency.
	superAdminOnly := auth.RequireSuperAdminMiddleware(authDeps)
	mux.Handle("GET /v1/admin/smtp/status", superAdminOnly(setup.SMTPStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/smtp/test", superAdminOnly(setup.SMTPTestHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/smtp/configure", superAdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		// Read current config before the handler overwrites it - needed to
		// build a "field: old → new" diff for the audit log.
		oldSMTP, _ := setup.ResolveSMTPConfig(r.Context(), pool, masterKey)

		// Buffer the body so the handler can still read it after we peek.
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		rw := &responseRecorder{ResponseWriter: w, code: http.StatusOK}
		setup.SMTPConfigureHandler(pool, masterKey)(rw, r)
		if rw.code < 400 {
			if sess, ok := auth.SessionFromContext(r.Context()); ok {
				var newReq struct {
					Host        string `json:"host"`
					Port        int    `json:"port"`
					FromAddress string `json:"from_address"`
					Encryption  string `json:"encryption"`
					Password    string `json:"password"`
				}
				_ = json.Unmarshal(bodyBytes, &newReq)
				details := smtpDiff(oldSMTP, newReq.Host, newReq.Port, newReq.FromAddress, newReq.Encryption)
				// smtpDiff omits the password (never log credentials). If the
				// diff is empty but the request contained a new password, make
				// that visible in the audit entry instead of showing nothing.
				if details == "{}" && newReq.Password != "" {
					details = `{"credentials":"updated"}`
				}
				if err := audit.Log(r.Context(), pool, masterKey, audit.LogParams{
					EventType:  audit.EventConfigSMTP,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					Details:    details,
				}); err != nil {
					log.Printf("main: audit smtp configure: %v", err)
				}
			}
		}
	})))
	mux.Handle("DELETE /v1/admin/smtp", superAdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseRecorder{ResponseWriter: w, code: http.StatusOK}
		setup.SMTPDeleteHandler(pool)(rw, r)
		if rw.code < 400 {
			masterKey, _ := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
			if sess, ok := auth.SessionFromContext(r.Context()); ok && masterKey != "" {
				if err := audit.Log(r.Context(), pool, masterKey, audit.LogParams{
					EventType:  audit.EventConfigSMTPDel,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
				}); err != nil {
					log.Printf("main: audit smtp delete: %v", err)
				}
			}
		}
	})))

	// Admin system page + OIDC post-wizard config + audit log.
	// All super-admin only (same tier as SMTP above).
	mux.Handle("GET /v1/admin/system", superAdminOnly(adminapi.SystemStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("PATCH /v1/admin/oidc", superAdminOnly(adminapi.OIDCUpdateHandler(pool, cfg.MasterKey)))
	mux.Handle("DELETE /v1/admin/oidc", superAdminOnly(adminapi.OIDCDeleteHandler(pool, cfg.MasterKey)))
	mux.Handle("GET /v1/audit-log", superAdminOnly(adminapi.AuditLogHandler(pool, cfg.MasterKey)))

	// Widget endpoints (spec section 8 / Home page). Not wrapped in any
	// auth middleware: weather data is not sensitive, and the 15-minute
	// Valkey cache (internal/weather) limits upstream Open-Meteo calls to
	// one per location per interval regardless of how many users load the
	// page simultaneously. lat and lon come from the browser's own
	// Geolocation API - Core never stores or logs them.
	mux.HandleFunc("GET /v1/widgets/weather", weather.Handler(valkeyClient))

	// SearXNG web-search proxy (spec section 6.4, search widget).
	// Admin configuration: super-admin only (same tier as SMTP).
	// Search endpoint: any approved session - proxies the query to the
	// configured SearXNG instance and returns trimmed JSON results.
	mux.Handle("GET /v1/admin/searxng/status", superAdminOnly(searxng.StatusHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/searxng/configure", superAdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		searxng.ConfigureHandler(pool, masterKey)(w, r)
	})))
	mux.Handle("DELETE /v1/admin/searxng", superAdminOnly(searxng.DeleteHandler(pool, cfg.MasterKey)))
	mux.HandleFunc("GET /v1/search/web", searxng.SearchHandler(authDeps, cfg.MasterKey))
	mux.HandleFunc("GET /v1/user/search-prefs", searxng.SearchPrefsHandler(authDeps))
	mux.HandleFunc("POST /v1/user/search-prefs", searxng.SearchPrefsHandler(authDeps))

	// News feed management (internal/news):
	//   Admin CRUD: org-admin and super-admin can manage the global feed pool.
	//   User endpoints: every approved session can list feeds, toggle their own
	//   subscriptions, and fetch aggregated articles. The aggregator caches
	//   each feed's articles in Valkey for 15 minutes per feed.
	mux.HandleFunc("POST /v1/admin/feeds/check", news.AdminCheckHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/feeds/opml-parse", news.AdminParseOPMLHandler(authDeps))
	mux.HandleFunc("GET /v1/admin/feeds/catalog", news.AdminCatalogHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/feeds/import", news.AdminImportHandler(authDeps))
	mux.HandleFunc("GET /v1/admin/feeds", news.AdminListHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/feeds", news.AdminCreateHandler(authDeps))
	mux.HandleFunc("PATCH /v1/admin/feeds/{id}", news.AdminUpdateHandler(authDeps))
	mux.HandleFunc("DELETE /v1/admin/feeds/{id}", news.AdminDeleteHandler(authDeps))
	mux.HandleFunc("GET /v1/feeds", news.FeedsHandler(authDeps))
	mux.HandleFunc("PATCH /v1/feeds/{id}/subscription", news.SubscriptionHandler(authDeps))
	mux.HandleFunc("GET /v1/news", news.NewsHandler(authDeps))
	mux.HandleFunc("GET /v1/news/config", news.NewsConfigHandler(authDeps))
	mux.HandleFunc("GET /v1/admin/news/settings", news.AdminNewsSettingsHandler(authDeps))
	mux.HandleFunc("PATCH /v1/admin/news/settings", news.AdminNewsSettingsHandler(authDeps))

	// AI provider management (internal/ai): admin CRUD is super-admin only
	// (same tier as SMTP/SearXNG); user key management and chat streaming
	// require any approved session. The chat endpoint streams SSE, so
	// Traefik/Nginx buffering is suppressed via X-Accel-Buffering: no inside
	// ChatHandler itself.
	mux.Handle("GET /v1/admin/ai/settings", superAdminOnly(ai.AdminSettingsHandler(authDeps)))
	mux.Handle("PATCH /v1/admin/ai/settings", superAdminOnly(ai.AdminSettingsHandler(authDeps)))
	mux.Handle("GET /v1/admin/ai/providers", superAdminOnly(ai.AdminListHandler(authDeps)))
	mux.Handle("POST /v1/admin/ai/providers", superAdminOnly(ai.AdminCreateHandler(authDeps)))
	mux.Handle("PATCH /v1/admin/ai/providers/{id}", superAdminOnly(ai.AdminPatchHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/ai/providers/{id}", superAdminOnly(ai.AdminDeleteHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/ai/providers/{id}/key", superAdminOnly(ai.AdminClearKeyHandler(authDeps)))
	mux.Handle("GET /v1/admin/ai/providers/{id}/models", superAdminOnly(ai.AdminListModelsHandler(authDeps)))
	mux.Handle("GET /v1/admin/ai/providers/{id}/balance", superAdminOnly(ai.AdminBalanceHandler(authDeps)))
	mux.HandleFunc("GET /v1/ai/providers", ai.UserProvidersHandler(authDeps))
	mux.HandleFunc("PUT /v1/ai/keys/{id}", ai.UserSetKeyHandler(authDeps))
	mux.HandleFunc("DELETE /v1/ai/keys/{id}", ai.UserDeleteKeyHandler(authDeps))
	mux.HandleFunc("PATCH /v1/ai/keys/{id}/model", ai.UserSetPreferredModelHandler(authDeps))
	mux.HandleFunc("GET /v1/ai/keys/{id}/models", ai.UserListModelsHandler(authDeps))
	mux.HandleFunc("PATCH /v1/ai/preference", ai.UserSetPreferredProviderHandler(authDeps))
	// Rate-limited on top of the global backstop below: this is the one
	// route that forwards to a paid external API per call, so it gets its
	// own tighter per-IP budget (see aiChatRateLimitWindow/Max's doc comment)
	// rather than relying solely on the generous global limit.
	mux.HandleFunc("POST /v1/ai/chat", rateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, "ai-chat", aiChatRateLimitWindow, aiChatRateLimitMax, ai.ChatHandler(authDeps)))

	// Quick links / Schnellzugriff-Grid (internal/quicklinks):
	//   User endpoints: any approved session can list merged tiles, create or
	//   delete personal tiles, and save their custom ordering.
	//   Admin CRUD: org-admin / super-admin only.
	mux.HandleFunc("GET /v1/quick-links", quicklinks.ListHandler(authDeps))
	mux.HandleFunc("POST /v1/quick-links", quicklinks.CreateUserLinkHandler(authDeps))
	mux.HandleFunc("DELETE /v1/quick-links/{id}", quicklinks.DeleteUserLinkHandler(authDeps))
	mux.HandleFunc("PATCH /v1/quick-links/order", quicklinks.SaveOrderHandler(authDeps))
	mux.HandleFunc("GET /v1/admin/quick-links", quicklinks.AdminListHandler(authDeps))
	mux.HandleFunc("POST /v1/admin/quick-links", quicklinks.AdminCreateHandler(authDeps))
	mux.HandleFunc("PATCH /v1/admin/quick-links/{id}", quicklinks.AdminUpdateHandler(authDeps))
	mux.HandleFunc("DELETE /v1/admin/quick-links/{id}", quicklinks.AdminDeleteHandler(authDeps))

	// Module Store registry sync (internal/store): fetches official + community
	// registry on startup and every 24 hours. Errors are logged, never fatal.
	// The background goroutine itself is started further down (after
	// moduleDeps exists, see onStoreSynced below) — storeDeps is declared
	// here because the route handlers below need it right away.
	storeDeps := store.Deps{Pool: pool, Valkey: valkeyClient}

	// Store browse endpoints (spec section 4.10).
	// GET /v1/store and GET /v1/store/{name} require any active session.
	// POST /v1/store/sync requires org-admin or super-admin.
	mux.HandleFunc("GET /v1/store", store.ListHandler(storeDeps, authDeps))
	mux.HandleFunc("GET /v1/store/{name}", store.DetailHandler(storeDeps, authDeps))

	// Module management endpoints (spec section 4.6–4.9).
	// List/detail: any active session. Install/uninstall/update/pin: org-admin+.
	// Note: GET /v1/modules/updates is registered before GET /v1/modules/{name}
	// so the literal path wins over the wildcard in Go's 1.22 ServeMux.
	// dbURL for Deno workers: no sslmode param here because postgres.js
	// (npm:postgres@3) uses its own TLS defaults. The search_path is added
	// per-module in WorkerPool.Start so each worker sees only its own schema.
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	workerPool := modules.NewWorkerPool(cfg.ModuleDataDir, dbURL)
	defer workerPool.StopAll()

	// A worker that crashes on its own (as opposed to Stop/StopAll or a
	// deliberate restart) used to just go silent: installed_modules.status
	// stayed "active" and nothing surfaced it anywhere. Mark the module
	// degraded and reuse the same notify.AdminChannel() an update-check's
	// "module.updates_available" event already publishes to, so a connected
	// admin's SSE stream picks it up live instead of only being discoverable by
	// noticing the module has stopped responding. See
	// WorkerPool.SetCrashHandler's doc comment for why this deliberately
	// does not attempt an automatic restart.
	workerPool.SetCrashHandler(func(name string) {
		crashCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.UpdateModuleStatus(crashCtx, name, db.ModuleStatusDegraded); err != nil {
			log.Printf("main: crash handler: mark %q degraded: %v", name, err)
		}
		ev := notify.Event{Type: "module.crashed", Data: map[string]any{"name": name}}
		if err := notify.Publish(crashCtx, valkeyClient, notify.AdminChannel(), ev); err != nil {
			log.Printf("main: crash handler: publish event for %q: %v", name, err)
		}
	})

	moduleDeps := modules.Deps{
		DB:        pool,
		DataDir:   cfg.ModuleDataDir,
		CosignBin: cfg.CosignBinaryPath,
		Workers:   workerPool,
		Valkey:    valkeyClient,
	}

	// onStoreSynced runs a module-update check immediately after every
	// registry sync (manual click or the hourly background one below),
	// instead of only finding out up to updateCheckInterval (15 min) later
	// purely because the ticker hadn't fired yet since the sync. Reported
	// 2026-07-05: an admin who manually synced and then updated a module
	// within minutes never saw the "update available" notification at all,
	// because the 15-minute tick simply hadn't happened yet by the time they
	// acted manually. store (internal/store) cannot import modules itself
	// (modules already imports store, so the reverse would cycle) — passing
	// this closure in is how the two meet without that.
	onStoreSynced := func(syncCtx context.Context) {
		modules.RunUpdateCheckOnce(syncCtx, moduleDeps, storeDeps)
	}

	// Now that moduleDeps exists, start the registry-sync goroutine and wire
	// the manual-sync route — both call onStoreSynced above after every sync.
	go store.RunSync(ctx, storeDeps, onStoreSynced)
	mux.HandleFunc("POST /v1/store/sync", store.SyncHandler(storeDeps, authDeps, onStoreSynced))

	// Installed-module update checking has no background loop of its own
	// (see modules.RunUpdateCheckOnce's doc comment for why a separate
	// 15-minute ticker was removed 2026-07-05 as pure redundancy): it is
	// entirely driven by onStoreSynced above, which fires right after every
	// registry sync - manual or the hourly background one - so connected
	// admins see new updates via SSE without needing to click "check
	// updates" or reload, without a second timer polling data that only
	// ever changes when a sync runs anyway.

	// GET /v1/admin/system/info — read-only diagnostics page (spec: "System
	// Info" card on /admin/system) aggregating everything an admin previously
	// had to piece together from /healthz, the Installed Modules page, and
	// the Store page separately: version/uptime, dependency reachability,
	// and a countdown until the next registry sync (which also drives the
	// next module-update check, see above), so "I published a release, why
	// hasn't ModuLab noticed yet" has a concrete answer instead of "wait and
	// see".
	mux.Handle("GET /v1/admin/system/info", superAdminOnly(systemInfoHandler(pool, valkeyClient, cfg, startTime, storeDeps, authDeps)))
	mux.Handle("DELETE /v1/admin/sessions/{id}", superAdminOnly(revokeSessionHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/system/rate-limits", superAdminOnly(resetRateLimitHandler(valkeyClient)))

	// At startup, restart Deno workers for all Tier 2/3 modules that were
	// active before the last shutdown.
	if installedAtBoot, err := pool.ListInstalledModules(ctx); err != nil {
		// Previously silently swallowed (no else branch at all): a failure
		// here skipped the entire worker-restart loop below with zero log
		// output, indistinguishable from "no modules installed". Logging it
		// is diagnostic-only - this doesn't change startup behavior.
		log.Printf("main: startup: could not list installed modules, no Deno workers will be restarted: %v", err)
	} else {
		for _, row := range installedAtBoot {
			if row.Tier >= 2 && row.Status == "active" {
				entrypoint := ""
				destDir := cfg.ModuleDataDir + "/" + row.Name
				var mf struct {
					Handler            string                `json:"handler"`
					EgressAllowlist    []string              `json:"egress_allowlist"`
					Jobs               []modules.ManifestJob `json:"jobs"`
					TLSSkipVerify      bool                  `json:"tls_skip_verify"`
					DynamicEgress      bool                  `json:"dynamic_egress"`
					EgressHostsHandler string                `json:"egress_hosts_handler"`
				}
				if row.Manifest != nil {
					if json.Unmarshal(row.Manifest, &mf) == nil {
						entrypoint = destDir + "/" + mf.Handler
					}
				}
				if entrypoint != "" {
					opts := modules.WorkerOptions{
						EgressHosts:   mf.EgressAllowlist,
						Jobs:          modules.ResolveJobEntrypoints(destDir, mf.Jobs, mf.EgressHostsHandler),
						SkipTLSVerify: mf.TLSSkipVerify,
					}
					if err := workerPool.Start(row.Name, entrypoint, opts); err != nil {
						log.Printf("main: startup: could not start worker for %q: %v", row.Name, err)
					} else if mf.DynamicEgress && mf.EgressHostsHandler != "" {
						// This is the fix for the Core-restart egress-reset
						// bug: at boot there is no previously-running worker
						// to ask for its runtime hosts (unlike the
						// module-update path in handlers.go), so the worker
						// above was just started with EgressAllowlist only
						// (empty for unifi-network by design). Ask the
						// freshly-started worker itself to recompute its
						// hosts from its own DB state (e.g. unifi-network's
						// configured gateway IPs) and reload egress
						// immediately, before any job/request needs it.
						if hosts, ok := workerPool.QueryEgressHosts(ctx, row.Name); ok {
							if err := workerPool.ReloadEgress(row.Name, hosts); err != nil {
								log.Printf("main: startup: egress hosts reload failed for %q: %v", row.Name, err)
							}
						}
					}
				}
			}
		}
	}

	// Scheduled job runner (manifest.yaml jobs: list, e.g. unifi-network's
	// poll_gateways) — see internal/modules/jobs.go. Runs for Core's entire
	// lifetime, same lifecycle as the mail worker below.
	jobRunner := modules.NewJobRunner(pool, workerPool, valkeyClient)
	jobRunner.Start(ctx)

	mux.HandleFunc("GET /v1/modules", modules.ListInstalledHandler(moduleDeps, authDeps))
	mux.HandleFunc("GET /v1/modules/updates", modules.CheckUpdatesHandler(moduleDeps, storeDeps, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}", modules.GetInstalledHandler(moduleDeps, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/egress-hosts", modules.GetModuleEgressHostsHandler(moduleDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/install", modules.InstallHandler(moduleDeps, storeDeps, authDeps))
	mux.HandleFunc("DELETE /v1/modules/{name}", modules.UninstallHandler(moduleDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/{name}/update", modules.UpdateModuleHandler(moduleDeps, storeDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/{name}/restart", modules.RestartModuleHandler(moduleDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/{name}/pin", modules.PinHandler(moduleDeps, authDeps))
	mux.HandleFunc("DELETE /v1/modules/{name}/pin", modules.UnpinHandler(moduleDeps, authDeps))

	// Module API proxy: /v1/modules/{name}/api/* → Deno worker for that module.
	// Registered after all specific lifecycle routes so the wildcard does not
	// shadow /install, /update, /pin, etc.
	modules.RegisterModuleRoutes(mux, moduleDeps, authDeps)

	// The mail worker (internal/mail) runs for Core's entire lifetime as a
	// single background goroutine, draining whatever
	// admin.go's enqueueMail calls push onto the queue - started
	// unconditionally even before SMTP has ever been configured, since
	// RunWorker itself handles "not configured yet" per message (logged,
	// dropped) rather than needing to be told to start later once it is.
	// Like store.RunSync above, it takes the
	// signal-aware ctx from main's top and returns on its own once that ctx
	// is cancelled during graceful shutdown (see the select block at the
	// end of main).
	go mail.RunWorker(ctx, valkeyClient, pool, cfg.MasterKey)

	// The group prefix has no environment fallback anymore (removed
	// 2026-06-21 alongside OIDC's) - it may legitimately be unconfigured
	// here if the operator hasn't run the Setup Wizard's group-prefix step
	// (6.5 step 5) yet, so this resolves the same way the login flow itself
	// does rather than printing an empty string.
	effectiveGroupPrefix, err := setup.ResolveGroupPrefix(ctx, pool)
	if err != nil {
		effectiveGroupPrefix = "(not yet configured)"
	}
	log.Printf("modulab-core listening on %s (group prefix %q, frontend origin %q)", cfg.HTTPAddr, effectiveGroupPrefix, cfg.FrontendBaseURL)
	handler := corsMiddleware(cfg.FrontendBaseURL, mux)
	handler = maxBodyMiddleware(pool, handler)
	handler = secHeadersMiddleware(handler)
	handler = globalRateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, handler)
	// Outermost: must run before every other middleware so a panic anywhere
	// downstream (a handler, or one of the middlewares above) is still
	// caught. Go's net/http already recovers a panicking handler goroutine
	// on its own - one bad request cannot crash the whole process - but
	// without this, the *only* symptom was the connection dropping with no
	// response at all and a bare, unstructured stack trace on stdout (no
	// request context: which route, which method, which IP). This adds a
	// proper 500 response for the caller and a one-line log with the
	// context needed to actually find the bug afterward.
	handler = recoverMiddleware(handler)

	srv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: handler,
	}

	// Serve on a separate goroutine so the main goroutine below can block on
	// ctx.Done() (the SIGTERM/SIGINT signal) instead of ListenAndServe, which
	// never returns on its own. http.ErrServerClosed is the expected error
	// once Shutdown below closes the listener - anything else is a real
	// startup/runtime failure.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	case <-ctx.Done():
		log.Printf("main: shutdown signal received, draining in-flight requests (up to 15s)")

		// jobRunner/workerPool are stopped explicitly (they don't watch ctx
		// themselves); RunSync/mail.RunWorker above already exit on their
		// own once ctx is cancelled.
		jobRunner.Stop()
		workerPool.StopAll()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("main: server shutdown did not complete cleanly: %v", err)
		}
		// Wait for ListenAndServe's goroutine to actually return so pool.Close()
		// and valkeyClient.Close() (deferred above) don't race with in-flight
		// handlers still using them.
		<-serveErr
		log.Printf("main: shutdown complete")
	}
}

// smtpDiff builds a JSON object containing only the SMTP fields that changed
// between old (the previously persisted config) and the new values submitted
// by the admin. Fields that did not change are omitted so the audit entry
// only shows what actually happened. Password is never included.
// Returns "{}" when nothing changed (e.g. saving without modifications).
func smtpDiff(old setup.SMTPRuntimeConfig, newHost string, newPort int, newFrom, newEnc string) string {
	type kv struct {
		key      string
		oldVal   string
		newVal   string
	}
	changes := []kv{
		{"host", old.Host, newHost},
		{"port", fmt.Sprintf("%d", old.Port), fmt.Sprintf("%d", newPort)},
		{"from", old.FromAddress, newFrom},
		{"encryption", old.Encryption, newEnc},
	}
	buf := bytes.NewBufferString("{")
	first := true
	for _, c := range changes {
		if c.oldVal == c.newVal {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		// Format: "field":"old → new"
		enc, _ := json.Marshal(fmt.Sprintf("%s → %s", c.oldVal, c.newVal))
		fmt.Fprintf(buf, "%q:%s", c.key, enc)
	}
	buf.WriteByte('}')
	return buf.String()
}

// responseRecorder wraps http.ResponseWriter and captures the status code
// written by the downstream handler so the caller can decide post-hoc
// whether to emit an audit log entry (only on success).
type responseRecorder struct {
	http.ResponseWriter
	code int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// maxBodyMiddleware caps every request body using the max_body_bytes setting
// stored in core_settings (default 1 MB; 0 = unlimited). The limit is read
// from the database on every request so changes via PATCH /v1/admin/ai/settings
// take effect immediately without a restart.
func maxBodyMiddleware(pool *db.Pool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := ai.MaxBodyBytes(r.Context(), pool)
		if limit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// secHeadersMiddleware adds defensive HTTP response headers that do not
// require per-route knowledge. TLS-related headers (HSTS, etc.) are handled
// by Traefik at the edge and are intentionally omitted here.
//
// Content-Security-Policy note: this is Core's API server, not the
// frontend's own HTTP server (the SPA is built by Vite and served
// separately, see frontend/nginx.conf for its CSP). Core's own CSP here
// matters for the handful of responses Core serves directly that a browser
// renders/executes rather than just consumes as JSON: module UI bundles
// (ModuleBundleHandler, GET /v1/modules/{name}/ui/bundle.js) and storage
// files (ModuleStorageHandler). script-src 'self' covers the bundle
// endpoint; object-src/frame-ancestors 'none' block the classic embedding
// vectors. This intentionally does not attempt to allow the frontend's own
// blob:-URL module loading (ModulePage.tsx's import(blobUrl); see the
// Frontend security review) — that decision belongs to the frontend's CSP,
// not Core's, and blob: script execution should be reconsidered as part of
// the planned iframe-sandboxed module rendering rather than allowlisted
// here.
func secHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"object-src 'none'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware turns a panicking handler into a 500 response with a
// structured log line instead of a dropped connection and a bare stack
// trace. debug.Stack() is still logged in full - the goal here is adding
// request context (method, path, client IP) alongside it, not replacing it,
// so a panic is still fully debuggable from the log alone.
//
// Deliberately does not attempt to keep serving other requests differently
// than Go already does: net/http recovers a panicking handler on its own
// goroutine-per-request model, so this middleware only ever affects the one
// request that panicked, not instance-wide availability.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("main: panic recovered: %v\nrequest: %s %s (from %s)\n%s",
					rec, r.Method, r.URL.Path, clientIP(r), debug.Stack())
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// authRateLimitWindow/authRateLimitMax bound how often a single client IP
// may hit a rate-limited auth endpoint. Sized for a homelab (a handful of
// real users, occasional retries) while still cutting off unbounded
// scripted hammering of the login/callback endpoints.
const (
	authRateLimitWindow = time.Minute
	authRateLimitMax    = 20
)

// aiChatRateLimitWindow/aiChatRateLimitMax bound how often a single client IP
// may call the AI chat proxy. Unlike login/callback, every call here forwards
// to a paid external provider (OpenAI/Anthropic/etc. - internal/ai), so an
// unbounded loop from a single approved-but-compromised account (or a buggy
// frontend retry) can run up real cost, not just load Core itself. 30/min is
// generous for interactive chat use (a few messages a minute, per browser
// tab) while still bounding worst-case spend to a known ceiling.
const (
	aiChatRateLimitWindow = time.Minute
	aiChatRateLimitMax    = 30
)

// globalRateLimitWindow/globalRateLimitMax is a coarse backstop applied to
// every route except /healthz (see main's handler chain). It exists because,
// before this, only /v1/auth/login and /v1/auth/callback had any rate limit
// at all - anything else (module API proxy, search, news aggregation, etc.)
// was reachable at unbounded volume by any approved session or, for routes
// that don't check auth themselves, any caller who can reach Core. The limit
// is deliberately generous (a self-hosted homelab has a handful of real
// users, not a fleet of API consumers) - it is meant to catch runaway loops
// and scripted abuse, not to shape normal interactive traffic.
const (
	globalRateLimitWindow = time.Minute
	globalRateLimitMax    = 600
)

// rateLimitMiddleware applies a per-client-IP fixed-window rate limit (via
// valkey.Client.IncrExpire) to a single handler. label distinguishes the
// Valkey key namespace per endpoint/scope (e.g. "login" vs "callback" vs
// "ai-chat" vs "global") so budgets don't bleed into each other. max is the
// number of requests allowed per window. On a Valkey error the request is
// let through (fail open) — a cache hiccup should degrade to "no rate
// limiting" rather than locking everyone out.
//
// pool/masterKeyEnv (added 2026-07-05, alongside System Info's "rate
// limits" section) are used only on the rare trip branch, to write an
// audit.EventRateLimitExceeded entry — a live Valkey counter tells you a
// limit is active right now, but says nothing about one that already
// expired by the time an admin goes looking, which is exactly what
// happened investigating an earlier "too many requests" report. ActorID is
// the client IP; there is usually no authenticated session yet at this
// layer (login/callback trip before auth even succeeds, and the global
// backstop wraps the whole mux before any handler has parsed a session).
func rateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, label string, window time.Duration, max int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		key := "ratelimit:" + label + ":" + ip
		count, err := vk.IncrExpire(r.Context(), key, window)
		if err != nil {
			log.Printf("main: rate limit check failed (failing open): %v", err)
			next.ServeHTTP(w, r)
			return
		}
		if count > max {
			// Logged (2026-07-05): previously silent, so a real trip of this
			// limit left zero trace in the logs — reported by a user as
			// "too many requests" with no way to tell which endpoint/label
			// or client IP was actually involved. See IncrExpire's doc
			// comment for the counter-never-resets bug this line's silence
			// was hiding.
			log.Printf("main: rate limit exceeded: label=%q ip=%q count=%d max=%d", label, ip, count, max)
			if masterKey, mkErr := setup.ResolveMasterKey(r.Context(), pool, masterKeyEnv); mkErr == nil {
				if auditErr := audit.Log(r.Context(), pool, masterKey, audit.LogParams{
					EventType: audit.EventRateLimitExceeded,
					ActorID:   ip,
					Details:   fmt.Sprintf(`{"label":%q,"count":%d,"max":%d}`, label, count, max),
				}); auditErr != nil {
					log.Printf("main: audit rate limit exceeded: %v", auditErr)
				}
			}
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// authRateLimitMiddleware is rateLimitMiddleware pinned to the auth-endpoint
// window/budget (kept as a separate name at call sites for readability).
func authRateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, label string, next http.HandlerFunc) http.HandlerFunc {
	return rateLimitMiddleware(vk, pool, masterKeyEnv, "auth:"+label, authRateLimitWindow, authRateLimitMax, next)
}

// globalRateLimitMiddleware wraps an entire http.Handler (not just a single
// HandlerFunc) with the coarse per-IP backstop described above. Applied once,
// around the whole mux, in main. /healthz is deliberately exempt: Docker and
// Traefik healthchecks poll it every few seconds for the container's entire
// lifetime, which would otherwise burn through the same budget as real
// traffic and could self-inflict a false "unhealthy" verdict.
func globalRateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, next http.Handler) http.Handler {
	limited := rateLimitMiddleware(vk, pool, masterKeyEnv, "global", globalRateLimitWindow, globalRateLimitMax, next.ServeHTTP)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		limited(w, r)
	})
}

// clientIP extracts the originating client address for rate-limiting
// purposes. Core sits behind Traefik (see project docs), which sets
// X-Forwarded-For — we take the first (left-most, i.e. original client)
// entry rather than r.RemoteAddr, which would otherwise always resolve to
// Traefik's own address and rate-limit the entire instance as a single
// client. Falls back to RemoteAddr when the header is absent (e.g. direct
// connections in local dev without Traefik in front).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// knownRateLimitLabels lists every label a rate limiter in this codebase
// currently uses (see rateLimitMiddleware's call sites and ai.go's own
// "chat" one). Matched as an exact prefix (label+":") rather than splitting
// a scanned key on its last ":", because an IPv6 client address contains
// colons itself and would otherwise be silently split apart. "chat"'s max is
// left at 0/omitted here rather than resolved from the DB (chatRPMLimit) -
// that's an admin-configurable setting, not a compile-time constant, and
// doing a DB round trip per live key just to fill in a number isn't worth it
// for a diagnostics page; the UI shows count-only for that one label.
var knownRateLimitLabels = []string{"auth:login", "auth:callback", "ai-chat", "global", "chat"}

func rateLimitMax(label string) int64 {
	switch label {
	case "auth:login", "auth:callback":
		return authRateLimitMax
	case "ai-chat":
		return aiChatRateLimitMax
	case "global":
		return globalRateLimitMax
	default:
		return 0
	}
}

// activeRateLimits enumerates every currently-live "ratelimit:*" Valkey key
// for System Info's "rate limits" section — a live counter says whether a
// limit is active right now, which is the one thing the audit-log entries
// (audit.EventRateLimitExceeded) added alongside this can't: those persist
// past the key's own TTL, this doesn't. Best-effort per key: a key that
// disappears between the SCAN and the follow-up Get/TTL calls (its window
// simply elapsed in the meantime) is skipped rather than treated as an
// error, since that's the expected common case, not a failure.
func activeRateLimits(ctx context.Context, vk *valkey.Client) []systemInfoRateLimit {
	keys, err := vk.ScanKeysWithPrefix(ctx, "ratelimit:")
	if err != nil {
		log.Printf("main: system info: scan rate limit keys: %v", err)
		return nil
	}

	limits := make([]systemInfoRateLimit, 0, len(keys))
	for _, key := range keys {
		rest := strings.TrimPrefix(key, "ratelimit:")
		label, identifier := rest, ""
		for _, l := range knownRateLimitLabels {
			if strings.HasPrefix(rest, l+":") {
				label = l
				identifier = strings.TrimPrefix(rest, l+":")
				break
			}
		}

		valueStr, ok, err := vk.Get(ctx, key)
		if err != nil || !ok {
			continue
		}
		count, err := strconv.ParseInt(valueStr, 10, 64)
		if err != nil {
			continue
		}

		ttl, ok, err := vk.TTL(ctx, key)
		if err != nil || !ok {
			continue
		}

		limits = append(limits, systemInfoRateLimit{
			Key:            key,
			Label:          label,
			Identifier:     identifier,
			Count:          count,
			Max:            rateLimitMax(label),
			ResetInSeconds: int64(ttl / time.Second),
		})
	}

	// Highest count first - whichever client is closest to (or already
	// past) its limit is the most actionable row, regardless of label.
	sort.Slice(limits, func(i, j int) bool { return limits[i].Count > limits[j].Count })
	return limits
}

// resetRateLimitHandler serves DELETE /v1/admin/system/rate-limits
// (super-admin only) - the reset button next to each row in System Info's
// live rate-limit table, for the rare case a client gets stuck (e.g. the
// counter-never-resets bug IncrExpire's doc comment describes) or an admin
// just wants to manually clear a legitimate trip early. Takes the exact
// Valkey key from the request body rather than reconstructing it from
// separate label/identifier fields, so activeRateLimits above stays the only
// place that knows how these keys are shaped. The "ratelimit:" prefix check
// is required, not optional - without it this becomes a generic "delete any
// Valkey key" primitive, which must never be reachable from an HTTP body.
func resetRateLimitHandler(vk *valkey.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(body.Key, "ratelimit:") {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		if err := vk.Del(r.Context(), body.Key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// systemInfoTimer describes the registry-sync loop's schedule so the
// frontend can render a "next run in X" countdown instead of the admin
// wondering whether it's running at all. A registry sync also drives the
// next installed-module update check (see modules.RunUpdateCheckOnce) - the
// two are the same event as far as an admin needs to know, which is why
// there is only one of these in the response, not one per background loop.
// LastRunAt/NextRunAt are nil until the loop has completed its first pass
// (in practice within a second or two of Core starting, since it runs once
// immediately at boot before starting its ticker).
type systemInfoTimer struct {
	LastRunAt       *string `json:"last_run_at,omitempty"`
	NextRunAt       *string `json:"next_run_at,omitempty"`
	IntervalSeconds int64   `json:"interval_seconds"`
}

// systemInfoModule is one row of the installed-module table on the System
// Info page — the same fields ModulesPage.tsx already shows, bundled here so
// an admin gets one page for "what's the state of everything" instead of
// needing to cross-reference Installed Modules separately.
type systemInfoModule struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	AvailableVersion string `json:"available_version,omitempty"`
	Status           string `json:"status"`
	Source           string `json:"source"`
	Pinned           bool   `json:"pinned"`
	Tier             int    `json:"tier"`
}

// systemInfoResponse is the JSON body of GET /v1/admin/system/info.
type systemInfoResponse struct {
	Version           string             `json:"version"`
	UptimeSeconds     int64              `json:"uptime_seconds"`
	PostgresReachable bool               `json:"postgres_reachable"`
	ValkeyReachable   bool               `json:"valkey_reachable"`
	SearxngConfigured bool               `json:"searxng_configured"`
	SearxngReachable  *bool              `json:"searxng_reachable,omitempty"`
	NTPDriftOK        *bool              `json:"ntp_drift_ok,omitempty"`
	RegistrySync      systemInfoTimer    `json:"registry_sync"`
	Modules           []systemInfoModule `json:"modules"`

	// LatestCoreVersion/CoreUpdateAvailable: best-effort check against
	// modulab-core's own GitHub releases, reusing the same
	// store.FetchLatestRelease call the module registry sync already uses
	// for community modules - Core checking its own repo the same way it
	// checks every module's is one code path, not two. Nil/false when the
	// check failed (offline homelab, GitHub rate limit, etc.) rather than
	// blocking the page - same "nil = unknown" convention as SearxngReachable
	// and NTPDriftOK above.
	LatestCoreVersion  string `json:"latest_core_version,omitempty"`
	CoreUpdateAvailable bool  `json:"core_update_available"`

	// ActiveSessions lists every currently active session (one per logged-in
	// browser tab/device, not per user - see auth.ListActiveSessions' doc
	// comment). Nil if the underlying SCAN failed outright; individual
	// undecryptable/expired-between-scan-and-read entries are just skipped
	// rather than failing the whole list.
	ActiveSessions []auth.ActiveSession `json:"active_sessions,omitempty"`

	// TLSCertExpiresAt/TLSCertDaysLeft: read from a live TLS handshake
	// against Traefik (see internal/tlscheck), not from acme.json directly -
	// that file lives in a Docker volume only Traefik's container mounts,
	// and it holds the private key alongside the cert, so reading it from
	// Core would mean either sharing that volume (a real secret) or parsing
	// Traefik's internal storage format. Dialing the already-public TLS
	// endpoint and reading the handshake's own certificate is the same
	// technique any external uptime/cert monitor uses, and it works
	// regardless of what's actually terminating TLS. Nil when the check
	// itself couldn't run (e.g. local dev without Traefik in front).
	TLSCertExpiresAt *string `json:"tls_cert_expires_at,omitempty"`
	TLSCertDaysLeft  *int    `json:"tls_cert_days_left,omitempty"`

	// RateLimits: every currently-live rate-limit counter (see
	// rateLimitMiddleware/activeRateLimits), added 2026-07-05 after a "too
	// many requests" report that turned out to be a stuck counter with
	// nothing in the logs to explain it. Nil if the underlying Valkey SCAN
	// failed outright.
	RateLimits []systemInfoRateLimit `json:"rate_limits,omitempty"`
}

// systemInfoRateLimit is one row of System Info's "rate limits" table - one
// currently-live Valkey counter from rateLimitMiddleware (or ai.go's
// per-user chat limiter). Key is the raw Valkey key, exposed so the reset
// button can name exactly what to delete without the frontend needing to
// reconstruct it from the other fields.
type systemInfoRateLimit struct {
	Key            string `json:"key"`
	Label          string `json:"label"`
	Identifier     string `json:"identifier"`
	Count          int64  `json:"count"`
	Max            int64  `json:"max,omitempty"`
	ResetInSeconds int64  `json:"reset_in_seconds"`
}

// bearerToken extracts the raw token from an "Authorization: Bearer ..."
// header - header-only, deliberately not the query-parameter fallback
// auth.BearerTokenAllowQuery offers for asset-serving GETs (see that
// function's doc comment on why a token in the URL is worse here): every
// request to this admin JSON endpoint already comes from the SPA via the
// header, same as auth's own unexported bearerToken this duplicates -
// can't call that one directly since it is unexported.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

// systemInfoHandler serves GET /v1/admin/system/info (super-admin only).
// Reuses the same best-effort checks as /healthz for the shared fields
// (dependency reachability, NTP drift, SearXNG) rather than duplicating a
// second, subtly-different implementation of each — the difference here is
// the registry-sync countdown and the per-module version table, neither of
// which /healthz carries since it's meant to stay a cheap, unauthenticated
// monitoring probe.
func systemInfoHandler(pool *db.Pool, valkeyClient *valkey.Client, cfg config.Config, startTime time.Time, storeDeps store.Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()

		resp := systemInfoResponse{
			Version:           version.Version,
			UptimeSeconds:     int64(time.Since(startTime).Seconds()),
			PostgresReachable: pool.Ping(ctx) == nil,
			ValkeyReachable:   valkeyClient.Ping(ctx) == nil,
		}

		if configured, err := searxng.IsConfigured(ctx, pool, cfg.MasterKey); err == nil {
			resp.SearxngConfigured = configured
			if configured {
				if rawURL, _, err := searxng.ResolveURLPublic(ctx, pool, cfg.MasterKey); err == nil {
					up := searxng.Ping(ctx, rawURL)
					resp.SearxngReachable = &up
				}
			}
		}

		if ok, err := ntpcheck.DriftOK(30 * time.Second); err == nil {
			resp.NTPDriftOK = &ok
		}

		// Core's own update check - reuses the exact same GitHub Releases
		// lookup CheckUpdates already uses for community modules, just
		// pointed at modulab-core's own repo instead of an installed
		// module's source_repo. version.Version has no leading "v" (see that
		// constant's doc comment); GitHub release tags conventionally do, so
		// both sides are normalized before comparing.
		if latest, err := store.FetchLatestRelease(ctx, "https://github.com/modulab-project/modulab-core"); err == nil && latest != "" {
			normalized := strings.TrimPrefix(strings.TrimSpace(latest), "v")
			resp.LatestCoreVersion = normalized
			resp.CoreUpdateAvailable = normalized != version.Version
		}

		// Active sessions: who's currently logged in and from how many
		// tabs/devices (see auth.ActiveSession's doc comment for exactly
		// what's shown) - best-effort, nil if the underlying SCAN failed.
		// The viewing admin's own row is flagged Current by recomputing
		// SessionID from this same request's own bearer token - only the
		// caller holding that token can know which row is "you", so this
		// can't happen inside ListActiveSessions itself.
		if sessions, err := auth.ListActiveSessions(ctx, authDeps); err == nil {
			if ownID := auth.SessionID(bearerToken(r)); ownID != "" {
				for i := range sessions {
					if sessions[i].ID == ownID {
						sessions[i].Current = true
						break
					}
				}
			}
			resp.ActiveSessions = sessions
		}

		// TLS certificate expiry - see internal/tlscheck's doc comment for
		// why this dials the reverse proxy directly instead of reading
		// Traefik's acme.json. serverName comes from PublicBaseURL so a
		// multi-vhost proxy returns the same certificate a real browser
		// would see; the dial target is the internal Docker address
		// (cfg.TLSCheckAddr), not that hostname itself.
		if u, err := url.Parse(cfg.PublicBaseURL); err == nil && u.Hostname() != "" {
			if expiry, err := tlscheck.Expiry(ctx, cfg.TLSCheckAddr, u.Hostname()); err == nil {
				expiryStr := expiry.UTC().Format(time.RFC3339)
				daysLeft := int(time.Until(expiry).Hours() / 24)
				resp.TLSCertExpiresAt = &expiryStr
				resp.TLSCertDaysLeft = &daysLeft
			}
		}

		// Registry sync (1h) - also drives the next installed-module update
		// check, see systemInfoTimer's doc comment. last_synced_at is already
		// persisted in module_registry (used by GET /v1/store today), so no
		// extra in-memory tracking is needed for this one.
		syncInterval := store.SyncInterval()
		resp.RegistrySync = systemInfoTimer{IntervalSeconds: int64(syncInterval / time.Second)}
		if lastSync, err := store.LastSyncedAt(ctx, pool); err == nil && !lastSync.IsZero() {
			lastStr := lastSync.UTC().Format(time.RFC3339)
			nextStr := lastSync.Add(syncInterval).UTC().Format(time.RFC3339)
			resp.RegistrySync.LastRunAt = &lastStr
			resp.RegistrySync.NextRunAt = &nextStr
		}

		resp.RateLimits = activeRateLimits(ctx, valkeyClient)

		if installed, err := pool.ListInstalledModules(ctx); err == nil {
			resp.Modules = make([]systemInfoModule, 0, len(installed))
			for _, m := range installed {
				mi := systemInfoModule{
					Name:    m.Name,
					Version: m.Version,
					Status:  m.Status,
					Source:  m.Source,
					Pinned:  m.Pinned,
					Tier:    m.Tier,
				}
				if m.AvailableVersion != nil {
					mi.AvailableVersion = *m.AvailableVersion
				}
				resp.Modules = append(resp.Modules, mi)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// revokeSessionHandler serves DELETE /v1/admin/sessions/{id} (super-admin
// only) - the System Info page's per-row "end session" button. id is
// auth.SessionID(token), never the token itself (see ActiveSession's doc
// comment), so ending a session an admin can see in that table never
// requires the raw bearer token to have left Valkey in the first place.
// Deliberately does not stop an admin from ending their own current
// session this way - closing your own only tab is equivalent to logging
// out, just from an unusual place to do it.
func revokeSessionHandler(authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing session id", http.StatusBadRequest)
			return
		}
		found, err := auth.RevokeSessionByID(r.Context(), authDeps, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// corsMiddleware allows cfg.FrontendBaseURL's origin to call every route on
// mux from a different origin than Core's own. This only matters in local
// dev, where Vite's dev server (FrontendBaseURL) and Core (HTTPAddr) run on
// different ports - same-origin browsers never trigger CORS preflights in
// the first place, so this is a no-op once frontend and backend are served
// from the same production origin. Allowing exactly one configured origin
// (rather than "*") keeps this from becoming an accidental open API. DELETE
// is allowed alongside GET/POST/OPTIONS for DeleteUserHandler above.
func corsMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+bootstrap.HeaderName)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
