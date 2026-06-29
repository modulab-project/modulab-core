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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	ntpcheck "github.com/modulab-project/modulab-core/backend/internal/ntp"
	"github.com/modulab-project/modulab-core/backend/internal/quicklinks"
	"github.com/modulab-project/modulab-core/backend/internal/searxng"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/store"
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

	ctx := context.Background()

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
	defer valkeyClient.Close()

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
		// handler's shape consistent with DNS-challenge configure below.
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		setup.OIDCConfigureHandler(pool, masterKey)(w, r)
	})))

	mux.Handle("/v1/setup/dns-challenge/status", bootstrapMgr.Middleware(setup.DNSChallengeStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("/v1/setup/dns-challenge/configure", bootstrapMgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same master-key dependency as the OIDC step above, for the same
		// reason: the DNS-challenge provider's credentials are encrypted
		// with it before being persisted.
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		setup.DNSChallengeConfigureHandler(pool, masterKey)(w, r)
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
	mux.HandleFunc("/v1/auth/login", auth.LoginHandler(authDeps))
	mux.HandleFunc("/v1/auth/callback", auth.CallbackHandler(authDeps))
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
	// bootstrapMgr.Middleware the way OIDC/DNS-challenge below are.
	// Super-admin only (auth.RequireSuperAdminMiddleware), same level as
	// OIDC configuration. The configure handler resolves the master key
	// per-request, same reasoning as the OIDC/DNS-challenge configure
	// handlers above: it can't actually fail in practice (no DB fallback
	// left to resolve), kept this shape purely for consistency.
	superAdminOnly := auth.RequireSuperAdminMiddleware(authDeps)
	mux.Handle("GET /v1/admin/smtp/status", superAdminOnly(setup.SMTPStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/smtp/test", superAdminOnly(setup.SMTPTestHandler()))
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

	// Admin system page + OIDC/DNS-challenge post-wizard config + audit log.
	// All super-admin only (same tier as SMTP above).
	mux.Handle("GET /v1/admin/system", superAdminOnly(adminapi.SystemStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("PATCH /v1/admin/oidc", superAdminOnly(adminapi.OIDCUpdateHandler(pool, cfg.MasterKey)))
	mux.Handle("PATCH /v1/admin/dns-challenge", superAdminOnly(adminapi.DNSChallengeUpdateHandler(pool, cfg.MasterKey)))
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
	mux.HandleFunc("GET /v1/ai/providers", ai.UserProvidersHandler(authDeps))
	mux.HandleFunc("PUT /v1/ai/keys/{id}", ai.UserSetKeyHandler(authDeps))
	mux.HandleFunc("DELETE /v1/ai/keys/{id}", ai.UserDeleteKeyHandler(authDeps))
	mux.HandleFunc("PATCH /v1/ai/keys/{id}/model", ai.UserSetPreferredModelHandler(authDeps))
	mux.HandleFunc("GET /v1/ai/keys/{id}/models", ai.UserListModelsHandler(authDeps))
	mux.HandleFunc("POST /v1/ai/chat", ai.ChatHandler(authDeps))

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
	storeDeps := store.Deps{Pool: pool, Valkey: valkeyClient}
	go store.RunSync(ctx, storeDeps)

	// Store browse endpoints (spec section 4.10).
	// GET /v1/store and GET /v1/store/{name} require any active session.
	// POST /v1/store/sync requires org-admin or super-admin.
	mux.HandleFunc("GET /v1/store", store.ListHandler(storeDeps, authDeps))
	mux.HandleFunc("GET /v1/store/{name}", store.DetailHandler(storeDeps, authDeps))
	mux.HandleFunc("POST /v1/store/sync", store.SyncHandler(storeDeps, authDeps))

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

	moduleDeps := modules.Deps{
		DB:        pool,
		DataDir:   cfg.ModuleDataDir,
		CosignBin: cfg.CosignBinaryPath,
		Workers:   workerPool,
	}

	// At startup, restart Deno workers for all Tier 2/3 modules that were
	// active before the last shutdown.
	if installedAtBoot, err := pool.ListInstalledModules(ctx); err == nil {
		for _, row := range installedAtBoot {
			if row.Tier >= 2 && row.Status == "active" {
				entrypoint := ""
				if row.Manifest != nil {
					var mf struct{ Handler string `json:"handler"` }
					if json.Unmarshal(row.Manifest, &mf) == nil {
						entrypoint = cfg.ModuleDataDir + "/" + row.Name + "/" + mf.Handler
					}
				}
				if entrypoint != "" {
					if err := workerPool.Start(row.Name, entrypoint); err != nil {
						log.Printf("main: startup: could not start worker for %q: %v", row.Name, err)
					}
				}
			}
		}
	}

	mux.HandleFunc("GET /v1/modules", modules.ListInstalledHandler(moduleDeps, authDeps))
	mux.HandleFunc("GET /v1/modules/updates", modules.CheckUpdatesHandler(moduleDeps, storeDeps, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}", modules.GetInstalledHandler(moduleDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/install", modules.InstallHandler(moduleDeps, storeDeps, authDeps))
	mux.HandleFunc("DELETE /v1/modules/{name}", modules.UninstallHandler(moduleDeps, authDeps))
	mux.HandleFunc("POST /v1/modules/{name}/update", modules.UpdateModuleHandler(moduleDeps, storeDeps, authDeps))
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
	// No graceful-shutdown plumbing exists anywhere else in main.go yet
	// (ListenAndServe below just blocks until it errors), so this matches
	// that same level of simplicity rather than introducing
	// signal.NotifyContext just for this one goroutine.
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
	if err := http.ListenAndServe(cfg.HTTPAddr, handler); err != nil {
		log.Fatalf("server: %v", err)
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
func secHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
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
