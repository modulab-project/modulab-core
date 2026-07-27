// Command core is the entry point for the modulab-core backend.
//
// Wires up HTTP routing, admin endpoints (internal/auth/admin.go), the
// module installation/update pipeline, and the Deno worker pool
// (internal/modules/deno.go) that supervises module subprocesses.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
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
	"github.com/modulab-project/modulab-core/backend/internal/coreupdate"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/mail"
	"github.com/modulab-project/modulab-core/backend/internal/modules"
	"github.com/modulab-project/modulab-core/backend/internal/news"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	ntpcheck "github.com/modulab-project/modulab-core/backend/internal/ntp"
	"github.com/modulab-project/modulab-core/backend/internal/quicklinks"
	"github.com/modulab-project/modulab-core/backend/internal/search"
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

	// One-time move from the old single-provider SearXNG settings into the
	// search_providers table (also seeds a disabled Serper.dev row). No-op
	// once already migrated - see MigrateSearchProviders's doc comment.
	if err := pool.MigrateSearchProviders(ctx); err != nil {
		log.Printf("search: could not migrate search providers: %v", err)
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
		// SearXNG is optional: only check reachability when a base URL is
		// saved. GetSearchProviderBaseURL is a fast DB lookup; the Ping adds
		// ~1 RTT on the internal network (same order of magnitude as the
		// Postgres/Valkey checks). Kept as its own healthz field (rather than
		// generalized to "any configured search provider") since SearXNG is
		// the only provider type with an admin-chosen network address worth
		// probing this way - Serper is a fixed public API host.
		if baseURL, configured, err := pool.GetSearchProviderBaseURL(r.Context(), db.DefaultSearchProviderID); err == nil {
			status.SearXNGConfigured = configured
			if configured {
				up := searxng.Ping(r.Context(), baseURL)
				status.SearXNGUp = &up
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

	// CSP violation reports (secHeadersMiddleware's report-uri/report-to
	// directives, cspReportHandler's own doc comment for the full
	// rationale) - deliberately public/unauthenticated, same reasoning as
	// /healthz above: a violation can be reported from a page a browser
	// hasn't logged in on yet.
	mux.HandleFunc("POST /v1/csp-report", cspReportHandler())

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
	mux.Handle("/v1/setup/group-prefix/configure", bootstrapMgr.Middleware(setup.GroupPrefixConfigureHandler(pool, cfg.MasterKey)))

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
	// Self-service "my devices" (Profile page) - any approved session can
	// list and end its OWN active sessions, no admin role required. Distinct
	// from the super-admin-only GET /v1/admin/system/info active-sessions
	// table and DELETE /v1/admin/sessions/{id} below: those can act on
	// anyone's session, these two are scoped to the caller's own by
	// RevokeOwnSessionByID's ownership check (see auth/mysessions.go).
	mux.HandleFunc("GET /v1/auth/sessions", auth.MySessionsHandler(authDeps))
	mux.HandleFunc("DELETE /v1/auth/sessions/{id}", auth.RevokeMySessionHandler(authDeps))
	// Rate-limited the same as login/callback (2026-07-15 security review):
	// reuses authRateLimitMiddleware/auth_rate_limit_max rather than a
	// dedicated logout_rate_limit_max setting - logout has far less abuse
	// potential than login (nothing to brute-force, no IdP round-trip to
	// exhaust), so a second configurable knob for it isn't worth the extra
	// admin-UI/settings surface. Falls back to the global 600/min backstop
	// like every other route if this were ever removed.
	mux.HandleFunc("/v1/auth/logout", authRateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, "logout", auth.LogoutHandler(authDeps)))
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
	// Step-up variant (auth.RequireSuperAdminReauthMiddleware): same role
	// check as superAdminOnly, plus requireRecentLogin's reauth gate - see
	// that middleware's doc comment for exactly why these particular
	// routes (SMTP write/delete, OIDC write/delete below) get it and the
	// read-only/reversible super-admin routes around them do not.
	superAdminReauthOnly := auth.RequireSuperAdminReauthMiddleware(authDeps)
	mux.Handle("GET /v1/admin/smtp/status", superAdminOnly(setup.SMTPStatusHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/smtp/test", superAdminOnly(setup.SMTPTestHandler(pool, cfg.MasterKey)))
	mux.Handle("POST /v1/admin/smtp/configure", superAdminReauthOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.Handle("DELETE /v1/admin/smtp", superAdminReauthOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.Handle("PATCH /v1/admin/oidc", superAdminReauthOnly(adminapi.OIDCUpdateHandler(pool, cfg.MasterKey)))
	mux.Handle("DELETE /v1/admin/oidc", superAdminReauthOnly(adminapi.OIDCDeleteHandler(pool, cfg.MasterKey)))
	mux.Handle("GET /v1/audit-log", superAdminOnly(adminapi.AuditLogHandler(pool, cfg.MasterKey)))
	mux.Handle("GET /v1/audit-log/verify", superAdminOnly(adminapi.AuditVerifyHandler(pool, cfg.MasterKey)))
	mux.Handle("GET /v1/audit-log/actors", superAdminOnly(adminapi.AuditActorsHandler(pool)))
	// Cross-cutting operational limits (upload/body size caps, rate limits,
	// Deno worker pool size) - see adminapi.AdminLimitsHandler's package doc
	// comment for why these were consolidated into one endpoint.
	mux.Handle("GET /v1/admin/system/limits", superAdminOnly(adminapi.AdminLimitsHandler(pool, cfg.MasterKey)))
	mux.Handle("PATCH /v1/admin/system/limits", superAdminOnly(adminapi.AdminLimitsHandler(pool, cfg.MasterKey)))

	// Widget endpoints (spec section 8 / Home page). Not wrapped in any
	// auth middleware: weather data is not sensitive, and the 15-minute
	// Valkey cache (internal/weather) limits upstream Open-Meteo calls to
	// one per location per interval regardless of how many users load the
	// page simultaneously. lat and lon come from the browser's own
	// Geolocation API - Core never stores or logs them.
	mux.HandleFunc("GET /v1/widgets/weather", weather.Handler(valkeyClient))
	// Reverse-geocodes the same lat/lon into a short place name via
	// Nominatim (OpenStreetMap) - same trust model as the weather endpoint
	// above (no auth, coordinates never stored/logged), just a much longer
	// cache TTL since a place name doesn't go stale the way weather does.
	mux.HandleFunc("GET /v1/widgets/weather/location", weather.LocationHandler(valkeyClient))
	// Admin-configurable geolocation timeout (see AdminLimitsHandler /
	// geo_timeout_ms) - the frontend needs this before it can even request a
	// position fix, so it can't just ride along with the two handlers above.
	mux.HandleFunc("GET /v1/widgets/weather/geo-config", weather.GeoConfigHandler(pool))

	// Web-search proxy (spec section 6.4, search widget). Backed by one or
	// more configurable providers (SearXNG, Serper.dev, ...) - see
	// internal/search's package doc comment. Admin configuration: super-admin
	// only (same tier as SMTP/AI providers). Search endpoint: any approved
	// session - resolves the active provider(s) and returns normalized JSON
	// results regardless of which one answered.
	mux.Handle("GET /v1/admin/search/providers", superAdminOnly(search.AdminListProvidersHandler(authDeps)))
	// Providers are pre-seeded, not admin-created (see patchProviderRequest's
	// doc comment) - so unlike AI providers there's no separate reauth-free
	// "create" case here; PATCH can touch the stored key, so it and the
	// dedicated key-clear route are both reauth-gated (2026-07-22).
	mux.Handle("PATCH /v1/admin/search/providers/{id}", superAdminReauthOnly(search.AdminPatchProviderHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/search/providers/{id}/key", superAdminReauthOnly(search.AdminClearProviderKeyHandler(authDeps)))
	mux.Handle("GET /v1/admin/search/settings", superAdminOnly(search.AdminSettingsHandler(authDeps)))
	mux.Handle("PATCH /v1/admin/search/settings", superAdminOnly(search.AdminSettingsHandler(authDeps)))
	mux.HandleFunc("GET /v1/search/web", search.SearchHandler(authDeps))
	mux.HandleFunc("GET /v1/search/providers", search.UserProvidersHandler(authDeps))
	mux.HandleFunc("PUT /v1/user/search/keys/{id}", search.UserSetKeyHandler(authDeps))
	mux.HandleFunc("DELETE /v1/user/search/keys/{id}", search.UserDeleteKeyHandler(authDeps))
	mux.HandleFunc("GET /v1/user/search-prefs", search.SearchPrefsHandler(authDeps))
	mux.HandleFunc("POST /v1/user/search-prefs", search.SearchPrefsHandler(authDeps))

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
	//
	// There used to be a GET/PATCH /v1/admin/ai/settings pair here
	// (ai.AdminSettingsHandler) for chat_rpm_limit — removed once that single
	// field moved to GET/PATCH /v1/admin/system/limits alongside its sibling
	// ai_chat_ip_rate_limit_max (see adminapi.AdminLimitsHandler).
	mux.Handle("GET /v1/admin/ai/providers", superAdminOnly(ai.AdminListHandler(authDeps)))
	// Create stays reauth-free ("anlegen" case) - PATCH/DELETE/clear-key are
	// reauth-gated (2026-07-22): adding a new provider is lower-risk than
	// changing or removing an already-trusted one's stored API key, same
	// create-vs-change/delete split as the custom module sources below.
	mux.Handle("POST /v1/admin/ai/providers", superAdminOnly(ai.AdminCreateHandler(authDeps)))
	mux.Handle("PATCH /v1/admin/ai/providers/{id}", superAdminReauthOnly(ai.AdminPatchHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/ai/providers/{id}", superAdminReauthOnly(ai.AdminDeleteHandler(authDeps)))
	mux.Handle("DELETE /v1/admin/ai/providers/{id}/key", superAdminReauthOnly(ai.AdminClearKeyHandler(authDeps)))
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
	mux.HandleFunc("POST /v1/ai/chat", rateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, "ai-chat", aiChatRateLimitWindow, aiChatRateLimitMax, identifyByIP, ai.ChatHandler(authDeps)))

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

	// Custom module source management (admin brainstorm 2026-07-16): lets an
	// admin add arbitrary GitHub repos as a third Store source alongside
	// official/community, HACS-style. Admin-only for both read and write -
	// unlike GET /v1/store above, the source list itself (repo URLs, who
	// added them) is not exposed to plain active sessions.
	//
	// Elevated from org-admin/super-admin to super-admin-only (2026-07-22):
	// a GitHub token plus the ability to point Core at arbitrary third-party
	// code is a higher-value target than typical org-admin-level config.
	// GET/POST stay reauth-free (listing, and "anlegen" per the same policy
	// as the AI provider create route above); PATCH (edit - e.g. rotating a
	// Cosign key) and DELETE are reauth-gated, same reasoning as locking a
	// user or deleting an AI provider's key.
	mux.Handle("GET /v1/admin/store/custom-sources", superAdminOnly(store.ListCustomSourcesHandler(storeDeps, authDeps)))
	mux.Handle("POST /v1/admin/store/custom-sources", superAdminOnly(store.AddCustomSourceHandler(storeDeps, authDeps)))
	mux.Handle("PATCH /v1/admin/store/custom-sources/{id}", superAdminReauthOnly(store.UpdateCustomSourceHandler(storeDeps, authDeps)))
	mux.Handle("DELETE /v1/admin/store/custom-sources/{id}", superAdminReauthOnly(store.DeleteCustomSourceHandler(storeDeps, authDeps)))

	// Module management endpoints (spec section 4.6–4.9).
	// List/detail: any active session. Install/uninstall/update/pin: org-admin+.
	// Note: GET /v1/modules/updates is registered before GET /v1/modules/{name}
	// so the literal path wins over the wildcard in Go's 1.22 ServeMux.
	// dbURL for Deno workers: no sslmode param here because postgres.js
	// (npm:postgres@3) uses its own TLS defaults. The search_path is added
	// per-module in WorkerPool.Start so each worker sees only its own schema.
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	// deno_conn_pool_size is only read here, at startup - see
	// modules.ConnPoolSize's doc comment for why a running worker's pool
	// can't be resized without restarting it.
	workerPool := modules.NewWorkerPool(cfg.ModuleDataDir, dbURL, cfg.ModulePIIKey, modules.ConnPoolSize(ctx, pool))
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
		PIIKey:    cfg.ModulePIIKey,
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

	// Core's own GitHub-release update check (internal/coreupdate): unlike
	// the registry sync above (fixed interval), this runs on an
	// admin-configurable weekday+time schedule (core_update_check_weekdays/
	// _time, default every day at 03:00 - see coreupdate's doc comments),
	// and notifies only super-admin sessions (notify.SuperAdminChannel), not
	// every org-admin, since Core/system settings are a super-admin-only
	// concern elsewhere in this app already. The manual "check now" route
	// below (adjacent to systemInfoHandler's registration further down)
	// lets an admin trigger the same check on demand instead of waiting for
	// the next scheduled tick.
	go coreupdate.RunScheduler(ctx, pool, valkeyClient)

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

	// POST /v1/admin/system/core-update-check — manual trigger for
	// coreupdate.CheckNow, alongside the scheduled weekday+time check
	// (coreupdate.RunScheduler, started above). Lets an admin get an
	// immediate answer (and, if a new version just shipped, the SSE
	// notification) right after changing the schedule, instead of waiting
	// for the next scheduled tick.
	mux.Handle("POST /v1/admin/system/core-update-check", superAdminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := coreupdate.CheckNow(r.Context(), pool, valkeyClient)
		if err != nil {
			http.Error(w, "check failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})))
	// Reauth-gated (not just superAdminOnly, 2026-07-22): forcibly ending
	// another user's session has the same immediate, hard-to-undo-for-them
	// effect as locking their account, which already gets this step-up
	// treatment - a compromised-but-still-within-SessionTTL admin session
	// shouldn't be able to kick people off any more than it should be able
	// to lock them.
	mux.Handle("DELETE /v1/admin/sessions/{id}", superAdminReauthOnly(revokeSessionHandler(authDeps)))
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
	mux.HandleFunc("POST /v1/modules/install-manual", modules.InstallManualHandler(moduleDeps, authDeps))
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

	// Periodically re-checks every active session's stored refresh token
	// against the configured OIDC provider, revoking sessions the IdP no
	// longer honors (account disabled/deleted/revoked there) instead of
	// letting them keep working here for up to SessionTTL (24h) - see
	// auth/revalidate.go's doc comment. Same unconditional-start pattern as
	// mail.RunWorker above: a tick before OIDC is configured is a logged
	// no-op, not fatal.
	go auth.RunSessionRevalidateWorker(ctx, authDeps)

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
	handler = globalRateLimitMiddleware(valkeyClient, pool, cfg.MasterKey, authDeps, handler)
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
		key    string
		oldVal string
		newVal string
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

// maxBodyMiddleware caps every non-upload request body using the
// max_body_bytes setting stored in core_settings (default 1 MB; 0 =
// unlimited). The limit is read from the database on every request so
// changes via PATCH /v1/admin/system/limits take effect immediately without
// a restart.
//
// multipart/form-data requests are exempt: every file-upload handler in
// Core (modules.ModuleProxyHandler's photo/image uploads, news.go's OPML
// importer, modules.InstallManualHandler's module ZIP upload) already parses
// its own body with its own, separately-configured limit via
// http.MaxBytesReader/ParseMultipartForm. Nesting this generic cap
// underneath those silently wins whenever it happens to be the smaller of
// the two — which is exactly what made every module photo upload over
// ~1 MB fail with a connection-reset 502 before this exemption existed
// (found 2026-07-07 chasing intermittent photo-upload failures in the
// my-place module that turned out to reproduce consistently above
// ~1024 KB, tracing back to this middleware wrapping r.Body before
// ModuleProxyHandler's own, much larger limit ever got a chance to apply).
// See adminapi.AdminLimitsHandler's doc comment for the full set of
// upload-specific limits this now defers to.
//
// The Content-Length pre-check (rather than only relying on
// http.MaxBytesReader tripping mid-stream) matters for the same reason:
// MaxBytesReader doesn't send a clean response when the limit is hit — it
// fails the next Read() and the Go server then closes the connection to
// avoid reading a request body it doesn't intend to trust, which is
// indistinguishable from a crash to any reverse proxy in front of Core and
// surfaces to the client as a bare 502 instead of a real status code.
// Checking Content-Length upfront (when the client sent one, which every
// browser fetch()/XHR upload does) rejects oversized requests with a clean
// 413 before a single body byte is read, so there's no mid-stream
// connection to abort in the first place.
func maxBodyMiddleware(pool *db.Pool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaType == "multipart/form-data" {
			next.ServeHTTP(w, r)
			return
		}
		limit := ai.MaxBodyBytes(r.Context(), pool)
		if limit > 0 {
			if r.ContentLength > limit {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
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
		// report-to/report-uri (added alongside cspReportHandler below): CSP
		// has blocked violations silently since this header was first
		// introduced - a real XSS attempt hitting it would leave no trace
		// anywhere an operator would think to look. report-uri is the
		// still-universally-supported legacy directive; report-to is the
		// modern replacement Chrome now prefers, which needs the separate
		// Reporting-Endpoints header below to name what "csp-endpoint"
		// actually points at. Sending both costs nothing extra (a browser
		// that understands report-to ignores report-uri, and vice versa)
		// and covers every browser either way.
		w.Header().Set("Reporting-Endpoints", `csp-endpoint="/v1/csp-report"`)
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; "+
				"script-src 'self'; "+
				// Split the same way as deploy/nginx.conf's CSP (2026-07-23
				// security pass, keep in sync - see that file's comment for
				// the reasoning): style-src-elem blocks injected <style>
				// blocks/<link>s (the actual CSS-exfiltration/selector-abuse
				// vector), style-src-attr keeps 'unsafe-inline' since a bare
				// style="..." attribute can't carry attacker-controlled
				// selectors on its own.
				"style-src-elem 'self'; "+
				"style-src-attr 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"object-src 'none'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"report-uri /v1/csp-report; "+
				"report-to csp-endpoint")
		// Permissions-Policy: default-deny every powerful browser feature,
		// then allow back exactly the three a module actually uses -
		// geolocation (my-place's MapLibre view), clipboard-write (copy
		// buttons), fullscreen (map view's fullscreen control). Scoped to
		// (self) only, never a third-party origin: modules run in this same
		// top-level document (no iframe sandbox yet - see the module-token
		// work in auth/moduletoken.go), so (self) already covers every
		// module's own UI. Camera/microphone/payment/usb/midi/sensors are
		// denied outright - nothing in ModuLab or any current module uses
		// them, so there is no cost to closing them off.
		w.Header().Set("Permissions-Policy",
			"geolocation=(self), clipboard-write=(self), fullscreen=(self), "+
				"camera=(), microphone=(), payment=(), usb=(), midi=(), "+
				"magnetometer=(), gyroscope=(), accelerometer=()")
		next.ServeHTTP(w, r)
	})
}

// cspReportMaxBodyBytes caps how much of a single CSP violation report body
// this handler will read - a real violation report (legacy or Reporting
// API shape) is a few hundred bytes at most; this is purely a backstop
// against a malicious or malfunctioning caller posting an oversized body to
// this deliberately unauthenticated endpoint.
const cspReportMaxBodyBytes = 16 * 1024

// cspReportHandler is POST /v1/csp-report, the target of secHeadersMiddleware's
// report-uri/report-to CSP directives (see that middleware's doc comment).
// Deliberately unauthenticated - a violation can fire on the login page
// itself, before any session exists - and covered only by the global rate
// limit backstop every route already gets (globalRateLimitMiddleware),
// rather than a bespoke limiter: this is not a high-value target, just an
// endpoint that should not be free to flood the log without any bound.
//
// Browsers send one of two incompatible JSON shapes depending on which of
// the two directives above they honor - the older report-uri POSTs
// {"csp-report": {...}}, the newer Reporting API (report-to) POSTs a JSON
// array of {"type":"csp-violation","body":{...}}. Both are decoded loosely
// into maps rather than strict structs: a browser's exact field set has
// drifted before (camelCase vs kebab-case, fields added/removed across
// versions) and the only thing this handler does with the result is log
// it for an operator to read, so a partial/best-effort parse that still
// surfaces the useful fields beats a strict schema that silently drops an
// entire report over one unexpected field.
func cspReportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, cspReportMaxBodyBytes))
		if err != nil {
			// Still 204: per the Reporting API spec, browsers do not
			// inspect this endpoint's response at all - there is no
			// legitimate retry/backoff behavior on the sending side to
			// preserve by returning an error status instead.
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Legacy report-uri shape: a single object with a "csp-report" key.
		var legacy struct {
			CSPReport map[string]any `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &legacy); err == nil && legacy.CSPReport != nil {
			log.Printf("csp: violation (report-uri): document=%v violated=%v blocked=%v",
				legacy.CSPReport["document-uri"], legacy.CSPReport["violated-directive"], legacy.CSPReport["blocked-uri"])
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Modern Reporting API shape: a JSON array of report objects.
		var reports []struct {
			Type string         `json:"type"`
			Body map[string]any `json:"body"`
		}
		if err := json.Unmarshal(body, &reports); err == nil {
			for _, rep := range reports {
				if rep.Type != "csp-violation" {
					continue
				}
				log.Printf("csp: violation (report-to): document=%v violated=%v blocked=%v",
					rep.Body["documentURL"], rep.Body["effectiveDirective"], rep.Body["blockedURL"])
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
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

// authRateLimitWindow bounds how often a single client IP may hit a
// rate-limited auth endpoint. The window is fixed (unlike the max — see
// authRateLimitMax below) since a tuning need for the window itself hasn't
// come up in practice; only the request-count ceiling has.
const authRateLimitWindow = time.Minute

// authRateLimitMax reads the configured auth-endpoint rate limit ceiling
// from core_settings ("auth_rate_limit_max"). Delegates to
// adminapi.AuthRateLimitMax (2026-07-27) rather than keeping its own copy
// of the "auth_rate_limit_max" key string and its default - main cannot be
// imported by other packages, but nothing stops main from importing
// adminapi (already does, for AdminLimitsHandler itself), so the two no
// longer need to be kept in sync by hand. Found alongside the
// __Host-modulab_session cookie-name bug: same "two independently-hardcoded
// copies" shape, just not yet actually drifted.
func authRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return adminapi.AuthRateLimitMax(ctx, pool)
}

// aiChatRateLimitWindow bounds how often a single client IP may call the AI
// chat proxy — see aiChatRateLimitMax below for the request-count ceiling
// and why it exists on top of ai.go's own separate per-user chat limiter.
const aiChatRateLimitWindow = time.Minute

// aiChatRateLimitMax reads the configured AI-chat per-IP rate limit
// ceiling from core_settings ("ai_chat_ip_rate_limit_max"). This is a
// coarse IP-based backstop layered on top of ai.go's own separate
// per-user "chat_rpm_limit" (ai.go's chatRPMLimit) — not a replacement for
// it. Delegates to adminapi.AIChatIPRateLimitMax - see authRateLimitMax's
// doc comment above for why.
func aiChatRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return adminapi.AIChatIPRateLimitMax(ctx, pool)
}

// globalRateLimitWindow bounds the coarse backstop applied to every route
// except /healthz — see globalRateLimitMax below for the request-count
// ceiling and globalRateLimitMiddleware's doc comment for the full
// rationale.
const globalRateLimitWindow = time.Minute

// globalRateLimitMax reads the configured global rate limit ceiling from
// core_settings ("global_rate_limit_max"). Delegates to
// adminapi.GlobalRateLimitMax - see authRateLimitMax's doc comment above
// for why.
func globalRateLimitMax(ctx context.Context, pool *db.Pool) int64 {
	return adminapi.GlobalRateLimitMax(ctx, pool)
}

// rateLimitMiddleware applies a fixed-window rate limit (via
// valkey.Client.IncrExpire) to a single handler. label distinguishes the
// Valkey key namespace per endpoint/scope (e.g. "login" vs "callback" vs
// "ai-chat" vs "global") so budgets don't bleed into each other. maxFn
// resolves the number of requests allowed per window — a function rather
// than a fixed value so changes via PATCH /v1/admin/system/limits take
// effect immediately on the next request, without a restart (same pattern
// as ai.MaxBodyBytes/maxBodyMiddleware). identify computes the bucket key
// per request (see identifyByIP/identifyBySessionOrIP below) — pulled out
// as a parameter (2026-07-05) rather than hardcoded to clientIP so the
// global backstop can bucket authenticated requests by user instead of IP
// (see globalRateLimitMiddleware's doc comment for why). On a Valkey error
// the request is let through (fail open) — a cache hiccup should degrade to
// "no rate limiting" rather than locking everyone out.
//
// pool/masterKeyEnv (added 2026-07-05, alongside System Info's "rate
// limits" section) are used both to resolve maxFn's current value and, on
// the rare trip branch, to write an audit.EventRateLimitExceeded entry — a
// live Valkey counter tells you a limit is active right now, but says
// nothing about one that already expired by the time an admin goes
// looking, which is exactly what happened investigating an earlier "too
// many requests" report. ActorID is whatever identify returned (an IP, or
// "user:<id>" for an authenticated request at the global layer).
func rateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, label string, window time.Duration, maxFn func(context.Context, *db.Pool) int64, identify func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identifier := identify(r)
		key := "ratelimit:" + label + ":" + identifier
		count, err := vk.IncrExpire(r.Context(), key, window)
		if err != nil {
			log.Printf("main: rate limit check failed (failing open): %v", err)
			next.ServeHTTP(w, r)
			return
		}
		max := maxFn(r.Context(), pool)
		if count > max {
			// Logged (2026-07-05): previously silent, so a real trip of this
			// limit left zero trace in the logs — reported by a user as
			// "too many requests" with no way to tell which endpoint/label
			// or client IP was actually involved. See IncrExpire's doc
			// comment for the counter-never-resets bug this line's silence
			// was hiding.
			log.Printf("main: rate limit exceeded: label=%q identifier=%q count=%d max=%d", label, identifier, count, max)
			// Notify currently-connected admins in the bell/notifications
			// panel (frontend/src/components/AppShell.tsx), on top of the
			// durable audit.Log entry below - the audit log is only ever
			// seen if an admin thinks to go check /admin/audit, whereas this
			// surfaces a trip live, the same way "user.pending"/
			// "module.updates_available" already do. Gated to count ==
			// max+1 (the exact request that tripped the limit), not every
			// subsequent blocked request while the window is still active -
			// IncrExpire keeps incrementing past max on every retry, and a
			// script hammering a blocked endpoint would otherwise flood the
			// panel with one toast per request instead of one per trip.
			if count == max+1 {
				if pubErr := notify.Publish(r.Context(), vk, notify.AdminChannel(), notify.Event{
					Type: "rate_limit.exceeded",
					Data: map[string]any{"label": label, "identifier": identifier, "count": count, "max": max},
				}); pubErr != nil {
					log.Printf("main: notify rate limit exceeded: %v", pubErr)
				}
			}
			if masterKey, mkErr := setup.ResolveMasterKey(r.Context(), pool, masterKeyEnv); mkErr == nil {
				if auditErr := audit.Log(r.Context(), pool, masterKey, audit.LogParams{
					EventType: audit.EventRateLimitExceeded,
					ActorID:   identifier,
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

// identifyByIP is rateLimitMiddleware's original, always-per-IP bucketing —
// used everywhere except the global backstop, since login/callback trip
// before auth even succeeds (no session to key by yet) and the ai-chat
// per-route limiter here is a coarse IP-based ceiling layered on top of
// ai.go's own separate per-user "chat" limiter (see that file), not a
// replacement for it.
func identifyByIP(r *http.Request) string {
	return clientIP(r)
}

// authRateLimitMiddleware is rateLimitMiddleware pinned to the auth-endpoint
// window/budget (kept as a separate name at call sites for readability).
func authRateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, label string, next http.HandlerFunc) http.HandlerFunc {
	return rateLimitMiddleware(vk, pool, masterKeyEnv, "auth:"+label, authRateLimitWindow, authRateLimitMax, identifyByIP, next)
}

// identifyBySessionOrIP is the global backstop's bucket key (added
// 2026-07-05, replacing a plain clientIP call): if the request carries a
// valid session, bucket by the user's OIDC subject ("user:<id>") instead of
// IP, so several people working concurrently from behind the same NAT/
// shared IP (same house, same office egress) don't drain one shared
// 600/minute budget on each other's behalf. Falls back to IP for anonymous
// requests (no bearer token, or one that doesn't resolve to a live
// session) — those still need *some* per-client bucket, and there is no
// user identity to bucket by yet.
//
// auth.ValidateSession is a Valkey GET plus a master-key resolution and an
// AES-GCM decrypt (see its doc comment) — heavier than the plain IP read,
// but it now runs on every request once, here, instead of only inside
// whichever handler already required a session; acceptable at homelab
// scale, and still just one extra Valkey round trip on top of the
// IncrExpire counter itself.
func identifyBySessionOrIP(authDeps auth.Deps) func(*http.Request) string {
	return func(r *http.Request) string {
		// Reads the session cookie, not the Authorization header - see
		// sessionToken's doc comment. Before this fix (found during the
		// 2026-07-15 post-migration security review), this always checked
		// bearerToken(r) instead, which ordinary browser sessions stopped
		// sending the moment the cookie migration landed - every logged-in
		// caller silently fell back to per-IP bucketing below, defeating
		// the whole point of bucketing by user (see this function's
		// package doc comment on the shared-NAT/office-egress case).
		if token := sessionToken(r); token != "" {
			if sess, ok, err := auth.ValidateSession(r.Context(), authDeps, token); err == nil && ok {
				return "user:" + sess.UserID
			}
		}
		return clientIP(r)
	}
}

// globalRateLimitMiddleware wraps an entire http.Handler (not just a single
// HandlerFunc) with the coarse backstop described above. Applied once,
// around the whole mux, in main. Buckets by user identity when a valid
// session is present (identifyBySessionOrIP) and falls back to per-IP
// otherwise. /healthz is deliberately exempt: Docker and Traefik
// healthchecks poll it every few seconds for the container's entire
// lifetime, which would otherwise burn through the same budget as real
// traffic and could self-inflict a false "unhealthy" verdict.
func globalRateLimitMiddleware(vk *valkey.Client, pool *db.Pool, masterKeyEnv string, authDeps auth.Deps, next http.Handler) http.Handler {
	limited := rateLimitMiddleware(vk, pool, masterKeyEnv, "global", globalRateLimitWindow, globalRateLimitMax, identifyBySessionOrIP(authDeps), next.ServeHTTP)
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
// client.
//
// X-Forwarded-For is only trusted when the immediate peer (r.RemoteAddr)
// is itself a private/loopback address (added 2026-07-05, pre-V1 security
// review) - i.e. the request arrived over the internal Docker network from
// Traefik, not from a client that reached Core directly. Without this
// check, anyone able to connect to Core's port directly (an exposed port,
// a misconfigured reverse proxy, or simply skipping Traefik) could put any
// value they like in X-Forwarded-For and pick their own rate-limit bucket,
// defeating login/callback/ai-chat/global limits entirely. A client that
// connects directly always falls through to its real RemoteAddr instead.
func clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && isTrustedProxyPeer(remoteHost) {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if remoteHost != "" {
		return remoteHost
	}
	return r.RemoteAddr
}

// isTrustedProxyPeer reports whether host (the immediate TCP peer, before
// any X-Forwarded-For is considered) is a loopback or private-range
// address - Traefik reaches Core over the Docker-internal network, which
// uses exactly these ranges, so this is "did this hop come from our own
// reverse proxy" without needing an explicit, easy-to-forget-to-update
// list of trusted proxy IPs in config.
func isTrustedProxyPeer(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
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
var knownRateLimitLabels = []string{"auth:login", "auth:callback", "auth:logout", "ai-chat", "global", "chat"}

func rateLimitMax(ctx context.Context, pool *db.Pool, label string) int64 {
	switch label {
	case "auth:login", "auth:callback", "auth:logout":
		return authRateLimitMax(ctx, pool)
	case "ai-chat":
		return aiChatRateLimitMax(ctx, pool)
	case "global":
		return globalRateLimitMax(ctx, pool)
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
//
// pool (added 2026-07-05 alongside identifyBySessionOrIP) resolves a
// "user:<sub>" identifier to a display name via GetUser, purely cosmetic —
// a raw OIDC subject is meaningless to an admin at a glance, unlike the
// active-sessions table which already shows a name. Cached per call via
// userNameCache so a burst of rows for the same repeat offender doesn't
// issue one DB round trip each.
func activeRateLimits(ctx context.Context, vk *valkey.Client, pool *db.Pool) []systemInfoRateLimit {
	keys, err := vk.ScanKeysWithPrefix(ctx, "ratelimit:")
	if err != nil {
		log.Printf("main: system info: scan rate limit keys: %v", err)
		return nil
	}

	userNameCache := make(map[string]string)

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

		var displayName string
		if subject, isUser := strings.CutPrefix(identifier, "user:"); isUser {
			if cached, seen := userNameCache[subject]; seen {
				displayName = cached
			} else {
				if u, found, err := pool.GetUser(ctx, subject); err == nil && found {
					if u.Name != "" {
						displayName = u.Name
					} else {
						displayName = u.Email
					}
				}
				userNameCache[subject] = displayName
			}
		}

		limits = append(limits, systemInfoRateLimit{
			Key:            key,
			Label:          label,
			Identifier:     identifier,
			DisplayName:    displayName,
			Count:          count,
			Max:            rateLimitMax(ctx, pool, label),
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
			httperr.Internal(w, err)
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
	// CosignVerified (added 2026-07-05) mirrors installed_modules.
	// cosign_verified - whether the Cosign signature check actually passed
	// for the currently-installed version. Always false for a "direct"
	// source install (no registry entry to carry a signature at all), and
	// for "official"/"community" installs that predate this field being
	// wired up (need a reinstall/update to pick up a real value).
	CosignVerified bool `json:"cosign_verified"`
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
	LatestCoreVersion   string `json:"latest_core_version,omitempty"`
	CoreUpdateAvailable bool   `json:"core_update_available"`

	// CosignAvailable (added 2026-07-05) reports whether the cosign binary
	// is actually reachable on this instance - if it isn't, every module's
	// CosignVerified will be false regardless of whether a signature
	// exists, which would otherwise look identical to "the signature check
	// failed" instead of "the check never ran". modules.CosignAvailable
	// itself existed since the initial Cosign support but was never called
	// anywhere - this is the first caller.
	CosignAvailable bool `json:"cosign_available"`

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
	Key        string `json:"key"`
	Label      string `json:"label"`
	Identifier string `json:"identifier"`
	// DisplayName (added 2026-07-05, alongside identifyBySessionOrIP)
	// resolves a "user:<sub>" identifier to the account's name/email via
	// db.Pool.GetUser, so an admin sees "sookie" instead of a bare OIDC
	// subject. Omitted entirely for IP-bucketed rows (no lookup possible or
	// needed) and for a user ID that no longer resolves to any row (account
	// deleted since the counter was created) - the raw identifier is still
	// shown in that case, same as before this field existed.
	DisplayName    string `json:"display_name,omitempty"`
	Count          int64  `json:"count"`
	Max            int64  `json:"max,omitempty"`
	ResetInSeconds int64  `json:"reset_in_seconds"`
}

// sessionToken reads the caller's session bearer token from its httpOnly
// session cookie (auth.SessionCookieName) - a package-local duplicate of
// auth's own unexported sessionToken (can't call that one directly since it
// is unexported, and main imports auth, not the other way around). Used by
// identifyBySessionOrIP and systemInfoHandler below, both of which need to
// resolve a live session from the request to bucket the global rate limit
// per-user (rather than per-IP) or flag the caller's own row as "current"
// in the Security Info active-sessions table - both lookups have to read
// the same cookie the browser actually sends now, not the Authorization
// header, which ordinary session-authenticated requests stopped carrying
// once the cookie migration landed (2026-07-15). Module-scoped tokens are
// unaffected and still travel via a header only (auth.BearerToken /
// auth.BearerTokenAllowQuery), so this addition does not change how those
// are identified. This replaced a package-local bearerToken(r) helper that
// used to serve the same two call sites via the Authorization header -
// removed once the cookie migration made it dead code (its only remaining
// caller was systemInfoHandler, fixed to use this function instead) rather
// than leaving an now always-empty, unused-by-anything-else function
// around.
//
// Reads via auth.SessionCookieName rather than a hardcoded string literal
// (found 2026-07-27): this used to duplicate the cookie name as a plain
// string, which silently fell out of sync when the cookie picked up its
// __Host- prefix - ownID was always "", so no row was ever flagged Current
// on Security Info. Using the shared constant means a future rename can't
// cause the same drift again.
func sessionToken(r *http.Request) string {
	c, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
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
			CosignAvailable:   modules.CosignAvailable(cfg.CosignBinaryPath),
		}

		if baseURL, configured, err := pool.GetSearchProviderBaseURL(ctx, db.DefaultSearchProviderID); err == nil {
			resp.SearxngConfigured = configured
			if configured {
				up := searxng.Ping(ctx, baseURL)
				resp.SearxngReachable = &up
			}
		}

		if ok, err := ntpcheck.DriftOK(30 * time.Second); err == nil {
			resp.NTPDriftOK = &ok
		}

		// Core's own update check - reads coreupdate's cache (last result
		// from either the scheduled weekday+time check or a manual "check
		// now" click) rather than calling GitHub live on every page load.
		// This used to call store.FetchLatestRelease directly here, which
		// meant simply opening/reloading this page repeatedly could exhaust
		// GitHub's unauthenticated rate limit (60 requests/hour/IP) on its
		// own - see coreupdate.CachedResult's doc comment.
		coreResult := coreupdate.CachedResult(ctx, pool)
		resp.LatestCoreVersion = coreResult.LatestVersion
		resp.CoreUpdateAvailable = coreResult.UpdateAvailable

		// Active sessions: who's currently logged in and from how many
		// tabs/devices (see auth.ActiveSession's doc comment for exactly
		// what's shown) - best-effort, nil if the underlying SCAN failed.
		// The viewing admin's own row is flagged Current by recomputing
		// SessionID from this same request's own session cookie - only the
		// caller holding that token can know which row is "you", so this
		// can't happen inside ListActiveSessions itself.
		//
		// Read via sessionToken(r), not bearerToken(r) (found during a
		// post-release check, 2026-07-15): the cookie migration means an
		// ordinary browser request no longer carries the session in the
		// Authorization header at all, so bearerToken(r) here always
		// returned "" and no row was ever flagged Current - the same class
		// of bug identifyBySessionOrIP had.
		if sessions, err := auth.ListActiveSessions(ctx, authDeps); err == nil {
			if ownID := auth.SessionID(sessionToken(r)); ownID != "" {
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
		syncInterval := store.SyncInterval(ctx, pool)
		resp.RegistrySync = systemInfoTimer{IntervalSeconds: int64(syncInterval / time.Second)}
		if lastSync, err := store.LastSyncedAt(ctx, pool); err == nil && !lastSync.IsZero() {
			lastStr := lastSync.UTC().Format(time.RFC3339)
			nextStr := lastSync.Add(syncInterval).UTC().Format(time.RFC3339)
			resp.RegistrySync.LastRunAt = &lastStr
			resp.RegistrySync.NextRunAt = &nextStr
		}

		resp.RateLimits = activeRateLimits(ctx, valkeyClient, pool)

		if installed, err := pool.ListInstalledModules(ctx); err == nil {
			resp.Modules = make([]systemInfoModule, 0, len(installed))
			for _, m := range installed {
				mi := systemInfoModule{
					Name:           m.Name,
					Version:        m.Version,
					Status:         m.Status,
					Source:         m.Source,
					Pinned:         m.Pinned,
					Tier:           m.Tier,
					CosignVerified: m.CosignVerified,
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
//
// Audited (audit.EventSessionRevokedByAdmin) - previously the only
// per-user-affecting admin action in this codebase with no audit trail at
// all, unlike LockUserHandler/DeleteUserHandler (which also revoke
// sessions, but log the users-table change itself, not the session-kill).
// This does not know which user the session belonged to without an extra
// lookup - RevokeSessionByID only reports found/not-found, not whose
// session it was (see its doc comment: it has to scan and match by hashed
// ID, same as ListActiveSessions) - so TargetID is intentionally left at
// the session's own opaque id, not an OIDC subject, unlike every other
// admin audit entry in this file. Good enough to prove "an admin ended
// session X at time Y"; cross-referencing which user that was means
// checking the audit log from around when that session was created.
func revokeSessionHandler(authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing session id", http.StatusBadRequest)
			return
		}
		found, err := auth.RevokeSessionByID(r.Context(), authDeps, id)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !found {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		// Best-effort, same tradeoff as every other audit.Log call in this
		// codebase: the revoke itself already succeeded above - a failed or
		// skipped audit write must not turn it into an error for the caller.
		if sess, ok := auth.SessionFromContext(r.Context()); ok {
			if masterKey, mkErr := setup.ResolveMasterKey(r.Context(), authDeps.Pool, authDeps.MasterKeyEnv); mkErr == nil {
				if auditErr := audit.Log(r.Context(), authDeps.Pool, masterKey, audit.LogParams{
					EventType:  audit.EventSessionRevokedByAdmin,
					ActorID:    sess.UserID,
					ActorEmail: sess.Email,
					TargetID:   id,
				}); auditErr != nil {
					log.Printf("main: audit session revoke by %s: %v", sess.UserID, auditErr)
				}
			}
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
//
// Two additions made alongside the session-cookie migration (2026-07-15,
// see auth/handlers.go's setSessionCookie), both pre-existing gaps this
// change turned from theoretical into real:
//
//  1. Access-Control-Allow-Credentials: true, plus only ever echoing
//     Access-Control-Allow-Origin back when the request's own Origin header
//     actually matches allowedOrigin (never blindly, and never "*", which
//     credentialed CORS forbids anyway). Before this, a cross-origin dev
//     setup (Vite on a different port) would have had its cookie silently
//     dropped by the browser: credentialed fetches require the server to
//     explicitly opt in with this header, which the previous version never
//     sent because there was no cookie to protect yet - the old bearer
//     token travelled in an Authorization header instead, which CORS's
//     credentials flag has never governed.
//
//  2. A same-origin check for every state-changing request (anything but
//     GET/HEAD/OPTIONS), independent of the CORS headers above: if the
//     request carries an Origin header at all (browsers always send one on
//     cross-origin requests, and on same-origin POST/PUT/PATCH/DELETE too)
//     and it does not match allowedOrigin, the request is rejected before
//     it ever reaches an auth check. This is the CSRF defense-in-depth that
//     the old Authorization-header transport got for free (a foreign page
//     cannot set a custom header on a cross-site request) but a cookie does
//     not: SameSite=Lax alone still allows a cross-site top-level GET
//     navigation to carry the cookie, and (in Chromium, as a compatibility
//     mitigation) a cross-site top-level POST form submission within ~2
//     minutes of the cookie being set. Requests with no Origin header at
//     all are allowed through unchanged - some legitimate same-origin
//     requests omit it - so this narrows the attack surface rather than
//     closing every theoretical gap, which is an acceptable trade for a
//     single-tenant homelab app with no untrusted origins to defend against
//     beyond "some other website the user also has open".
func corsMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	// Normalized once here rather than at every call site: an Origin header
	// never has a trailing slash (or a path at all), but cfg.FrontendBaseURL
	// is operator-supplied and main.go's own frontendCallbackURL-adjacent
	// code already has to guard against a trailing "/" for the same reason.
	allowedOrigin = strings.TrimRight(allowedOrigin, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+bootstrap.HeaderName)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if origin != "" && origin != allowedOrigin &&
			r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
