// Command core is the entry point for the modulab-core backend.
//
// This commit adds the actual OIDC login flow (internal/auth, spec section
// 6.5 wizard step 6 and the runtime side of section 3.3's Dynamic Prefix
// Hard Gate): /v1/auth/login redirects to the configured IdP,
// /v1/auth/callback verifies the ID token, derives a role from the groups
// claim, JIT-provisions the user, and issues a Core-managed session;
// /v1/auth/me and /v1/auth/logout round out the flow for testing without a
// frontend. The Deno subprocess supervisor (spec section 4.7) is still
// unimplemented - that lands later, as part of the module-pipeline phase
// of the project roadmap.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/bootstrap"
	"github.com/modulab-project/modulab-core/backend/internal/config"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"github.com/modulab-project/modulab-core/backend/internal/version"
)

type healthStatus struct {
	Status         string `json:"status"`
	Version        string `json:"version"`
	PostgresUp     bool   `json:"postgres_reachable"`
	ValkeyUp       bool   `json:"valkey_reachable"`
	MasterKeySetUp bool   `json:"master_key_present"`
	SetupCompleted bool   `json:"setup_completed"`
}

func main() {
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
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()
	log.Printf("db: connected to postgres at %s:%s/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)

	if err := pool.EnsureCoreSchema(ctx); err != nil {
		log.Fatalf("db: %v", err)
	}

	valkeyClient := valkey.New(net.JoinHostPort(cfg.ValkeyHost, cfg.ValkeyPort))
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

	// No master-key check here anymore: MODULAB_MASTER_KEY is mandatory and
	// already validated by config.Load above, so by this point it is
	// guaranteed present - see validateMasterKey in config.go and
	// wizard.go's doc comments for why the old DB-fallback check that used
	// to live here was removed.
	oidcConfigured, err := setup.OIDCConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: oidc check failed: %v", err)
	}
	dnsChallengeConfigured, err := setup.DNSChallengeConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: dns-challenge check failed: %v", err)
	}
	groupPrefixConfigured, err := setup.GroupPrefixConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: group prefix check failed: %v", err)
	}
	log.Printf("setup wizard progress: oidc=%t dns-challenge=%t group-prefix=%t", oidcConfigured, dnsChallengeConfigured, groupPrefixConfigured)

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
			PostgresUp:     pool.Ping(r.Context()) == nil,
			ValkeyUp:       valkeyClient.Ping(r.Context()) == nil,
			MasterKeySetUp: cfg.MasterKey != "",
			SetupCompleted: bootstrapMgr.Completed(),
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

	mux.Handle("/v1/setup/oidc/status", bootstrapMgr.Middleware(setup.OIDCStatusHandler(pool)))
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

	mux.Handle("/v1/setup/dns-challenge/status", bootstrapMgr.Middleware(setup.DNSChallengeStatusHandler(pool)))
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
	mux.Handle("/v1/setup/complete", bootstrapMgr.Middleware(setup.CompleteHandler(pool, bootstrapMgr)))

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
		GroupPrefixEnv:  cfg.GroupPrefix,
		PublicBaseURL:   cfg.PublicBaseURL,
		FrontendBaseURL: cfg.FrontendBaseURL,
	}
	mux.HandleFunc("/v1/auth/login", auth.LoginHandler(authDeps))
	mux.HandleFunc("/v1/auth/callback", auth.CallbackHandler(authDeps))
	mux.HandleFunc("/v1/auth/me", auth.MeHandler(authDeps))
	mux.HandleFunc("/v1/auth/logout", auth.LogoutHandler(authDeps))

	// GroupPrefix no longer has an implicit default (see config.go) - it
	// may legitimately be empty here if the operator hasn't run the Setup
	// Wizard's group-prefix step (6.5 step 5) yet, so this resolves the
	// same way the login flow itself does rather than printing an empty
	// string.
	effectiveGroupPrefix, err := setup.ResolveGroupPrefix(ctx, pool, cfg.GroupPrefix)
	if err != nil {
		effectiveGroupPrefix = "(not yet configured)"
	}
	log.Printf("modulab-core listening on %s (group prefix %q, frontend origin %q)", cfg.HTTPAddr, effectiveGroupPrefix, cfg.FrontendBaseURL)
	if err := http.ListenAndServe(cfg.HTTPAddr, corsMiddleware(cfg.FrontendBaseURL, mux)); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// corsMiddleware allows cfg.FrontendBaseURL's origin to call every route on
// mux from a different origin than Core's own. This only matters in local
// dev, where Vite's dev server (FrontendBaseURL) and Core (HTTPAddr) run on
// different ports - same-origin browsers never trigger CORS preflights in
// the first place, so this is a no-op once frontend and backend are served
// from the same production origin. Allowing exactly one configured origin
// (rather than "*") keeps this from becoming an accidental open API.
func corsMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+bootstrap.HeaderName)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
