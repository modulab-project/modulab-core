// Command core is the entry point for the modulab-core backend.
//
// This commit gives Valkey a real client (internal/valkey, go-redis under
// the hood - Valkey is RESP-compatible with Redis), replacing the
// TCP-reachability stub previously used both at boot and in /healthz. The
// Deno subprocess supervisor (spec section 4.7) is still unimplemented -
// that lands later, as part of the module-pipeline phase of the project
// roadmap.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/bootstrap"
	"github.com/modulab-project/modulab-core/backend/internal/config"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
	"github.com/modulab-project/modulab-core/backend/internal/version"
)

type healthStatus struct {
	Status         string `json:"status"`
	PostgresUp     bool   `json:"postgres_reachable"`
	ValkeyUp       bool   `json:"valkey_reachable"`
	MasterKeySetUp bool   `json:"master_key_present"`
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("ModuLab Core %s — %s", version.Version, version.ProjectURL)

	// Generated and logged before the DB connection, so the token is visible
	// as early as possible after boot even if Postgres takes a moment to
	// become reachable.
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

	masterKeyConfigured, err := setup.MasterKeyConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: master key check failed: %v", err)
	}
	oidcConfigured, err := setup.OIDCConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: oidc check failed: %v", err)
	}
	groupPrefixConfigured, err := setup.GroupPrefixConfigured(ctx, pool)
	if err != nil {
		log.Printf("setup: group prefix check failed: %v", err)
	}
	log.Printf("setup wizard progress: master-key=%t oidc=%t group-prefix=%t", masterKeyConfigured, oidcConfigured, groupPrefixConfigured)

	mux := http.NewServeMux()

	// /healthz is intentionally exempt from the bootstrap-token gate: it is
	// meant for unauthenticated monitoring (e.g. Docker healthchecks,
	// Traefik) and never reveals anything more sensitive than booleans.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// master_key_present reflects either source of truth: a real
		// MODULAB_MASTER_KEY (env/.env) or a key already persisted to
		// core_settings by the Setup Wizard's /v1/setup/init. Without the
		// second check, this would falsely report false right after a
		// fresh install bootstraps its key but before the operator copies
		// it into .env.
		dbKeyConfigured, err := setup.MasterKeyConfigured(r.Context(), pool)
		if err != nil {
			log.Printf("healthz: master key lookup failed: %v", err)
		}

		status := healthStatus{
			Status:         "ok",
			PostgresUp:     pool.Ping(r.Context()) == nil,
			ValkeyUp:       valkeyClient.Ping(r.Context()) == nil,
			MasterKeySetUp: cfg.MasterKey != "" || dbKeyConfigured,
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
		// The OIDC step needs the master key to encrypt the client secret,
		// so it can only run after step 1 (master-key bootstrap) has
		// completed. Resolving it per-request (rather than once at startup)
		// means a key generated via /v1/setup/init works immediately,
		// without requiring a process restart.
		masterKey, err := setup.ResolveMasterKey(r.Context(), pool, cfg.MasterKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}
		setup.OIDCConfigureHandler(pool, masterKey)(w, r)
	})))

	mux.Handle("/v1/setup/group-prefix/status", bootstrapMgr.Middleware(setup.GroupPrefixStatusHandler(pool)))
	mux.Handle("/v1/setup/group-prefix/configure", bootstrapMgr.Middleware(setup.GroupPrefixConfigureHandler(pool)))

	log.Printf("modulab-core listening on %s (group prefix %q)", cfg.HTTPAddr, cfg.GroupPrefix)
	if err := http.ListenAndServe(cfg.HTTPAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}
