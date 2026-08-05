// Package db wraps a Postgres connection pool (pgx) and provides the
// minimal key/value access Core needs for its own bootstrap state
// (core_settings), the users table populated by OIDC JIT provisioning
// (spec section 3.3), and module bookkeeping (installed_modules). Module
// schemas and per-module roles (spec section 4.3) are handled elsewhere,
// once the module installation pipeline lands.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps *pgxpool.Pool so Core-specific helper methods can be attached
// without polluting the pgx API surface everywhere it's used.
// masterKey is the AES-256 master key used to encrypt/decrypt all PII stored
// in the users table (email, name) transparently - callers pass and receive
// plaintext; the encrypt/decrypt happens inside each method.
type Pool struct {
	*pgxpool.Pool
	masterKey string
}

// Pool sizing (M-3, PERFORMANCE_AUDIT.md). deploy/docker-compose.yml connects
// Core directly to Postgres (MODULAB_DB_HOST=postgres) - there is no
// PgBouncer in front of it, so this pool is the only connection pooling
// layer in the whole deployment.
const (
	// dbMinConns keeps this many connections warm at all times, so the
	// first request after an idle period (a homelab instance sitting
	// unused overnight is the common case) does not pay a fresh TCP+auth
	// handshake to Postgres on top of its own work.
	dbMinConns = 2
	// dbMaxConns bounds how many connections Core itself will ever open,
	// independent of Postgres's own max_connections - without an explicit
	// cap, pgx's default (max(4, runtime.NumCPU())) has no relationship to
	// what the rest of the deployment (module DB roles, admin tooling)
	// might also need concurrently.
	dbMaxConns = 10
	// dbMaxConnIdleTime closes a connection that has sat idle this long,
	// so a burst of traffic followed by a long quiet period does not keep
	// dbMaxConns connections open against Postgres for no reason.
	dbMaxConnIdleTime = 5 * time.Minute
	// dbMaxConnLifetime forces even a busy connection to be recycled
	// periodically - bounds how long a single connection can go without a
	// address change (DNS-based Postgres failover, a planned restart)
	// being picked up naturally next time a new connection is opened.
	dbMaxConnLifetime = 30 * time.Minute
)

// Connect opens a pooled connection to Postgres and verifies it is reachable.
// masterKey is the AES-256 hex key (MODULAB_MASTER_KEY) used to encrypt/
// decrypt user PII transparently in UpsertUser, GetUser, ListUsers, and
// ListAdmins - the same key that protects OIDC/SMTP/DNS secrets in
// core_settings.
func Connect(ctx context.Context, dsn, masterKey string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse dsn: %w", err)
	}
	cfg.MinConns = dbMinConns
	cfg.MaxConns = dbMaxConns
	cfg.MaxConnIdleTime = dbMaxConnIdleTime
	cfg.MaxConnLifetime = dbMaxConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{Pool: pool, masterKey: masterKey}, nil
}
