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

// Connect opens a pooled connection to Postgres and verifies it is reachable.
// masterKey is the AES-256 hex key (MODULAB_MASTER_KEY) used to encrypt/
// decrypt user PII transparently in UpsertUser, GetUser, ListUsers, and
// ListAdmins - the same key that protects OIDC/SMTP/DNS secrets in
// core_settings.
func Connect(ctx context.Context, dsn, masterKey string) (*Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{Pool: pool, masterKey: masterKey}, nil
}
