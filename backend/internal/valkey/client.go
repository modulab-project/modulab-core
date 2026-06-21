// Package valkey wraps a connection to Valkey (Redis-protocol compatible)
// for the minimal key/value access Core needs right now: a real
// reachability check (replacing the TCP-dial stub previously used in
// cmd/core/main.go) and a small TTL-based Set/Get/Del surface that the
// future session-management code (spec section 3.2: sessions live in
// Valkey) can build on, without every later caller having to learn the
// underlying client library.
package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps *redis.Client. Valkey speaks the same RESP protocol as
// Redis, so the standard go-redis client works against it unmodified.
type Client struct {
	rdb *redis.Client
}

// New creates a client for addr ("host:port"). No authentication is
// configured yet - neither .env.example nor config.Config has a
// MODULAB_VALKEY_PASSWORD field today, so this matches current behavior.
// Add one here (and to config.Config) if/when a password is introduced.
//
// This does not dial immediately - go-redis connects lazily on first use -
// so it never fails here even if Valkey is not yet reachable at process
// start. Call Ping to check reachability; main.go does this once at boot
// (for the startup log) and again on every /healthz request, mirroring the
// TCP-reachability stub this replaces.
func New(addr string) *Client {
	return &Client{rdb: redis.NewClient(&redis.Options{Addr: addr})}
}

// Ping verifies the connection is currently alive.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Close releases the underlying connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// SetWithTTL stores value under key, expiring it after ttl. Intended for
// session tokens and similarly short-lived data once the login flow exists.
func (c *Client) SetWithTTL(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("valkey: set %q: %w", key, err)
	}
	return nil
}

// Get returns the stored value for key and whether it was present (a
// missing or expired key is not an error).
func (c *Client) Get(ctx context.Context, key string) (string, bool, error) {
	value, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", false, nil
		}
		return "", false, fmt.Errorf("valkey: get %q: %w", key, err)
	}
	return value, true, nil
}

// Del removes key, if present.
func (c *Client) Del(ctx context.Context, key string) error {
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("valkey: del %q: %w", key, err)
	}
	return nil
}
