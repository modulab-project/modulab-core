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

// AddSetMember adds member to the set at key and (re)sets the set's TTL to
// ttl. Used by auth.CreateSession to track which session tokens belong to a
// given user (key "usersessions:{subject}") so an admin lock/delete action
// can find and revoke them immediately, instead of only blocking the user's
// *next* login. Resetting the TTL on every call means the set survives at
// least ttl past the most recently added member - slightly longer than
// strictly necessary for any single token, but harmless: a stale token
// reference left behind once its own session key has expired is cleaned up
// the next time something iterates the set (deleting an already-absent
// session key is a no-op), and the set itself disappears on its own once no
// new session has been added to it for a full ttl.
func (c *Client) AddSetMember(ctx context.Context, key, member string, ttl time.Duration) error {
	if err := c.rdb.SAdd(ctx, key, member).Err(); err != nil {
		return fmt.Errorf("valkey: sadd %q: %w", key, err)
	}
	if err := c.rdb.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("valkey: expire %q: %w", key, err)
	}
	return nil
}

// SetMembers returns every member currently in the set at key (empty, not an
// error, if key does not exist or has expired).
func (c *Client) SetMembers(ctx context.Context, key string) ([]string, error) {
	members, err := c.rdb.SMembers(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("valkey: smembers %q: %w", key, err)
	}
	return members, nil
}
