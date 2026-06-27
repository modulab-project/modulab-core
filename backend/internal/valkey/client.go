// Package valkey wraps a connection to Valkey (Redis-protocol compatible)
// for the access patterns Core needs: a real reachability check (replacing
// the TCP-dial stub previously used in cmd/core/main.go), a small
// TTL-based Set/Get/Del surface for session storage (spec section 3.2,
// internal/auth), set operations for the per-user session index (also
// internal/auth), and Pub/Sub plus a list-backed queue for spec section
// 3.5's real-time notifications and mail queue (internal/notify,
// internal/mail) - all without every later caller having to learn the
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

// New creates a client for addr ("host:port"). password may be empty when
// Valkey runs without authentication (the default for a single-node homelab
// deployment where Valkey is not exposed beyond the Docker-internal network).
// Set MODULAB_VALKEY_PASSWORD to require authentication; the value is passed
// through to go-redis as-is.
//
// This does not dial immediately - go-redis connects lazily on first use -
// so it never fails here even if Valkey is not yet reachable at process
// start. Call Ping to check reachability; main.go does this once at boot
// (for the startup log) and again on every /healthz request, mirroring the
// TCP-reachability stub this replaces.
func New(addr, password string) *Client {
	return &Client{rdb: redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
	})}
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

// Expire resets the TTL of an existing key without changing its value. A
// no-op (not an error) if the key does not exist or has already expired.
// Used by auth.ValidateSession to slide the session window on every request.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
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

// Publish sends message to every current subscriber of channel (spec
// section 3.5's SSE/Pub-Sub backbone - see internal/notify). Valkey
// Pub/Sub delivers to whoever happens to be subscribed *right now* and
// nothing else - there is no queue or replay for a subscriber that
// connects later, which is fine for live notifications but would be the
// wrong primitive for anything that must survive a missed connection (the
// mail queue below uses a list instead, for exactly that reason).
func (c *Client) Publish(ctx context.Context, channel, message string) error {
	if err := c.rdb.Publish(ctx, channel, message).Err(); err != nil {
		return fmt.Errorf("valkey: publish %q: %w", channel, err)
	}
	return nil
}

// Subscription wraps a Valkey Pub/Sub subscription, hiding the underlying
// go-redis type from callers - same reasoning as Client wrapping
// *redis.Client itself: callers should not need to learn the underlying
// library just to read messages and close the subscription.
type Subscription struct {
	ps *redis.PubSub
}

// Subscribe opens a Pub/Sub subscription to every channel listed. The
// subscription is tied to ctx only in the sense that go-redis uses it for
// the initial SUBSCRIBE command - closing it later (Close) is still the
// caller's responsibility, typically via defer right after this call, the
// same way os.Open/Close pairs work.
func (c *Client) Subscribe(ctx context.Context, channels ...string) *Subscription {
	return &Subscription{ps: c.rdb.Subscribe(ctx, channels...)}
}

// Messages returns a channel of message payloads (channel names are
// discarded - a caller that subscribed to several channels and needs to
// tell them apart should encode that in the payload itself, which
// internal/notify's Event.Type already does). The returned channel closes
// once the subscription is closed or the connection drops.
func (s *Subscription) Messages() <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for msg := range s.ps.Channel() {
			out <- msg.Payload
		}
	}()
	return out
}

// Close ends the subscription. Safe to call from a deferred statement even
// if the subscription was never read from.
func (s *Subscription) Close() error {
	return s.ps.Close()
}

// RPush appends value to the list at key (used by the mail queue,
// internal/mail, as a durable work queue - unlike Publish/Subscribe above,
// a value pushed here is still there for whichever worker calls BLPop
// next, even if no worker happens to be running at push time).
func (c *Client) RPush(ctx context.Context, key, value string) error {
	if err := c.rdb.RPush(ctx, key, value).Err(); err != nil {
		return fmt.Errorf("valkey: rpush %q: %w", key, err)
	}
	return nil
}

// BLPop blocks for up to timeout waiting for an item at the front of the
// list at key, removing and returning it. ok is false (not an error) if
// timeout elapsed with nothing to pop - the normal, expected outcome of an
// idle queue, which is why the mail worker's poll loop calls this in a
// plain for-loop rather than treating a timeout as something to log.
func (c *Client) BLPop(ctx context.Context, timeout time.Duration, key string) (string, bool, error) {
	result, err := c.rdb.BLPop(ctx, timeout, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", false, nil
		}
		return "", false, fmt.Errorf("valkey: blpop %q: %w", key, err)
	}
	// BLPop's result is [key, value] - result[0] is always the key name we
	// already know (key), only result[1] is new information.
	return result[1], true, nil
}

// IncrExpire atomically increments key and (re)sets its TTL to ttl via a
// pipeline. Returns the new counter value. Intended for fixed-window rate
// limiting: the TTL is refreshed on every increment so the window slides
// forward from the last request, which is slightly stricter than a pure
// fixed window but simpler and requires no Lua scripting. On Valkey/Redis
// error the caller should fail open (let the request through) rather than
// blocking everyone on a cache hiccup.
func (c *Client) IncrExpire(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipe := c.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("valkey: incr-expire %q: %w", key, err)
	}
	return incr.Val(), nil
}
