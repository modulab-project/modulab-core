// Package mail implements spec section 3.5's Mail-Queue: a Valkey
// list-backed durable queue (internal/valkey's RPush/BLPop) plus a worker
// that drains it via SMTP, using the configuration internal/setup/smtp.go
// persists from the Admin Panel. Deliberately a list, not the same
// Pub/Sub primitive internal/notify uses for SSE - a queued mail must
// still be delivered even if no worker happened to be running at the
// moment it was enqueued (e.g. Core mid-restart), whereas a Pub/Sub
// message with zero subscribers is just gone. See valkey.Client.Publish's
// doc comment for the same distinction from the other side.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

const queueKey = "mailqueue"

// pollTimeout bounds how long each BLPop call blocks before returning
// empty - purely so RunWorker's loop gets a chance to notice ctx
// cancellation between waits on an idle queue. Not a retry/backoff
// interval: a non-empty queue is drained continuously, with no delay
// between messages.
const pollTimeout = 5 * time.Second

// Message is one queued, fully-rendered email - see templates.go for the
// spec section 3.5 lifecycle events that build one of these today
// (ApprovedMessage/LockedMessage/UnlockedMessage).
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// Enqueue durably queues msg for delivery by RunWorker.
func Enqueue(ctx context.Context, vk *valkey.Client, msg Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("mail: marshal message: %w", err)
	}
	return vk.RPush(ctx, queueKey, string(payload))
}

// RunWorker drains the mail queue forever, until ctx is cancelled. Meant
// to run as exactly one long-lived goroutine, started once from main.go -
// running a second one would just mean two workers racing BLPop against
// the same list, which is harmless (each message is still delivered
// exactly once, to whichever worker popped it first) but pointless.
//
// masterKeyEnv is passed through to setup.ResolveMasterKey/
// ResolveSMTPConfig on every single message, not resolved once at
// startup - the same "re-resolve every time" choice ResolveOIDCConfig
// already makes for the login flow (handlers.go), so an SMTP
// configuration entered or changed in the admin panel takes effect on the
// very next queued message without a Core restart.
func RunWorker(ctx context.Context, vk *valkey.Client, pool *db.Pool, masterKeyEnv string) {
	for {
		if ctx.Err() != nil {
			return
		}
		raw, ok, err := vk.BLPop(ctx, pollTimeout, queueKey)
		if err != nil {
			// A Valkey hiccup must not crash the worker goroutine - logged,
			// then retried next loop iteration. BLPop failing means nothing
			// was popped, so the queue itself is untouched: nothing lost,
			// just delayed.
			log.Printf("mail: poll failed: %v", err)
			continue
		}
		if !ok {
			continue // idle queue - the normal case, not worth logging
		}

		var msg Message
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			log.Printf("mail: dropping unreadable queued message: %v", err)
			continue
		}
		if err := deliver(ctx, pool, masterKeyEnv, msg); err != nil {
			// No retry or dead-letter queue yet: a failed send (SMTP
			// unreachable, bad credentials, or never configured at all)
			// just logs and drops the message. Acceptable for what these
			// particular messages are - a courtesy copy of something the
			// user could also see live over SSE (internal/notify) if they
			// happen to be connected when it happens - not acceptable if
			// mail is ever used for something the user truly cannot miss,
			// which would need this revisited.
			log.Printf("mail: failed to deliver to %s: %v", msg.To, err)
		}
	}
}

func deliver(ctx context.Context, pool *db.Pool, masterKeyEnv string, msg Message) error {
	masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
	if err != nil {
		return fmt.Errorf("resolve master key: %w", err)
	}
	cfg, err := setup.ResolveSMTPConfig(ctx, pool, masterKey)
	if err != nil {
		// Most commonly "smtp has not been configured yet" - an instance
		// that never set up SMTP in the admin panel is expected to hit
		// this on every queued message, not a real failure worth
		// distinguishing from one here; RunWorker's caller logs it either
		// way.
		return fmt.Errorf("resolve smtp config: %w", err)
	}
	return send(cfg, msg)
}
