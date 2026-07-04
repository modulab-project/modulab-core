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

	"github.com/modulab-project/modulab-core/backend/internal/crypto"
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

// storedMessage is the on-the-wire (Valkey list) representation of a
// Message. To and Body are AES-256-GCM encrypted before being pushed to the
// queue: To is the recipient's email address, and Body is templates.go's
// fully-rendered text, which always embeds the recipient's name
// (greeting()) and — for PendingApprovalMessage — the new signup's own
// name and email too. Found during the pre-V1 re-audit: a message stuck in
// the queue after an SMTP failure (RunWorker's no-retry, log-and-drop path)
// was sitting in Valkey as plaintext PII in the meantime. Subject stays
// plaintext: every template.go subject line is a static string with no
// PII in it (see templates.go), so there is nothing there to encrypt.
type storedMessage struct {
	ToEnc   string `json:"to_enc"`
	Subject string `json:"subject"`
	BodyEnc string `json:"body_enc"`
}

// Enqueue durably queues msg (encrypted, see storedMessage) for delivery by
// RunWorker. masterKeyEnv is resolved fresh on every call, the same
// "re-resolve every time" choice deliver() already makes below.
func Enqueue(ctx context.Context, vk *valkey.Client, pool *db.Pool, masterKeyEnv string, msg Message) error {
	masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
	if err != nil {
		return fmt.Errorf("mail: resolve master key: %w", err)
	}
	toEnc, err := crypto.EncryptIfNotEmpty(masterKey, msg.To)
	if err != nil {
		return fmt.Errorf("mail: encrypt to: %w", err)
	}
	bodyEnc, err := crypto.EncryptIfNotEmpty(masterKey, msg.Body)
	if err != nil {
		return fmt.Errorf("mail: encrypt body: %w", err)
	}
	stored := storedMessage{ToEnc: toEnc, Subject: msg.Subject, BodyEnc: bodyEnc}

	payload, err := json.Marshal(stored)
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

		var stored storedMessage
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			log.Printf("mail: dropping unreadable queued message: %v", err)
			continue
		}
		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			log.Printf("mail: dropping queued message, could not resolve master key: %v", err)
			continue
		}
		to, err := crypto.DecryptIfNotEmpty(masterKey, stored.ToEnc)
		if err != nil {
			log.Printf("mail: dropping queued message, could not decrypt to: %v", err)
			continue
		}
		body, err := crypto.DecryptIfNotEmpty(masterKey, stored.BodyEnc)
		if err != nil {
			log.Printf("mail: dropping queued message, could not decrypt body: %v", err)
			continue
		}
		msg := Message{To: to, Subject: stored.Subject, Body: body}
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
