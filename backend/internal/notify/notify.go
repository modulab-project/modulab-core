// Package notify implements spec section 3.5's real-time notifications:
// channel-naming conventions and a thin Publish wrapper around Valkey's
// Pub/Sub (internal/valkey), used by internal/auth to announce events
// (new pending user, approval) and read back by auth.EventsHandler's SSE
// endpoint (GET /v1/events).
//
// Deliberately depends only on internal/valkey, not internal/auth:
// auth needs to call Publish (e.g. CallbackHandler, admin.go), and
// auth.EventsHandler needs to know which channels to subscribe to for a
// given session - if this package depended on auth in turn (e.g. to
// accept a Session directly), the two packages would import each other.
// Keeping notify auth-agnostic - it only ever sees channel name strings
// and JSON-able event payloads - avoids that import cycle; auth.go's own
// SSE handler is the one place that translates "this session has role
// org-admin" into "subscribe to AdminChannel() too".
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/valkey"
)

// HeartbeatInterval matches spec section 3.5 exactly ("Heartbeat alle 30
// Sekunden zur Erkennung von Zombie-Connections") - auth.EventsHandler
// sends an SSE comment line on this interval so a dead connection (router
// reboot, laptop sleep) is noticed by the browser/proxy without needing
// TCP-level keepalive tuning.
const HeartbeatInterval = 30 * time.Second

// AdminChannel is where events meant for every currently-connected
// org-admin/super-admin are published - spec section 3.5's "Neuer
// Pending-User" row today; "Modul-Health-Statuswechsel" and "Modul-
// Installation" rows once the module pipeline (Phase 3) exists to trigger
// them.
func AdminChannel() string {
	return "notify:admin"
}

// SuperAdminChannel is where events meant only for currently-connected
// super-admin sessions are published - narrower than AdminChannel above,
// which also reaches org-admin. Used for "core.update_available"
// (internal/coreupdate): Core/system-level settings are already a
// super-admin-exclusive concern elsewhere in this app (see /admin/system's
// own super-admin gate), so an org-admin session deliberately does not
// subscribe to this channel at all (see auth.EventsHandler's channel
// selection) rather than receiving and having to ignore an event about
// something it can't act on anyway.
func SuperAdminChannel() string {
	return "notify:super-admin"
}

// UserChannel is where events meant for exactly one subject are
// published - spec section 3.5's "user.approved" row. Takes the OIDC
// subject (Session.UserID), not the email, since that is what every
// other per-user lookup in this codebase already keys on (see
// db.Pool.UserApproved/UserLocked/UserRole).
func UserChannel(subject string) string {
	return "notify:user:" + subject
}

// Event is the JSON payload published to and read back from a channel.
// Type identifies which kind of event this is (e.g. "user.pending",
// "user.approved") so a subscriber - the frontend, via auth.EventsHandler
// - can dispatch without inspecting Data first. Data is the event's own
// detail and may be nil for events that need none.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// Publish marshals ev and publishes it to channel. A Valkey Publish with
// zero current subscribers is not an error and is not queued for later -
// see valkey.Client.Publish's doc comment on why that is the accepted
// tradeoff for live notifications specifically (the mail queue,
// internal/mail, is the durable alternative used wherever "nobody was
// listening" must not mean "lost").
func Publish(ctx context.Context, vk *valkey.Client, channel string, ev Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("notify: marshal event %q: %w", ev.Type, err)
	}
	return vk.Publish(ctx, channel, string(payload))
}
