// This file implements spec section 3.5's real-time notification
// transport: GET /v1/events, a Server-Sent Events stream backed by Valkey
// Pub/Sub (internal/notify). The actual events published onto these
// channels are triggered from handlers.go (CallbackHandler, a new
// pending user) and admin.go (ApproveUserHandler, user.approved) - this
// file only knows how to turn "this session" into "these channels" and
// forward whatever notify.Publish sends on them.
package auth

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
)

// EventsHandler is GET /v1/events. Every authenticated, non-pending
// session gets its own long-lived connection - spec section 3.5's own
// sizing estimate ("1000 gleichzeitige Verbindungen kosten Megabytes statt
// Gigabytes") is for exactly this: one goroutine plus one Valkey Pub/Sub
// subscription per open tab, not per user.
//
// The session token travels as the httpOnly modulab_session cookie (see
// handlers.go's setSessionCookie), same as every other endpoint now -
// EventSource cannot set custom request headers, but it does send cookies
// automatically for a same-origin URL, so no special-cased transport is
// needed here anymore. This used to require a ?token=... query parameter
// instead (the one alternative EventSource had for a header-only bearer
// token), which meant the token could end up in an access log or proxy log
// in a way the header form did not - the cookie switch removes that
// exposure entirely, not just relocates it.
func EventsHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := sessionToken(r)
		if token == "" {
			http.Error(w, "missing session cookie", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		sess, ok, err := ValidateSession(ctx, d, token, clientIP(r), loginCountry(r), r.Header.Get("User-Agent"))
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !ok {
			http.Error(w, "invalid or expired session", http.StatusUnauthorized)
			return
		}
		// Same sliding-cookie reasoning as admin.go's requireAdmin/
		// requireActiveSessionWithToken: keep the browser's Max-Age in step
		// with the Valkey TTL ValidateSession just extended. Must happen
		// before the SSE headers are written below (a cookie can't be set
		// once the response has started streaming).
		setSessionCookie(w, token)
		// Deliberately NOT gated against RolePending the way every other
		// endpoint is (see CallbackHandler's doc comment: a pending session
		// may otherwise only reach /v1/auth/me and /v1/auth/logout). This
		// is the one exception, and on purpose: spec section 3.5's
		// "user.approved" event is meant for exactly this session - someone
		// sitting on /pending right now - so they hear about their own
		// approval the instant it happens rather than waiting up to
		// useAuthenticatedSession/Pending.tsx's POLL_INTERVAL_MS. It is
		// still safe: the channel selection below gives a pending session
		// only its own UserChannel, never AdminChannel (that requires the
		// admin role, which a pending session's role never is), so this
		// grants no visibility into anything pending wasn't already going
		// to learn about by signing back in.
		flusher, ok := w.(http.Flusher)
		if !ok {
			// Should not happen with net/http's own ResponseWriter, but
			// checked rather than assumed - a panic on a bad type assertion
			// would take the whole handler down instead of just this request.
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Every session subscribes to its own channel (user.approved and
		// any future per-user event); admin sessions additionally get the
		// shared admin channel (new pending user, core.update_available,
		// eventually module health/install events too). Before
		// 2026-07-29's role-model change there was a narrower
		// SuperAdminChannel reserved for core.update_available, excluding
		// org-admin sessions - removed along with the org-admin tier
		// itself, since there is now only one admin role and no one left
		// to exclude.
		channels := []string{notify.UserChannel(sess.UserID)}
		if sess.Role == RoleAdmin {
			channels = append(channels, notify.AdminChannel())
		}
		sub := d.Valkey.Subscribe(ctx, channels...)
		defer func() {
			if err := sub.Close(); err != nil {
				log.Printf("auth: events: close subscription: %v", err)
			}
		}()

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		messages := sub.Messages(ctx)
		heartbeat := time.NewTicker(notify.HeartbeatInterval)
		defer heartbeat.Stop()

		for {
			select {
			case <-ctx.Done():
				// Browser navigated away or closed the tab - r.Context() is
				// cancelled by net/http itself once the client disconnects,
				// which is the only signal this handler needs to clean up.
				return
			case payload, open := <-messages:
				if !open {
					// The Valkey connection backing this subscription
					// dropped - same outcome as the client disconnecting:
					// nothing left to forward, so end the response rather
					// than spin on a closed channel.
					return
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
					return
				}
				flusher.Flush()
			case <-heartbeat.C:
				// A comment line (": ...") per the SSE spec - ignored by
				// EventSource's onmessage, but still bytes-on-the-wire that
				// let the browser/any proxy in between notice a dead
				// connection well before TCP would.
				if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
