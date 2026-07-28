// Package adminapi provides the super-admin-only endpoints that expose and
// mutate system configuration post-Setup-Wizard completion:
//
//	GET  /v1/admin/system          — OIDC, group prefix (read-only)
//	PATCH /v1/admin/oidc           — update OIDC configuration
//	GET  /v1/audit-log             — paginated, filtered audit log
//	GET  /v1/audit-log/actors      — distinct actors for the audit log's filter dropdown
//
// All three require a super-admin session (enforced by the
// auth.RequireSuperAdminMiddleware wrapper that main.go applies to each
// route). OIDC changes are also written to the audit log.
//
// Relationship to the Setup Wizard: oidc.go in the setup package handles the
// wizard steps (behind the bootstrap token, inaccessible post-completion).
// These handlers reuse the same core_settings keys and crypto helpers but
// require a live super-admin session instead, making the config editable
// without re-running the wizard.
package adminapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// ---- /v1/admin/system ----------------------------------------------------------

// SystemStatusResponse is what GET /v1/admin/system returns: the current
// non-secret state of every system-level configuration block. The frontend's
// AdminSystemPage uses this to pre-fill the edit forms.
type SystemStatusResponse struct {
	OIDC        OIDCStatus `json:"oidc"`
	GroupPrefix string     `json:"group_prefix"`
}

// OIDCStatus mirrors setup.OIDCStatusResponse for the system page.
type OIDCStatus struct {
	Configured bool   `json:"configured"`
	IssuerURL  string `json:"issuer_url,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
}

// SystemStatusHandler serves GET /v1/admin/system. masterKey must already be
// resolved (or be the env fallback) - same convention as smtp.go's handlers.
func SystemStatusHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		// OIDC
		var oidcStatus OIDCStatus
		encIssuer, issuerExists, err := pool.GetSetting(ctx, "oidc_issuer_url")
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if issuerExists && encIssuer != "" {
			oidcStatus.Configured = true
			oidcStatus.IssuerURL, _ = crypto.DecryptIfNotEmpty(masterKey, encIssuer)
			encClientID, cidExists, _ := pool.GetSetting(ctx, "oidc_client_id")
			if cidExists {
				oidcStatus.ClientID, _ = crypto.DecryptIfNotEmpty(masterKey, encClientID)
			}
		}

		// Group prefix (plaintext)
		prefix, _, err := pool.GetSetting(ctx, "group_prefix")
		if err != nil {
			httperr.Internal(w, err)
			return
		}

		writeJSON(w, http.StatusOK, SystemStatusResponse{
			OIDC:        oidcStatus,
			GroupPrefix: prefix,
		})
	}
}

// ---- PATCH /v1/admin/oidc ------------------------------------------------------

// OIDCUpdateRequest is the body for PATCH /v1/admin/oidc.
// ClientSecret is optional: omit or set to "" to keep the existing secret.
type OIDCUpdateRequest struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // "" = keep existing
}

// OIDCUpdateHandler persists updated OIDC configuration. Mirrors the wizard's
// OIDCConfigureHandler logic but requires a super-admin session instead of
// the bootstrap token, making the config editable after wizard completion.
func OIDCUpdateHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		var req OIDCUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}
		req.IssuerURL = strings.TrimSpace(req.IssuerURL)
		req.ClientID = strings.TrimSpace(req.ClientID)
		req.ClientSecret = strings.TrimSpace(req.ClientSecret)

		if req.IssuerURL == "" || req.ClientID == "" {
			http.Error(w, "issuer_url and client_id are required", http.StatusBadRequest)
			return
		}

		encIssuer, err := crypto.Encrypt(masterKey, req.IssuerURL)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		encClientID, err := crypto.Encrypt(masterKey, req.ClientID)
		if err != nil {
			httperr.Internal(w, err)
			return
		}

		if err := pool.SetSetting(ctx, "oidc_issuer_url", encIssuer); err != nil {
			httperr.Internal(w, err)
			return
		}
		if err := pool.SetSetting(ctx, "oidc_client_id", encClientID); err != nil {
			httperr.Internal(w, err)
			return
		}
		if req.ClientSecret != "" {
			encSecret, err := crypto.Encrypt(masterKey, req.ClientSecret)
			if err != nil {
				httperr.Internal(w, err)
				return
			}
			if err := pool.SetSetting(ctx, "oidc_client_secret_enc", encSecret); err != nil {
				httperr.Internal(w, err)
				return
			}
		}

		// Audit — best-effort.
		if sess, ok := auth.SessionFromContext(ctx); ok {
			if err := audit.Log(ctx, pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigOIDC,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"issuer_url":%q}`, req.IssuerURL),
			}); err != nil {
				log.Printf("adminapi: audit oidc update: %v", err)
			}
		}

		writeJSON(w, http.StatusOK, OIDCStatus{
			Configured: true,
			IssuerURL:  req.IssuerURL,
			ClientID:   req.ClientID,
		})
	}
}

// ---- DELETE /v1/admin/oidc ----------------------------------------------------

// OIDCDeleteHandler clears all OIDC settings from core_settings.
func OIDCDeleteHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		for _, key := range []string{"oidc_issuer_url", "oidc_client_id", "oidc_client_secret_enc"} {
			if err := pool.DeleteSetting(ctx, key); err != nil {
				httperr.Internal(w, err)
				return
			}
		}

		// Audit — best-effort.
		if sess, ok := auth.SessionFromContext(ctx); ok {
			if err := audit.Log(ctx, pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigOIDCDel,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
			}); err != nil {
				log.Printf("adminapi: audit oidc delete: %v", err)
			}
		}

		writeJSON(w, http.StatusOK, OIDCStatus{Configured: false})
	}
}

// ---- GET /v1/audit-log --------------------------------------------------------

// AuditLogHandler serves GET /v1/audit-log with optional query parameters:
//
//	event_type  — filter to entries of exactly this event type
//	actor_id    — filter to entries by exactly this actor (see audit.ListActors)
//	since       — filter to entries on/after this date (YYYY-MM-DD, local server date)
//	until       — filter to entries on/before this date (YYYY-MM-DD, inclusive)
//	search      — case-insensitive substring match across all decrypted text
//	              fields (see audit.List's doc comment on how this is scanned)
//	before      — cursor: return entries with id < before (newest-first paging)
//	limit       — max entries per page (1-200, default 50)
func AuditLogHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		q := r.URL.Query()
		var before int64
		if s := q.Get("before"); s != "" {
			before, _ = strconv.ParseInt(s, 10, 64)
		}
		limit := 50
		if s := q.Get("limit"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				limit = n
			}
		}

		// since/until come from a plain <input type="date"> on the frontend
		// (YYYY-MM-DD, no timezone) - parsed as UTC dates. until is bumped to
		// the last instant of that day so "until 2026-07-16" includes
		// everything logged on the 16th, not just up to midnight.
		var since, until time.Time
		if s := q.Get("since"); s != "" {
			if t, err := time.Parse("2006-01-02", s); err == nil {
				since = t
			}
		}
		if s := q.Get("until"); s != "" {
			if t, err := time.Parse("2006-01-02", s); err == nil {
				until = t.Add(24*time.Hour - time.Nanosecond)
			}
		}

		entries, err := audit.List(ctx, pool, masterKey, audit.ListParams{
			EventType: q.Get("event_type"),
			ActorID:   q.Get("actor_id"),
			Since:     since,
			Until:     until,
			Search:    q.Get("search"),
			Before:    before,
			Limit:     limit,
		})
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if entries == nil {
			entries = []audit.Entry{}
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

// ---- GET /v1/audit-log/actors ---------------------------------------------------

// AuditActorsHandler serves GET /v1/audit-log/actors: every distinct actor
// that has ever produced an audit entry, for the audit page's actor filter
// dropdown. Cheap at homelab scale (DISTINCT over an indexed column), no
// pagination needed.
func AuditActorsHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actors, err := audit.ListActors(r.Context(), pool, masterKeyEnv)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if actors == nil {
			actors = []audit.ActorOption{}
		}
		writeJSON(w, http.StatusOK, actors)
	}
}

// ---- GET /v1/audit-log/verify --------------------------------------------------

// AuditVerifyHandler serves GET /v1/audit-log/verify, walking the whole
// HMAC hash chain (audit.Verify) and reporting whether it's intact. Exposed
// as an on-demand action on the Security Info page rather than run
// automatically on every page load - the full-table scan is cheap at
// homelab scale but there is no reason to pay it on every visit when the
// chain only changes by appending, never rewriting.
func AuditVerifyHandler(pool *db.Pool, masterKeyEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		masterKey, err := setup.ResolveMasterKey(ctx, pool, masterKeyEnv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusPreconditionFailed)
			return
		}

		result, err := audit.Verify(ctx, pool, masterKey)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// writeJSON is a local copy of the same helper from setup/wizard.go and
// auth/admin.go - each package keeps its own so there is no shared utility
// dependency just for one line of JSON encoding.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
