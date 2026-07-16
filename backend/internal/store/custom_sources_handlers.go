// Admin endpoints for custom module sources (HACS-style "custom repositories"):
// arbitrary GitHub repos an admin explicitly trusts on top of the built-in
// official/community registries. See db.CustomSourceRow and
// syncAll/FetchCustomRepo for how these feed into the module_registry cache.
package store

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// CustomSourceResponse is what the admin-only custom-sources endpoints
// return. PubKey is included as-is (a public key has no confidentiality
// need - see db's custom_sources.pubkey column comment) so the admin UI can
// show it back for verification without a separate reveal step. The token
// itself is a real credential and is intentionally NEVER included here -
// HasToken only says whether one is on file, same pattern as
// AIProviderRow.HasAdminKey.
type CustomSourceResponse struct {
	ID       string `json:"id"`
	RepoURL  string `json:"repo_url"`
	Name     string `json:"name"`
	PubKey   string `json:"pubkey,omitempty"`
	HasToken bool   `json:"has_token"`
	AddedBy  string `json:"added_by"`
	AddedAt  string `json:"added_at"`
}

func toCustomSourceResponse(r db.CustomSourceRow) CustomSourceResponse {
	return CustomSourceResponse{
		ID:       r.ID,
		RepoURL:  r.RepoURL,
		Name:     r.Name,
		PubKey:   r.PubKey,
		HasToken: r.Token != "",
		AddedBy:  r.AddedBy,
		AddedAt:  r.AddedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// ── GET /v1/admin/store/custom-sources ────────────────────────────────────────

// ListCustomSourcesHandler serves GET /v1/admin/store/custom-sources.
// Requires org-admin or super-admin — same trust boundary as adding one:
// deliberately not exposed to the plain GET /v1/store list (which already
// surfaces the resulting module_registry rows to any active session).
func ListCustomSourcesHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
			return
		}
		rows, err := d.Pool.ListCustomSources(r.Context())
		if err != nil {
			http.Error(w, "failed to list custom sources", http.StatusInternalServerError)
			return
		}
		out := make([]CustomSourceResponse, 0, len(rows))
		for _, row := range rows {
			out = append(out, toCustomSourceResponse(row))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// ── POST /v1/admin/store/custom-sources ───────────────────────────────────────

type addCustomSourceRequest struct {
	RepoURL string `json:"repo_url"`
	Name    string `json:"name"`
	// PubKey is the Cosign public key (PEM text), manually entered by the
	// admin - deliberately not auto-fetched from the repo (see Entry.
	// CosignPubKey's doc comment for the trust-on-first-use reasoning).
	// Optional: an empty value means the source installs as
	// unsigned/unverified, same as a community module without a .sig file.
	PubKey string `json:"pubkey"`
	// Token is an optional GitHub PAT (fine-grained or classic) for a
	// private repo. Empty means the repo is public. Always GCM-encrypted at
	// rest (db.CreateCustomSource) and never echoed back - see
	// CustomSourceResponse.HasToken.
	Token string `json:"token"`
}

// AddCustomSourceHandler serves POST /v1/admin/store/custom-sources.
// Requires org-admin or super-admin. Validates the repo URL, stores the
// source (encrypted - see db.CreateCustomSource), then does a one-off fetch
// to populate the Store listing immediately instead of waiting for the next
// scheduled/manual sync. The fetch failing does not fail the request - the
// source is still saved, and the admin will see it succeed on the next sync
// once whatever was wrong (missing manifest.yaml, no releases yet, ...) is
// fixed - same "save now, verify later" pattern as adding a quick link with
// an unreachable URL.
func AddCustomSourceHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}

		var req addCustomSourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.RepoURL = strings.TrimSpace(req.RepoURL)
		req.Name = strings.TrimSpace(req.Name)
		req.PubKey = strings.TrimSpace(req.PubKey)
		req.Token = strings.TrimSpace(req.Token)

		if req.RepoURL == "" {
			http.Error(w, "repo_url is required", http.StatusBadRequest)
			return
		}
		if !isValidGithubRepoURL(req.RepoURL) {
			http.Error(w, "repo_url must be a https://github.com/<owner>/<repo> URL", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			// Default to "<owner>/<repo>" so the admin isn't forced to invent
			// a label just to add a source.
			req.Name = strings.TrimPrefix(strings.TrimSuffix(req.RepoURL, "/"), "https://github.com/")
		}
		if req.PubKey != "" && !strings.Contains(req.PubKey, "-----BEGIN PUBLIC KEY-----") {
			http.Error(w, "pubkey must be a PEM-encoded public key (or left empty)", http.StatusBadRequest)
			return
		}

		row, err := d.Pool.CreateCustomSource(r.Context(), req.RepoURL, req.Name, req.PubKey, req.Token, sess.UserID)
		if err != nil {
			log.Printf("store: create custom source: %v", err)
			http.Error(w, "failed to save custom source", http.StatusInternalServerError)
			return
		}

		logStoreAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventCustomSourceAdded,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details: fmt.Sprintf(`{"repo_url":%q,"name":%q,"has_pubkey":%v,"has_token":%v}`,
				req.RepoURL, req.Name, req.PubKey != "", req.Token != ""),
		})

		// Best-effort immediate fetch - errors are logged, not fatal to the
		// request (see doc comment above).
		if entry, err := FetchCustomRepo(r.Context(), d.Pool, row.RepoURL, row.PubKey, row.Token); err != nil {
			log.Printf("store: custom source %q: initial fetch failed: %v", row.RepoURL, err)
		} else if err := UpsertEntry(r.Context(), d.Pool, entry); err != nil {
			log.Printf("store: custom source %q: upsert entry: %v", row.RepoURL, err)
		}

		writeJSON(w, http.StatusCreated, toCustomSourceResponse(row))
	}
}

// ── DELETE /v1/admin/store/custom-sources/{id} ────────────────────────────────

// DeleteCustomSourceHandler serves DELETE /v1/admin/store/custom-sources/{id}.
// Requires org-admin or super-admin. Removes the source and, best-effort, any
// module_registry rows it produced right away (see
// DeleteEntriesBySourceRepo) so the Store list updates immediately rather
// than only on the next sync.
func DeleteCustomSourceHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(authDeps, w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		// Look up the row first so we know its repo_url for the cleanup
		// below and for a meaningful audit log entry - DeleteCustomSource
		// itself only returns whether a row existed.
		rows, err := d.Pool.ListCustomSources(r.Context())
		if err != nil {
			http.Error(w, "failed to look up custom source", http.StatusInternalServerError)
			return
		}
		var target *db.CustomSourceRow
		for i := range rows {
			if rows[i].ID == id {
				target = &rows[i]
				break
			}
		}
		if target == nil {
			http.Error(w, "custom source not found", http.StatusNotFound)
			return
		}

		deleted, err := d.Pool.DeleteCustomSource(r.Context(), id)
		if err != nil {
			http.Error(w, "failed to delete custom source", http.StatusInternalServerError)
			return
		}
		if !deleted {
			http.Error(w, "custom source not found", http.StatusNotFound)
			return
		}

		if err := DeleteEntriesBySourceRepo(r.Context(), d.Pool, target.RepoURL); err != nil {
			log.Printf("store: custom source %q: cleanup registry entries: %v", target.RepoURL, err)
		}

		logStoreAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventCustomSourceRemoved,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details:    fmt.Sprintf(`{"repo_url":%q,"name":%q}`, target.RepoURL, target.Name),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

// isValidGithubRepoURL reports whether s looks like
// "https://github.com/<owner>/<repo>" (optionally with a trailing slash),
// no deeper path, query, or fragment. Deliberately conservative - custom
// sources fetch raw content and release assets by string-concatenating this
// URL (see FetchCustomRepo, installer.go's zipURL construction), so a
// malformed or unexpected-shape URL here would otherwise surface as a
// confusing downstream fetch failure instead of a clear validation error.
func isValidGithubRepoURL(s string) bool {
	const prefix = "https://github.com/"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := strings.TrimSuffix(s[len(prefix):], "/")
	if rest == "" {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}
