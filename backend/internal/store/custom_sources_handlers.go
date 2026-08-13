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
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
)

// CustomSourceResponse is what the admin-only custom-sources endpoints
// return. PubKey is included as-is (a public key has no confidentiality
// need - see db's custom_sources.pubkey column comment) so the admin UI can
// show it back for verification without a separate reveal step. The token
// itself is a real credential and is intentionally NEVER included here -
// HasToken only says whether one is on file, same pattern as
// AIProviderRow.HasAdminKey.
type CustomSourceResponse struct {
	ID      string `json:"id"`
	RepoURL string `json:"repo_url"`
	Name    string `json:"name"`
	// Kind is "github" or "forgejo" - see db's custom_sources.kind column
	// comment. Always present (defaults to "github" for rows created before
	// this field existed).
	Kind     string `json:"kind"`
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
		Kind:     r.Kind,
		PubKey:   r.PubKey,
		HasToken: r.Token != "",
		AddedBy:  r.AddedBy,
		AddedAt:  r.AddedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// ── GET /v1/admin/store/custom-sources ────────────────────────────────────────

// ListCustomSourcesHandler serves GET /v1/admin/store/custom-sources.
// Super-admin only (main.go wraps this in superAdminOnly) - same trust
// boundary as adding/changing/removing one: deliberately not exposed to
// the plain GET /v1/store list (which already surfaces the resulting
// module_registry rows to any active session).
func ListCustomSourcesHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.Pool.ListCustomSources(r.Context())
		if err != nil {
			http.Error(w, "failed to list custom sources", http.StatusInternalServerError)
			return
		}
		out := make([]CustomSourceResponse, 0, len(rows))
		for _, row := range rows {
			out = append(out, toCustomSourceResponse(row))
		}
		httperr.JSON(w, http.StatusOK, out)
	}
}

// ── POST /v1/admin/store/custom-sources ───────────────────────────────────────

type addCustomSourceRequest struct {
	RepoURL string `json:"repo_url"`
	Name    string `json:"name"`
	// Kind selects which git-hosting API repo_url speaks: "github" (default
	// when omitted/empty - preserves every existing integration's exact
	// prior behaviour) or "forgejo" for a self-hosted Forgejo/Gitea
	// instance. See db's custom_sources.kind column comment and
	// store.gitProvider (github.go).
	Kind string `json:"kind"`
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
	//
	// Only honored for kind == "github": resolveCustomSourceCredential
	// (modules/installer.go) binds a token to a github.com owner/repo path
	// and never attaches it to any other host, so a token saved against a
	// "forgejo" source would silently never be used. Rejected outright at
	// add-time instead, so an admin who sets one gets a clear error rather
	// than a token that quietly does nothing - private self-hosted sources
	// are not supported yet.
	Token string `json:"token"`
}

// AddCustomSourceHandler serves POST /v1/admin/store/custom-sources.
// Super-admin only (main.go wraps this in superAdminOnly - deliberately
// NOT superAdminReauthOnly: adding a new source is the "anlegen" case,
// which stays reauth-free per the same policy the AI/search provider key
// endpoints follow - creating something new to review/act on later is
// lower-risk than changing or removing an already-trusted one, see
// UpdateCustomSourceHandler/DeleteCustomSourceHandler below). Validates
// the repo URL, stores the source (encrypted - see db.CreateCustomSource),
// then does a one-off fetch to populate the Store listing immediately
// instead of waiting for the next scheduled/manual sync. The fetch
// failing does not fail the request - the source is still saved, and the
// admin will see it succeed on the next sync once whatever was wrong
// (missing manifest.yaml, no releases yet, ...) is fixed - same "save
// now, verify later" pattern as adding a quick link with an unreachable
// URL.
func AddCustomSourceHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := auth.SessionFromContext(r.Context())

		var req addCustomSourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.RepoURL = strings.TrimSpace(req.RepoURL)
		req.Name = strings.TrimSpace(req.Name)
		req.Kind = strings.TrimSpace(req.Kind)
		req.PubKey = strings.TrimSpace(req.PubKey)
		req.Token = strings.TrimSpace(req.Token)

		if req.Kind == "" {
			req.Kind = "github"
		}
		if req.Kind != "github" && req.Kind != "forgejo" {
			http.Error(w, `kind must be "github" or "forgejo"`, http.StatusBadRequest)
			return
		}

		if req.RepoURL == "" {
			http.Error(w, "repo_url is required", http.StatusBadRequest)
			return
		}
		if !isValidCustomSourceRepoURL(req.RepoURL, req.Kind) {
			if req.Kind == "github" {
				http.Error(w, "repo_url must be a https://github.com/<owner>/<repo> URL", http.StatusBadRequest)
			} else {
				http.Error(w, "repo_url must be a https://<host>/<owner>/<repo> URL", http.StatusBadRequest)
			}
			return
		}
		if req.Kind == "forgejo" && req.Token != "" {
			http.Error(w, "token is only supported for github custom sources at the moment", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			// Default to "<owner>/<repo>" (github) or "<host>/<owner>/<repo>"
			// (forgejo, where the host itself carries useful information -
			// several self-hosted instances are far more common than several
			// github.com sources ever are) so the admin isn't forced to
			// invent a label just to add a source.
			if req.Kind == "github" {
				req.Name = strings.TrimPrefix(strings.TrimSuffix(req.RepoURL, "/"), "https://github.com/")
			} else {
				req.Name = strings.TrimPrefix(strings.TrimSuffix(req.RepoURL, "/"), "https://")
			}
		}
		if req.PubKey != "" && !strings.Contains(req.PubKey, "-----BEGIN PUBLIC KEY-----") {
			http.Error(w, "pubkey must be a PEM-encoded public key (or left empty)", http.StatusBadRequest)
			return
		}

		row, err := d.Pool.CreateCustomSource(r.Context(), req.RepoURL, req.Name, req.PubKey, req.Token, req.Kind, sess.UserID)
		if err != nil {
			log.Printf("store: create custom source: %v", err)
			http.Error(w, "failed to save custom source", http.StatusInternalServerError)
			return
		}

		logStoreAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventCustomSourceAdded,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details: fmt.Sprintf(`{"repo_url":%q,"name":%q,"kind":%q,"has_pubkey":%v,"has_token":%v}`,
				req.RepoURL, req.Name, req.Kind, req.PubKey != "", req.Token != ""),
		})

		// Best-effort immediate fetch - errors are logged, not fatal to the
		// request (see doc comment above). entries: 1 for a single-module
		// repo, N for a monorepo (see FetchCustomRepo's doc comment).
		if entries, err := FetchCustomRepo(r.Context(), d.Pool, row.RepoURL, row.Kind, row.PubKey, row.Token); err != nil {
			log.Printf("store: custom source %q: initial fetch failed: %v", row.RepoURL, err)
		} else {
			for _, entry := range entries {
				if err := UpsertEntry(r.Context(), d.Pool, entry); err != nil {
					log.Printf("store: custom source %q: upsert entry %q: %v", row.RepoURL, entry.Name, err)
				}
			}
		}

		httperr.JSON(w, http.StatusCreated, toCustomSourceResponse(row))
	}
}

// ── DELETE /v1/admin/store/custom-sources/{id} ────────────────────────────────

// DeleteCustomSourceHandler serves DELETE /v1/admin/store/custom-sources/{id}.
// Super-admin only, and step-up reauth-gated (main.go wraps this in
// superAdminReauthOnly, added 2026-07-22 alongside AddCustomSourceHandler's
// role elevation): removing a trusted source is the kind of action a
// compromised-but-still-within-SessionTTL session shouldn't be able to do
// without a fresh login, same reasoning as locking a user or deleting an
// AI provider. Removes the source and, best-effort, any module_registry
// rows it produced right away (see DeleteEntriesBySourceRepo) so the Store
// list updates immediately rather than only on the next sync.
func DeleteCustomSourceHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := auth.SessionFromContext(r.Context())
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

// ── PATCH /v1/admin/store/custom-sources/{id} ─────────────────────────────────

// updateCustomSourceRequest mirrors search.patchProviderRequest's *string
// convention: a field absent from the request body is nil (leave
// unchanged), any field present - including an empty string - is applied
// as-is. Name/PubKey are echoed back in full either way (they're not
// secrets), so the frontend always sends both. Token is the one field
// callers are expected to omit entirely when the admin didn't type a new
// one - see db.UpdateCustomSource's doc comment.
type updateCustomSourceRequest struct {
	Name   *string `json:"name"`
	PubKey *string `json:"pubkey"`
	Token  *string `json:"token"`
}

// UpdateCustomSourceHandler serves PATCH /v1/admin/store/custom-sources/{id}.
// Added 2026-07-22: until now the only way to react to a maintainer
// rotating their Cosign key, fix a typo'd display name, or replace an
// expiring GitHub token was to delete the source and re-add it from
// scratch - losing added_by/added_at and re-triggering a full initial
// fetch for no reason. Super-admin only and step-up reauth-gated
// (superAdminReauthOnly in main.go), same reasoning as
// DeleteCustomSourceHandler above. repo_url is deliberately not part of
// the request body - see db.UpdateCustomSource's doc comment for why.
func UpdateCustomSourceHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := auth.SessionFromContext(r.Context())
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}

		var req updateCustomSourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Name != nil {
			trimmed := strings.TrimSpace(*req.Name)
			req.Name = &trimmed
		}
		if req.PubKey != nil {
			trimmed := strings.TrimSpace(*req.PubKey)
			if trimmed != "" && !strings.Contains(trimmed, "-----BEGIN PUBLIC KEY-----") {
				http.Error(w, "pubkey must be a PEM-encoded public key (or left empty)", http.StatusBadRequest)
				return
			}
			req.PubKey = &trimmed
		}
		if req.Token != nil {
			trimmed := strings.TrimSpace(*req.Token)
			req.Token = &trimmed
		}

		updated, found, err := d.Pool.UpdateCustomSource(r.Context(), id, req.Name, req.PubKey, req.Token)
		if err != nil {
			log.Printf("store: update custom source %q: %v", id, err)
			http.Error(w, "failed to update custom source", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "custom source not found", http.StatusNotFound)
			return
		}

		logStoreAudit(r.Context(), authDeps, audit.LogParams{
			EventType:  audit.EventCustomSourceUpdated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			Details: fmt.Sprintf(`{"repo_url":%q,"name_changed":%v,"pubkey_changed":%v,"token_changed":%v}`,
				updated.RepoURL, req.Name != nil, req.PubKey != nil, req.Token != nil),
		})

		httperr.JSON(w, http.StatusOK, toCustomSourceResponse(updated))
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

// isValidCustomSourceRepoURL is isValidGithubRepoURL's kind-aware
// counterpart: for kind == "github" it is exactly isValidGithubRepoURL
// (including the github.com-only restriction, so a "github" source can
// never quietly point somewhere else); for kind == "forgejo" it accepts
// "https://<any host>/<owner>/<repo>" - same shape check (exactly two
// non-empty path segments, no query/fragment), just without the fixed host.
// Used instead of a bare url.Parse so githubRepoPath/parseGitProvider
// (installer.go/github.go) can keep assuming any repo_url that made it into
// custom_sources already has this shape.
func isValidCustomSourceRepoURL(s, kind string) bool {
	if kind == "github" {
		return isValidGithubRepoURL(s)
	}
	const prefix = "https://"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := strings.TrimSuffix(s[len(prefix):], "/")
	slash := strings.Index(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return false
	}
	host := rest[:slash]
	path := rest[slash+1:] // expected "owner/repo"
	if host == "" || strings.EqualFold(host, "github.com") {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}
