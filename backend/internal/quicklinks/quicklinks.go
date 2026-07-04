// Package quicklinks implements the Schnellzugriff-Grid feature: admin-managed
// global tiles and per-user personal tiles that can be freely reordered per
// user via a drag-and-drop interface on the Home page.
//
// The merged tile list (GET /v1/quick-links) applies the user's saved order
// (user_tile_order) to a combined set of admin and user tiles. Unknown tiles
// (added since the order was last saved) are appended at the end. User order
// is persisted via PATCH /v1/quick-links/order.
//
// Admin CRUD (POST/PATCH/DELETE /v1/admin/quick-links/*) requires org-admin
// or super-admin role. All other endpoints require any approved session.
package quicklinks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// logQuickLinkAudit writes one audit_log entry for a quick-link admin
// action. Mirrors auth/admin.go's logAudit and its counterparts in the
// modules/news packages (same "resolve master key, log-and-swallow on
// failure" shape).
func logQuickLinkAudit(ctx context.Context, d auth.Deps, p audit.LogParams) {
	masterKey, err := setup.ResolveMasterKey(ctx, d.Pool, d.MasterKeyEnv)
	if err != nil {
		log.Printf("quicklinks: audit: failed to resolve master key for %s: %v", p.EventType, err)
		return
	}
	if err := audit.Log(ctx, d.Pool, masterKey, p); err != nil {
		log.Printf("quicklinks: audit: failed to write %s: %v", p.EventType, err)
	}
}

// ---- Response types ---------------------------------------------------------

// Tile is one entry in the merged quick-links list returned to the frontend.
// Type tells the frontend which "bucket" (and therefore which delete endpoint)
// this tile belongs to.
type Tile struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "admin" | "user"
	Title       string `json:"title"`
	URL         string `json:"url"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
}

// AdminTile is one entry in the admin-only list (GET /v1/admin/quick-links).
// Identical shape to Tile but with the extra created_by field.
type AdminTile struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
	CreatedBy   string `json:"created_by"`
}

// ---- Local helpers ----------------------------------------------------------

// isValidTileURL returns true for URLs that are safe to store as quick-link tile
// hrefs. Accepts http/https absolute URLs and absolute-path URLs (e.g.
// /modules/rezepte) for internal ModuLab module links. Blocks javascript:,
// data:, and other dangerous schemes.
func isValidTileURL(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	// Absolute internal path (starts with / but not //).
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return true
	}
	// Absolute HTTP(S) URL.
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// ---- Merge helper -----------------------------------------------------------

// mergedTiles combines admin and user tiles in the user's saved order.
// Tiles not present in the order are appended at the end (admin first, then
// user), so newly created tiles always appear without the user having to
// explicitly save a new order.
func mergedTiles(adminLinks []db.AdminQuickLinkRow, userLinks []db.UserQuickLinkRow, order []db.TileRef) []Tile {
	// Build lookup maps for O(1) access.
	adminMap := make(map[string]db.AdminQuickLinkRow, len(adminLinks))
	for _, a := range adminLinks {
		adminMap[a.ID] = a
	}
	userMap := make(map[string]db.UserQuickLinkRow, len(userLinks))
	for _, u := range userLinks {
		userMap[u.ID] = u
	}

	seen := make(map[string]bool)
	var out []Tile

	// Apply saved order first.
	for _, ref := range order {
		switch ref.Type {
		case "admin":
			if a, ok := adminMap[ref.ID]; ok {
				out = append(out, Tile{
					ID: a.ID, Type: "admin", Title: a.Title, URL: a.URL,
					Icon: a.Icon, Description: a.Description, SortOrder: a.SortOrder,
				})
				seen[ref.ID] = true
			}
		case "user":
			if u, ok := userMap[ref.ID]; ok {
				out = append(out, Tile{
					ID: u.ID, Type: "user", Title: u.Title, URL: u.URL,
					Icon: u.Icon, Description: u.Description, SortOrder: u.SortOrder,
				})
				seen[ref.ID] = true
			}
		}
	}

	// Append admin tiles not yet in the order (e.g. newly created).
	for _, a := range adminLinks {
		if !seen[a.ID] {
			out = append(out, Tile{
				ID: a.ID, Type: "admin", Title: a.Title, URL: a.URL,
				Icon: a.Icon, Description: a.Description, SortOrder: a.SortOrder,
			})
		}
	}
	// Append user tiles not yet in the order.
	for _, u := range userLinks {
		if !seen[u.ID] {
			out = append(out, Tile{
				ID: u.ID, Type: "user", Title: u.Title, URL: u.URL,
				Icon: u.Icon, Description: u.Description, SortOrder: u.SortOrder,
			})
		}
	}

	return out
}

// ---- User-facing handlers ---------------------------------------------------

// ListHandler is GET /v1/quick-links.
// Returns the merged, user-ordered list of all admin and personal tiles.
func ListHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		adminLinks, err := d.Pool.ListAdminQuickLinks(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userLinks, err := d.Pool.ListUserQuickLinks(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		order, err := d.Pool.GetUserTileOrder(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tiles := mergedTiles(adminLinks, userLinks, order)
		if tiles == nil {
			tiles = []Tile{}
		}
		writeJSON(w, http.StatusOK, tiles)
	}
}

// CreateUserLinkHandler is POST /v1/quick-links.
// Body: {"title":"…","url":"…","icon":"…","description":"…"}
// Creates a personal tile for the current user and returns the new tile id.
func CreateUserLinkHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		var body struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Icon        string `json:"icon"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.Title) == "" || strings.TrimSpace(body.URL) == "" {
			http.Error(w, "title and url are required", http.StatusBadRequest)
			return
		}
		if !isValidTileURL(body.URL) {
			http.Error(w, "url must be a valid http/https URL or an absolute path", http.StatusBadRequest)
			return
		}
		id, err := d.Pool.CreateUserQuickLink(r.Context(), sess.UserID, body.Title, body.URL, body.Icon, body.Description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteUserLinkHandler is DELETE /v1/quick-links/{id}.
// Deletes a personal tile owned by the current user (user_id guard in DB).
func DeleteUserLinkHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		found, err := d.Pool.DeleteUserQuickLink(r.Context(), sess.UserID, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SaveOrderHandler is PATCH /v1/quick-links/order.
// Body: {"order":[{"type":"admin","id":"…"},…]}
// Persists the user's custom tile ordering.
func SaveOrderHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireActiveSession(d, w, r)
		if !ok {
			return
		}
		var body struct {
			Order []db.TileRef `json:"order"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := d.Pool.SetUserTileOrder(r.Context(), sess.UserID, body.Order); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- Admin handlers ---------------------------------------------------------

// AdminListHandler is GET /v1/admin/quick-links.
func AdminListHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(d, w, r); !ok {
			return
		}
		links, err := d.Pool.ListAdminQuickLinks(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := make([]AdminTile, 0, len(links))
		for _, l := range links {
			resp = append(resp, AdminTile{
				ID:          l.ID,
				Title:       l.Title,
				URL:         l.URL,
				Icon:        l.Icon,
				Description: l.Description,
				SortOrder:   l.SortOrder,
				CreatedBy:   l.CreatedBy,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// AdminCreateHandler is POST /v1/admin/quick-links.
// Body: {"title":"…","url":"…","icon":"…","description":"…","sort_order":0}
func AdminCreateHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}
		var body struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Icon        string `json:"icon"`
			Description string `json:"description"`
			SortOrder   int    `json:"sort_order"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.Title) == "" || strings.TrimSpace(body.URL) == "" {
			http.Error(w, "title and url are required", http.StatusBadRequest)
			return
		}
		if !isValidTileURL(body.URL) {
			http.Error(w, "url must be a valid http/https URL or an absolute path", http.StatusBadRequest)
			return
		}
		link, err := d.Pool.CreateAdminQuickLink(r.Context(),
			body.Title, body.URL, body.Icon, body.Description, body.SortOrder, sess.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logQuickLinkAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventQuickLinkCreated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   link.ID,
			Details:    fmt.Sprintf(`{"title":%q,"url":%q}`, link.Title, link.URL),
		})
		writeJSON(w, http.StatusCreated, AdminTile{
			ID:          link.ID,
			Title:       link.Title,
			URL:         link.URL,
			Icon:        link.Icon,
			Description: link.Description,
			SortOrder:   link.SortOrder,
			CreatedBy:   link.CreatedBy,
		})
	}
}

// AdminUpdateHandler is PATCH /v1/admin/quick-links/{id}.
// Body: {"title":"…","url":"…","icon":"…","description":"…","sort_order":0}
func AdminUpdateHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		var body struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Icon        string `json:"icon"`
			Description string `json:"description"`
			SortOrder   int    `json:"sort_order"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.Title) == "" || strings.TrimSpace(body.URL) == "" {
			http.Error(w, "title and url are required", http.StatusBadRequest)
			return
		}
		if !isValidTileURL(body.URL) {
			http.Error(w, "url must be a valid http/https URL or an absolute path", http.StatusBadRequest)
			return
		}
		found, err := d.Pool.UpdateAdminQuickLink(r.Context(),
			id, body.Title, body.URL, body.Icon, body.Description, body.SortOrder)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		logQuickLinkAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventQuickLinkUpdated,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   id,
			Details:    fmt.Sprintf(`{"title":%q,"url":%q}`, body.Title, body.URL),
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminDeleteHandler is DELETE /v1/admin/quick-links/{id}.
func AdminDeleteHandler(d auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.RequireAdminSession(d, w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		found, err := d.Pool.DeleteAdminQuickLink(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		logQuickLinkAudit(r.Context(), d, audit.LogParams{
			EventType:  audit.EventQuickLinkDeleted,
			ActorID:    sess.UserID,
			ActorEmail: sess.Email,
			TargetID:   id,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}
