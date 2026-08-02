package quicklinks

import (
	"testing"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// isValidTileURL is the XSS guard on quick-link tile hrefs: only absolute
// http(s) URLs and absolute-path (same-origin) URLs are accepted, blocking
// javascript:/data:/vbscript: and similar dangerous schemes.
func TestIsValidTileURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"https URL", "https://example.com", true},
		{"http URL", "http://example.com/path?x=1", true},
		{"internal module path", "/modules/recipes", true},
		{"root path", "/", true},
		{"empty string rejected", "", false},
		{"whitespace-only rejected", "   ", false},
		{"protocol-relative rejected", "//evil.example", false},
		{"javascript scheme rejected", "javascript:alert(1)", false},
		{"data scheme rejected", "data:text/html,<script>alert(1)</script>", false},
		{"vbscript scheme rejected", "vbscript:msgbox(1)", false},
		{"relative path without leading slash rejected", "modules/recipes", false},
		{"ftp scheme rejected", "ftp://example.com/file", false},
		{"mailto scheme rejected", "mailto:test@example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidTileURL(tc.in)
			if got != tc.want {
				t.Fatalf("isValidTileURL(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// mergedTiles combines admin + user tiles in the user's saved order, with
// anything not yet in that order (newly created tiles) appended at the end,
// admin first then user.
func TestMergedTiles(t *testing.T) {
	admin := []db.AdminQuickLinkRow{
		{ID: "a1", Title: "Admin One", URL: "/a1"},
		{ID: "a2", Title: "Admin Two", URL: "/a2"},
	}
	user := []db.UserQuickLinkRow{
		{ID: "u1", Title: "User One", URL: "/u1"},
	}

	t.Run("respects saved order", func(t *testing.T) {
		order := []db.TileRef{
			{Type: "user", ID: "u1"},
			{Type: "admin", ID: "a2"},
			{Type: "admin", ID: "a1"},
		}
		got := mergedTiles(admin, user, order)
		wantIDs := []string{"u1", "a2", "a1"}
		assertTileIDOrder(t, got, wantIDs)
	})

	t.Run("appends tiles missing from order, admin then user", func(t *testing.T) {
		got := mergedTiles(admin, user, nil)
		wantIDs := []string{"a1", "a2", "u1"}
		assertTileIDOrder(t, got, wantIDs)
	})

	t.Run("order referencing a deleted tile is silently skipped", func(t *testing.T) {
		order := []db.TileRef{
			{Type: "admin", ID: "does-not-exist"},
			{Type: "admin", ID: "a1"},
		}
		got := mergedTiles(admin, user, order)
		wantIDs := []string{"a1", "a2", "u1"}
		assertTileIDOrder(t, got, wantIDs)
	})

	t.Run("newly created tile not yet in saved order appears at the end", func(t *testing.T) {
		order := []db.TileRef{
			{Type: "admin", ID: "a1"},
		}
		got := mergedTiles(admin, user, order)
		wantIDs := []string{"a1", "a2", "u1"}
		assertTileIDOrder(t, got, wantIDs)
	})

	t.Run("empty inputs produce empty output", func(t *testing.T) {
		got := mergedTiles(nil, nil, nil)
		if len(got) != 0 {
			t.Fatalf("expected empty result, got %v", got)
		}
	})
}

func assertTileIDOrder(t *testing.T, got []Tile, wantIDs []string) {
	t.Helper()
	if len(got) != len(wantIDs) {
		t.Fatalf("got %d tiles %v, want %d IDs %v", len(got), got, len(wantIDs), wantIDs)
	}
	for i, id := range wantIDs {
		if got[i].ID != id {
			t.Fatalf("position %d: got ID %q, want %q (full result: %v)", i, got[i].ID, id, got)
		}
	}
}
