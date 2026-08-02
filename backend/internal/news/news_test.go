package news

import "testing"

// detectFormat peeks at the root XML element to distinguish RSS from Atom
// (or reject anything else) before the format-specific parser runs.
func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"RSS 2.0", `<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`, "rss"},
		{"Atom 1.0", `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>`, "feed"},
		{"unrelated XML root", `<?xml version="1.0"?><html><body>not a feed</body></html>`, "html"},
		{"not XML at all", "this is not xml", ""},
		{"empty body", "", ""},
		{"leading whitespace/comments tolerated", `<?xml version="1.0"?><!-- comment --><rss></rss>`, "rss"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectFormat([]byte(tc.body))
			if got != tc.want {
				t.Fatalf("detectFormat(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// isHTTPURL gates which OPML/feed URLs are accepted - only absolute http(s),
// blocking file:/javascript:/data: and other schemes an attacker-supplied
// OPML file or feed link could otherwise smuggle in.
func TestIsHTTPURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"https URL", "https://example.com/feed.xml", true},
		{"http URL", "http://example.com/feed.xml", true},
		{"URL with surrounding whitespace", "  https://example.com/feed.xml  ", true},
		{"empty string", "", false},
		{"file scheme rejected", "file:///etc/passwd", false},
		{"javascript scheme rejected", "javascript:alert(1)", false},
		{"relative path rejected", "/feed.xml", false},
		{"no scheme at all", "example.com/feed.xml", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isHTTPURL(tc.in)
			if got != tc.want {
				t.Fatalf("isHTTPURL(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// flattenOPML recursively collects every leaf <outline> that carries an
// xmlUrl attribute, so folder-grouped feeds are treated the same as a flat
// list - folders themselves (no xmlUrl) are dropped, not flattened into
// empty entries.
func TestFlattenOPML(t *testing.T) {
	t.Run("flat list", func(t *testing.T) {
		in := []opmlOutline{
			{Text: "Feed A", XMLURL: "https://a.example/feed.xml"},
			{Text: "Feed B", XMLURL: "https://b.example/feed.xml"},
		}
		got := flattenOPML(in)
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2: %v", len(got), got)
		}
	})

	t.Run("nested folders are flattened", func(t *testing.T) {
		in := []opmlOutline{
			{
				Text: "Tech (folder)",
				Children: []opmlOutline{
					{Text: "Feed A", XMLURL: "https://a.example/feed.xml"},
					{
						Text: "Nested folder",
						Children: []opmlOutline{
							{Text: "Feed B", XMLURL: "https://b.example/feed.xml"},
						},
					},
				},
			},
			{Text: "Top-level feed", XMLURL: "https://c.example/feed.xml"},
		}
		got := flattenOPML(in)
		if len(got) != 3 {
			t.Fatalf("got %d entries, want 3: %v", len(got), got)
		}
		urls := map[string]bool{}
		for _, o := range got {
			urls[o.XMLURL] = true
		}
		for _, want := range []string{"https://a.example/feed.xml", "https://b.example/feed.xml", "https://c.example/feed.xml"} {
			if !urls[want] {
				t.Fatalf("missing expected URL %q in flattened result %v", want, got)
			}
		}
	})

	t.Run("folder-only outline (no xmlUrl) is dropped, not emitted empty", func(t *testing.T) {
		in := []opmlOutline{
			{Text: "Empty folder", Children: nil},
		}
		got := flattenOPML(in)
		if len(got) != 0 {
			t.Fatalf("expected no entries for a folder with no feeds, got %v", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got := flattenOPML(nil)
		if len(got) != 0 {
			t.Fatalf("expected empty result, got %v", got)
		}
	})
}
