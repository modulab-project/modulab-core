package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// testBundle mirrors the shape of a real Vite build (see frontend/dist
// after `npm run build`): hashed chunks under assets/, plus the unhashed
// PWA/bootstrap files that sit in the root and must NOT be cached
// immutably.
func testBundle() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                    {Data: []byte(`<!doctype html><html><body><div id="root"></div></body></html>`)},
		"assets/index--MsWK79C.js":      {Data: []byte("console.log('app');")},
		"assets/index-ABC123.css":       {Data: []byte("body{color:red}")},
		"assets/tabler-icons-XYZ.woff2": {Data: []byte("woff2-bytes")},
		"theme-init.js":                 {Data: []byte("console.log('theme');")},
		"sw.js":                         {Data: []byte("self.skipWaiting();")},
		"registerSW.js":                 {Data: []byte("// register")},
		"workbox-0bb07689.js":           {Data: []byte("// workbox")},
		"manifest.webmanifest":          {Data: []byte(`{"name":"ModuLab"}`)},
		"logo.svg":                      {Data: []byte("<svg/>")},
	}
}

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := newHandler(testBundle())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h
}

func do(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// A bundle without index.html cannot serve the SPA fallback, so it must be
// rejected at construction rather than 404ing at runtime.
func TestNewHandlerRequiresIndex(t *testing.T) {
	if _, err := newHandler(fstest.MapFS{"assets/x.js": {Data: []byte("x")}}); err == nil {
		t.Fatal("newHandler accepted a bundle without index.html")
	}
}

// Cache classes must match deploy/nginx.conf exactly: only assets/ is
// immutable, everything else revalidates.
func TestCacheClasses(t *testing.T) {
	h := newTestHandler(t)
	cases := map[string]string{
		"/assets/index--MsWK79C.js":      immutableCache,
		"/assets/index-ABC123.css":       immutableCache,
		"/assets/tabler-icons-XYZ.woff2": immutableCache,
		"/":                              revalidateCache,
		"/index.html":                    revalidateCache,
		"/sw.js":                         revalidateCache,
		"/registerSW.js":                 revalidateCache,
		"/workbox-0bb07689.js":           revalidateCache,
		"/theme-init.js":                 revalidateCache,
		"/manifest.webmanifest":          revalidateCache,
		"/logo.svg":                      revalidateCache,
		"/settings/deep/route":           revalidateCache,
	}
	for target, want := range cases {
		if got := do(t, h, "GET", target, nil).Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", target, got, want)
		}
	}
}

// .webmanifest and .woff2 are absent from Go's built-in MIME table; a wrong
// type on the manifest silently breaks PWA installability.
func TestContentTypes(t *testing.T) {
	h := newTestHandler(t)
	cases := map[string]string{
		"/manifest.webmanifest":          "application/manifest+json",
		"/assets/tabler-icons-XYZ.woff2": "font/woff2",
		"/assets/index--MsWK79C.js":      "text/javascript",
		"/assets/index-ABC123.css":       "text/css",
		"/logo.svg":                      "image/svg+xml",
		"/":                              "text/html",
	}
	for target, want := range cases {
		got := do(t, h, "GET", target, nil).Header().Get("Content-Type")
		if !strings.HasPrefix(got, want) {
			t.Errorf("%s: Content-Type = %q, want prefix %q", target, got, want)
		}
	}
}

// Equivalent to nginx's "try_files $uri $uri/ /index.html".
func TestSPAFallback(t *testing.T) {
	h := newTestHandler(t)
	for _, target := range []string{"/", "/settings", "/settings/deep/route", "/modules/my-place", "/some.file.with.dots"} {
		rec := do(t, h, "GET", target, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", target, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `<div id="root">`) {
			t.Errorf("%s: did not serve index.html", target)
		}
	}
}

// A miss under assets/ must NOT fall through to index.html: nginx answered
// 404 there, and a browser holding a stale index.html depends on that to
// notice its asset hashes are gone instead of parsing HTML as a module.
func TestMissingAssetIs404(t *testing.T) {
	h := newTestHandler(t)
	for _, target := range []string{"/assets/index-GONE1234.js", "/assets/nope.css", "/assets/", "/assets"} {
		rec := do(t, h, "GET", target, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), `<div id="root">`) {
			t.Errorf("%s: served the SPA shell instead of 404ing", target)
		}
	}
}

// embed.FS has a zero ModTime, so ETags are the only thing that can produce
// a 304. Without them every revalidation would re-transfer the full body.
func TestConditionalRequests(t *testing.T) {
	h := newTestHandler(t)
	for _, target := range []string{"/", "/sw.js", "/manifest.webmanifest", "/assets/index--MsWK79C.js"} {
		first := do(t, h, "GET", target, nil)
		etag := first.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("%s: no ETag on the first response", target)
		}
		if first.Header().Get("Last-Modified") != "" {
			t.Errorf("%s: unexpected Last-Modified (embed has no modtime)", target)
		}

		second := do(t, h, "GET", target, map[string]string{"If-None-Match": etag})
		if second.Code != http.StatusNotModified {
			t.Errorf("%s: revalidation = %d, want 304", target, second.Code)
		}
		if second.Body.Len() != 0 {
			t.Errorf("%s: 304 carried a %d-byte body", target, second.Body.Len())
		}
		if second.Header().Get("Cache-Control") == "" {
			t.Errorf("%s: 304 lost Cache-Control", target)
		}
	}
}

// Two different files must not share an ETag, or a browser would keep a
// stale copy of one after the other changed.
func TestETagsDiffer(t *testing.T) {
	h := newTestHandler(t)
	a := do(t, h, "GET", "/sw.js", nil).Header().Get("ETag")
	b := do(t, h, "GET", "/theme-init.js", nil).Header().Get("ETag")
	if a == b {
		t.Errorf("distinct files share an ETag: %q", a)
	}
}

func TestPathTraversal(t *testing.T) {
	h := newTestHandler(t)
	for _, target := range []string{"/../secret", "/assets/../../secret", "/./../../etc/passwd", "/assets/%2e%2e/%2e%2e/secret"} {
		rec := do(t, h, "GET", target, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="root">`) {
			t.Errorf("%s: status %d — expected the SPA fallback, not a leak", target, rec.Code)
		}
	}
}

func TestRangeRequest(t *testing.T) {
	h := newTestHandler(t)
	rec := do(t, h, "GET", "/assets/index--MsWK79C.js", map[string]string{"Range": "bytes=0-4"})
	if rec.Code != http.StatusPartialContent {
		t.Errorf("status = %d, want 206", rec.Code)
	}
	if rec.Body.Len() != 5 {
		t.Errorf("got %d bytes, want 5", rec.Body.Len())
	}
}

func TestHEAD(t *testing.T) {
	h := newTestHandler(t)
	rec := do(t, h, "HEAD", "/", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("no ETag on HEAD")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD returned a %d-byte body", rec.Body.Len())
	}
}

// The placeholder-only bundle is what the CI "backend" job compiles
// against; it must still produce a working handler.
func TestPlaceholderOnlyBundle(t *testing.T) {
	h, err := newHandler(fstest.MapFS{
		"index.html": {Data: []byte("<html>Frontend not built.</html>")},
	})
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	rec := do(t, h, "GET", "/anything", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Frontend not built.") {
		t.Errorf("status %d, body %q", rec.Code, rec.Body.String())
	}
}

// The real embedded bundle must at minimum be constructible - this is what
// catches a broken //go:embed or a missing placeholder.
func TestEmbeddedBundleLoads(t *testing.T) {
	if _, err := Handler(); err != nil {
		t.Fatalf("Handler(): %v", err)
	}
}
