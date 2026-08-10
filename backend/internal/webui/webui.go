// Package webui holds the frontend bundle that is compiled into the Core
// binary, and serves it.
//
// dist/ MUST live inside this package directory. go:embed patterns cannot
// point outside the package they are declared in - //go:embed
// all:../../../frontend/dist is rejected at compile time with "invalid
// pattern syntax" - so there is no way to embed frontend/dist/ from where
// Vite writes it. The Dockerfile's go-builder stage copies it here before
// running go build; that copy step is required, not an optimization.
//
// The "all:" prefix includes files whose names start with "_" or "."
// Without it those would be skipped silently, which is the wrong failure
// mode for a build artifact directory.
//
// dist/index.html is committed on purpose and must not be deleted. go:embed
// fails the build outright on a directory containing no embeddable files,
// which would break `go build ./...` and the CI "backend" job - that job
// runs without a frontend build, so the directory would otherwise be empty
// there. An HTML page is committed rather than a .gitkeep (which would
// satisfy go:embed just as well, since "all:" covers dotfiles) so that a
// Core built without the frontend serves one page explaining that, instead
// of 404ing every route with no hint why.
package webui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the embedded frontend build rooted at dist/, so callers
// resolve "index.html" and "assets/..." rather than "dist/index.html".
func Dist() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}

const (
	indexFile    = "index.html"
	assetsDir    = "assets"
	assetsPrefix = assetsDir + "/"

	// Cache classes, carried over 1:1 from deploy/nginx.conf.
	//
	// Everything under assets/ carries a content hash in its filename
	// (Vite's assets/<name>-<hash>.js|css), so a new build never reuses an
	// old URL and a stale cached copy still matches its own hash.
	//
	// Everything else - index.html, sw.js, registerSW.js, theme-init.js,
	// workbox-<hash>.js, manifest.webmanifest, logo.svg, the PWA icons -
	// keeps a stable URL across builds and must always be revalidated,
	// otherwise a cached index.html keeps pointing at asset hashes that no
	// longer exist after a deploy. That was the "clear your browser cache
	// after every release" problem fixed in nginx on 2026-08-03.
	immutableCache  = "public, max-age=31536000, immutable"
	revalidateCache = "no-cache, must-revalidate"
)

// extraMIMETypes covers extensions Go's built-in table does not know.
// TypeByExtension is only augmented from /etc/mime.types on Unix when that
// file exists, and the final image (debian:bookworm-slim) is not guaranteed
// to ship one - without these, manifest.webmanifest would go out as
// application/octet-stream and browsers would refuse the PWA manifest
// outright, silently removing installability. nginx got these from its
// bundled mime.types; Core has to state them.
var extraMIMETypes = map[string]string{
	".webmanifest": "application/manifest+json",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".ttf":         "font/ttf",
	".map":         "application/json",
}

// Handler serves the embedded frontend bundle.
func Handler() (http.Handler, error) {
	dist, err := Dist()
	if err != nil {
		return nil, fmt.Errorf("webui: sub fs: %w", err)
	}
	return newHandler(dist)
}

// newHandler is Handler's testable core: it takes the file system rather
// than reaching for the embedded one, so tests can supply a synthetic
// bundle. They have to - the CI "backend" job builds without a frontend, so
// the real dist/ there holds nothing but the placeholder index.html.
func newHandler(dist fs.FS) (http.Handler, error) {
	for ext, typ := range extraMIMETypes {
		if err := mime.AddExtensionType(ext, typ); err != nil {
			return nil, fmt.Errorf("webui: register mime type %q: %w", ext, err)
		}
	}

	// ETags are precomputed once at startup rather than per request, and
	// they are needed at all because embed.FS reports a zero ModTime: with
	// neither Last-Modified nor ETag, http.ServeContent cannot answer a
	// conditional request, so every revalidation of index.html/sw.js/
	// manifest.webmanifest would transfer the full body again. nginx sent
	// both headers; without this, dropping it would be a straight
	// regression. Only the hashes are kept in memory - the bodies stay in
	// the embedded FS and are streamed from there.
	etags := make(map[string]string)
	err := fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(dist, p)
		if err != nil {
			return fmt.Errorf("webui: read %s: %w", p, err)
		}
		sum := sha256.Sum256(body)
		etags[p] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := etags[indexFile]; !ok {
		return nil, fmt.Errorf("webui: %s missing from the bundle", indexFile)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// path.Clean resolves ".." before the lookup, so a traversal
		// attempt can only ever end up at some other in-bundle name (or at
		// none, and then the SPA fallback below). fs.FS would reject an
		// escaping path anyway, but resolving here keeps the ETag lookup
		// and the file open agreeing on one name.
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")

		etag, ok := etags[name]
		if !ok {
			// A miss under assets/ is a real 404, not a client-side route.
			// nginx drew the same line: "location ^~ /assets/" carried no
			// try_files, and the ^~ prefix stopped "location /"'s fallback
			// from ever applying there.
			//
			// The distinction matters after a deploy. A browser still
			// holding the previous release's index.html asks for an asset
			// hash that no longer exists; answering 200 with the HTML shell
			// makes the module loader fail on a MIME error ("expected a
			// JavaScript module script but the server responded with a MIME
			// type of text/html") and the page goes blank - with a 200 in
			// the access log and nothing pointing at a stale cache. A 404
			// says what actually happened, and is what the SPA's own
			// stale-build detection expects to see.
			//
			// The name == assetsDir case covers a request for the directory
			// itself, which WalkDir never puts in the map.
			if name == assetsDir || strings.HasPrefix(name, assetsPrefix) {
				http.NotFound(w, r)
				return
			}
			// SPA fallback for everything else, equivalent to nginx's
			// "try_files $uri $uri/ /index.html": an unknown path is a
			// client-side route, so React Router gets to resolve it.
			name, etag = indexFile, etags[indexFile]
		}

		if strings.HasPrefix(name, assetsPrefix) {
			w.Header().Set("Cache-Control", immutableCache)
		} else {
			w.Header().Set("Cache-Control", revalidateCache)
		}
		// Set before ServeContent: it reads this header to answer
		// If-None-Match with a 304 itself.
		w.Header().Set("ETag", etag)

		f, err := dist.Open(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer func() { _ = f.Close() }()

		// embed.FS files implement io.ReadSeeker (verified), which lets
		// ServeContent handle Range requests and content sniffing. The
		// fallback keeps this correct for any other fs.FS a caller or test
		// might pass in.
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			body, readErr := io.ReadAll(f)
			if readErr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			rs = bytes.NewReader(body)
		}

		// Zero modtime: embed.FS has none, and passing it explicitly stops
		// ServeContent from emitting a bogus Last-Modified. The ETag above
		// is what drives revalidation.
		http.ServeContent(w, r, name, time.Time{}, rs)
	}), nil
}
