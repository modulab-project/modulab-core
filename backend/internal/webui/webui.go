// Package webui holds the frontend bundle that is compiled into the Core
// binary.
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
// there. A .gitkeep would satisfy go:embed just as well (verified: "all:"
// covers dotfiles, a bare "dist" pattern does not). An HTML page is
// committed instead so that a Core built without the frontend serves one
// page explaining that, rather than 404ing every route with no hint why.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the embedded frontend build rooted at dist/, so callers
// resolve "index.html" and "assets/..." rather than "dist/index.html".
func Dist() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
