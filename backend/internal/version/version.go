// Package version holds modulab-core's build-time version string. The CI
// release pipeline (.github/workflows/ci.yml's publish-image job) builds
// and tags the ghcr.io image from the GitHub release tag, but does not
// inject this constant via -ldflags - it is still a manually maintained
// constant, bumped by hand to match each tagged release.
package version

// Version is the current modulab-core version. Bump it by hand for now.
// No leading "v" - the frontend's package.json version has never had one
// either, and showing both with/without "v" side by side (e.g. footer:
// "Core v1.0.0 . Frontend 1.0.0") read as inconsistent.
const Version = "1.0.7"

// ProjectURL points operators at the project's homepage for docs and
// updates.
const ProjectURL = "https://modulab.app"
