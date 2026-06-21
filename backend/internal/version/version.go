// Package version holds modulab-core's build-time version string. There is
// no CI/release pipeline yet, so Version is a manually maintained constant -
// once tagged releases exist, this becomes the natural place to inject a
// real version via -ldflags instead of hand-editing it.
package version

// Version is the current modulab-core version. Bump it by hand for now.
// No leading "v" - the frontend's package.json version has never had one
// either, and showing both with/without "v" side by side (e.g. footer:
// "Core v0.1.0-dev . Frontend 0.1.0") read as inconsistent.
const Version = "0.1.0-dev"

// ProjectURL points operators at the project's homepage for docs and
// updates.
const ProjectURL = "https://modulab.app"
