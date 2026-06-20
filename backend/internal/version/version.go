// Package version holds modulab-core's build-time version string. There is
// no CI/release pipeline yet, so Version is a manually maintained constant -
// once tagged releases exist, this becomes the natural place to inject a
// real version via -ldflags instead of hand-editing it.
package version

// Version is the current modulab-core version. Bump it by hand for now.
const Version = "v0.1.0-dev"

// ProjectURL points operators at the project's homepage for docs and
// updates.
const ProjectURL = "https://modulab.app"
