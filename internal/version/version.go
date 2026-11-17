// Package version is the build's version, shared by the Hub and the
// worker agent (set at build time with -ldflags "-X
// github.com/portcullis/hub/internal/version.Version=<v>": a release
// tag's semver, else 0.0.0-edge). The Hub accepts an agent whose version
// servers.Compatible says goes with its own, and sends requests only to
// such agents.
package version

// Version is semver ("0.1.0-dev" for a local build).
var Version = "0.1.0-dev"
