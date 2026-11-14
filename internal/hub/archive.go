package hub

import "github.com/portcullis/hub/internal/runtime/archive"

// The engine archive forms live in internal/runtime/archive (shared with
// the docker backend's Podman extract).
type archiveNames = archive.Names

const formBase = archive.FormBase

var (
	newArchiveNames  = archive.NewNames
	normalizeArchive = archive.Normalize
	relativeArchive  = archive.Relative
)
