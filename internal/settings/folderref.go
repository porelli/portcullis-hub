package settings

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// FolderRefPrefix marks a path value that names a shared folder
// (contract §13.15): folder:<id> or folder:<id>/<subpath>.
const FolderRefPrefix = "folder:"

// FolderIDRe is a shared folder's id (§14.1).
var FolderIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// maxFolderSubpath bounds a folder ref's subpath (bytes).
const maxFolderSubpath = 255

// ErrFolderRef: a folder ref reached a path kind directly. Only the Hub
// resolves refs (against its folder definitions); the kind fails closed.
var ErrFolderRef = errors.New("a shared folder value is resolved by the Hub")

// ParseFolderRef splits a folder ref into its folder id and subpath ("" =
// the folder root). ok is false for a value without the prefix (a plain
// host path, err nil); err is set for a malformed ref.
func ParseFolderRef(v string) (id, sub string, ok bool, err error) {
	rest, ok := strings.CutPrefix(v, FolderRefPrefix)
	if !ok {
		return "", "", false, nil
	}
	id, sub, hasSub := strings.Cut(rest, "/")
	if !FolderIDRe.MatchString(id) {
		return "", "", true, fmt.Errorf("%q: the folder id must match %s", v, FolderIDRe)
	}
	if !hasSub {
		return id, "", true, nil
	}
	switch {
	case sub == "":
		return "", "", true, fmt.Errorf("%q: the subpath is empty (no trailing /)", v)
	case len(sub) > maxFolderSubpath:
		return "", "", true, fmt.Errorf("%q: the subpath is longer than %d bytes", v, maxFolderSubpath)
	case templates.HasControlChars(sub):
		return "", "", true, fmt.Errorf("%q: the subpath contains control characters", v)
	case strings.Contains(sub, ":"):
		return "", "", true, fmt.Errorf("%q: the subpath may not contain ':'", v)
	case path.IsAbs(sub) || path.Clean(sub) != sub:
		return "", "", true, fmt.Errorf("%q: the subpath must be relative and clean (no //, no trailing /, no . segment)", v)
	case sub == ".." || strings.HasPrefix(sub, "../") || strings.Contains(sub, "/../") || strings.HasSuffix(sub, "/.."):
		return "", "", true, fmt.Errorf("%q: the subpath may not contain ..", v)
	}
	return id, sub, true, nil
}
