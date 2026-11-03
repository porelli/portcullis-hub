package settings

import (
	"fmt"
	"path"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// pathKind is a host directory the app bind-mounts (§13.2 path). The
// canonical value is the cleaned absolute path.
type pathKind struct{}

func (pathKind) Name() string { return templates.TypePath }

func (pathKind) CheckOption(o *templates.Option) error {
	if err := onlyFields(o, "target", "mode", "needs", "folder"); err != nil {
		return err
	}
	if o.Folder != nil && (o.Mode != "" || o.Needs != "" || o.WritesAs != nil) {
		return fmt.Errorf("folder together with mode, needs or writes_as: folder.access and folder.runs_as replace them")
	}
	switch o.Mode {
	case "", "ro", "rw":
	default:
		return fmt.Errorf("mode %q must be ro or rw", o.Mode)
	}
	switch o.Needs {
	case "", "read", "write":
	default:
		return fmt.Errorf("needs %q must be read or write", o.Needs)
	}
	if o.Mode == "ro" && o.Needs == "write" {
		return fmt.Errorf("needs: write with mode: ro: the app could never write there")
	}
	return nil
}

func cleanHostPath(raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("want a host directory as a string, not %T", raw)
	}
	if strings.HasPrefix(s, FolderRefPrefix) {
		return "", fmt.Errorf("%q: %w", s, ErrFolderRef)
	}
	if err := templates.ValidatePathSetting(s); err != nil {
		return "", err
	}
	if !path.IsAbs(s) {
		return "", fmt.Errorf("path %q must be absolute", s)
	}
	c := path.Clean(s)
	if c == "/" {
		return "", fmt.Errorf("path %q: the host's / can't be mounted", s)
	}
	return c, nil
}

func (pathKind) Parse(_ *templates.Option, raw any) (Value, error) { return cleanHostPath(raw) }

func (pathKind) Display(_ *templates.Option, v Value) string { s, _ := v.(string); return s }

func (pathKind) Compare(*templates.Option, Value, Value) (int, bool) { return 0, false }

// HostPath is the host directory to bind-mount (re-checked: stored values
// are never trusted blindly).
func (pathKind) HostPath(_ *templates.Option, v Value) (string, error) { return cleanHostPath(v) }
