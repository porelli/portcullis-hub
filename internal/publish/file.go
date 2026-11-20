package publish

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/portcullis/hub/internal/fsutil"
)

// fileModes are today's file modes (contract §4, §4.1, §4.2, §8.1, §10,
// §16): the group-gate and Keycloak files 0644 (read as another user
// from a read-only mount), the mcp-gate files 0640 (group 10001 through
// the setgid volume) and vpn.json 0640 in its own group.
var fileModes = map[Doc]os.FileMode{
	GroupGatePolicy: 0644,
	UserAttributes:  0644,
	PortalApps:      0644,
	SignInKeycloak:  0644,
	Impersonation:   0644,
	MCPGate:         0640,
	MCPCredentials:  0640,
	VPN:             0640,
}

// FileSink writes each document to Dirs[d]/<key> atomically (temp file
// + rename, through the write gate), with today's mode and, when GID has
// d, that group set before the rename. Docker and Podman: the readers
// mount the directories; on Kubernetes the Hub keeps the same files on
// its own volume for its own reads (no reader mounts it).
type FileSink struct {
	Dirs map[Doc]string
	GID  map[Doc]int
}

func (s FileSink) path(d Doc) (string, error) {
	if !Known(d) {
		return "", fmt.Errorf("publish: unknown document %q", d)
	}
	dir := s.Dirs[d]
	if dir == "" {
		return "", fmt.Errorf("publish: no directory for %s", d)
	}
	return filepath.Join(dir, Spec(d).Key), nil
}

// Has: d has a directory.
func (s FileSink) Has(d Doc) bool { return s.Dirs[d] != "" }

func (s FileSink) Publish(_ context.Context, d Doc, data []byte) (string, error) {
	if err := Check(d, data, 0); err != nil {
		return "", err
	}
	p, err := s.path(d)
	if err != nil {
		return "", err
	}
	if gid, ok := s.GID[d]; ok {
		err = fsutil.WriteFileAtomicGroup(p, data, fileModes[d], gid)
	} else {
		err = fsutil.WriteFileAtomic(p, data, fileModes[d])
	}
	if err != nil {
		return "", err
	}
	return Rev(data), nil
}

// Confirmed: a renamed file is what every reader reads next.
func (s FileSink) Confirmed(context.Context, Doc, string) (bool, error) { return true, nil }

// Remove removes the file (missing is fine).
func (s FileSink) Remove(_ context.Context, d Doc) error {
	p, err := s.path(d)
	if err != nil {
		return err
	}
	if err := fsutil.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
