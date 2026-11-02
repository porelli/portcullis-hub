package docker

import (
	"context"
	"fmt"
	"io"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// Labels compose sets on the volumes it creates.
const (
	LabelVolume = "com.docker.compose.volume"
	// LabelHelper marks the Hub's volume I/O helper containers (value:
	// the instance id they serve).
	LabelHelper = "io.portcullis.hub.helper"
)

// Volume is the subset of a Docker volume the Hub uses.
type Volume struct {
	Name    string
	Driver  string
	Labels  map[string]string
	Options map[string]string
}

// ListVolumes lists the volumes matching f (e.g. a label filter).
func (c *Client) ListVolumes(ctx context.Context, f Filters) ([]Volume, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.VolumeList(ctx, client.VolumeListOptions{Filters: f.sdk()})
	if err != nil {
		return nil, err
	}
	out := make([]Volume, 0, len(res.Items))
	for _, v := range res.Items {
		out = append(out, Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels, Options: v.Options})
	}
	return out, nil
}

// InspectVolume returns one volume (IsNotFound when it doesn't exist).
func (c *Client) InspectVolume(ctx context.Context, name string) (Volume, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err != nil {
		return Volume{}, err
	}
	v := res.Volume
	return Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels, Options: v.Options}, nil
}

// CreateVolume creates a volume (driver "" = local).
func (c *Client) CreateVolume(ctx context.Context, v Volume) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := c.api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: v.Name, Driver: v.Driver, DriverOpts: v.Options, Labels: v.Labels})
	return err
}

// RemoveVolume removes a volume (never forced: a volume still in use is
// an error). A missing volume is IsNotFound.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := c.api.VolumeRemove(ctx, name, client.VolumeRemoveOptions{})
	return err
}

// EnsureImage pulls ref unless the daemon already has it. ref should be
// pinned by digest (name:tag@sha256:…): the daemon then fetches exactly
// that content.
func (c *Client) EnsureImage(ctx context.Context, ref string) error {
	ictx, cancel := context.WithTimeout(ctx, requestTimeout)
	_, err := c.api.ImageInspect(ictx, ref)
	cancel()
	if err == nil {
		return nil
	}
	if !IsNotFound(err) {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*requestTimeout)
	defer cancel()
	resp, err := c.api.ImagePull(pctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer resp.Close()
	if err := resp.Wait(pctx); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

// HelperSpec is a volume I/O helper container: created, never started.
// The daemon reads and writes the mounted volumes itself (the archive
// endpoints), so no process ever runs in it.
type HelperSpec struct {
	Image string
	// Volumes maps volume names to mount targets.
	Volumes map[string]string
	// ReadOnly mounts the volumes read-only and makes the rootfs
	// read-only (backups). Restores need a writable rootfs: the daemon
	// refuses an archive upload to "/" otherwise, and only an upload to
	// "/" applies the volume root's own owner and mode.
	ReadOnly bool
	// Instance is the instance the helper serves (LabelHelper).
	Instance string
}

// CreateHelper creates a helper container (see HelperSpec): no network,
// every capability dropped, no-new-privileges, nobody's uid, only the
// given volumes (no copy-up of image content into them). Returns its id.
func (c *Client) CreateHelper(ctx context.Context, s HelperSpec) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	mounts := make([]mount.Mount, 0, len(s.Volumes))
	for name, target := range s.Volumes {
		mounts = append(mounts, mount.Mount{Type: mount.TypeVolume, Source: name, Target: target, ReadOnly: s.ReadOnly,
			VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
	}
	pids := int64(8)
	res, err := c.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:           s.Image,
			Entrypoint:      []string{"/bin/true"},
			User:            "65534:65534",
			NetworkDisabled: true,
			Labels:          map[string]string{LabelHelper: s.Instance},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    "none",
			ReadonlyRootfs: s.ReadOnly,
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			Mounts:         mounts,
			Resources:      container.Resources{PidsLimit: &pids, Memory: 32 << 20},
		},
	})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

// RemoveContainer force-removes a container (its anonymous volumes too;
// named volumes are never removed).
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := c.api.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return err
}

// CopyFromContainer streams path of container id as a tar (entries
// prefixed with path's base name, numeric owners, modes and mtimes as on
// disk). Bounded by ctx only. The caller closes the reader.
func (c *Client) CopyFromContainer(ctx context.Context, id, path string) (io.ReadCloser, error) {
	res, err := c.api.CopyFromContainer(ctx, id, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		return nil, err
	}
	return res.Content, nil
}

// CopyToContainer extracts the tar content at path in container id; the
// entries' owners are applied as in the archive (no copyUIDGID), an
// existing directory is never replaced by a file. Bounded by ctx only.
func (c *Client) CopyToContainer(ctx context.Context, id, path string, content io.Reader) error {
	_, err := c.api.CopyToContainer(ctx, id, client.CopyToContainerOptions{DestinationPath: path, Content: content})
	return err
}
