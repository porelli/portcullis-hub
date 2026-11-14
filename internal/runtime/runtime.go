// Package runtime is the Hub's runtime interface: everything the Hub does
// to app instances (bring them up and down, read their state, logs and
// events, exec, signal, move volume contents, run the shared-folder
// fixer) goes through Instances. The docker backend (runtime/docker)
// serves Docker and Podman with the compose CLI plus the Engine API; the
// kube backend (runtime/kube) serves Kubernetes.
package runtime

import (
	"context"
	"io"

	"github.com/compose-spec/compose-go/v2/types"
)

// Project is one instance's project: its name (portcullis-<instance>),
// the instance id, the compose invocation and (when loaded) the
// interpolated model with the instance's profiles applied.
type Project struct {
	Name, Instance string
	Files          ComposeFiles
	Model          *types.Project
	// Inputs are what a backend that doesn't read the host's files needs
	// besides the model (Kubernetes; nil under Docker and Podman).
	Inputs *ProjectInputs
}

// ProjectInputs carry an instance's files and facts into objects
// (Kubernetes: ConfigMaps, Secrets, Services).
type ProjectInputs struct {
	// Template is the template id; TemplateFiles the files compose binds
	// from ./templates/<template>/ (path relative to it → content).
	Template      string
	TemplateFiles map[string][]byte
	// AppFiles: a data file's bind source (as in the model) → the file.
	AppFiles map[string]AppFileInput
	// PersonSecrets: person_secret option key → <user>.nt → content.
	PersonSecrets map[string]map[string][]byte
	// LanOnly: published ports whose manifest port is lan_only;
	// LocalNetworks the Local networks (their source ranges).
	LanOnly       map[int]bool
	LocalNetworks []string
	// Jobs are the one-off jobs (§3).
	Jobs map[string]bool
	// VPNSlot / IngressService: a wired VPN provider's slot and the
	// service whose pod is its ingress (nil: not wired).
	VPNSlot        *int
	IngressService string
	// VPNOnly: the instance is VPN-only (its routes stay off websecure).
	VPNOnly bool
}

// AppFileInput is a data file (§13.7): its name, content, its secrets
// file's (nil: none) and the delivery revision.
type AppFileInput struct {
	Name, FileName string
	Data, Secrets  []byte
	Rev            string
}

// SecretDelivery is a person_secret option's hash files delivered into
// a running instance (Kubernetes: its *-pw Secret).
type SecretDelivery struct {
	Key            string
	Files          map[string][]byte
	Service, Mount string
	Rev            string
}

// FileDelivery is a data file delivered into a running instance
// (Kubernetes: its ConfigMap and Secret, then the mounted .rev waited
// for): the file, its secrets file (nil: none), the service mounting it
// at Mount, the revision.
type FileDelivery struct {
	Name, FileName string
	Data, Secrets  []byte
	Service, Mount string
	Rev            string
}

// Instances is the runtime as the Hub uses it. Every method but Kind, Env
// and Info answers the runtime guard's refusal while the runtime is not
// verified (503).
type Instances interface {
	Kind() Kind
	// Env is the environment the project is interpolated with (docker:
	// compose.Runner.Env, PassedEnv only).
	Env() []string
	Info(ctx context.Context) (Info, error)

	// Create creates the project's units without starting any (compose
	// up --no-start); Up starts them. onPull (nil = none) hears of image
	// pulls the runtime does itself (Kubernetes: pod events, sized
	// false); Docker pulls in Pull, before Create.
	Create(ctx context.Context, p Project) error
	Up(ctx context.Context, p Project, onPull func(svc string, done, total int64, sized bool)) error
	// Down takes the project down; volumes are kept.
	Down(ctx context.Context, p Project) error
	// DownByName takes a project down from its name alone (its files
	// may be gone or broken).
	DownByName(ctx context.Context, name string) error
	// Pull downloads ref unless present, reporting progress (the up's
	// images step).
	Pull(ctx context.Context, ref string, onBytes func(done, total int64, sized bool)) error

	List(ctx context.Context, f Filter) ([]Unit, error)
	Inspect(ctx context.Context, id string) (UnitInfo, error)
	Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error)
	Exec(ctx context.Context, id string, in ExecInput) (*ExecResult, error)
	ExecSplit(ctx context.Context, id string, in ExecInput) (*ExecSplitResult, error)
	ExecRunning(ctx context.Context, execID string) (bool, error)
	Signal(ctx context.Context, id, sig string) error
	State(ctx context.Context, id string) (State, error)
	Events(ctx context.Context, f Filter, fn func(Event)) error

	ListVolumes(ctx context.Context, f Filter) ([]Volume, error)
	InspectVolume(ctx context.Context, name string) (Volume, error)
	CreateVolume(ctx context.Context, v Volume) error
	RemoveVolume(ctx context.Context, name string) error
	// VolumeOut streams volume's content as a tar whose entries are under
	// path (the helper's mount point; closing it removes the helper);
	// VolumeIn extracts r (entries under path) into volume.
	VolumeOut(ctx context.Context, instance, volume, path string) (io.ReadCloser, error)
	VolumeIn(ctx context.Context, instance, volume, path string, r io.Reader) error
	// RemoveHelper removes a leftover helper (List with Filter.Helper).
	RemoveHelper(ctx context.Context, id string) error

	RunFixer(ctx context.Context, s FixerSpec, out func(tar io.Reader) error) (*RunResult, error)
	EnsureImage(ctx context.Context, ref string) error
}
