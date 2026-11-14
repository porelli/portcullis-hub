package runtime

import (
	"io"
	"net/netip"
	"strings"
	"time"
)

// Kind is the runtime core and its app instances run on (contract §6:
// HUB_CONTAINER_RUNTIME, from core's CONTAINER_RUNTIME).
type Kind string

const (
	KindDocker     Kind = "docker"
	KindPodman     Kind = "podman"
	KindKubernetes Kind = "kubernetes"
)

// ProjectPrefix starts every app instance's project name
// (portcullis-<instance id>); core's own project is "portcullis".
const ProjectPrefix = "portcullis-"

// ProjectName is the project name of instance id.
func ProjectName(id string) string { return ProjectPrefix + id }

// ComposeFiles identifies one compose project invocation (compose.Project
// is this type).
type ComposeFiles struct {
	Name       string   // -p
	Files      []string // -f (in order)
	ProjectDir string   // --project-directory (HOST path: the daemon resolves bind mounts there)
	EnvFile    string   // --env-file
}

// Unit is one running (or created, or ended) container of a project: on
// Docker/Podman a container, on Kubernetes a pod's container.
type Unit struct {
	ID string
	// Name is the primary container name (no leading "/"; the short id
	// when the runtime names none).
	Name string
	// Project and Service are the compose project and service labels;
	// Instance is the instance id the project names ("" for core's own
	// project and anything not portcullis-<id>).
	Project, Instance, Service string
	Image                      string
	// State is the runtime's run state word (created, running, exited,
	// restarting, paused, dead, …) and Status its human status text
	// ("Up 3 minutes (healthy)").
	State  string
	Status string
	Labels map[string]string
	// Created is the creation time (Unix seconds).
	Created int64
	// Networks: each network the container is attached to → the names
	// it answers to there (its aliases and DNS names, deduplicated).
	Networks map[string][]string
}

// Filter selects units, volumes or events. The zero Filter selects
// everything the runtime has; All selects every project's units (core's
// and every instance's); Instance one instance's (and Service one service
// of it); Helper the Hub's helpers.
type Filter struct {
	Instance, Service string
	Helper            bool
	All               bool
}

// State is a container's run state: running, and its healthcheck status
// ("" = no healthcheck; else starting, healthy or unhealthy); Status is
// the daemon's (created, running, exited, restarting, …) and ExitCode the
// last exit's (a finished one-shot: exited, 0).
type State struct {
	Running  bool
	Health   string
	Status   string
	ExitCode int
}

// ExecResult is the outcome of Exec.
type ExecResult struct {
	Output    []byte
	ExitCode  int // -1 if unknown (timeout / still running)
	TimedOut  bool
	Truncated bool
	// ExecID names the exec instance (ExecRunning: a timed-out process
	// may still run — Docker can't kill it).
	ExecID string
}

// ExecInput is one exec run: argv (never through a shell), the user to
// run as ("" = the container's), the stdin bytes and the timeout. NoStdin
// runs it with no stdin attached at all (a read-only console command, the
// doctor's probes; User and Stdin must be empty then).
type ExecInput struct {
	Cmd     []string
	User    string
	Stdin   []byte
	Timeout time.Duration
	NoStdin bool
}

// ExecSplitResult is the outcome of ExecSplit: stdout and stderr apart,
// each capped (MaxRunStdout / MaxRunStderr, the first bytes kept).
type ExecSplitResult struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int // -1 if unknown (timeout / still running)
	TimedOut        bool
	ExecID          string
}

// Event is the subset of a runtime event the Hub uses.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	TimeNano int64 `json:"timeNano"`
}

// Volume is the subset of a volume the Hub uses.
type Volume struct {
	Name    string
	Driver  string
	Labels  map[string]string
	Options map[string]string
}

// Network is a network with its subnets (the VPN overlap guard, contract
// §3.3).
type Network struct {
	Name    string
	Subnets []netip.Prefix
}

// BindMount is one host directory bound into a started helper (always the
// long form, Type bind; never Docker's CreateMountpoint, which would
// create a missing host path following host symlinks — ruling 23).
type BindMount struct {
	Source   string // host path, absolute and clean
	Target   string // container path
	ReadOnly bool
}

// FixerSpec is a started helper: the shared-folder fixer (contract §6).
// Every isolation field the runtime would otherwise take from the image or
// its defaults is set here.
type FixerSpec struct {
	// Image: an image ID (sha256:…) or a reference pinned by digest
	// (…@sha256:…); never a tag alone. The Hub's own image (fixer.go
	// selfImage).
	Image string
	// Cmd is the full argv, set as the Entrypoint (absolute path, no
	// shell); the container's Cmd stays empty.
	Cmd  []string
	User string // "0:0"
	// Env is added to the image's environment.
	Env []string
	// Binds are the only host paths the helper sees.
	Binds []BindMount
	// Scratch are anonymous volume targets ("/out", "/in"), removed with
	// the container.
	Scratch []string
	// CapAdd is added after CapDrop ALL (the fixer's caps only).
	CapAdd  []string
	Label   string // the helper label's value, e.g. "folder:photos"
	Pids    int64
	Memory  int64 // also the memory+swap limit: no swap
	Timeout time.Duration
	// InPath / In: a tar stream extracted at InPath before the start
	// ("" = none). OutPath: copied out as a tar after a 0 exit ("" = none).
	InPath  string
	In      io.Reader
	OutPath string
}

// RunResult is a finished helper: its exit code and demultiplexed output,
// stdout's last MaxRunStdout bytes and stderr's first MaxRunStderr.
type RunResult struct {
	ExitCode      int
	Stdout        []byte
	Stderr        []byte
	StdoutClipped bool
	StderrClipped bool
}

// Output caps of a started helper and of ExecSplit (contract §6: the
// report is the last stdout line, ≤ 256 KiB; stderr is for crashes only).
const (
	MaxRunStdout = 256 << 10
	MaxRunStderr = 16 << 10
)

// UnitInfo is the part of a unit's inspect the Hub uses.
type UnitInfo struct {
	ID     string
	Image  string // the image ID (sha256:…) the container runs
	Labels map[string]string
	// PidMode is HostConfig.PidMode ("host": the container sees the
	// host's processes; the doctor's gid check never reads it).
	PidMode string
	// Memory / PidsLimit: HostConfig's memory limit (bytes) and pids
	// limit (0 = none; -1 or unset read as 0): limits_not_enforced.
	Memory    int64
	PidsLimit int64
	// Privileged, CapAdd and Devices: HostConfig's (the doctor's
	// vpn_gateway_privileged).
	Privileged bool
	CapAdd     []string
	Devices    []string
}

// Info is what the runtime says about itself.
type Info struct {
	Kind Kind
	// Verified / Why: the runtime guard's state (Why: its refusal).
	Verified bool
	Why      string
	// ForbiddenRoots: no shared folder at, above or under any of them
	// (Docker's data root; on Kubernetes PORTCULLIS_RUNTIME_ROOTS).
	ForbiddenRoots []string
	// APIVersion is the engine's highest API version (Docker: volume
	// subpath mounts need 1.45, contract §6).
	APIVersion string
	// SecurityOptions are Docker's Info SecurityOptions (nil elsewhere);
	// SELinux and IDMapped are read from them (IDMapped: userns-remap or
	// rootless, Remapped names which).
	SecurityOptions []string
	SELinux         bool
	IDMapped        bool
	Remapped        string
	// Networks are the runtime's networks with their subnets (the VPN
	// overlap guard, contract §3.3; on Kubernetes the pod and service
	// CIDRs).
	Networks []Network
}

// SecurityOption reports whether Docker's SecurityOptions carry
// name=<name>.
func SecurityOption(opts []string, name string) bool {
	for _, o := range opts {
		for _, kv := range strings.Split(o, ",") {
			if k, v, _ := strings.Cut(kv, "="); k == "name" && v == name {
				return true
			}
		}
	}
	return false
}
