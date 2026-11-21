// Package agentapi is agent API v1 (contract §17): the wire types, the
// route table (one route per runtime.Instances method, pre-flight P8),
// the bundle rules and the scope checks shared by the worker's
// portcullis-agent and the Hub's agent backend. Every body either side
// reads is untrusted: decode with Decode (strict, capped) and the caps in
// limits.go.
//
// JSON conventions: snake_case keys; lists, maps, optional strings and
// booleans are omitempty (an empty list is absent, never null: the strict
// decoder refuses null), so whatever Marshal writes Decode reads.
package agentapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/usage"
)

// Version is the API version, the path prefix's segment (/v1).
const Version = "v1"

// Prefix starts every route.
const Prefix = "/" + Version

// Error is the error shape of every non-2xx answer: {"error"}, at most
// MaxError runes.
type Error struct {
	Error string `json:"error"`
	// Kind classifies the failure where the Hub must act on it (final
	// review B2): the Hub never reads the message for that.
	Kind string `json:"error_kind,omitempty"`
}

// ErrorKindNoPlatform: the image has no variant for the worker's
// platform (an architecture mismatch).
const ErrorKindNoPlatform = "no_platform"

// ErrorBody is msg as the error shape (redact before: this only clips).
func ErrorBody(msg string) []byte {
	if utf8.RuneCountInString(msg) > MaxError {
		r := []rune(msg)
		msg = string(r[:MaxError-1]) + "…"
	}
	b, _ := json.Marshal(Error{Error: msg})
	return b
}

// OpHeader names a long call (up, down, pull, the helpers) so the Hub's
// Stop can cancel it with DELETE /v1/ops/{op} (as stop_op; the op id is
// the Hub's, ^[0-9a-f]{16}$). A dropped connection cancels it too.
const OpHeader = "Portcullis-Op"

// Info is GET /v1/info (≤ MaxInfo): the agent, its engine (through
// socket-proxy-agent) and the worker host. Disk is DockerRootDir's, Data
// the agent's data dir's. PortBinds are the engine's published host
// ports (every container's, so the Hub can check collisions on this
// server; P10). Clock is the agent's time (the Hub reports skew).
type Info struct {
	AgentVersion string `json:"agent_version"`
	// API is the API version the agent serves (Version).
	API string `json:"api"`
	// Runtime is the engine kind, docker or podman (never kubernetes).
	Runtime       string `json:"runtime"`
	Arch          string `json:"arch"`
	EngineVersion string `json:"engine_version"`
	// EngineAPI is the engine's highest API version (runtime.Info
	// APIVersion: subpath mounts need 1.45).
	EngineAPI string `json:"engine_api,omitempty"`
	// Verified / Why: the agent's engine guard (as the Hub's: the
	// engine is the runtime the agent was configured with).
	Verified bool   `json:"verified,omitempty"`
	Why      string `json:"why,omitempty"`
	Rootless bool   `json:"rootless,omitempty"`
	// UIDMap / GIDMap: the engine's /proc/self/uid_map and gid_map text
	// under rootless Podman ("" otherwise).
	UIDMap   string `json:"uid_map,omitempty"`
	GIDMap   string `json:"gid_map,omitempty"`
	IDMapped bool   `json:"id_mapped,omitempty"`
	Remapped string `json:"remapped,omitempty"`
	CPUs     int    `json:"cpus"`
	MemBytes int64  `json:"mem_bytes"`
	// DockerRootDir is the engine's data root (a shared-folder
	// forbidden root, runtime.Info ForbiddenRoots).
	DockerRootDir string `json:"docker_root_dir"`
	DiskTotal     int64  `json:"disk_total"`
	DiskFree      int64  `json:"disk_free"`
	// DataDir is the agent's data dir, the same absolute path on the
	// host and in the agent (bundles live in <DataDir>/projects/<id>/).
	DataDir   string `json:"data_dir"`
	DataTotal int64  `json:"data_total"`
	DataFree  int64  `json:"data_free"`
	// SecurityOptions are the engine's (SELinux is read from them).
	SecurityOptions       []string `json:"security_options,omitempty"`
	SELinux               bool     `json:"selinux,omitempty"`
	UnprivilegedPortStart int      `json:"unprivileged_port_start"`
	// BindRoots are the worker's folder roots (PORTCULLIS_WORKER_BIND_ROOTS).
	BindRoots []string   `json:"bind_roots,omitempty"`
	PortBinds []PortBind `json:"port_binds,omitempty"`
	// Networks are the engine's networks with their subnets (the VPN
	// overlap guard, runtime.Info Networks).
	Networks []Network `json:"networks,omitempty"`
	Clock    time.Time `json:"clock"`
	// Quarantined: instance → why a container start failed the agent's
	// bind check (killed, taken down; refused until a new bundle).
	Quarantined map[string]string `json:"quarantined,omitempty"`
	// OwnProject is the agent's own compose project: no instance id may
	// map to it on this worker.
	OwnProject string `json:"own_project,omitempty"`
	// QuarantineError: the agent couldn't persist its quarantine (it
	// holds in memory; "" = none).
	QuarantineError string `json:"quarantine_error,omitempty"`
}

// PortBind is one published host port: the compose project and service
// labels ("" when not compose's), the host address, port and protocol.
type PortBind struct {
	Project  string `json:"project,omitempty"`
	Service  string `json:"service,omitempty"`
	HostIP   string `json:"host_ip,omitempty"`
	HostPort int    `json:"host_port"`
	Proto    string `json:"proto"`
}

// Network is one engine network with its subnets.
type Network struct {
	Name    string         `json:"name"`
	Subnets []netip.Prefix `json:"subnets,omitempty"`
}

// RuntimeInfo is info as runtime.Info (the agent backend's Info): kind
// from the agent's runtime word (anything but docker|podman is an error),
// the data root as the forbidden root.
func (i Info) RuntimeInfo() (runtime.Info, error) {
	k := runtime.Kind(i.Runtime)
	if k != runtime.KindDocker && k != runtime.KindPodman {
		return runtime.Info{}, fmt.Errorf("agent runtime %q: only docker or podman", i.Runtime)
	}
	out := runtime.Info{Kind: k, Verified: i.Verified, Why: i.Why, APIVersion: i.EngineAPI,
		SecurityOptions: i.SecurityOptions, SELinux: i.SELinux, IDMapped: i.IDMapped, Remapped: i.Remapped,
		EngineVersion: i.EngineVersion, CPUs: i.CPUs, MemoryBytes: i.MemBytes}
	if out.CPUs < 0 || out.MemoryBytes < 0 {
		// An untrusted answer: a negative size is no size.
		out.CPUs, out.MemoryBytes = 0, 0
	}
	if i.DockerRootDir != "" {
		out.ForbiddenRoots = []string{i.DockerRootDir}
	}
	for _, n := range i.Networks {
		out.Networks = append(out.Networks, runtime.Network{Name: n.Name, Subnets: n.Subnets})
	}
	return out, nil
}

// BundleManifest is a bundle's MANIFEST.json, the tar's first member
// (ReadBundle): Instance must be the path's id; Files maps every other
// regular file's path to its entry.
//
// Template is the instance's template id (the default instance's id is
// its template's), Volumes each compose volume key's engine name as the
// Hub derives it (§11.2, templates NamesFor): the only names the agent
// lets the model use (ValidateBundle).
type BundleManifest struct {
	Instance string               `json:"instance"`
	Template string               `json:"template"`
	Volumes  map[string]string    `json:"volumes,omitempty"`
	Files    map[string]FileEntry `json:"files"`
	// AdoptVolumes: the Hub knowingly brings existing volumes of the
	// instance into scope (an undo onto a kept copy, a kept copy's
	// removal). Without it a first bundle of an id the agent never held
	// is refused while volumes labelled with its project exist (final
	// review M1: never a silent adoption of an earlier instance's data).
	AdoptVolumes bool `json:"adopt_volumes,omitempty"`
}

// FileEntry is one bundle file: its sha256 (hex), permission bits (0–0777;
// the primary's modes) and size.
type FileEntry struct {
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
}

// Helper kinds (HelperSpec.Kind).
const (
	HelperVolumeIO  = "volume_io"
	HelperFolderFix = "folder_fix"
)

// HelperSpec is POST /v1/helpers (contract §17.4): volume_io (Instance,
// Volume, Path the helper's mount point, Write: VolumeIn, else
// VolumeOut) or folder_fix (Spec: RunFixer). The agent runs only fixed
// specs: the Hub's volume helper, and the fixer it rebuilds with its own
// builder and compares byte for byte (SameFixer), on its own image (P7).
type HelperSpec struct {
	Kind     string     `json:"kind"`
	Instance string     `json:"instance,omitempty"`
	Volume   string     `json:"volume,omitempty"`
	Path     string     `json:"path,omitempty"`
	Write    bool       `json:"write,omitempty"`
	Spec     *FixerSpec `json:"spec,omitempty"`
}

// HelperCreated is POST /v1/helpers' answer: the helper's id ({h}).
type HelperCreated struct {
	ID string `json:"id"`
}

// BindMount is runtime.BindMount on the wire.
type BindMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// VolumeMount is runtime.VolumeMount on the wire (a usage helper's one
// named volume, ux3).
type VolumeMount struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Instance string `json:"instance,omitempty"`
}

// FixerSpec is runtime.FixerSpec on the wire, without the image (the
// agent's own, P7) and without the In reader (the stream after the
// header). TimeoutMS is the timeout in milliseconds. Volumes: a usage
// run's named volume (ux3; absent otherwise, so the other modes'
// encodings are unchanged).
type FixerSpec struct {
	Cmd       []string      `json:"cmd"`
	User      string        `json:"user"`
	Env       []string      `json:"env,omitempty"`
	Binds     []BindMount   `json:"binds,omitempty"`
	Volumes   []VolumeMount `json:"volumes,omitempty"`
	Scratch   []string      `json:"scratch,omitempty"`
	CapAdd    []string      `json:"cap_add,omitempty"`
	Label     string        `json:"label"`
	Pids      int64         `json:"pids"`
	Memory    int64         `json:"memory"`
	TimeoutMS int64         `json:"timeout_ms"`
	InPath    string        `json:"in_path,omitempty"`
	OutPath   string        `json:"out_path,omitempty"`
}

// FixerSpecOf is s on the wire (Image and In dropped).
func FixerSpecOf(s runtime.FixerSpec) FixerSpec {
	out := FixerSpec{Cmd: s.Cmd, User: s.User, Env: s.Env, Scratch: s.Scratch, CapAdd: s.CapAdd, Label: s.Label,
		Pids: s.Pids, Memory: s.Memory, TimeoutMS: s.Timeout.Milliseconds(), InPath: s.InPath, OutPath: s.OutPath}
	for _, b := range s.Binds {
		out.Binds = append(out.Binds, BindMount{Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
	}
	for _, v := range s.Volumes {
		out.Volumes = append(out.Volumes, VolumeMount{Name: v.Name, Target: v.Target, Instance: v.Instance})
	}
	return out
}

// Runtime is f as a runtime.FixerSpec on image, reading in.
func (f FixerSpec) Runtime(image string, in io.Reader) runtime.FixerSpec {
	out := runtime.FixerSpec{Image: image, Cmd: f.Cmd, User: f.User, Env: f.Env, Scratch: f.Scratch, CapAdd: f.CapAdd,
		Label: f.Label, Pids: f.Pids, Memory: f.Memory, Timeout: time.Duration(f.TimeoutMS) * time.Millisecond,
		InPath: f.InPath, OutPath: f.OutPath}
	if f.InPath != "" {
		out.In = in
	}
	for _, b := range f.Binds {
		out.Binds = append(out.Binds, runtime.BindMount{Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
	}
	for _, v := range f.Volumes {
		out.Volumes = append(out.Volumes, runtime.VolumeMount{Name: v.Name, Target: v.Target, Instance: v.Instance})
	}
	return out
}

// Canonical is f's encoding (struct order, no indentation): what
// SameFixer compares.
func (f FixerSpec) Canonical() []byte {
	b, _ := json.Marshal(f)
	return b
}

// SameFixer: got is byte for byte the spec the agent built itself.
func SameFixer(got, built FixerSpec) bool { return bytes.Equal(got.Canonical(), built.Canonical()) }

// RunResult is runtime.RunResult on the wire (POST
// /v1/helpers/{h}/run; the out tar is then GET /v1/helpers/{h}/archive,
// only when OutPath is set and the exit code is 0).
type RunResult struct {
	ExitCode      int    `json:"exit_code"`
	Stdout        []byte `json:"stdout,omitempty"`
	Stderr        []byte `json:"stderr,omitempty"`
	StdoutClipped bool   `json:"stdout_clipped,omitempty"`
	StderrClipped bool   `json:"stderr_clipped,omitempty"`
}

// DataPreamble is the first line of a data connection on :7000, written
// by link (never by a relay): {"instance","service","port"}\n.
type DataPreamble struct {
	Instance string `json:"instance"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
}

// MaxPreamble bounds the preamble line.
const MaxPreamble = 1024

// Encode is the preamble line.
func (p DataPreamble) Encode() []byte {
	b, _ := json.Marshal(p)
	return append(b, '\n')
}

// ReadPreamble reads exactly the preamble line from r (byte by byte:
// nothing after the newline is consumed) and decodes it strictly. A port
// outside 1–65535 or an empty instance or service is refused.
func ReadPreamble(r io.Reader) (DataPreamble, error) {
	line, err := readLine(r, MaxPreamble)
	if err != nil {
		return DataPreamble{}, err
	}
	var p DataPreamble
	if err := jsonstrict.Decode(line, &p); err != nil {
		return DataPreamble{}, fmt.Errorf("data preamble: %v", err)
	}
	if p.Instance == "" || p.Service == "" || p.Port < 1 || p.Port > 65535 {
		return DataPreamble{}, errors.New("data preamble: instance, service and a port 1–65535 are required")
	}
	return p, nil
}

// readLine reads up to and without '\n', one byte at a time, at most max
// bytes before it.
func readLine(r io.Reader, max int) ([]byte, error) {
	var out []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				return out, nil
			}
			if len(out) >= max {
				return nil, ErrTooLarge
			}
			out = append(out, b[0])
			continue
		}
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
	}
}

// ProgressLine is one ndjson line of a long call (up: step, service,
// done, total; pull: done, total, sized), then exactly one last line with
// End set (Error and Status when it failed: the status the call would
// have answered, e.g. 409).
type ProgressLine struct {
	Step    string `json:"step,omitempty"`
	Service string `json:"service,omitempty"`
	Done    int64  `json:"done,omitempty"`
	Total   int64  `json:"total,omitempty"`
	Sized   bool   `json:"sized,omitempty"`
	End     bool   `json:"end,omitempty"`
	Error   string `json:"error,omitempty"`
	Status  int    `json:"status,omitempty"`
	// Kind classifies an end line's error (ErrorKindNoPlatform).
	Kind string `json:"error_kind,omitempty"`
}

// RefRequest names an image (POST /v1/images/pull, /v1/images/ensure).
// Preflight (pull only): the Hub's placement pre-pull before any bundle
// exists — the ref must be pinned by digest (contract §17.4).
type RefRequest struct {
	Ref       string `json:"ref"`
	Preflight bool   `json:"preflight,omitempty"`
}

// SignalRequest is POST /v1/containers/{cid}/signal.
type SignalRequest struct {
	Signal string `json:"signal"`
}

// ExecRequest is runtime.ExecInput on the wire (TimeoutMS milliseconds).
type ExecRequest struct {
	Cmd       []string `json:"cmd"`
	User      string   `json:"user,omitempty"`
	Stdin     []byte   `json:"stdin,omitempty"`
	TimeoutMS int64    `json:"timeout_ms"`
	NoStdin   bool     `json:"no_stdin,omitempty"`
}

// ExecRequestOf is in on the wire.
func ExecRequestOf(in runtime.ExecInput) ExecRequest {
	return ExecRequest{Cmd: in.Cmd, User: in.User, Stdin: in.Stdin, TimeoutMS: in.Timeout.Milliseconds(), NoStdin: in.NoStdin}
}

// Runtime is r as runtime.ExecInput.
func (r ExecRequest) Runtime() runtime.ExecInput {
	return runtime.ExecInput{Cmd: r.Cmd, User: r.User, Stdin: r.Stdin, Timeout: time.Duration(r.TimeoutMS) * time.Millisecond, NoStdin: r.NoStdin}
}

// ExecResult is runtime.ExecResult on the wire.
type ExecResult struct {
	Output    []byte `json:"output,omitempty"`
	ExitCode  int    `json:"exit_code"`
	TimedOut  bool   `json:"timed_out,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	ExecID    string `json:"exec_id,omitempty"`
}

// ExecSplitResult is runtime.ExecSplitResult on the wire.
type ExecSplitResult struct {
	Stdout          []byte `json:"stdout,omitempty"`
	Stderr          []byte `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	ExitCode        int    `json:"exit_code"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	ExecID          string `json:"exec_id,omitempty"`
}

// ExecRunning is GET /v1/execs/{eid}.
type ExecRunning struct {
	Running bool `json:"running,omitempty"`
}

// Unit is runtime.Unit on the wire.
type Unit struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Project  string              `json:"project,omitempty"`
	Instance string              `json:"instance,omitempty"`
	Service  string              `json:"service,omitempty"`
	Image    string              `json:"image,omitempty"`
	State    string              `json:"state,omitempty"`
	Status   string              `json:"status,omitempty"`
	Labels   map[string]string   `json:"labels,omitempty"`
	Created  int64               `json:"created,omitempty"`
	Networks map[string][]string `json:"networks,omitempty"`
	// NamesUnread: the names were asked for (names=1) and couldn't be read.
	NamesUnread bool `json:"names_unread,omitempty"`
}

// UnitOf / Runtime convert units. A network without aliases (a created,
// never started container's) is an empty list on the wire, never null
// (the strict decoder refuses null).
func UnitOf(u runtime.Unit) Unit {
	nets := u.Networks
	if nets != nil {
		nets = make(map[string][]string, len(u.Networks))
		for n, a := range u.Networks {
			if a == nil {
				a = []string{}
			}
			nets[n] = a
		}
	}
	return Unit{ID: u.ID, Name: u.Name, Project: u.Project, Instance: u.Instance, Service: u.Service, Image: u.Image,
		State: u.State, Status: u.Status, Labels: u.Labels, Created: u.Created, Networks: nets, NamesUnread: u.NamesUnread}
}

func (u Unit) Runtime() runtime.Unit {
	return runtime.Unit{ID: u.ID, Name: u.Name, Project: u.Project, Instance: u.Instance, Service: u.Service, Image: u.Image,
		State: u.State, Status: u.Status, Labels: u.Labels, Created: u.Created, Networks: u.Networks, NamesUnread: u.NamesUnread}
}

// UnitInfo is runtime.UnitInfo on the wire.
type UnitInfo struct {
	ID         string            `json:"id"`
	Image      string            `json:"image"`
	Labels     map[string]string `json:"labels,omitempty"`
	PidMode    string            `json:"pid_mode,omitempty"`
	Memory     int64             `json:"memory,omitempty"`
	PidsLimit  int64             `json:"pids_limit,omitempty"`
	Privileged bool              `json:"privileged,omitempty"`
	CapAdd     []string          `json:"cap_add,omitempty"`
	Devices    []string          `json:"devices,omitempty"`
}

func UnitInfoOf(u runtime.UnitInfo) UnitInfo {
	return UnitInfo{ID: u.ID, Image: u.Image, Labels: u.Labels, PidMode: u.PidMode, Memory: u.Memory, PidsLimit: u.PidsLimit,
		Privileged: u.Privileged, CapAdd: u.CapAdd, Devices: u.Devices}
}

func (u UnitInfo) Runtime() runtime.UnitInfo {
	return runtime.UnitInfo{ID: u.ID, Image: u.Image, Labels: u.Labels, PidMode: u.PidMode, Memory: u.Memory, PidsLimit: u.PidsLimit,
		Privileged: u.Privileged, CapAdd: u.CapAdd, Devices: u.Devices}
}

// State is runtime.State on the wire.
type State struct {
	Running  bool   `json:"running,omitempty"`
	Health   string `json:"health,omitempty"`
	Status   string `json:"status,omitempty"`
	ExitCode int    `json:"exit_code"`
}

func StateOf(s runtime.State) State {
	return State{Running: s.Running, Health: s.Health, Status: s.Status, ExitCode: s.ExitCode}
}

func (s State) Runtime() runtime.State {
	return runtime.State{Running: s.Running, Health: s.Health, Status: s.Status, ExitCode: s.ExitCode}
}

// Event is runtime.Event on the wire (one ndjson line of GET /v1/events).
type Event struct {
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	ActorID    string            `json:"actor_id,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	TimeNano   int64             `json:"time_nano"`
}

func EventOf(e runtime.Event) Event {
	return Event{Type: e.Type, Action: e.Action, ActorID: e.Actor.ID, Attributes: e.Actor.Attributes, TimeNano: e.TimeNano}
}

func (e Event) Runtime() runtime.Event {
	var out runtime.Event
	out.Type, out.Action, out.TimeNano = e.Type, e.Action, e.TimeNano
	out.Actor.ID, out.Actor.Attributes = e.ActorID, e.Attributes
	return out
}

// Volume is runtime.Volume on the wire.
type Volume struct {
	Name    string            `json:"name"`
	Driver  string            `json:"driver,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

func VolumeOf(v runtime.Volume) Volume {
	return Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels, Options: v.Options}
}

func (v Volume) Runtime() runtime.Volume {
	return runtime.Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels, Options: v.Options}
}

// Filter query parameters (List, Events, ListVolumes).
const (
	QueryInstance = "instance"
	QueryService  = "service"
	QueryHelper   = "helper"
	QueryAll      = "all"
	QueryNames    = "names"
)

// FilterQuery is f as query parameters (booleans as "1").
func FilterQuery(f runtime.Filter) map[string]string {
	q := map[string]string{}
	if f.Instance != "" {
		q[QueryInstance] = f.Instance
	}
	if f.Service != "" {
		q[QueryService] = f.Service
	}
	if f.Helper {
		q[QueryHelper] = "1"
	}
	if f.All {
		q[QueryAll] = "1"
	}
	if f.Names {
		q[QueryNames] = "1"
	}
	return q
}

// ParseFilter is FilterQuery's inverse, strict: unknown or repeated
// parameters, booleans other than "1", and a service without an instance
// are refused.
func ParseFilter(q map[string][]string) (runtime.Filter, error) {
	var f runtime.Filter
	for k, vs := range q {
		if len(vs) != 1 {
			return f, fmt.Errorf("query parameter %s: exactly once", k)
		}
		v := vs[0]
		switch k {
		case QueryInstance:
			f.Instance = v
		case QueryService:
			f.Service = v
		case QueryHelper, QueryAll, QueryNames:
			if v != "1" {
				return f, fmt.Errorf("query parameter %s: only 1", k)
			}
			switch k {
			case QueryHelper:
				f.Helper = true
			case QueryAll:
				f.All = true
			default:
				f.Names = true
			}
		default:
			return f, fmt.Errorf("unknown query parameter %q", strings.ToValidUTF8(k, "?"))
		}
	}
	if f.Service != "" && f.Instance == "" {
		return f, errors.New("query parameter service needs instance")
	}
	return f, nil
}

// Enrolment and identity bodies (contract §17; pre-flight P5/P6 order:
// nonce → proof → CSR → sign → PUT cert → PUT network → PUT wg).

// B64URL is bytes as base64url without padding (strict) on the wire.
type B64URL []byte

func (b B64URL) MarshalText() ([]byte, error) {
	return []byte(base64.RawURLEncoding.EncodeToString(b)), nil
}

func (b *B64URL) UnmarshalText(t []byte) error {
	d, err := base64.RawURLEncoding.Strict().DecodeString(string(t))
	if err != nil {
		return errors.New("not base64url without padding")
	}
	*b = d
	return nil
}

// EnrolNonce is GET /v1/enrol/nonce: servers.NonceLen random bytes
// (single use, valid 60 s).
type EnrolNonce struct {
	Nonce B64URL `json:"nonce"`
}

// EnrolProof is POST /v1/enrol: servers.Proof over the nonce and the
// agent's enrolling certificate SPKI, and the CN the CSR must carry
// (<id>.node.portcullis.internal). A good proof answers IdentityCSR.
type EnrolProof struct {
	Proof B64URL `json:"proof"`
	CSRCN string `json:"csr_cn"`
}

// IdentityCSR is the answer of POST /v1/enrol and POST
// /v1/identity/csr: a PEM CSR for the agent's new TLS key and its new
// WireGuard public key (private keys never leave the worker).
type IdentityCSR struct {
	CSR         string `json:"csr"`
	WGPublicKey string `json:"wg_public_key"`
}

// IdentityCert is PUT /v1/identity/cert: the signed node-worker
// certificate (PEM) and the pki_node CA (PEM; sha256 of its DER is the
// join code's ca_sha256).
type IdentityCert struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// NetworkParams is PUT /v1/network (once, at enrolment; contract §17.7):
// the worker's portcullis-proxy subnet and dynamic range and the address
// the agent pins itself at (the primary's PORTCULLIS_PROXY_SUBNET,
// PORTCULLIS_PROXY_IP_RANGE and PORTCULLIS_TRAEFIK_IP).
type NetworkParams struct {
	ProxySubnet  netip.Prefix `json:"proxy_subnet"`
	ProxyIPRange netip.Prefix `json:"proxy_ip_range"`
	TraefikIP    netip.Addr   `json:"traefik_ip"`
}

// IdentityWG is PUT /v1/identity/wg: the link's public key the agent
// keeps as its peer when it switches to its own WireGuard key.
type IdentityWG struct {
	LinkPub string `json:"link_pub"`
}

// UnitStats is runtime.UnitStats on the wire (GET
// /v1/containers/{cid}/stats, ux3): every counter the engine left out is
// absent (never null, never 0).
type UnitStats struct {
	Read            time.Time `json:"read"`
	CPUUsageNS      *uint64   `json:"cpu_usage_ns,omitempty"`
	CPUCores        *float64  `json:"cpu_cores,omitempty"`
	MemUsage        *uint64   `json:"mem_usage,omitempty"`
	MemInactiveFile *uint64   `json:"mem_inactive_file,omitempty"`
	MemWorkingSet   *uint64   `json:"mem_working_set,omitempty"`
	Pids            *uint64   `json:"pids,omitempty"`
	NetRx           *uint64   `json:"net_rx,omitempty"`
	NetTx           *uint64   `json:"net_tx,omitempty"`
	BlkRead         *uint64   `json:"blk_read,omitempty"`
	BlkWrite        *uint64   `json:"blk_write,omitempty"`
}

func UnitStatsOf(s runtime.UnitStats) UnitStats {
	return UnitStats{Read: s.Read, CPUUsageNS: s.CPUUsageNS, CPUCores: s.CPUCores, MemUsage: s.MemUsage, MemInactiveFile: s.MemInactiveFile,
		MemWorkingSet: s.MemWorkingSet, Pids: s.Pids, NetRx: s.NetRx, NetTx: s.NetTx, BlkRead: s.BlkRead, BlkWrite: s.BlkWrite}
}

func (s UnitStats) Runtime() runtime.UnitStats {
	return runtime.UnitStats{Read: s.Read, CPUUsageNS: s.CPUUsageNS, CPUCores: s.CPUCores, MemUsage: s.MemUsage, MemInactiveFile: s.MemInactiveFile,
		MemWorkingSet: s.MemWorkingSet, Pids: s.Pids, NetRx: s.NetRx, NetTx: s.NetTx, BlkRead: s.BlkRead, BlkWrite: s.BlkWrite}
}

// Check refuses a sample no engine gives (an untrusted worker's answer):
// no read time, a negative or non-finite CPU rate.
func (s UnitStats) Check() error {
	switch {
	case s.Read.IsZero():
		return errors.New("agent API: stats without a read time")
	case s.CPUCores != nil && (*s.CPUCores < 0 || math.IsNaN(*s.CPUCores) || math.IsInf(*s.CPUCores, 0)):
		return errors.New("agent API: stats with a bad CPU rate")
	}
	return nil
}

// SizeBody is a size answer (GET /v1/containers/{cid}/size, GET
// /v1/images/size, ux3): bytes, never negative.
type SizeBody struct {
	Bytes int64 `json:"bytes"`
}

// HostCounters is usage.HostCounters on the wire (GET /v1/host/usage,
// ux3): the worker's own procfs counters.
type HostCounters struct {
	At           time.Time `json:"at"`
	CPUTotal     uint64    `json:"cpu_total"`
	CPUIdle      uint64    `json:"cpu_idle"`
	MemTotal     int64     `json:"mem_total"`
	MemAvailable int64     `json:"mem_available"`
	DiskRead     uint64    `json:"disk_read"`
	DiskWrite    uint64    `json:"disk_write"`
}

func HostCountersOf(c usage.HostCounters) HostCounters {
	return HostCounters{At: c.At, CPUTotal: c.CPUTotal, CPUIdle: c.CPUIdle, MemTotal: c.MemTotal, MemAvailable: c.MemAvailable, DiskRead: c.DiskRead, DiskWrite: c.DiskWrite}
}

func (c HostCounters) Usage() usage.HostCounters {
	return usage.HostCounters{At: c.At, CPUTotal: c.CPUTotal, CPUIdle: c.CPUIdle, MemTotal: c.MemTotal, MemAvailable: c.MemAvailable, DiskRead: c.DiskRead, DiskWrite: c.DiskWrite}
}

// Check refuses counters no procfs gives (an untrusted worker's answer):
// no time, no CPU ticks or more idle than total, memory out of range
// (MemTotal 0 / MemAvailable −1: not read, as ReadHost leaves them).
func (c HostCounters) Check() error {
	switch {
	case c.At.IsZero():
		return errors.New("agent API: host counters without a time")
	case c.CPUTotal == 0 || c.CPUIdle > c.CPUTotal:
		return errors.New("agent API: host CPU ticks out of range")
	case c.MemTotal < 0 || c.MemAvailable < -1 || (c.MemTotal > 0 && c.MemAvailable > c.MemTotal):
		return errors.New("agent API: host memory out of range")
	}
	return nil
}
