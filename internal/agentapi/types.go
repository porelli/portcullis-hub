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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/runtime"
)

// Version is the API version, the path prefix's segment (/v1).
const Version = "v1"

// Prefix starts every route.
const Prefix = "/" + Version

// Error is the error shape of every non-2xx answer: {"error"}, at most
// MaxError runes.
type Error struct {
	Error string `json:"error"`
}

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
		EngineVersion: i.EngineVersion}
	if i.DockerRootDir != "" {
		out.ForbiddenRoots = []string{i.DockerRootDir}
	}
	for _, n := range i.Networks {
		out.Networks = append(out.Networks, runtime.Network{Name: n.Name, Subnets: n.Subnets})
	}
	return out, nil
}

// BundleManifest is the sha256 manifest of a bundle: the body of PUT
// /v1/projects/{id}/bundle is the manifest as one JSON line (ReadHeader),
// then the tar (ReadBundle). Instance must be the path's id; Files maps
// every regular file's path to its entry.
type BundleManifest struct {
	Instance string               `json:"instance"`
	Files    map[string]FileEntry `json:"files"`
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

// Volume IO directions (HelperSpec.Mode).
const (
	VolumeOut = "out"
	VolumeIn  = "in"
)

// HelperSpec is the first line of a helper call (WriteHeader /
// ReadHeader), then the stream: volume_io (Instance, Volume, Path the
// helper's mount point, Mode out|in: VolumeOut / VolumeIn) or folder_fix
// (Fixer: RunFixer). The agent runs only its own fixed specs: it rebuilds
// a folder_fix spec with its own builder and compares the encodings byte
// for byte (SameFixer), and runs it on its own image (P7).
type HelperSpec struct {
	Kind     string     `json:"kind"`
	Instance string     `json:"instance,omitempty"`
	Volume   string     `json:"volume,omitempty"`
	Path     string     `json:"path,omitempty"`
	Mode     string     `json:"mode,omitempty"`
	Fixer    *FixerSpec `json:"fixer,omitempty"`
}

// BindMount is runtime.BindMount on the wire.
type BindMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// FixerSpec is runtime.FixerSpec on the wire, without the image (the
// agent's own, P7) and without the In reader (the stream after the
// header). TimeoutMS is the timeout in milliseconds.
type FixerSpec struct {
	Cmd       []string    `json:"cmd"`
	User      string      `json:"user"`
	Env       []string    `json:"env,omitempty"`
	Binds     []BindMount `json:"binds,omitempty"`
	Scratch   []string    `json:"scratch,omitempty"`
	CapAdd    []string    `json:"cap_add,omitempty"`
	Label     string      `json:"label"`
	Pids      int64       `json:"pids"`
	Memory    int64       `json:"memory"`
	TimeoutMS int64       `json:"timeout_ms"`
	InPath    string      `json:"in_path,omitempty"`
	OutPath   string      `json:"out_path,omitempty"`
}

// FixerSpecOf is s on the wire (Image and In dropped).
func FixerSpecOf(s runtime.FixerSpec) FixerSpec {
	out := FixerSpec{Cmd: s.Cmd, User: s.User, Env: s.Env, Scratch: s.Scratch, CapAdd: s.CapAdd, Label: s.Label,
		Pids: s.Pids, Memory: s.Memory, TimeoutMS: s.Timeout.Milliseconds(), InPath: s.InPath, OutPath: s.OutPath}
	for _, b := range s.Binds {
		out.Binds = append(out.Binds, BindMount{Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
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
// /v1/helpers/folder-fix: the first response line, then the out tar when
// OutPath is set and the exit code is 0).
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

// WriteHeader writes v as one JSON line (the header of a header + stream
// body).
func WriteHeader(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadHeader decodes the first line of r (≤ MaxJSON) strictly into v and
// returns the rest of the stream.
func ReadHeader(r io.Reader, v any) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	line, err := br.ReadSlice('\n')
	var full []byte
	for errors.Is(err, bufio.ErrBufferFull) {
		full = append(full, line...)
		if len(full) > MaxJSON {
			return nil, ErrTooLarge
		}
		line, err = br.ReadSlice('\n')
	}
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	full = append(full, line[:len(line)-1]...)
	if len(full) > MaxJSON {
		return nil, ErrTooLarge
	}
	if err := jsonstrict.Decode(full, v); err != nil {
		return nil, fmt.Errorf("agent API: header: %v", err)
	}
	return br, nil
}

// ProgressLine is one ndjson line of a long call (up, pull): progress of
// a service's image (Service, Done/Total bytes, Sized), then exactly one
// last line with End set (Error and Status when it failed: the status the
// call would have answered, e.g. 409).
type ProgressLine struct {
	Service string `json:"service,omitempty"`
	Done    int64  `json:"done,omitempty"`
	Total   int64  `json:"total,omitempty"`
	Sized   bool   `json:"sized,omitempty"`
	End     bool   `json:"end,omitempty"`
	Error   string `json:"error,omitempty"`
	Status  int    `json:"status,omitempty"`
}

// RefRequest names an image (POST /v1/images/pull, /v1/images/ensure).
type RefRequest struct {
	Ref string `json:"ref"`
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
}

// UnitOf / Runtime convert units.
func UnitOf(u runtime.Unit) Unit {
	return Unit{ID: u.ID, Name: u.Name, Project: u.Project, Instance: u.Instance, Service: u.Service, Image: u.Image,
		State: u.State, Status: u.Status, Labels: u.Labels, Created: u.Created, Networks: u.Networks}
}

func (u Unit) Runtime() runtime.Unit {
	return runtime.Unit{ID: u.ID, Name: u.Name, Project: u.Project, Instance: u.Instance, Service: u.Service, Image: u.Image,
		State: u.State, Status: u.Status, Labels: u.Labels, Created: u.Created, Networks: u.Networks}
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
		case QueryHelper, QueryAll:
			if v != "1" {
				return f, fmt.Errorf("query parameter %s: only 1", k)
			}
			if k == QueryHelper {
				f.Helper = true
			} else {
				f.All = true
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

// EnrolNonce is GET /v1/enrol/nonce: servers.NonceLen random bytes.
type EnrolNonce struct {
	Nonce []byte `json:"nonce"`
}

// EnrolProof is POST /v1/enrol: the server id and servers.Proof over the
// nonce and the agent's enrolling certificate SPKI.
type EnrolProof struct {
	ServerID string `json:"server_id"`
	Nonce    []byte `json:"nonce"`
	Proof    []byte `json:"proof"`
}

// IdentityCSR is POST /v1/identity/csr's answer: a PEM CSR for the
// agent's new TLS key (CN/SAN <id>.node.portcullis.internal) and the
// agent's new WireGuard public key (private keys never leave the worker).
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

// NetworkParams is PUT /v1/network (once, at enrolment): the worker's
// portcullis-proxy subnet and the address the agent pins itself at (the
// primary's PORTCULLIS_PROXY_SUBNET / PORTCULLIS_TRAEFIK_IP).
type NetworkParams struct {
	ProxySubnet netip.Prefix `json:"proxy_subnet"`
	TraefikIP   netip.Addr   `json:"traefik_ip"`
}
